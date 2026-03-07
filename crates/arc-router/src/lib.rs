use arc_common::{ArcError, Result};
use std::cmp::Ordering;
use std::collections::HashSet;

/// Router maps request paths to a u32 route id.
///
/// `insert()` validates and compiles patterns. `at()` performs allocation-free matching.
#[derive(Debug, Clone)]
pub struct Router {
    // Fast path: literal exact and literal prefix (`/*`) patterns are stored in this radix tree.
    nodes: Vec<Node>,

    // Complex patterns (params / segment-globs / segment wildcards) and an index by literal prefix.
    complex: Vec<ComplexPattern>,
    complex_index: RadixMulti,

    // Used to reject clearly ambiguous duplicates (e.g. `/user/:id/profile` vs `/user/:name/profile`).
    complex_sig: HashSet<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct Node {
    prefix: Box<[u8]>,
    edges: Box<[Edge]>,
    value: Option<u32>,          // exact match
    wildcard_value: Option<u32>, // `/*` prefix wildcard match (boundary-checked)
}

#[derive(Debug, Clone)]
struct Edge {
    b: u8,
    child: u32,
}

impl Router {
    pub fn new() -> Self {
        Self {
            nodes: vec![Node {
                prefix: Box::new([]),
                edges: Box::new([]),
                value: None,
                wildcard_value: None,
            }],
            complex: Vec::new(),
            complex_index: RadixMulti::new(),
            complex_sig: HashSet::new(),
        }
    }

    pub fn insert(&mut self, path_pat: &str, value: u32) -> Result<()> {
        if !path_pat.starts_with('/') {
            return Err(ArcError::config(format!(
                "route path must start with '/': {path_pat}"
            )));
        }
        if path_pat.as_bytes().iter().any(|&b| b == b'?' || b == b'#') {
            return Err(ArcError::config(format!(
                "route path must not include '?' or '#': {path_pat}"
            )));
        }

        // `/*` suffix: prefix wildcard
        let (base, is_prefix_wildcard) = match path_pat.strip_suffix("/*") {
            Some(base) => (base, true),
            None => (path_pat, false),
        };

        // Tokenize segments (compile time only; allocations here are OK).
        let mut seg_tokens: Vec<SegToken<'_>> = Vec::new();
        let mut has_special = false;

        for seg in base.split('/').skip(1) {
            let tok = classify_segment(seg)?;
            has_special |= tok.is_special();
            seg_tokens.push(tok);
        }

        // Literal-only patterns stay on the fast radix path.
        if !has_special {
            return self.insert_bytes(base.as_bytes(), is_prefix_wildcard, value);
        }

        // Compile as a complex pattern.
        let mut kind = if is_prefix_wildcard {
            PatternKind::Prefix
        } else {
            PatternKind::Exact
        };

        // Convert SegToken -> Seg, enforcing `**` constraints if present.
        let mut segs: Vec<Seg> = Vec::with_capacity(seg_tokens.len());
        for (i, tok) in seg_tokens.iter().enumerate() {
            if matches!(tok, SegToken::DeepStar) {
                // For now: `**` is only supported as the LAST segment; it behaves like a prefix.
                if i + 1 != seg_tokens.len() {
                    return Err(ArcError::config(format!(
                        "path glob '**' is only supported as the last segment: {path_pat}"
                    )));
                }
                kind = PatternKind::Prefix;
                // do not push `**` segment itself; prefix semantics cover it
                continue;
            }

            segs.push(compile_segment(tok)?);
        }

        let segs: Box<[Seg]> = segs.into_boxed_slice();

        // Build a normalized signature to reject obvious ambiguous duplicates.
        let sig = build_signature(kind, &segs);
        if !self.complex_sig.insert(sig) {
            return Err(ArcError::config(format!(
                "ambiguous duplicated route path pattern (same semantics): {path_pat}"
            )));
        }

        // Index by leading literal prefix segments to avoid scanning all complex patterns.
        let prefix = leading_literal_prefix(&segs);
        let pat_idx = self.complex.len() as u32;
        self.complex_index.insert(&prefix, true, pat_idx);

        let spec = compute_spec(kind, &segs);
        self.complex.push(ComplexPattern {
            route_id: value,
            kind,
            segs,
            spec,
        });

        Ok(())
    }

    pub fn at(&self, path: &[u8]) -> Option<u32> {
        let path = strip_query_and_fragment(path);
        if path.is_empty() || path[0] != b'/' {
            return None;
        }

        // Fast path: exact literal wins immediately.
        let (exact_lit, best_prefix_lit) = self.match_literal(path);
        if let Some(id) = exact_lit {
            return Some(id);
        }

        let best_complex = self.match_complex(path);

        match (best_prefix_lit, best_complex) {
            (None, None) => None,
            (Some((id, _)), None) => Some(id),
            (None, Some((id, _))) => Some(id),
            (Some((lit_id, lit_spec)), Some((cx_id, cx_spec))) => {
                match cx_spec.cmp(&lit_spec) {
                    Ordering::Greater => Some(cx_id),
                    Ordering::Less => Some(lit_id),
                    Ordering::Equal => Some(cx_id.min(lit_id)), // deterministic tie-break
                }
            }
        }
    }

    pub fn for_each_candidate<F: FnMut(u32)>(&self, path: &[u8], mut f: F) {
        let path = strip_query_and_fragment(path);
        if path.is_empty() || path[0] != b'/' {
            return;
        }
        self.for_each_literal_candidate(path, &mut f);
        self.for_each_complex_candidate(path, &mut f);
    }

    fn insert_bytes(&mut self, path_pat: &[u8], wildcard: bool, value: u32) -> Result<()> {
        // This is the original radix insert with one behavior change:
        // we now reject duplicates instead of silently overwriting.
        let mut nidx = 0u32;
        let mut rest = path_pat;

        loop {
            let (prefix_len, split_payload) = {
                let node = &self.nodes[nidx as usize];
                let prefix_len = common_prefix_len(&node.prefix, rest);
                if prefix_len < node.prefix.len() {
                    let (p1, p2) = node.prefix.split_at(prefix_len);
                    (
                        prefix_len,
                        Some((
                            p1.to_vec(),
                            p2.to_vec(),
                            node.edges.clone(),
                            node.value,
                            node.wildcard_value,
                        )),
                    )
                } else {
                    (prefix_len, None)
                }
            };

            // Need to split existing node.
            if let Some((p1, p2, child_edges, child_value, child_wildcard_value)) = split_payload {
                let cidx = self.nodes.len() as u32;
                {
                    // Mutate current node into the parent containing only the shared prefix.
                    let node_mut = &mut self.nodes[nidx as usize];
                    node_mut.prefix = p1.into_boxed_slice();
                    node_mut.edges = vec![Edge {
                        b: p2[0],
                        child: cidx,
                    }]
                    .into_boxed_slice();
                    node_mut.value = None;
                    node_mut.wildcard_value = None;
                }

                self.nodes.push(Node {
                    prefix: p2.into_boxed_slice(),
                    edges: child_edges,
                    value: child_value,
                    wildcard_value: child_wildcard_value,
                });
            }

            rest = &rest[prefix_len..];

            if rest.is_empty() {
                let node = &mut self.nodes[nidx as usize];
                if wildcard {
                    if node.wildcard_value.is_some() {
                        return Err(ArcError::config(format!(
                            "duplicate wildcard route path: {}/*",
                            String::from_utf8_lossy(path_pat)
                        )));
                    }
                    node.wildcard_value = Some(value);
                } else {
                    if node.value.is_some() {
                        return Err(ArcError::config(format!(
                            "duplicate route path: {}",
                            String::from_utf8_lossy(path_pat)
                        )));
                    }
                    node.value = Some(value);
                }
                return Ok(());
            }

            // Find child edge by the next byte.
            let b = rest[0];
            let next_child = {
                let node = &self.nodes[nidx as usize];
                find_edge_ref(&node.edges, b).map(|e| e.child)
            };

            if let Some(child) = next_child {
                nidx = child;
                continue;
            }

            let mut child = Node {
                prefix: rest.into(),
                edges: Box::new([]),
                value: None,
                wildcard_value: None,
            };
            if wildcard {
                child.wildcard_value = Some(value);
            } else {
                child.value = Some(value);
            }
            let cidx = self.nodes.len() as u32;
            self.nodes.push(child);

            let node = &mut self.nodes[nidx as usize];
            let mut edges: Vec<Edge> = node.edges.to_vec();
            edges.push(Edge { b, child: cidx });
            edges.sort_by_key(|e| e.b);
            node.edges = edges.into_boxed_slice();
            return Ok(());
        }
    }

    fn match_literal(&self, path: &[u8]) -> (Option<u32>, Option<(u32, SpecKey)>) {
        let mut nidx = 0u32;
        let mut rest = path;

        let mut best_prefix: Option<(u32, usize)> = None; // (route_id, matched_len)

        loop {
            let node = &self.nodes[nidx as usize];

            if rest.len() < node.prefix.len() {
                return (
                    None,
                    best_prefix.map(|(id, len)| (id, spec_for_literal_prefix(path, len))),
                );
            }
            if &rest[..node.prefix.len()] != node.prefix.as_ref() {
                return (
                    None,
                    best_prefix.map(|(id, len)| (id, spec_for_literal_prefix(path, len))),
                );
            }

            let after = &rest[node.prefix.len()..];
            let consumed = path.len() - after.len();

            if let Some(w) = node.wildcard_value {
                // boundary check: either end-of-path, or next byte is `/`
                if after.is_empty() || after[0] == b'/' {
                    best_prefix = Some((w, consumed));
                }
            }

            rest = after;
            if rest.is_empty() {
                let exact = node.value;
                let best = best_prefix.map(|(id, len)| (id, spec_for_literal_prefix(path, len)));
                return (exact, best);
            }

            let b = rest[0];
            let Some(edge) = find_edge_ref(&node.edges, b) else {
                return (
                    None,
                    best_prefix.map(|(id, len)| (id, spec_for_literal_prefix(path, len))),
                );
            };
            nidx = edge.child;
        }
    }

    fn match_complex(&self, path: &[u8]) -> Option<(u32, SpecKey)> {
        let Some(candidates) = self.complex_index.at(path) else {
            return None;
        };

        let mut best: Option<(u32, SpecKey)> = None;
        for &idx in candidates {
            let Some(pat) = self.complex.get(idx as usize) else {
                continue;
            };
            if pat.matches(path) {
                best = match best {
                    None => Some((pat.route_id, pat.spec)),
                    Some((best_id, best_spec)) => match pat.spec.cmp(&best_spec) {
                        Ordering::Greater => Some((pat.route_id, pat.spec)),
                        Ordering::Less => Some((best_id, best_spec)),
                        Ordering::Equal => Some((best_id.min(pat.route_id), best_spec)),
                    },
                };
            }
        }
        best
    }

    fn for_each_literal_candidate<F: FnMut(u32)>(&self, path: &[u8], f: &mut F) {
        let mut nidx = 0u32;
        let mut rest = path;

        loop {
            let node = &self.nodes[nidx as usize];

            if rest.len() < node.prefix.len() {
                return;
            }
            if &rest[..node.prefix.len()] != node.prefix.as_ref() {
                return;
            }

            let after = &rest[node.prefix.len()..];

            if let Some(w) = node.wildcard_value {
                if after.is_empty() || after[0] == b'/' {
                    f(w);
                }
            }

            rest = after;
            if rest.is_empty() {
                if let Some(exact) = node.value {
                    f(exact);
                }
                return;
            }

            let b = rest[0];
            let Some(edge) = find_edge_ref(&node.edges, b) else {
                return;
            };
            nidx = edge.child;
        }
    }

    fn for_each_complex_candidate<F: FnMut(u32)>(&self, path: &[u8], f: &mut F) {
        let Some(candidates) = self.complex_index.at(path) else {
            return;
        };
        for &idx in candidates {
            let Some(pat) = self.complex.get(idx as usize) else {
                continue;
            };
            if pat.matches(path) {
                f(pat.route_id);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PatternKind {
    Exact,
    Prefix,
}

#[derive(Debug, Clone)]
struct ComplexPattern {
    route_id: u32,
    kind: PatternKind,
    segs: Box<[Seg]>,
    spec: SpecKey,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum Seg {
    Lit(Box<[u8]>),
    Param(Box<[u8]>), // param name (for future capture use)
    Star,             // single-segment wildcard
    Glob(Box<[u8]>),  // `*` and `?` within a segment
}

impl ComplexPattern {
    fn matches(&self, path: &[u8]) -> bool {
        // Path is expected to start with `/`.
        if path.is_empty() || path[0] != b'/' {
            return false;
        }

        // Segment scanning without allocation.
        let mut pos = 1usize; // after leading `/`
        for seg_pat in self.segs.iter() {
            let Some((seg, next_pos)) = next_segment(path, pos) else {
                return false;
            };

            if !segment_matches(seg_pat, seg) {
                return false;
            }
            pos = next_pos;
        }

        match self.kind {
            PatternKind::Prefix => true,
            PatternKind::Exact => pos > path.len(), // no remaining segments (including empty trailing)
        }
    }
}

fn segment_matches(pat: &Seg, seg: &[u8]) -> bool {
    match pat {
        Seg::Lit(lit) => seg == lit.as_ref(),
        Seg::Param(_) => true,
        Seg::Star => true,
        Seg::Glob(g) => glob_match_segment(g.as_ref(), seg),
    }
}

fn next_segment<'a>(path: &'a [u8], pos: usize) -> Option<(&'a [u8], usize)> {
    let len = path.len();
    if pos > len {
        return None;
    }
    if pos == len {
        // trailing empty segment (path ends with `/`)
        return Some((&path[len..len], len + 1));
    }

    let mut i = pos;
    while i < len && path[i] != b'/' {
        i += 1;
    }

    if i == len {
        Some((&path[pos..len], len + 1))
    } else {
        Some((&path[pos..i], i + 1))
    }
}

/// Glob match inside a single path segment.
/// - `*` matches any sequence (including empty) within the segment
/// - `?` matches any single byte within the segment
fn glob_match_segment(pat: &[u8], text: &[u8]) -> bool {
    let mut pi = 0usize;
    let mut ti = 0usize;

    let mut star_pi: Option<usize> = None;
    let mut star_ti: usize = 0;

    while ti < text.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == text[ti]) {
            pi += 1;
            ti += 1;
            continue;
        }

        if pi < pat.len() && pat[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
            continue;
        }

        if let Some(sp) = star_pi {
            // backtrack: let `*` consume one more char
            star_ti += 1;
            ti = star_ti;
            pi = sp + 1;
            continue;
        }

        return false;
    }

    // Consume trailing `*`
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }

    pi == pat.len()
}

fn strip_query_and_fragment(path: &[u8]) -> &[u8] {
    for (i, &b) in path.iter().enumerate() {
        if b == b'?' || b == b'#' {
            return &path[..i];
        }
    }
    path
}

fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    let mut i = 0usize;
    let len = a.len().min(b.len());
    while i < len {
        if a[i] != b[i] {
            break;
        }
        i += 1;
    }
    i
}

fn find_edge_ref(edges: &[Edge], b: u8) -> Option<&Edge> {
    edges
        .binary_search_by_key(&b, |e| e.b)
        .ok()
        .map(|i| &edges[i])
}

#[derive(Debug, Clone, Copy)]
enum SegToken<'a> {
    Lit(&'a str),
    Param(&'a str),
    Star,
    Glob(&'a str),
    DeepStar,
}

impl<'a> SegToken<'a> {
    fn is_special(&self) -> bool {
        !matches!(self, SegToken::Lit(_))
    }
}

fn classify_segment(seg: &str) -> Result<SegToken<'_>> {
    if seg == "**" {
        return Ok(SegToken::DeepStar);
    }
    if seg == "*" {
        return Ok(SegToken::Star);
    }
    if let Some(name) = seg.strip_prefix(':') {
        if name.is_empty() {
            return Err(ArcError::config(
                "named param segment ':<name>' requires a non-empty name".into(),
            ));
        }
        validate_param_name(name)?;
        return Ok(SegToken::Param(name));
    }
    if seg.as_bytes().iter().any(|&b| b == b'*' || b == b'?') {
        return Ok(SegToken::Glob(seg));
    }
    Ok(SegToken::Lit(seg))
}

fn validate_param_name(name: &str) -> Result<()> {
    // Keep it strict to avoid surprising behavior and to align with `$path.<name>` use cases.
    let bytes = name.as_bytes();
    if bytes.is_empty() {
        return Err(ArcError::config("param name must be non-empty".into()));
    }
    // first char: [A-Za-z_]
    let b0 = bytes[0];
    let ok0 = (b0 >= b'a' && b0 <= b'z') || (b0 >= b'A' && b0 <= b'Z') || b0 == b'_';
    if !ok0 {
        return Err(ArcError::config(format!(
            "invalid param name '{name}': must start with [A-Za-z_]"
        )));
    }
    // rest: [A-Za-z0-9_]
    for &b in &bytes[1..] {
        let ok = (b >= b'a' && b <= b'z')
            || (b >= b'A' && b <= b'Z')
            || (b >= b'0' && b <= b'9')
            || b == b'_';
        if !ok {
            return Err(ArcError::config(format!(
                "invalid param name '{name}': only [A-Za-z0-9_] allowed"
            )));
        }
    }
    Ok(())
}

fn compile_segment(tok: &SegToken<'_>) -> Result<Seg> {
    Ok(match tok {
        SegToken::Lit(s) => Seg::Lit(s.as_bytes().to_vec().into_boxed_slice()),
        SegToken::Param(name) => Seg::Param(name.as_bytes().to_vec().into_boxed_slice()),
        SegToken::Star => Seg::Star,
        SegToken::Glob(s) => Seg::Glob(s.as_bytes().to_vec().into_boxed_slice()),
        SegToken::DeepStar => {
            // handled earlier
            return Err(ArcError::config(
                "internal error: unexpected DeepStar in compile_segment".into(),
            ));
        }
    })
}

fn build_signature(kind: PatternKind, segs: &[Seg]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(match kind {
        PatternKind::Exact => b'E',
        PatternKind::Prefix => b'P',
    });
    out.push(b'|');

    for seg in segs {
        match seg {
            Seg::Lit(b) => {
                out.push(b'L');
                out.push(b'(');
                out.extend_from_slice(b.as_ref());
                out.push(b')');
            }
            Seg::Param(_) => {
                out.push(b'W'); // wildcard segment
            }
            Seg::Star => {
                out.push(b'W'); // wildcard segment (same as param)
            }
            Seg::Glob(b) => {
                out.push(b'G');
                out.push(b'(');
                out.extend_from_slice(b.as_ref());
                out.push(b')');
            }
        }
        out.push(b'/');
    }

    out
}

fn leading_literal_prefix(segs: &[Seg]) -> Vec<u8> {
    let mut prefix: Vec<u8> = Vec::new();
    for seg in segs {
        match seg {
            Seg::Lit(b) => {
                prefix.push(b'/');
                prefix.extend_from_slice(b.as_ref());
            }
            _ => break,
        }
    }
    prefix
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SpecKey {
    // exact (2) beats prefix (1)
    exactness: u8,
    // more segments is more specific
    segs: u16,
    // more literal bytes (including literals inside globs) is more specific
    lit_bytes: u16,
    // fewer wildcards is more specific (compared reversed)
    wildcards: u16,
}

impl Ord for SpecKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher is better for exactness, segs, lit_bytes.
        // Lower is better for wildcards.
        self.exactness
            .cmp(&other.exactness)
            .then(self.segs.cmp(&other.segs))
            .then(self.lit_bytes.cmp(&other.lit_bytes))
            .then_with(|| other.wildcards.cmp(&self.wildcards))
    }
}

impl PartialOrd for SpecKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compute_spec(kind: PatternKind, segs: &[Seg]) -> SpecKey {
    let exactness = match kind {
        PatternKind::Exact => 2,
        PatternKind::Prefix => 1,
    };

    let mut lit_bytes: u16 = 0;
    let mut wildcards: u16 = 0;

    for seg in segs {
        match seg {
            Seg::Lit(b) => {
                lit_bytes = lit_bytes.saturating_add(b.len() as u16);
            }
            Seg::Param(_) => {
                wildcards = wildcards.saturating_add(1);
            }
            Seg::Star => {
                wildcards = wildcards.saturating_add(1);
            }
            Seg::Glob(b) => {
                wildcards = wildcards.saturating_add(1);
                // Count non-wildcard bytes inside glob segment as contributing to specificity.
                let mut g_lit = 0usize;
                for &ch in b.as_ref() {
                    if ch != b'*' && ch != b'?' {
                        g_lit += 1;
                    }
                }
                lit_bytes = lit_bytes.saturating_add(g_lit as u16);
            }
        }
    }

    // Prefix patterns all include an implicit tail wildcard.
    if kind == PatternKind::Prefix {
        wildcards = wildcards.saturating_add(1);
    }

    SpecKey {
        exactness,
        segs: segs.len() as u16,
        lit_bytes,
        wildcards,
    }
}

fn spec_for_literal_prefix(path: &[u8], matched_len: usize) -> SpecKey {
    let prefix = &path[..matched_len.min(path.len())];
    let segs = prefix.iter().filter(|&&b| b == b'/').count() as u16;
    let lit_bytes = (matched_len.saturating_sub(segs as usize)).min(u16::MAX as usize) as u16;

    SpecKey {
        exactness: 1,
        segs,
        lit_bytes,
        wildcards: 1, // implicit tail wildcard
    }
}

/// A radix-tree index that maps a prefix to a *set* of u32 values.
///
/// We use it to map literal prefixes to candidate complex-pattern indices.
#[derive(Debug, Clone)]
struct RadixMulti {
    nodes: Vec<MultiNode>,
    sets: Vec<Box<[u32]>>,
}

#[derive(Debug, Clone)]
struct MultiNode {
    prefix: Box<[u8]>,
    edges: Box<[Edge]>,
    wildcard_set: Option<u32>, // set id
}

impl RadixMulti {
    fn new() -> Self {
        Self {
            nodes: vec![MultiNode {
                prefix: Box::new([]),
                edges: Box::new([]),
                wildcard_set: None,
            }],
            sets: Vec::new(),
        }
    }

    fn insert(&mut self, path_pat: &[u8], wildcard: bool, value: u32) {
        debug_assert!(wildcard, "RadixMulti is only used with wildcard inserts");
        let mut nidx = 0u32;
        let mut rest = path_pat;

        loop {
            let (prefix_len, split_payload) = {
                let node = &self.nodes[nidx as usize];
                let prefix_len = common_prefix_len(&node.prefix, rest);
                if prefix_len < node.prefix.len() {
                    let (p1, p2) = node.prefix.split_at(prefix_len);
                    (
                        prefix_len,
                        Some((
                            p1.to_vec(),
                            p2.to_vec(),
                            node.edges.clone(),
                            node.wildcard_set,
                        )),
                    )
                } else {
                    (prefix_len, None)
                }
            };

            if let Some((p1, p2, child_edges, child_set)) = split_payload {
                let cidx = self.nodes.len() as u32;
                {
                    let node_mut = &mut self.nodes[nidx as usize];
                    node_mut.prefix = p1.into_boxed_slice();
                    node_mut.edges = vec![Edge {
                        b: p2[0],
                        child: cidx,
                    }]
                    .into_boxed_slice();
                    node_mut.wildcard_set = None;
                }

                self.nodes.push(MultiNode {
                    prefix: p2.into_boxed_slice(),
                    edges: child_edges,
                    wildcard_set: child_set,
                });
            }

            rest = &rest[prefix_len..];

            if rest.is_empty() {
                // Add to wildcard set
                let old = self.nodes[nidx as usize].wildcard_set;
                let new = self.add_to_set(old, value);
                self.nodes[nidx as usize].wildcard_set = new;
                return;
            }

            let b = rest[0];
            let next_child = {
                let node = &self.nodes[nidx as usize];
                find_edge_ref(&node.edges, b).map(|e| e.child)
            };
            if let Some(child) = next_child {
                nidx = child;
                continue;
            }

            let child_set = self.add_to_set(None, value);
            let child = MultiNode {
                prefix: rest.into(),
                edges: Box::new([]),
                wildcard_set: child_set,
            };

            let cidx = self.nodes.len() as u32;
            self.nodes.push(child);

            let node = &mut self.nodes[nidx as usize];
            let mut edges: Vec<Edge> = node.edges.to_vec();
            edges.push(Edge { b, child: cidx });
            edges.sort_by_key(|e| e.b);
            node.edges = edges.into_boxed_slice();
            return;
        }
    }

    fn at(&self, path: &[u8]) -> Option<&[u32]> {
        let mut nidx = 0u32;
        let mut rest = path;

        let mut best_set: Option<u32> = None;

        loop {
            let node = &self.nodes[nidx as usize];

            if rest.len() < node.prefix.len() {
                return best_set.map(|sid| self.sets[sid as usize].as_ref());
            }
            if &rest[..node.prefix.len()] != node.prefix.as_ref() {
                return best_set.map(|sid| self.sets[sid as usize].as_ref());
            }

            let after = &rest[node.prefix.len()..];
            if let Some(sid) = node.wildcard_set {
                // boundary check: either end-of-path, or next byte is `/`
                if after.is_empty() || after[0] == b'/' {
                    best_set = Some(sid);
                }
            }

            rest = after;
            if rest.is_empty() {
                return best_set.map(|sid| self.sets[sid as usize].as_ref());
            }

            let b = rest[0];
            let Some(edge) = find_edge_ref(&node.edges, b) else {
                return best_set.map(|sid| self.sets[sid as usize].as_ref());
            };
            nidx = edge.child;
        }
    }

    fn add_to_set(&mut self, slot: Option<u32>, value: u32) -> Option<u32> {
        match slot {
            None => {
                let id = self.sets.len() as u32;
                self.sets.push(vec![value].into_boxed_slice());
                Some(id)
            }
            Some(id) => {
                let idx = id as usize;
                let mut v: Vec<u32> = self.sets[idx].iter().copied().collect();
                if !v.contains(&value) {
                    v.push(value);
                }
                self.sets[idx] = v.into_boxed_slice();
                Some(id)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_not_starting_with_slash() {
        let mut r = Router::new();
        assert!(r.insert("a", 0).is_err());
    }

    #[test]
    fn exact_and_wildcard_longest_prefix() {
        let mut r = Router::new();
        r.insert("/a/b/c", 4).unwrap();
        r.insert("/a/*", 1).unwrap();
        r.insert("/a/b/*", 3).unwrap();
        r.insert("/x/y/*", 2).unwrap();

        assert_eq!(r.at(b"/"), None);
        assert_eq!(r.at(b"/x"), None);
        assert_eq!(r.at(b"/a"), Some(1));
        assert_eq!(r.at(b"/a/x"), Some(1));
        assert_eq!(r.at(b"/a/b/c"), Some(4));
        assert_eq!(r.at(b"/a/b/c/d"), Some(3));
        assert_eq!(r.at(b"/x/y"), Some(2));
        assert_eq!(r.at(b"/x/y/z"), Some(2));
    }

    #[test]
    fn wildcard_requires_boundary() {
        let mut r = Router::new();
        r.insert("/static/*", 1).unwrap();

        assert_eq!(r.at(b"/static"), Some(1));
        assert_eq!(r.at(b"/static/"), Some(1));
        assert_eq!(r.at(b"/static/app.js"), Some(1));
        assert_eq!(r.at(b"/staticx"), None);
    }

    #[test]
    fn query_and_fragment_are_ignored() {
        let mut r = Router::new();
        r.insert("/a/*", 1).unwrap();
        r.insert("/b", 2).unwrap();

        assert_eq!(r.at(b"/a/x?y=1"), Some(1));
        assert_eq!(r.at(b"/a?y=1"), Some(1));
        assert_eq!(r.at(b"/b?x=1"), Some(2));
        assert_eq!(r.at(b"/b#frag"), Some(2));
    }

    #[test]
    fn for_each_candidate_collects_literal_and_complex_matches() {
        let mut r = Router::new();
        r.insert("/a/*", 1).unwrap();
        r.insert("/a/:id/profile", 2).unwrap();

        let mut got = Vec::new();
        r.for_each_candidate(b"/a/123/profile?x=1", |id| got.push(id));
        got.sort_unstable();
        assert_eq!(got, vec![1, 2]);
    }

    #[test]
    fn named_params_and_prefix_params() {
        let mut r = Router::new();
        r.insert("/user/*", 10).unwrap();
        r.insert("/user/:id/profile", 20).unwrap();
        r.insert("/user/:id/*", 30).unwrap();

        assert_eq!(r.at(b"/user"), Some(10));
        assert_eq!(r.at(b"/user/123/profile"), Some(20));
        assert_eq!(r.at(b"/user/123/other"), Some(30));
        assert_eq!(r.at(b"/userx/123/profile"), None);
    }

    #[test]
    fn param_name_does_not_change_semantics() {
        let mut r = Router::new();
        r.insert("/user/:id/profile", 1).unwrap();
        // same semantics -> rejected
        assert!(r.insert("/user/:name/profile", 2).is_err());
    }

    #[test]
    fn segment_glob_patterns() {
        let mut r = Router::new();
        r.insert("/assets/*.css", 1).unwrap();
        r.insert("/assets/*", 2).unwrap();

        // exact glob is more specific than a shorter prefix wildcard
        assert_eq!(r.at(b"/assets/main.css"), Some(1));
        assert_eq!(r.at(b"/assets/main.js"), Some(2));
        assert_eq!(r.at(b"/assets/css/main.css"), Some(2));
    }

    #[test]
    fn segment_star_in_the_middle() {
        let mut r = Router::new();
        r.insert("/foo/*/bar", 7).unwrap();

        assert_eq!(r.at(b"/foo/x/bar"), Some(7));
        assert_eq!(r.at(b"/foo/x/y/bar"), None);
        assert_eq!(r.at(b"/foo//bar"), Some(7)); // empty segment is still a segment
    }
}
