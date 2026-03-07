use crate::util::lowercase_ascii;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct RedactionRules {
    headers_lc: HashSet<String>,
    query_lc: HashSet<String>,
    body_paths: Vec<Vec<String>>,
}

impl Default for RedactionRules {
    fn default() -> Self {
        Self {
            headers_lc: HashSet::new(),
            query_lc: HashSet::new(),
            body_paths: Vec::new(),
        }
    }
}

impl RedactionRules {
    /// Build from config lists.
    pub fn new(headers: &[String], query_params: &[String], body_fields: &[String]) -> Self {
        let mut out = Self::default();

        for h in headers {
            out.headers_lc.insert(lowercase_ascii(h));
        }
        for q in query_params {
            out.query_lc.insert(lowercase_ascii(q));
        }
        for p in body_fields {
            if let Some(path) = parse_body_path(p) {
                out.body_paths.push(path);
            }
        }

        out
    }

    /// Redact a header value if header name matches config.
    ///
    /// Returns `[REDACTED]` if matched; otherwise returns original.
    pub fn redact_header_value<'a>(&self, name: &str, value: &'a str) -> Cow<'a, str> {
        let n = lowercase_ascii(name);
        if self.headers_lc.contains(&n) {
            Cow::Borrowed("[REDACTED]")
        } else {
            Cow::Borrowed(value)
        }
    }

    pub fn redact_query<'a>(&self, query: &'a str) -> Cow<'a, str> {
        if query.is_empty() || self.query_lc.is_empty() {
            return Cow::Borrowed(query);
        }

        // Fast path: if no key appears, return borrowed.
        // (This is best-effort; we still may miss due to encoding/case differences.)
        let mut any_match = false;
        for key in self.query_lc.iter() {
            if query.to_ascii_lowercase().contains(key) {
                any_match = true;
                break;
            }
        }
        if !any_match {
            return Cow::Borrowed(query);
        }

        let mut out = String::with_capacity(query.len().saturating_add(16));
        for (i, part) in query.split('&').enumerate() {
            if i > 0 {
                out.push('&');
            }
            if part.is_empty() {
                continue;
            }
            let mut it = part.splitn(2, '=');
            let k = it.next().unwrap_or("");
            let v = it.next();

            let k_lc = lowercase_ascii(k);
            if self.query_lc.contains(&k_lc) {
                out.push_str(k);
                out.push('=');
                out.push_str("[REDACTED]");
            } else {
                out.push_str(k);
                if let Some(vv) = v {
                    out.push('=');
                    out.push_str(vv);
                }
            }
        }

        Cow::Owned(out)
    }

    #[allow(dead_code)]
    pub fn redact_body_json(&self, body: &mut Value) {
        if self.body_paths.is_empty() {
            return;
        }
        for path in self.body_paths.iter() {
            apply_path_redaction(body, path);
        }
    }
}

fn parse_body_path(s: &str) -> Option<Vec<String>> {
    let ss = s.trim();
    if ss.is_empty() {
        return None;
    }
    // Only support "$.a.b.c"
    let rest = ss.strip_prefix("$.")?;
    if rest.is_empty() {
        return None;
    }
    let parts: Vec<String> = rest
        .split('.')
        .filter_map(|p| {
            let t = p.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        })
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

#[allow(dead_code)]
fn apply_path_redaction(root: &mut Value, path: &[String]) {
    let mut cur = root;
    for (i, key) in path.iter().enumerate() {
        let is_last = i + 1 == path.len();
        match cur {
            Value::Object(map) => {
                if is_last {
                    if map.contains_key(key) {
                        map.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                    }
                    return;
                }
                let Some(next) = map.get_mut(key) else {
                    return;
                };
                cur = next;
            }
            _ => return,
        }
    }
}
