use crate::config::{
    CookieMatch, HeaderMatch, QueryMatch, RouteAction, RouteConfig, RouteMatch,
};
use ahash::AHashMap;
use matchit::Router as Radix;
use regex::Regex;
use std::sync::Arc;

/// A compiled route.
#[derive(Debug, Clone)]
pub struct CompiledRoute {
    pub name: Arc<str>,
    pub r#match: CompiledMatch,
    pub action: RouteAction,
    pub order: usize,
}

/// Compiled matchers.
#[derive(Debug, Clone)]
pub struct CompiledMatch {
    pub hosts: Vec<HostPattern>,
    pub methods: Vec<Arc<str>>,
    pub path: Arc<str>,
    pub headers: Vec<CompiledHeaderMatch>,
    pub cookies: Vec<CompiledCookieMatch>,
    pub query: Vec<CompiledQueryMatch>,
}

#[derive(Debug, Clone)]
pub enum HostPattern {
    Exact(Arc<str>),
    WildcardSuffix(Arc<str>), // "*.example.com" => suffix "example.com"
}

#[derive(Debug, Clone)]
pub enum CompiledHeaderMatch {
    Exists { name: Arc<str> },
    Contains { name: Arc<str>, value: Arc<str> },
    Equals { name: Arc<str>, value: Arc<str> },
    Regex { name: Arc<str>, re: Arc<Regex> },
}

#[derive(Debug, Clone)]
pub enum CompiledCookieMatch {
    Equals { name: Arc<str>, value: Arc<str> },
    Regex { name: Arc<str>, re: Arc<Regex> },
}

#[derive(Debug, Clone)]
pub enum CompiledQueryMatch {
    Exists { name: Arc<str> },
    Equals { name: Arc<str>, value: Arc<str> },
    Regex { name: Arc<str>, re: Arc<Regex> },
}

/// A matched route result.
#[derive(Debug, Clone)]
pub struct MatchedRoute {
    pub route: Arc<CompiledRoute>,
    pub params: AHashMap<Arc<str>, Arc<str>>,
}

#[derive(Debug)]
pub struct Router {
    default: HostRouter,
    exact: AHashMap<Arc<str>, HostRouter>,
    wildcards: Vec<(Arc<str>, HostRouter)>, // (suffix, router)
}

#[derive(Debug, Default)]
struct HostRouter {
    methods: AHashMap<Arc<str>, MethodRouter>,
}

#[derive(Debug, Default)]
struct MethodRouter {
    radix: Radix<usize>,
    buckets: Vec<Vec<Arc<CompiledRoute>>>,
    by_path: AHashMap<Arc<str>, usize>,
}

impl Router {
    /// Build router from routes.
    pub fn build(routes: &[RouteConfig]) -> anyhow::Result<Self> {
        let mut router = Router {
            default: HostRouter::default(),
            exact: AHashMap::new(),
            wildcards: vec![],
        };

        for (order, r) in routes.iter().enumerate() {
            let compiled = Arc::new(compile_route(order, r)?);

            // Host routing: if no hosts specified, attach to default.
            let hosts = &compiled.r#match.hosts;
            if hosts.is_empty() {
                router.default.insert(&compiled)?;
                continue;
            }

            for hp in hosts {
                match hp {
                    HostPattern::Exact(h) => {
                        router
                            .exact
                            .entry(h.clone())
                            .or_insert_with(HostRouter::default)
                            .insert(&compiled)?;
                    }
                    HostPattern::WildcardSuffix(suffix) => {
                        // Find existing wildcard router by same suffix.
                        if let Some((_, hr)) = router
                            .wildcards
                            .iter_mut()
                            .find(|(s, _)| s.as_ref() == suffix.as_ref())
                        {
                            hr.insert(&compiled)?;
                        } else {
                            let mut hr = HostRouter::default();
                            hr.insert(&compiled)?;
                            router.wildcards.push((suffix.clone(), hr));
                        }
                    }
                }
            }
        }

        // Sort wildcards by suffix length desc (longest wins).
        router
            .wildcards
            .sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()));

        Ok(router)
    }

    /// Match a request.
    ///
    /// `headers_get` is a callback to avoid building a full header map.
    pub fn match_request<'h, F>(
        &self,
        host: &str,
        method: &str,
        path: &str,
        mut headers_get: F,
        query: Option<&'h str>,
    ) -> Option<MatchedRoute>
    where
        F: FnMut(&str) -> Option<&'h str>,
    {
        let hr = self.host_router(host);
        let mr = hr
            .methods
            .get(method)
            .or_else(|| hr.methods.get("*"))?;

        let m = mr.radix.at(path).ok()?;
        let bucket = mr.buckets.get(*m.value)?;

        // Lazy cookie parse.
        let cookie_hdr = headers_get("cookie");
        let cookies = LazyCookies::new(cookie_hdr);
        let query_map = LazyQuery::new(query);

        for r in bucket {
            if !predicates_match(&r.r#match, &mut headers_get, &cookies, &query_map) {
                continue;
            }

            let mut params = AHashMap::new();
            for (k, v) in m.params.iter() {
                params.insert(Arc::<str>::from(k.to_string()), Arc::<str>::from(v.to_string()));
            }
            return Some(MatchedRoute {
                route: r.clone(),
                params,
            });
        }

        None
    }

    fn host_router(&self, host: &str) -> &HostRouter {
        if let Some(hr) = self.exact.get(host) {
            return hr;
        }
        // Wildcard suffix match: "foo.bar.example.com" matches "example.com".
        for (suffix, hr) in &self.wildcards {
            if host == suffix.as_ref() {
                continue;
            }
            if let Some(rest) = host.strip_suffix(suffix.as_ref()) {
                if rest.ends_with('.') {
                    return hr;
                }
            }
        }
        &self.default
    }
}

impl HostRouter {
    fn insert(&mut self, route: &Arc<CompiledRoute>) -> anyhow::Result<()> {
        let methods = &route.r#match.methods;
        if methods.is_empty() {
            self.method_router("*").insert(route)?;
            return Ok(());
        }
        for m in methods {
            self.method_router(m).insert(route)?;
        }
        Ok(())
    }

    fn method_router(&mut self, method: &str) -> &mut MethodRouter {
        self.methods
            .entry(Arc::<str>::from(method.to_string()))
            .or_insert_with(MethodRouter::default)
    }
}

impl MethodRouter {
    fn insert(&mut self, route: &Arc<CompiledRoute>) -> anyhow::Result<()> {
        let path = route.r#match.path.clone();
        let bucket_id = if let Some(id) = self.by_path.get(&path).copied() {
            id
        } else {
            let id = self.buckets.len();
            self.buckets.push(Vec::new());
            self.radix.insert(path.as_ref(), id)?;
            self.by_path.insert(path.clone(), id);
            id
        };
        self.buckets[bucket_id].push(route.clone());
        // Stable order by rule order.
        self.buckets[bucket_id].sort_by_key(|r| r.order);
        Ok(())
    }
}

fn compile_route(order: usize, r: &RouteConfig) -> anyhow::Result<CompiledRoute> {
    Ok(CompiledRoute {
        name: Arc::<str>::from(r.name.clone()),
        r#match: compile_match(&r.r#match)?,
        action: r.action.clone(),
        order,
    })
}

fn compile_match(m: &RouteMatch) -> anyhow::Result<CompiledMatch> {
    let mut hosts = Vec::new();
    for h in &m.host {
        if let Some(suffix) = h.strip_prefix("*.") {
            hosts.push(HostPattern::WildcardSuffix(Arc::<str>::from(suffix.to_string())));
        } else {
            hosts.push(HostPattern::Exact(Arc::<str>::from(h.clone())));
        }
    }

    let methods = m
        .methods
        .iter()
        .map(|s| Arc::<str>::from(s.to_ascii_uppercase()))
        .collect();

    let headers = m.headers.iter().map(compile_header).collect::<anyhow::Result<_>>()?;
    let cookies = m.cookies.iter().map(compile_cookie).collect::<anyhow::Result<_>>()?;
    let query = m.query.iter().map(compile_query).collect::<anyhow::Result<_>>()?;

    Ok(CompiledMatch {
        hosts,
        methods,
        path: Arc::<str>::from(m.path.clone()),
        headers,
        cookies,
        query,
    })
}

fn compile_header(h: &HeaderMatch) -> anyhow::Result<CompiledHeaderMatch> {
    Ok(match h {
        HeaderMatch::Exists { name } => CompiledHeaderMatch::Exists {
            name: Arc::<str>::from(name.to_ascii_lowercase()),
        },
        HeaderMatch::Contains { name, value } => CompiledHeaderMatch::Contains {
            name: Arc::<str>::from(name.to_ascii_lowercase()),
            value: Arc::<str>::from(value.clone()),
        },
        HeaderMatch::Equals { name, value } => CompiledHeaderMatch::Equals {
            name: Arc::<str>::from(name.to_ascii_lowercase()),
            value: Arc::<str>::from(value.clone()),
        },
        HeaderMatch::Regex { name, pattern } => CompiledHeaderMatch::Regex {
            name: Arc::<str>::from(name.to_ascii_lowercase()),
            re: Arc::new(Regex::new(pattern)?),
        },
    })
}

fn compile_cookie(c: &CookieMatch) -> anyhow::Result<CompiledCookieMatch> {
    Ok(match c {
        CookieMatch::Equals { name, value } => CompiledCookieMatch::Equals {
            name: Arc::<str>::from(name.clone()),
            value: Arc::<str>::from(value.clone()),
        },
        CookieMatch::Regex { name, pattern } => CompiledCookieMatch::Regex {
            name: Arc::<str>::from(name.clone()),
            re: Arc::new(Regex::new(pattern)?),
        },
    })
}

fn compile_query(q: &QueryMatch) -> anyhow::Result<CompiledQueryMatch> {
    Ok(match q {
        QueryMatch::Exists { name } => CompiledQueryMatch::Exists {
            name: Arc::<str>::from(name.clone()),
        },
        QueryMatch::Equals { name, value } => CompiledQueryMatch::Equals {
            name: Arc::<str>::from(name.clone()),
            value: Arc::<str>::from(value.clone()),
        },
        QueryMatch::Regex { name, pattern } => CompiledQueryMatch::Regex {
            name: Arc::<str>::from(name.clone()),
            re: Arc::new(Regex::new(pattern)?),
        },
    })
}

fn predicates_match<'h, F>(
    m: &CompiledMatch,
    headers_get: &mut F,
    cookies: &LazyCookies<'h>,
    query: &LazyQuery<'h>,
) -> bool
where
    F: FnMut(&str) -> Option<&'h str>,
{
    // Headers
    for h in &m.headers {
        let ok = match h {
            CompiledHeaderMatch::Exists { name } => headers_get(name.as_ref()).is_some(),
            CompiledHeaderMatch::Contains { name, value } => headers_get(name.as_ref())
                .map(|v| v.contains(value.as_ref()))
                .unwrap_or(false),
            CompiledHeaderMatch::Equals { name, value } => headers_get(name.as_ref())
                .map(|v| v == value.as_ref())
                .unwrap_or(false),
            CompiledHeaderMatch::Regex { name, re } => headers_get(name.as_ref())
                .map(|v| re.is_match(v))
                .unwrap_or(false),
        };
        if !ok {
            return false;
        }
    }

    // Cookies
    for c in &m.cookies {
        let ok = match c {
            CompiledCookieMatch::Equals { name, value } => cookies
                .get(name.as_ref())
                .map(|v| v == value.as_ref())
                .unwrap_or(false),
            CompiledCookieMatch::Regex { name, re } => cookies
                .get(name.as_ref())
                .map(|v| re.is_match(v))
                .unwrap_or(false),
        };
        if !ok {
            return false;
        }
    }

    // Query
    for q in &m.query {
        let ok = match q {
            CompiledQueryMatch::Exists { name } => query.get(name.as_ref()).is_some(),
            CompiledQueryMatch::Equals { name, value } => query
                .get(name.as_ref())
                .map(|v| v == value.as_ref())
                .unwrap_or(false),
            CompiledQueryMatch::Regex { name, re } => query
                .get(name.as_ref())
                .map(|v| re.is_match(v))
                .unwrap_or(false),
        };
        if !ok {
            return false;
        }
    }

    true
}

/// Lazy cookie parser.
struct LazyCookies<'a> {
    raw: Option<&'a str>,
}

impl<'a> LazyCookies<'a> {
    fn new(raw: Option<&'a str>) -> Self {
        Self { raw }
    }

    fn get(&self, name: &str) -> Option<&'a str> {
        let raw = self.raw?;
        // Fast, allocation-free scan.
        for part in raw.split(';') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                if k.trim() == name {
                    return Some(v.trim());
                }
            }
        }
        None
    }
}

/// Lazy query parser.
struct LazyQuery<'a> {
    raw: Option<&'a str>,
}

impl<'a> LazyQuery<'a> {
    fn new(raw: Option<&'a str>) -> Self {
        Self { raw }
    }

    fn get(&self, name: &str) -> Option<&'a str> {
        let raw = self.raw?;
        for part in raw.split('&') {
            if let Some((k, v)) = part.split_once('=') {
                if k == name {
                    return Some(v);
                }
            } else if part == name {
                return Some("");
            }
        }
        None
    }
}
