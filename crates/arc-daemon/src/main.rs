use arc_core::{
    compiled::{CompiledConfig, SharedConfig},
    config::{load_from_path, ArcConfig, ListenerKind},
    control::{ConfigPushRequest, ConfigPushResponse, ControlState, StatusResponse},
    telemetry::Metrics,
    upstream::UpstreamGroup,
};
use clap::Parser;
use pingora::listeners::tls::TlsSettings;
use pingora::prelude::*;
use pingora::proxy::{http_proxy_service, ProxyHttp};
use std::sync::Arc;
use std::time::Instant;

// Allocator strategy.
#[cfg(not(target_os = "windows"))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(target_os = "windows")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser, Debug)]
#[command(name = "arc-daemon", version, about = "Arc node")]
struct Args {
    /// Path to arc.yaml
    #[arg(long, default_value = "arc.yaml")]
    config: String,

    /// Log level (env_filter), e.g. "info" or "arc=debug".
    #[arg(long, default_value = "info")]
    log: String,
}

#[derive(Clone)]
struct ArcProxy {
    cfg: Arc<SharedConfig>,
    metrics: Option<Metrics>,
}

#[derive(Debug)]
struct Ctx {
    started: Instant,
    route_name: Option<Arc<str>>,
    upstream: Option<String>,
    upstream_group: Option<Arc<UpstreamGroup>>,
    upstream_idx: Option<usize>,
    upstream_done: bool,
    // For production: store matched params, split choice, mirror flags, etc.
}

impl ProxyHttp for ArcProxy {
    type CTX = Ctx;

    fn new_ctx(&self) -> Self::CTX {
        Ctx {
            started: Instant::now(),
            route_name: None,
            upstream: None,
            upstream_group: None,
            upstream_idx: None,
            upstream_done: false,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        // Load current config snapshot (per-request).
        let cfg = self.cfg.load();

        let req = session.req_header();
        let host = req
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let method = req.method.as_str();
        let path = req.uri.path();
        let query = req.uri.query();

        let matched = cfg.router.match_request(
            host,
            method,
            path,
            |name| req.headers.get(name).and_then(|v| v.to_str().ok()),
            query,
        );

        let Some(m) = matched else {
            // 404
            session.respond_error(404).await?;
            return Ok(true);
        };

        ctx.route_name = Some(m.route.name.clone());
        ctx.upstream = Some(m.route.action.upstream.clone());
        ctx.upstream_group = None;

        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let cfg = self.cfg.load();
        let upstream_name = ctx
            .upstream
            .as_deref()
            .ok_or_else(|| Error::new_str("missing upstream"))?;

        let group = cfg
            .upstreams
            .get(upstream_name)
            .ok_or_else(|| Error::new_str("unknown upstream"))?;

        // Deterministic key for LB (placeholder).
        let key = 0u64;
        let idx = group
            .select(key)
            .ok_or_else(|| Error::new_str("no healthy upstream"))?;

        group.on_request_start(idx);
        ctx.upstream_group = Some(group.clone());
        ctx.upstream_idx = Some(idx);
        let addr = group.endpoints[idx].address.as_ref();

        // NOTE: HttpPeer::new signature is stable in Pingora examples.
        // use_tls=false here; configure per-upstream scheme in production.
        Ok(Box::new(HttpPeer::new(addr, false, "".to_string())))
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        resp: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        let route = ctx.route_name.as_deref().unwrap_or("<none>");
        if let Some(metrics) = &self.metrics {
            let status = resp.status.to_string();
            metrics
                .requests_total
                .with_label_values(&[route, &status])
                .inc();
            metrics
                .latency_seconds
                .with_label_values(&[route])
                .observe(ctx.started.elapsed().as_secs_f64());
        }

        if let (Some(group), Some(idx)) = (ctx.upstream_group.as_ref(), ctx.upstream_idx) {
            let ok = resp.status.as_u16() < 500;
            group.on_request_end(idx, ctx.started.elapsed(), ok);
            ctx.upstream_done = true;
        }
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Propagate tracing headers when caller already provides one.
        if let Some(tp) = session
            .req_header()
            .headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
        {
            upstream_request.insert_header("traceparent", tp)?;
        }

        // Propagate request id when provided by downstream.
        if upstream_request.headers.get("x-request-id").is_none() {
            if let Some(req_id) = session
                .req_header()
                .headers
                .get("x-request-id")
                .and_then(|v| v.to_str().ok())
            {
                upstream_request.insert_header("x-request-id", req_id)?;
            }
        }

        Ok(())
    }

    async fn logging(&self, session: &mut Session, _e: Option<&Error>, ctx: &mut Self::CTX) {
        let req = session.req_header();
        let route = ctx.route_name.as_deref().unwrap_or("<none>");
        let status = session
            .response_written()
            .map(|h| h.status.as_u16())
            .unwrap_or(0);

        if !ctx.upstream_done {
            if let (Some(group), Some(idx)) = (ctx.upstream_group.as_ref(), ctx.upstream_idx) {
                let ok = status > 0 && status < 500;
                group.on_request_end(idx, ctx.started.elapsed(), ok);
                ctx.upstream_done = true;
            }
        }

        tracing::info!(
            target: "arc.access",
            route = %route,
            method = %req.method,
            path = %req.uri,
            status = status,
            latency_ms = ctx.started.elapsed().as_millis() as u64,
        );
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(args.log)
        .json()
        .init();

    let cfg = load_from_path(&args.config)?;
    let compiled = CompiledConfig::compile(cfg.clone())?;
    let shared = Arc::new(SharedConfig::new(compiled));

    let metrics = if cfg.observability.metrics_enabled {
        Some(Metrics::init_global()?)
    } else {
        None
    };

    // Node-local control plane.
    if cfg.control_plane.enabled {
        spawn_control_plane(cfg.clone(), shared.clone());
    }

    // Pingora server bootstrap.
    let mut server = Server::new(None).unwrap();
    {
        let conf = Arc::get_mut(&mut server.configuration)
            .ok_or_else(|| anyhow::anyhow!("server config should be uniquely owned before bootstrap"))?;
        let workers = if cfg.node.workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            cfg.node.workers
        };
        conf.threads = workers.max(1);

        // Bridge Arc upstream pool config into Pingora's connector keepalive pool.
        // Pingora defaults to 128, which is too small under high downstream concurrency.
        let desired_pool = cfg
            .upstreams
            .iter()
            .map(|u| u.pool.max_idle)
            .max()
            .unwrap_or(conf.upstream_keepalive_pool_size);
        conf.upstream_keepalive_pool_size = desired_pool.max(128);
    }
    server.bootstrap();

    let proxy = ArcProxy {
        cfg: shared.clone(),
        metrics: metrics.clone(),
    };

    let mut svc = http_proxy_service(&server.configuration, proxy);

    // Configure listeners.
    for l in &cfg.listeners {
        match l.kind {
            ListenerKind::Http => {
                svc.add_tcp(&l.bind);
            }
            ListenerKind::Https => {
                // Static TLS for skeleton. For Arc: dynamic certs via TlsAccept callbacks.
                let tls = l
                    .tls
                    .as_ref()
                    .and_then(|t| t.certificates.first())
                    .ok_or_else(|| anyhow::anyhow!("https listener requires tls.certificates"))?;

                let mut tls_settings = TlsSettings::intermediate(&tls.cert_pem, &tls.key_pem)?;
                tls_settings.enable_h2();
                svc.add_tls_with_settings(&l.bind, None, tls_settings);
            }
            ListenerKind::H3 => {
                tracing::warn!("http/3 listener is implemented by arc-quic module (not wired in this skeleton)");
            }
            ListenerKind::Tcp => {
                tracing::warn!("tcp l4 proxy listener is implemented by arc-l4 module (not wired in this skeleton)");
            }
            ListenerKind::Udp => {
                tracing::warn!("udp l4 proxy listener is implemented by arc-udp module (not wired in this skeleton)");
            }
        }
    }

    // Metrics endpoint via Pingora built-in prometheus service.
    if cfg.observability.metrics_enabled {
        let mut prom = pingora::services::listening::Service::prometheus_http_service();
        prom.add_tcp(&cfg.observability.metrics_bind);
        server.add_service(prom);
    }

    server.add_service(svc);

    tracing::info!("arc started");
    server.run_forever();
}

fn spawn_control_plane(cfg: ArcConfig, shared: Arc<SharedConfig>) {
    use axum::{routing::get, routing::post, Json, Router};

    let state = ControlState { cfg: shared };

    let app = Router::new()
        .route(
            "/v1/status",
            get({
                let node_id = cfg.node.id.clone();
                let state = state.clone();
                move || async move {
                    let gen = state.cfg.load().generation;
                    Json(StatusResponse {
                        generation: gen,
                        node_id,
                    })
                }
            }),
        )
        .route(
            "/v1/config",
            post({
                let state = state.clone();
                move |Json(req): Json<ConfigPushRequest>| async move {
                    let gen = state.apply_config(req.config).map_err(|e| {
                        (
                            axum::http::StatusCode::BAD_REQUEST,
                            format!("{:#}", e),
                        )
                    })?;
                    Ok::<_, (axum::http::StatusCode, String)>(Json(ConfigPushResponse { generation: gen }))
                }
            }),
        )
        .route(
            "/v1/config",
            get({
                let state = state.clone();
                move || async move {
                    let raw = state.cfg.load().raw.clone();
                    Json(raw)
                }
            }),
        );

    let bind = cfg.control_plane.bind.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build control-plane runtime");

        rt.block_on(async move {
            tracing::info!(%bind, "control plane listening");
            let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
}
