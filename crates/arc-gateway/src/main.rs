#[cfg(not(target_os = "linux"))]
compile_error!("arc-gateway currently targets Linux only (io_uring + thread-per-core).");

mod acme;
mod cluster_circuit;
mod control;
mod downstream_tls;
mod gossip;
mod h2;
#[allow(dead_code)]
mod mirror_dispatcher;
#[allow(dead_code)]
mod timeout_tier;
mod tls;
mod worker;

use arc_common::{ArcError, Result};
use arc_config::{ConfigManager, ControlRole, GlobalRateLimitBackend, SharedConfig};
use arc_global_rate_limit::{
    redis_backend::RedisLuaBackend, GlobalRateLimiter, GlobalRateLimiterConfig, InMemoryBackend,
    RateLimiterBackend, WorkerLimiter as GlobalWorkerLimiter,
};
use arc_logging::LoggingError;
use arc_net::cpu;
use arc_observability::{start_admin_server, MetricsRegistry};
use cluster_circuit::{ClusterCircuit, ClusterCircuitConfig};

use std::collections::HashSet;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// NEW: XDP userspace integration
use arc_xdp_userspace::manager::{set_global_xdp_manager, L7LinkHandle};
use arc_xdp_userspace::XdpManager;
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::flag as signal_flag;

const DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    if let Err(e) = ignore_sigpipe() {
        eprintln!("{e}");
        process::exit(1);
    }
    if let Err(e) = real_main() {
        eprintln!("{e}");
        process::exit(1);
    }
}

fn ignore_sigpipe() -> Result<()> {
    let prev = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    if prev == libc::SIG_ERR {
        return Err(ArcError::io("ignore SIGPIPE", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn real_main() -> Result<()> {
    let args = Args::from_env()?;
    if args.check_only {
        let report = ConfigManager::check_from_path(&args.config_path)?;
        if report.errors.is_empty() {
            println!("config OK");
            return Ok(());
        }
        for (idx, err) in report.errors.iter().enumerate() {
            eprintln!("error[{}]: {}", idx + 1, err);
        }
        eprintln!(
            "Found {} errors, config not valid",
            report.errors.len()
        );
        process::exit(1);
    }
    let cfg = ConfigManager::load_from_path(&args.config_path)?;
    let admin_auth_token = resolve_management_auth_token(&cfg);
    warn_if_management_surface_public(&cfg);

    let detected = cpu::cpu_count().unwrap_or(1).max(1);
    let workers = if cfg.workers == 0 {
        detected
    } else {
        cfg.workers
    };
    if workers == 0 {
        return Err(ArcError::config("workers must be > 0".to_string()));
    }

    let mgr = ConfigManager::new(cfg);
    mgr.spawn_hot_reload(args.config_path.clone(), 500);
    let swap = mgr.swap();
    let initial_raw_json = swap.load().raw_json.clone();

    match arc_logging::init_global_from_raw_json(workers, initial_raw_json.as_ref()) {
        Ok(_) => {}
        Err(LoggingError::AlreadyInitialized) => {}
        Err(e) => return Err(ArcError::config(format!("init arc-logging failed: {e}"))),
    }

    let cfg_path = args
        .config_path
        .to_str()
        .ok_or_else(|| ArcError::config("config path must be valid UTF-8".to_string()))?;
    acme::init_from_config_path(cfg_path)?;

    let bootstrap_cfg = swap.load();
    let cp_cfg = bootstrap_cfg.control_plane.clone();
    let cc_cfg = bootstrap_cfg.cluster_circuit.clone();
    let cluster_mode_configured = cp_cfg.enabled
        && (!cp_cfg.peers.is_empty()
            || !matches!(cp_cfg.role, ControlRole::Standalone)
            || cp_cfg.pull_from.is_some());
    let mut circuit_cfg = ClusterCircuitConfig::default();
    circuit_cfg.enabled = cluster_mode_configured;
    circuit_cfg.fail_streak_threshold = cc_cfg.failure_threshold.max(1);
    circuit_cfg.open_ms = cc_cfg.circuit_open_ms.max(1);
    circuit_cfg.half_open_probe_interval_ms = cc_cfg.half_open_probe_interval_ms.max(1);
    circuit_cfg.peer_sync_interval_ms = cp_cfg.pull_interval_ms.max(200);
    circuit_cfg.peer_ttl_ms = cp_cfg.peer_timeout_ms.saturating_mul(4).max(1_000);
    circuit_cfg.peer_open_quorum = cc_cfg.quorum.max(1);
    let cluster_circuit = Arc::new(ClusterCircuit::new(cp_cfg.node_id.clone(), circuit_cfg));
    if cluster_mode_configured {
        spawn_active_upstream_health_checker(mgr.clone(), cluster_circuit.clone())?;
    }

    control::start_control_plane(mgr.clone(), cluster_circuit.clone())?;

    let reg = MetricsRegistry::new(workers);
    start_admin_server(swap.load().admin_listen, reg.clone(), admin_auth_token)?;

    let grl_cfg = swap.load().global_rate_limit.clone();
    let mut grl_runtime_cfg = GlobalRateLimiterConfig::default();
    let backend: Arc<dyn RateLimiterBackend> = match grl_cfg.backend {
        GlobalRateLimitBackend::InMemory => Arc::new(InMemoryBackend::new(workers.max(1) * 4)),
        GlobalRateLimitBackend::Redis => {
            let redis = grl_cfg.redis.as_ref().ok_or_else(|| {
                ArcError::config(
                    "global_rate_limit.backend=redis but global_rate_limit.redis is missing"
                        .to_string(),
                )
            })?;

            grl_runtime_cfg.redis_budget = Duration::from_millis(redis.budget_ms.max(1));
            grl_runtime_cfg.circuit_open = Duration::from_millis(redis.circuit_open_ms.max(1));
            grl_runtime_cfg.prefetch = redis.prefetch.max(1);
            grl_runtime_cfg.low_watermark = redis
                .low_watermark
                .min(grl_runtime_cfg.prefetch.saturating_sub(1).max(1));
            grl_runtime_cfg.refill_backoff = Duration::from_millis(redis.refill_backoff_ms.max(1));

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|e| {
                    ArcError::config(format!("build global_rate_limit redis runtime failed: {e}"))
                })?;
            let redis_backend = rt
                .block_on(RedisLuaBackend::connect(redis.url.as_str()))
                .map_err(|e| {
                    ArcError::config(format!(
                        "connect global_rate_limit redis failed ({}): {e}",
                        redis.url
                    ))
                })?;
            Arc::new(redis_backend)
        }
    };

    let (global_rl, handles) = GlobalRateLimiter::spawn(backend, workers, grl_runtime_cfg);
    let mut global_worker_limiters: Vec<Option<GlobalWorkerLimiter>> =
        handles.into_iter().map(Some).collect();
    let _global_rl = global_rl;

    // ---------------- NEW: start XDP manager (best-effort, never fatal) ----------------
    //
    // 说明：
    // - XdpManager 会从 swap.load().raw_json 旁路解析 xdp/l7_protection 配置。
    // - XDP Disabled 模式下不报错，仅输出明确提示（由内部模块负责）。
    // - L7 联动：这里先提供一个 noop channel。后续接入 arc-rate-limit 模块时，
    //   可把 rx 挂到控制面 runtime 或专门任务中执行实际封禁/倍率调整。
    let (l7_link, _l7_rx) = L7LinkHandle::noop();
    let xdp_mgr = match XdpManager::spawn(swap.clone(), l7_link) {
        Ok(v) => {
            set_global_xdp_manager(v.clone());
            Some(v)
        }
        Err(e) => {
            eprintln!("xdp warn: init failed, running without xdp: {e}");
            None
        }
    };
    let _xdp_mgr_keepalive = xdp_mgr;

    let shutdown = Arc::new(AtomicBool::new(false));
    let drained_workers = Arc::new(AtomicUsize::new(0));
    install_shutdown_signal_handlers(shutdown.clone())?;

    {
        let watchdog_shutdown = shutdown.clone();
        let watchdog_drained = drained_workers.clone();
        let watchdog_workers = workers;
        thread::Builder::new()
            .name("arc-grace-watchdog".to_string())
            .spawn(move || {
                while !watchdog_shutdown.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(50));
                }
                let deadline = std::time::Instant::now()
                    + DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT
                    + Duration::from_secs(2);
                loop {
                    if watchdog_drained.load(Ordering::Relaxed) >= watchdog_workers {
                        eprintln!("graceful shutdown: all workers drained, exiting process");
                        process::exit(0);
                    }
                    if std::time::Instant::now() >= deadline {
                        eprintln!(
                            "graceful shutdown: process-level timeout reached, forcing process exit"
                        );
                        process::exit(0);
                    }
                    thread::sleep(Duration::from_millis(50));
                }
            })
            .map_err(|e| ArcError::io("spawn graceful watchdog", e))?;
    }

    let mut worker_handles = Vec::with_capacity(workers);
    for wid in 0..workers {
        let swap = swap.clone();
        let metrics = reg.worker(wid);
        let global_limiter = global_worker_limiters
            .get_mut(wid)
            .and_then(|slot| slot.take());
        let cluster_circuit = cluster_circuit.clone();
        let worker_shutdown = shutdown.clone();
        let worker_drained = drained_workers.clone();

        let builder = std::thread::Builder::new().name(format!("arc-gw-{wid}"));
        let h = builder
            .spawn(move || {
                if let Err(e) = worker::Worker::run(
                    wid,
                    workers,
                    swap,
                    metrics,
                    global_limiter,
                    cluster_circuit,
                    worker_shutdown,
                    worker_drained,
                    DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT,
                ) {
                    eprintln!("worker[{wid}] fatal: {e}");
                    process::exit(1);
                }
            })
            .map_err(|e| ArcError::io("spawn worker", e))?;
        worker_handles.push(h);
    }

    for h in worker_handles {
        if h.join().is_err() {
            return Err(ArcError::internal("worker thread panicked"));
        }
    }

    Ok(())
}

fn install_shutdown_signal_handlers(shutdown: Arc<AtomicBool>) -> Result<()> {
    signal_flag::register(SIGTERM, shutdown.clone())
        .map_err(|e| ArcError::io("register SIGTERM handler", e))?;
    signal_flag::register(SIGINT, shutdown)
        .map_err(|e| ArcError::io("register SIGINT handler", e))?;
    Ok(())
}

fn resolve_management_auth_token(cfg: &SharedConfig) -> Option<Arc<str>> {
    let token = cfg
        .control_plane
        .auth_token
        .as_deref()
        .map(str::trim)
        .unwrap_or("");
    if token.is_empty() {
        eprintln!(
            "WARNING: control_plane.auth_token is empty; management endpoints allow loopback only, external requests will return 401"
        );
        return None;
    }
    Some(Arc::from(token))
}

fn warn_if_management_surface_public(cfg: &SharedConfig) {
    let token_empty = cfg
        .control_plane
        .auth_token
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty();

    if let Ok(cp_bind) = cfg.control_plane.bind.parse::<SocketAddr>() {
        if cp_bind.ip().is_unspecified() {
            if token_empty {
                eprintln!(
                    "SECURITY WARNING: control_plane.bind={} with empty control_plane.auth_token; external control-plane requests will be rejected with 401, only loopback is allowed",
                    cp_bind
                );
            } else {
                eprintln!(
                    "SECURITY WARNING: control_plane.bind={} (0.0.0.0/::) exposes control plane to external network; this is dangerous unless intentionally required",
                    cp_bind
                );
            }
        }
    }
    if cfg.admin_listen.ip().is_unspecified() {
        if token_empty {
            eprintln!(
                "SECURITY WARNING: admin_listen={} with empty control_plane.auth_token; external admin requests will be rejected with 401, only loopback is allowed",
                cfg.admin_listen
            );
        } else {
            eprintln!(
                "SECURITY WARNING: admin_listen={} (0.0.0.0/::) exposes admin endpoint to external network; this is dangerous unless intentionally required",
                cfg.admin_listen
            );
        }
    }
}

fn spawn_active_upstream_health_checker(
    mgr: ConfigManager,
    cluster_circuit: Arc<ClusterCircuit>,
) -> Result<()> {
    thread::Builder::new()
        .name("arc-up-health".to_string())
        .spawn(move || loop {
            let cfg = mgr.current();
            let cc = cfg.cluster_circuit.clone();
            let interval_ms = cc.active_probe_interval_ms.max(1);

            if cc.active_probe_enabled && cluster_circuit.enabled() {
                let timeout = Duration::from_millis(cc.active_probe_timeout_ms.max(1));
                let mut seen = HashSet::with_capacity(cfg.upstreams.len());
                for up in cfg.upstreams.iter() {
                    if !seen.insert(up.addr) {
                        continue;
                    }
                    match TcpStream::connect_timeout(&up.addr, timeout) {
                        Ok(stream) => {
                            let _ = stream.shutdown(Shutdown::Both);
                            cluster_circuit.record_success(up.addr);
                        }
                        Err(_) => {
                            cluster_circuit.record_failure(up.addr);
                        }
                    }
                }
            }

            thread::sleep(Duration::from_millis(interval_ms));
        })
        .map_err(|e| ArcError::io("spawn upstream active health checker", e))?;
    Ok(())
}

struct Args {
    config_path: PathBuf,
    check_only: bool,
}

impl Args {
    fn from_env() -> Result<Self> {
        let mut it = std::env::args();
        let _program = it.next();

        let mut config_path: Option<PathBuf> = None;
        let mut check_only = false;

        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--config" => {
                    let v = it
                        .next()
                        .ok_or_else(|| ArcError::config("--config requires <path>".to_string()))?;
                    config_path = Some(PathBuf::from(v));
                }
                "--help" | "-h" => {
                    print_help();
                    process::exit(0);
                }
                "--check" => {
                    check_only = true;
                }
                _ => {
                    return Err(ArcError::config(format!(
                        "unknown argument: {arg} (use --help)"
                    )));
                }
            }
        }

        let config_path = config_path.unwrap_or_else(|| PathBuf::from("arc.example.json"));
        Ok(Self {
            config_path,
            check_only,
        })
    }
}

fn print_help() {
    println!(
        "\
arc-gateway — io_uring thread-per-core HTTP/1.1 reverse proxy

USAGE:
  arc-gateway [--check] [--config <path>]

OPTIONS:
  --check            Validate config then exit (no worker/listener start)
  --config <path>    Config file (.json/.toml/.yaml/.yml), default: arc.example.json
  -h, --help         Print this help
"
    );
}
