# Arc Gateway

> [!NOTE]
> Documentation is largely complete. The project is currently in active testing.

A high-performance HTTP reverse proxy built on Linux io_uring, designed for modern cloud-native environments.

Arc delivers 2x the throughput of Nginx in HTTP/1.1 proxy scenarios while maintaining zero-error guarantees under load. It combines a thread-per-core architecture with lock-free algorithms to minimize latency and maximize resource efficiency.

## Performance

Benchmarked on WSL2 Debian (2 vCPU):

| Scenario | Arc | Nginx | Ratio |
|---|---|---|---|
| HTTP/1.1 proxy (c=256) | 102,203 RPS | 49,930 RPS | **2.05x** |
| HTTP/1.1 proxy (c=512) | 96,143 RPS | 41,740 RPS | **2.30x** |
| HTTP/2 high concurrency | 100% success | 91.5% success | — |
| Proxy latency overhead | +0.82ms | +1.35ms | **39% lower** |

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/shuakami/Arc/master/install.sh | sh
arc-gateway --help
```

The installer downloads the latest release, verifies SHA256, and installs `arc-gateway` to `/usr/local/bin`. Supports Linux `x86_64` and `arm64`.

Create `arc.yaml`:

```yaml
node:
  workers: 0

listeners:
  - name: http
    kind: http
    bind: "0.0.0.0:8080"

upstreams:
  - name: app
    discovery:
      type: static
      endpoints:
        - address: "127.0.0.1:3000"

routes:
  - name: root
    match:
      path: "/{*rest}"
    action:
      upstream: app
```

Run:

```bash
arc-gateway --config arc.yaml
```

Verify:

```bash
curl http://localhost:8080/         # proxied response
curl http://localhost:9090/healthz  # "ok"
curl http://localhost:9090/metrics  # Prometheus text
```

## Features

- **io_uring data plane** — Fixed buffers, multishot accept, SQPOLL; syscall-free hot path
- **Thread-per-core** — Each worker owns its ring, buffer pool, and connection slab; no cross-thread contention
- **Radix tree routing** — O(log n) path matching with captures, wildcards, and multi-predicate matching (host, method, headers, cookies)
- **Lock-free rate limiting** — GCRA algorithm with atomic CAS; no mutex in hot path
- **WASM plugins** — Wasmtime instance pool with epoch-based timeout isolation; `on_request` ABI
- **Hot reload** — ArcSwap-based config updates without dropping connections
- **TLS termination** — Rustls with SNI-based certificate selection and ACME automation (TLS-ALPN-01, HTTP-01, DNS-01)
- **HTTP/2 support** — Full multiplexing with HPACK, flow control, and configurable stream limits
- **Distributed rate limiting** — Redis-backed global limits with circuit breaker fallback to local GCRA
- **XDP/eBPF filtering** — Kernel-level packet filtering; SYN flood detection; dynamic blacklist/whitelist
- **Traffic mirroring** — Fire-and-forget shadow traffic with sampling and response comparison
- **Observability** — Prometheus metrics, per-phase latency counters, NDJSON access logs, W3C trace context

## Documentation

Full documentation is available at **[arc.sdjz.wiki](https://arc.sdjz.wiki)**.

| Page | Description |
|---|---|
| [Getting Started](https://arc.sdjz.wiki/getting-started) | Install, first config, verify |
| [Configuration](https://arc.sdjz.wiki/configuration) | Complete field reference |
| [Architecture](https://arc.sdjz.wiki/architecture) | Thread-per-core, io_uring, crate graph |
| [Security](https://arc.sdjz.wiki/security) | XDP, rate limiting, L7 protection |
| [TLS & Certificates](https://arc.sdjz.wiki/tls-and-certificates) | Rustls, ACME, mTLS |
| [Traffic Management](https://arc.sdjz.wiki/traffic-management) | Routing, plugins, mirroring |
| [Observability](https://arc.sdjz.wiki/observability) | Metrics, access logs, tracing |
| [Deployment](https://arc.sdjz.wiki/deployment) | systemd, Kubernetes, production checklist |
| [Control Plane API](https://arc.sdjz.wiki/control-plane-api) | HTTP management API reference |
| [CLI](https://arc.sdjz.wiki/cli) | `arc logs tail` and `arc logs query` |
| [Benchmarks](https://arc.sdjz.wiki/benchmarks) | Methodology and results |

## Requirements

- Linux kernel ≥ 5.10 (6.1+ recommended for best io_uring support)
- Redis 6+ (optional — only needed for cluster-wide rate limiting)

## License

Apache 2.0