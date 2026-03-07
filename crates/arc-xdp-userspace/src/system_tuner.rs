use crate::bpf;
use arc_common::{ArcError, Result};
use std::ffi::CString;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuneMode {
    Check,
    Auto,
}

#[derive(Debug, Clone)]
pub struct TuneItemResult {
    pub name: String,
    pub ok: bool,
    pub skipped: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct TuneResult {
    pub mode: TuneMode,
    pub items: Vec<TuneItemResult>,
}

/// Snapshot for `arc system status`.
#[derive(Debug, Clone)]
pub struct SystemStatusSnapshot {
    pub kernel_release: String,
    pub cpu_count: usize,
    pub irq_affinity_configured: bool,
    pub worker_affinity_configured: bool,
}

pub struct SystemTuner;

impl SystemTuner {
    /// Run tune in check or auto mode.
    ///
    /// `iface`: target NIC for queue/irq tuning.
    pub fn run(mode: TuneMode, iface: &str) -> Result<TuneResult> {
        let mut items: Vec<TuneItemResult> = Vec::new();

        // 1) sysctl tuning
        items.extend(Self::tune_sysctls(mode));

        // 2) NIC queues => CPU cores
        items.push(Self::tune_nic_queues(mode, iface));

        // 3) IRQ affinity for NIC
        items.push(Self::tune_irq_affinity(mode, iface));

        Ok(TuneResult { mode, items })
    }

    /// System status snapshot (best-effort).
    pub fn status_snapshot() -> SystemStatusSnapshot {
        let kernel_release = bpf::kernel_release();
        let cpu_count = bpf::cpu_count_online();

        // Best-effort: without per-host persistent markers we cannot know for sure.
        // We heuristically say "configured" if at least one NIC irq affinity list exists and is not "0".
        let irq_affinity_configured = Self::heuristic_irq_affinity_configured();
        // Worker affinity: Arc worker already does sched_setaffinity; outside process can't verify reliably.
        let worker_affinity_configured = false;

        SystemStatusSnapshot {
            kernel_release,
            cpu_count,
            irq_affinity_configured,
            worker_affinity_configured,
        }
    }

    fn tune_sysctls(mode: TuneMode) -> Vec<TuneItemResult> {
        // 你提到 tcp_syncookies 等 6 项；这里选择“保守且常用”的 6 个。
        // 调整值都以抗 SYN flood 为目标，不做过度激进的减少重试（避免弱网环境过多失败）。
        let sysctls = [
            ("net.ipv4.tcp_syncookies", "1"),
            ("net.ipv4.tcp_max_syn_backlog", "262144"),
            ("net.ipv4.tcp_synack_retries", "3"),
            ("net.ipv4.tcp_syn_retries", "5"),
            ("net.core.somaxconn", "65535"),
            ("net.core.netdev_max_backlog", "16384"),
        ];

        let mut out = Vec::with_capacity(sysctls.len());
        for (k, want) in sysctls {
            out.push(Self::apply_sysctl(mode, k, want));
        }
        out
    }

    fn apply_sysctl(mode: TuneMode, key: &str, want: &str) -> TuneItemResult {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        let name = format!("sysctl:{key}");

        let cur = fs::read_to_string(&path).ok().map(|s| s.trim().to_string());
        if let Some(cur) = cur.as_ref() {
            if cur == want {
                return TuneItemResult {
                    name,
                    ok: true,
                    skipped: true,
                    message: format!("already {want}"),
                };
            }
        }

        if mode == TuneMode::Check {
            return TuneItemResult {
                name,
                ok: true,
                skipped: true,
                message: format!(
                    "would set to {want} (current: {})",
                    cur.unwrap_or_else(|| "unknown".to_string())
                ),
            };
        }

        match fs::write(&path, want.as_bytes()) {
            Ok(_) => TuneItemResult {
                name,
                ok: true,
                skipped: false,
                message: format!("set to {want}"),
            },
            Err(e) => TuneItemResult {
                name,
                ok: false,
                skipped: false,
                message: format!("write failed: {e}"),
            },
        }
    }

    fn tune_nic_queues(mode: TuneMode, iface: &str) -> TuneItemResult {
        let name = format!("ethtool-queues:{iface}");
        let cpu = bpf::cpu_count_online().max(1);

        // We use `ethtool -l` to read current, `ethtool -L` to set.
        // Many environments require CAP_NET_ADMIN.
        let cur = Self::ethtool_show_queues(iface).ok();
        if let Some(cur) = cur {
            if cur == cpu {
                return TuneItemResult {
                    name,
                    ok: true,
                    skipped: true,
                    message: format!("already combined={cpu}"),
                };
            }
        }

        if mode == TuneMode::Check {
            return TuneItemResult {
                name,
                ok: true,
                skipped: true,
                message: format!(
                    "would set combined queues to {cpu} (current: {})",
                    cur.map(|v| v.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                ),
            };
        }

        let rc = Command::new("ethtool")
            .arg("-L")
            .arg(iface)
            .arg("combined")
            .arg(cpu.to_string())
            .status();

        match rc {
            Ok(st) if st.success() => TuneItemResult {
                name,
                ok: true,
                skipped: false,
                message: format!("set combined={cpu}"),
            },
            Ok(st) => TuneItemResult {
                name,
                ok: false,
                skipped: false,
                message: format!("ethtool exit status: {st}"),
            },
            Err(e) => TuneItemResult {
                name,
                ok: false,
                skipped: false,
                message: format!("spawn ethtool failed: {e}"),
            },
        }
    }

    fn ethtool_show_queues(iface: &str) -> io::Result<usize> {
        // Parse output from: ethtool -l iface
        let out = Command::new("ethtool").arg("-l").arg(iface).output()?;
        if !out.status.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "ethtool -l failed"));
        }
        let s = String::from_utf8_lossy(&out.stdout);

        // Example lines include:
        // "Combined: 8"
        for line in s.lines() {
            let line = line.trim();
            if line.starts_with("Combined:") {
                if let Some(v) = line.split(':').nth(1) {
                    let n = v.trim().parse::<usize>().unwrap_or(0);
                    if n > 0 {
                        return Ok(n);
                    }
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            "failed to parse combined queues",
        ))
    }

    fn tune_irq_affinity(mode: TuneMode, iface: &str) -> TuneItemResult {
        let name = format!("irq-affinity:{iface}");
        let cpu = bpf::cpu_count_online().max(1);

        let irqs = match Self::find_iface_irqs(iface) {
            Ok(v) => v,
            Err(e) => {
                return TuneItemResult {
                    name,
                    ok: false,
                    skipped: false,
                    message: format!("find irqs failed: {e}"),
                }
            }
        };

        if irqs.is_empty() {
            return TuneItemResult {
                name,
                ok: true,
                skipped: true,
                message: "no IRQs found (maybe virtio/af_xdp/offload?)".to_string(),
            };
        }

        // Round-robin bind IRQs to CPUs.
        let mut any_fail = false;
        let mut applied = 0usize;

        for (idx, irq) in irqs.iter().enumerate() {
            let cpu_id = idx % cpu;
            let want = cpu_id.to_string();
            let path = format!("/proc/irq/{irq}/smp_affinity_list");

            let cur = fs::read_to_string(&path).ok().map(|s| s.trim().to_string());
            if let Some(cur) = cur.as_ref() {
                if cur == &want {
                    continue;
                }
            }

            if mode == TuneMode::Auto {
                if let Err(e) = fs::write(&path, want.as_bytes()) {
                    any_fail = true;
                    eprintln!("system tune warn: write {path} failed: {e}");
                } else {
                    applied += 1;
                }
            }
        }

        if mode == TuneMode::Check {
            TuneItemResult {
                name,
                ok: true,
                skipped: true,
                message: format!(
                    "would bind {} IRQs across {} CPUs (round-robin)",
                    irqs.len(),
                    cpu
                ),
            }
        } else if any_fail {
            TuneItemResult {
                name,
                ok: false,
                skipped: false,
                message: format!("applied {applied} updates, some failed"),
            }
        } else {
            TuneItemResult {
                name,
                ok: true,
                skipped: applied == 0,
                message: if applied == 0 {
                    "already configured".to_string()
                } else {
                    format!("applied {applied} updates")
                },
            }
        }
    }

    fn find_iface_irqs(iface: &str) -> io::Result<Vec<u32>> {
        // Parse /proc/interrupts and find lines containing iface.
        let s = fs::read_to_string("/proc/interrupts")?;
        let mut out = Vec::new();

        for line in s.lines() {
            if !line.contains(iface) {
                continue;
            }
            // Format: "  123: ... iface-TxRx-0"
            let mut it = line.split(':');
            let Some(left) = it.next() else { continue };
            let left = left.trim();
            if left.is_empty() {
                continue;
            }
            if let Ok(n) = left.parse::<u32>() {
                out.push(n);
            }
        }

        Ok(out)
    }

    fn heuristic_irq_affinity_configured() -> bool {
        let p = Path::new("/proc/irq");
        let Ok(rd) = fs::read_dir(p) else {
            return false;
        };
        for ent in rd.flatten() {
            let path = ent.path().join("smp_affinity_list");
            if let Ok(s) = fs::read_to_string(&path) {
                let v = s.trim();
                if !v.is_empty() && v != "0" {
                    return true;
                }
            }
        }
        false
    }

    /// Best-effort helper to get ifindex (for future netlink operations).
    pub fn ifindex(iface: &str) -> Result<u32> {
        let c = CString::new(iface.as_bytes())
            .map_err(|_| ArcError::config("iface contains NUL".to_string()))?;
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if idx == 0 {
            Err(ArcError::io("if_nametoindex", io::Error::last_os_error()))
        } else {
            Ok(idx)
        }
    }
}
