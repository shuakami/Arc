use core::mem;

#[inline]
pub fn monotonic_nanos() -> u64 {
    unsafe {
        let mut ts: libc::timespec = mem::zeroed();
        // SAFETY: ts is valid, CLOCK_MONOTONIC is supported on Linux.
        let rc = libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts as *mut libc::timespec);
        if rc != 0 {
            // 无法在热路径返回 Result；此处退化为 0（等价“立刻超时/立刻允许”的上层可控行为）。
            // 生产环境建议用 metrics 监控此异常。
            return 0;
        }
        (ts.tv_sec as u64)
            .saturating_mul(1_000_000_000u64)
            .saturating_add(ts.tv_nsec as u64)
    }
}
