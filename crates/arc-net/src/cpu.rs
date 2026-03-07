use std::io;
use std::mem;

pub fn cpu_count() -> io::Result<usize> {
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n <= 0 {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "sysconf(_SC_NPROCESSORS_ONLN) failed",
        ))
    } else {
        Ok(n as usize)
    }
}

pub fn set_thread_affinity(cpu: usize) -> io::Result<()> {
    unsafe {
        let mut set: libc::cpu_set_t = mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        let rc = libc::sched_setaffinity(
            0,
            mem::size_of::<libc::cpu_set_t>(),
            &set as *const libc::cpu_set_t,
        );
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn set_current_thread_name(name: &str) {
    // Linux pthread_setname_np limit is 16 bytes including NUL.
    let mut buf = [0u8; 16];
    let b = name.as_bytes();
    let n = b.len().min(15);
    buf[..n].copy_from_slice(&b[..n]);
    buf[n] = 0;

    unsafe {
        let _ = libc::pthread_setname_np(libc::pthread_self(), buf.as_ptr() as *const libc::c_char);
    }
}
