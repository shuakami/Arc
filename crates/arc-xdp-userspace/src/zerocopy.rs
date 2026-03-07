use std::io;
use std::mem;
use std::os::fd::RawFd;

pub const DEFAULT_ZEROCOPY_THRESHOLD: usize = 4096;

/// ZeroCopyResponder config + helper.
#[derive(Debug, Clone, Copy)]
pub struct ZeroCopyResponder {
    threshold: usize,
}

impl ZeroCopyResponder {
    /// Create with threshold bytes.
    #[inline]
    pub fn new(threshold: usize) -> Self {
        Self {
            threshold: threshold.max(1),
        }
    }

    /// Get threshold.
    #[inline]
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Decide whether to use zerocopy for a payload size.
    #[inline]
    pub fn should_zerocopy(&self, body_len: usize) -> bool {
        body_len > self.threshold
    }

    pub fn enable_socket_zerocopy(fd: RawFd) -> io::Result<()> {
        let val: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ZEROCOPY,
                &val as *const libc::c_int as *const libc::c_void,
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Send buffer using sendmsg; if body_len > threshold uses MSG_ZEROCOPY.
    ///
    /// 这是一个“同步路径”实现，便于验证；未来可替换为 io_uring sendmsg/SEND_ZC。
    pub fn send_best_effort(&self, fd: RawFd, buf: &[u8]) -> io::Result<usize> {
        if !self.should_zerocopy(buf.len()) {
            return send_plain(fd, buf);
        }
        send_msg_zerocopy(fd, buf).or_else(|e| {
            // fallback to plain send for unsupported kernels/paths
            let _ = e;
            send_plain(fd, buf)
        })
    }
}

fn send_plain(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    let rc = unsafe {
        libc::send(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

fn send_msg_zerocopy(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;

    let flags = libc::MSG_NOSIGNAL | libc::MSG_ZEROCOPY;
    let rc = unsafe { libc::sendmsg(fd, &msg as *const libc::msghdr, flags) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}
