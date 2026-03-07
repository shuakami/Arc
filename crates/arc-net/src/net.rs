use std::io;
use std::mem;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::RawFd;

pub struct SockAddr {
    storage: libc::sockaddr_storage,
    len: libc::socklen_t,
}

impl SockAddr {
    pub fn from_socket_addr(addr: &SocketAddr) -> Self {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let len: libc::socklen_t = match addr {
            SocketAddr::V4(a) => {
                let sa = sockaddr_in_from_v4(a);
                unsafe {
                    std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in, sa);
                }
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(a) => {
                let sa = sockaddr_in6_from_v6(a);
                unsafe {
                    std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in6, sa);
                }
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        };

        Self { storage, len }
    }

    #[inline]
    pub fn as_ptr(&self) -> *const libc::sockaddr {
        &self.storage as *const libc::sockaddr_storage as *const libc::sockaddr
    }

    #[inline]
    pub fn len(&self) -> libc::socklen_t {
        self.len
    }
}

fn sockaddr_in_from_v4(a: &SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: a.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(a.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

fn sockaddr_in6_from_v6(a: &SocketAddrV6) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: a.port().to_be(),
        sin6_flowinfo: a.flowinfo(),
        sin6_addr: libc::in6_addr {
            s6_addr: a.ip().octets(),
        },
        sin6_scope_id: a.scope_id(),
    }
}

pub fn create_listener(addr: &SocketAddr, backlog: i32, reuse_port: bool) -> io::Result<RawFd> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };

    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    if let Err(e) = set_reuseaddr(fd) {
        unsafe { libc::close(fd) };
        return Err(e);
    }

    if reuse_port {
        if let Err(e) = set_reuseport(fd) {
            unsafe { libc::close(fd) };
            return Err(e);
        }
    }

    // Best-effort: allow both v4/v6 on an IPv6 wildcard socket.
    if let SocketAddr::V6(v6) = addr {
        if v6.ip().is_unspecified() {
            let _ = set_ipv6_v6only(fd, false);
        }
    }

    let sa = SockAddr::from_socket_addr(addr);
    let rc = unsafe { libc::bind(fd, sa.as_ptr(), sa.len()) };
    if rc != 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }

    let rc = unsafe { libc::listen(fd, backlog) };
    if rc != 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }

    Ok(fd)
}

pub fn create_client_socket(addr: &SocketAddr) -> io::Result<RawFd> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };

    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let _ = set_tcp_nodelay(fd);
    let _ = set_keepalive(fd);
    Ok(fd)
}

pub fn set_tcp_nodelay(fd: RawFd) -> io::Result<()> {
    set_sockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)
}

pub fn set_keepalive(fd: RawFd) -> io::Result<()> {
    set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)
}

pub fn set_zerocopy(fd: RawFd, enabled: bool) -> io::Result<()> {
    set_sockopt_int(
        fd,
        libc::SOL_SOCKET,
        libc::SO_ZEROCOPY,
        if enabled { 1 } else { 0 },
    )
}

pub fn set_linger(fd: RawFd, linger_ms: u32) -> io::Result<()> {
    let l_onoff = if linger_ms == 0 { 0 } else { 1 };
    let secs = if linger_ms == 0 {
        0
    } else {
        ((linger_ms + 999) / 1000) as i32
    };

    let opt = libc::linger {
        l_onoff,
        l_linger: secs,
    };

    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &opt as *const libc::linger as *const libc::c_void,
            mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };

    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn set_reuseaddr(fd: RawFd) -> io::Result<()> {
    set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)
}

pub fn set_reuseport(fd: RawFd) -> io::Result<()> {
    set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)
}

pub fn set_ipv6_v6only(fd: RawFd, v6only: bool) -> io::Result<()> {
    set_sockopt_int(
        fd,
        libc::IPPROTO_IPV6,
        libc::IPV6_V6ONLY,
        if v6only { 1 } else { 0 },
    )
}

fn set_sockopt_int(fd: RawFd, level: i32, optname: i32, val: i32) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &val as *const i32 as *const libc::c_void,
            mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Best-effort probe: check whether an idle upstream socket still looks reusable.
pub fn is_idle_stream_reusable(fd: RawFd) -> bool {
    let mut b = [0u8; 1];
    let rc = unsafe {
        libc::recv(
            fd,
            b.as_mut_ptr().cast(),
            b.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };

    if rc == 0 {
        return false;
    }
    if rc > 0 {
        return false;
    }

    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK || code == libc::EINTR => {
            true
        }
        _ => false,
    }
}
