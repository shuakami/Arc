use std::mem;
use std::os::fd::RawFd;

use crate::uring::sys;

#[inline]
fn blank() -> sys::io_uring_sqe {
    unsafe { mem::zeroed() }
}

#[inline]
pub fn accept(
    listener_fd: RawFd,
    fixed_file: bool,
    multishot: bool,
    user_data: u64,
) -> sys::io_uring_sqe {
    let mut sqe = blank();
    sqe.opcode = sys::IORING_OP_ACCEPT;
    sqe.fd = listener_fd;
    if fixed_file {
        sqe.flags |= sys::IOSQE_FIXED_FILE;
    }
    // accept4 flags:
    let mut flags = (libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u32;
    if multishot {
        flags |= sys::IORING_ACCEPT_MULTISHOT;
    }
    sqe.op_flags = flags;
    sqe.user_data = user_data;
    sqe
}

#[inline]
pub fn connect(
    fd: RawFd,
    fixed_file: bool,
    addr: *const libc::sockaddr,
    addrlen: u32,
    user_data: u64,
) -> sys::io_uring_sqe {
    let mut sqe = blank();
    sqe.opcode = sys::IORING_OP_CONNECT;
    sqe.fd = fd;
    if fixed_file {
        sqe.flags |= sys::IOSQE_FIXED_FILE;
    }
    sqe.addr = addr as u64;
    // For IORING_OP_CONNECT, addrlen is carried in `off`, not `len`.
    sqe.off = addrlen as u64;
    sqe.user_data = user_data;
    sqe
}

#[inline]
pub fn read_fixed(
    fd: RawFd,
    fixed_file: bool,
    buf: *mut u8,
    len: u32,
    buf_index: u16,
    user_data: u64,
) -> sys::io_uring_sqe {
    let mut sqe = blank();
    sqe.opcode = sys::IORING_OP_READ_FIXED;
    sqe.fd = fd;
    if fixed_file {
        sqe.flags |= sys::IOSQE_FIXED_FILE;
    }
    sqe.off = 0;
    sqe.addr = buf as u64;
    sqe.len = len;
    sqe.buf_index = buf_index;
    sqe.user_data = user_data;
    sqe
}

#[inline]
pub fn write_fixed(
    fd: RawFd,
    fixed_file: bool,
    buf: *const u8,
    len: u32,
    buf_index: u16,
    user_data: u64,
) -> sys::io_uring_sqe {
    let mut sqe = blank();
    sqe.opcode = sys::IORING_OP_WRITE_FIXED;
    sqe.fd = fd;
    if fixed_file {
        sqe.flags |= sys::IOSQE_FIXED_FILE;
    }
    sqe.off = 0;
    sqe.addr = buf as u64;
    sqe.len = len;
    sqe.buf_index = buf_index;
    sqe.user_data = user_data;
    sqe
}

#[inline]
pub fn close(fd: RawFd, fixed_file: bool, user_data: u64) -> sys::io_uring_sqe {
    let mut sqe = blank();
    sqe.opcode = sys::IORING_OP_CLOSE;
    sqe.fd = fd;
    if fixed_file {
        sqe.flags |= sys::IOSQE_FIXED_FILE;
    }
    sqe.user_data = user_data;
    sqe
}

#[inline]
pub fn timeout(
    ts: *const sys::__kernel_timespec,
    multishot: bool,
    user_data: u64,
) -> sys::io_uring_sqe {
    let mut sqe = blank();
    sqe.opcode = sys::IORING_OP_TIMEOUT;
    sqe.fd = -1;
    sqe.addr = ts as u64;
    sqe.len = 1; // number of events; 1 is typical
    if multishot {
        sqe.op_flags = sys::IORING_TIMEOUT_MULTISHOT;
    } else {
        sqe.op_flags = 0;
    }
    sqe.user_data = user_data;
    sqe
}
