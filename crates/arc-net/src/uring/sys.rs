#![allow(non_camel_case_types)]

pub const IORING_OFF_SQ_RING: libc::off_t = 0;
pub const IORING_OFF_CQ_RING: libc::off_t = 0x8000000;
pub const IORING_OFF_SQES: libc::off_t = 0x10000000;

pub const IORING_SETUP_IOPOLL: u32 = 1 << 0;
pub const IORING_SETUP_SQPOLL: u32 = 1 << 1;
pub const IORING_SETUP_SQ_AFF: u32 = 1 << 2;

pub const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;

pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;
pub const IORING_ENTER_SQ_WAKEUP: u32 = 1 << 1;

pub const IORING_SQ_NEED_WAKEUP: u32 = 1 << 0;

pub const IORING_REGISTER_BUFFERS: u32 = 0;
pub const IORING_UNREGISTER_BUFFERS: u32 = 1;
pub const IORING_REGISTER_FILES: u32 = 2;
pub const IORING_UNREGISTER_FILES: u32 = 3;
pub const IORING_REGISTER_FILES_UPDATE: u32 = 6;

pub const IORING_OP_READ_FIXED: u8 = 4;
pub const IORING_OP_WRITE_FIXED: u8 = 5;
pub const IORING_OP_ACCEPT: u8 = 13;
pub const IORING_OP_CONNECT: u8 = 16;
pub const IORING_OP_CLOSE: u8 = 19;
pub const IORING_OP_TIMEOUT: u8 = 11;

pub const IOSQE_FIXED_FILE: u8 = 1 << 0;

pub const IORING_ACCEPT_MULTISHOT: u32 = 1 << 0;

pub const IORING_TIMEOUT_MULTISHOT: u32 = 1 << 0;

pub const IORING_CQE_F_MORE: u32 = 1 << 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct io_sqring_offsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub resv2: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct io_cqring_offsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub resv2: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct io_uring_params {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: io_sqring_offsets,
    pub cq_off: io_cqring_offsets,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct io_uring_sqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub pad: [u64; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct io_uring_cqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct io_uring_files_update {
    pub offset: u32,
    pub resv: u32,
    pub fds: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct __kernel_timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}
