use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::uring::sys;

struct SqRing {
    khead: *mut u32,
    ktail: *mut u32,
    kring_mask: *mut u32,
    kring_entries: *mut u32,
    kflags: *mut u32,
    kdropped: *mut u32,
    array: *mut u32,
}

struct CqRing {
    khead: *mut u32,
    ktail: *mut u32,
    kring_mask: *mut u32,
    kring_entries: *mut u32,
    koverflow: *mut u32,
    cqes: *mut sys::io_uring_cqe,
}

pub struct Uring {
    fd: RawFd,
    params: sys::io_uring_params,

    sq: SqRing,
    cq: CqRing,
    sqes: *mut sys::io_uring_sqe,

    // Local SQ tracking (like liburing sqe_head/sqe_tail).
    sqe_head: u32,
    sqe_tail: u32,

    // Mmap bookkeeping.
    sq_ring_ptr: *mut libc::c_void,
    sq_ring_sz: usize,
    cq_ring_ptr: *mut libc::c_void,
    cq_ring_sz: usize,
    sqes_ptr: *mut libc::c_void,
    sqes_sz: usize,
    single_mmap: bool,

    // Registration state.
    files_registered: bool,
}

impl Uring {
    pub fn new(
        entries: u32,
        setup_flags: u32,
        sq_thread_cpu: u32,
        sq_thread_idle_ms: u32,
    ) -> io::Result<Self> {
        let mut params: sys::io_uring_params = unsafe { mem::zeroed() };
        params.flags = setup_flags;
        if (setup_flags & sys::IORING_SETUP_SQPOLL) != 0 {
            params.sq_thread_cpu = sq_thread_cpu;
            params.sq_thread_idle = sq_thread_idle_ms;
        }

        let ret = unsafe {
            libc::syscall(
                libc::SYS_io_uring_setup,
                entries as libc::c_uint,
                &mut params as *mut sys::io_uring_params,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = ret as RawFd;

        let sq_ring_sz =
            (params.sq_off.array as usize) + (params.sq_entries as usize) * mem::size_of::<u32>();
        let cq_ring_sz = (params.cq_off.cqes as usize)
            + (params.cq_entries as usize) * mem::size_of::<sys::io_uring_cqe>();

        let single_mmap = (params.features & sys::IORING_FEAT_SINGLE_MMAP) != 0;
        let (sq_ring_ptr, cq_ring_ptr, sq_mmap_sz, cq_mmap_sz) = if single_mmap {
            let ring_sz = sq_ring_sz.max(cq_ring_sz);
            let p = mmap_ring(fd, ring_sz, sys::IORING_OFF_SQ_RING)?;
            (
                p as *mut libc::c_void,
                p as *mut libc::c_void,
                ring_sz,
                0usize,
            )
        } else {
            let sqp = mmap_ring(fd, sq_ring_sz, sys::IORING_OFF_SQ_RING)?;
            let cqp = mmap_ring(fd, cq_ring_sz, sys::IORING_OFF_CQ_RING)?;
            (
                sqp as *mut libc::c_void,
                cqp as *mut libc::c_void,
                sq_ring_sz,
                cq_ring_sz,
            )
        };

        let sqes_sz = (params.sq_entries as usize) * mem::size_of::<sys::io_uring_sqe>();
        let sqes_ptr = mmap_ring(fd, sqes_sz, sys::IORING_OFF_SQES)? as *mut libc::c_void;

        let sq_base = sq_ring_ptr as *mut u8;
        let cq_base = cq_ring_ptr as *mut u8;

        let sq = SqRing {
            khead: unsafe { sq_base.add(params.sq_off.head as usize) as *mut u32 },
            ktail: unsafe { sq_base.add(params.sq_off.tail as usize) as *mut u32 },
            kring_mask: unsafe { sq_base.add(params.sq_off.ring_mask as usize) as *mut u32 },
            kring_entries: unsafe { sq_base.add(params.sq_off.ring_entries as usize) as *mut u32 },
            kflags: unsafe { sq_base.add(params.sq_off.flags as usize) as *mut u32 },
            kdropped: unsafe { sq_base.add(params.sq_off.dropped as usize) as *mut u32 },
            array: unsafe { sq_base.add(params.sq_off.array as usize) as *mut u32 },
        };

        let cq = CqRing {
            khead: unsafe { cq_base.add(params.cq_off.head as usize) as *mut u32 },
            ktail: unsafe { cq_base.add(params.cq_off.tail as usize) as *mut u32 },
            kring_mask: unsafe { cq_base.add(params.cq_off.ring_mask as usize) as *mut u32 },
            kring_entries: unsafe { cq_base.add(params.cq_off.ring_entries as usize) as *mut u32 },
            koverflow: unsafe { cq_base.add(params.cq_off.overflow as usize) as *mut u32 },
            cqes: unsafe { cq_base.add(params.cq_off.cqes as usize) as *mut sys::io_uring_cqe },
        };

        let tail = unsafe { atomic_u32(sq.ktail).load(Ordering::Acquire) };
        let head = unsafe { atomic_u32(sq.khead).load(Ordering::Acquire) };

        Ok(Self {
            fd,
            params,
            sq,
            cq,
            sqes: sqes_ptr as *mut sys::io_uring_sqe,
            sqe_head: head,
            sqe_tail: tail,
            sq_ring_ptr,
            sq_ring_sz: sq_mmap_sz,
            cq_ring_ptr,
            cq_ring_sz: cq_mmap_sz,
            sqes_ptr,
            sqes_sz,
            single_mmap,
            files_registered: false,
        })
    }

    #[inline]
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    pub fn register_buffers(&mut self, iovecs: &mut [libc::iovec]) -> io::Result<()> {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd,
                sys::IORING_REGISTER_BUFFERS,
                iovecs.as_mut_ptr(),
                iovecs.len() as u32,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn unregister_buffers(&mut self) -> io::Result<()> {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd,
                sys::IORING_UNREGISTER_BUFFERS,
                ptr::null_mut::<libc::c_void>(),
                0u32,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn register_files(&mut self, fds: &[RawFd]) -> io::Result<()> {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd,
                sys::IORING_REGISTER_FILES,
                fds.as_ptr(),
                fds.len() as u32,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            self.files_registered = true;
            Ok(())
        }
    }

    pub fn unregister_files(&mut self) -> io::Result<()> {
        if !self.files_registered {
            return Ok(());
        }
        let ret = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd,
                sys::IORING_UNREGISTER_FILES,
                ptr::null::<libc::c_void>(),
                0u32,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            self.files_registered = false;
            Ok(())
        }
    }

    pub fn update_files(&mut self, offset: u32, fds: &[RawFd]) -> io::Result<()> {
        if !self.files_registered {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "update_files called before register_files",
            ));
        }

        let upd = sys::io_uring_files_update {
            offset,
            resv: 0,
            fds: fds.as_ptr() as u64,
        };

        let ret = unsafe {
            libc::syscall(
                libc::SYS_io_uring_register,
                self.fd,
                sys::IORING_REGISTER_FILES_UPDATE,
                &upd as *const sys::io_uring_files_update,
                fds.len() as u32,
            )
        };

        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Push an SQE into the submission ring. Returns WouldBlock if the ring is full.
    pub fn push_sqe(&mut self, sqe: sys::io_uring_sqe) -> io::Result<()> {
        let head = unsafe { atomic_u32(self.sq.khead).load(Ordering::Acquire) };
        let tail = self.sqe_tail;

        let ring_entries = unsafe { ptr::read_volatile(self.sq.kring_entries) };
        let used = tail.wrapping_sub(head);
        if used >= ring_entries {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "io_uring SQ ring full",
            ));
        }

        let mask = unsafe { ptr::read_volatile(self.sq.kring_mask) };
        let index = tail & mask;

        unsafe {
            ptr::write(self.sqes.add(index as usize), sqe);
            ptr::write(self.sq.array.add(index as usize), index);
        }

        self.sqe_tail = tail.wrapping_add(1);
        Ok(())
    }

    #[inline]
    fn flush_sq(&mut self) {
        unsafe {
            atomic_u32(self.sq.ktail).store(self.sqe_tail, Ordering::Release);
        }
    }

    #[inline]
    fn sq_need_wakeup(&self) -> bool {
        let flags = unsafe { atomic_u32(self.sq.kflags).load(Ordering::Acquire) };
        (flags & sys::IORING_SQ_NEED_WAKEUP) != 0
    }

    pub fn submit_and_wait(&mut self, min_complete: u32) -> io::Result<u32> {
        self.flush_sq();

        let to_submit = self.sqe_tail.wrapping_sub(self.sqe_head);
        debug_assert!(to_submit <= self.params.sq_entries);
        if to_submit == 0 && min_complete == 0 {
            return Ok(0);
        }

        let mut flags = 0u32;
        if min_complete > 0 {
            flags |= sys::IORING_ENTER_GETEVENTS;
        }
        if self.sq_need_wakeup() {
            flags |= sys::IORING_ENTER_SQ_WAKEUP;
        }

        let ret = unsafe {
            libc::syscall(
                libc::SYS_io_uring_enter,
                self.fd,
                to_submit,
                min_complete,
                flags,
                ptr::null::<libc::sigset_t>(),
                0usize,
            )
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let submitted = ret as u32;
        self.sqe_head = self.sqe_head.wrapping_add(submitted);
        Ok(submitted)
    }

    pub fn pop_cqe(&mut self) -> Option<sys::io_uring_cqe> {
        let head = unsafe { atomic_u32(self.cq.khead).load(Ordering::Acquire) };
        let tail = unsafe { atomic_u32(self.cq.ktail).load(Ordering::Acquire) };

        if head == tail {
            return None;
        }

        let ring_entries = unsafe { ptr::read_volatile(self.cq.kring_entries) };
        if ring_entries == 0 {
            return None;
        }
        let mask = unsafe { ptr::read_volatile(self.cq.kring_mask) };
        debug_assert_eq!(ring_entries, mask.wrapping_add(1));
        debug_assert_eq!(self.params.cq_entries, ring_entries);
        let index = head & mask;

        let cqe = unsafe { ptr::read(self.cq.cqes.add(index as usize)) };
        let new_head = head.wrapping_add(1);

        unsafe {
            atomic_u32(self.cq.khead).store(new_head, Ordering::Release);
        }

        Some(cqe)
    }

    #[inline]
    pub fn sq_dropped(&self) -> u32 {
        unsafe { ptr::read_volatile(self.sq.kdropped) }
    }

    #[inline]
    pub fn cq_overflow(&self) -> u32 {
        unsafe { ptr::read_volatile(self.cq.koverflow) }
    }
}

impl Drop for Uring {
    fn drop(&mut self) {
        let _ = self.unregister_files();
        let _ = self.unregister_buffers();

        unsafe {
            if !self.sqes_ptr.is_null() && self.sqes_sz != 0 {
                let _ = libc::munmap(self.sqes_ptr, self.sqes_sz);
            }

            if !self.sq_ring_ptr.is_null() && self.sq_ring_sz != 0 {
                if !self.single_mmap && !self.cq_ring_ptr.is_null() && self.cq_ring_sz != 0 {
                    let _ = libc::munmap(self.cq_ring_ptr, self.cq_ring_sz);
                }
                let _ = libc::munmap(self.sq_ring_ptr, self.sq_ring_sz);
            }

            let _ = libc::close(self.fd);
        }
    }
}

#[inline]
unsafe fn atomic_u32<'a>(p: *mut u32) -> &'a AtomicU32 {
    &*(p as *const AtomicU32)
}

fn mmap_ring(fd: RawFd, len: usize, offset: libc::off_t) -> io::Result<*mut u8> {
    // MAP_POPULATE is a latency optimization; fall back if unsupported.
    let mut flags = libc::MAP_SHARED;
    #[cfg(any(target_os = "linux"))]
    {
        flags |= libc::MAP_POPULATE;
    }

    let ptr1 = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            flags,
            fd,
            offset,
        )
    };

    if ptr1 != libc::MAP_FAILED {
        return Ok(ptr1 as *mut u8);
    }

    // Retry without MAP_POPULATE.
    let ptr2 = unsafe {
        libc::mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            offset,
        )
    };
    if ptr2 == libc::MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(ptr2 as *mut u8)
    }
}
