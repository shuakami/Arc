use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::ptr;

const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_MAP_GET_NEXT_KEY: u32 = 4;
const BPF_OBJ_GET: u32 = 7;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfMapInfo {
    pub map_type: u32,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub name: [u8; 16],
    // UAPI 结构体后续还有更多字段；这里保留对齐/扩展空间，避免 kernel 写越界。
    pub ifindex: u32,
    pub btf_vmlinux_value_type_id: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub map_extra: u64,
}

#[repr(C)]
union BpfAttr {
    obj: BpfAttrObj,
    map_elem: BpfAttrMapElem,
    map_delete: BpfAttrMapDeleteElem,
    map_next_key: BpfAttrMapGetNextKey,
    info: BpfAttrInfo,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfAttrObj {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfAttrMapElem {
    map_fd: u32,
    pad0: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfAttrMapDeleteElem {
    map_fd: u32,
    pad0: u32,
    key: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfAttrMapGetNextKey {
    map_fd: u32,
    pad0: u32,
    key: u64,
    next_key: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfAttrInfo {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

unsafe fn sys_bpf(cmd: u32, attr: *const BpfAttr, size: u32) -> i64 {
    // SAFETY: caller ensures attr points to a valid bpf_attr union with correct fields for cmd.
    libc::syscall(libc::SYS_bpf, cmd, attr, size) as i64
}

/// RAII wrapper for a BPF fd.
#[derive(Debug)]
pub struct BpfFd {
    fd: RawFd,
}

impl BpfFd {
    #[inline]
    pub fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    #[inline]
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    #[inline]
    pub fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        std::mem::forget(self);
        fd
    }
}

impl Drop for BpfFd {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                let _ = libc::close(self.fd);
            }
        }
    }
}

/// Open a pinned BPF object (map/prog/link) from bpffs.
pub fn obj_get(path: &str) -> io::Result<BpfFd> {
    let c = CString::new(path.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut attr = BpfAttr {
        obj: BpfAttrObj {
            pathname: c.as_ptr() as u64,
            bpf_fd: 0,
            file_flags: 0,
        },
    };

    let ret = unsafe {
        sys_bpf(
            BPF_OBJ_GET,
            &attr as *const BpfAttr,
            mem::size_of::<BpfAttrObj>() as u32,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(BpfFd::new(ret as RawFd))
    }
}

/// Read map info by fd.
pub fn map_info_by_fd(fd: RawFd) -> io::Result<BpfMapInfo> {
    let mut info: BpfMapInfo = BpfMapInfo::default();
    let mut attr = BpfAttr {
        info: BpfAttrInfo {
            bpf_fd: fd as u32,
            info_len: mem::size_of::<BpfMapInfo>() as u32,
            info: (&mut info as *mut BpfMapInfo) as u64,
        },
    };

    let ret = unsafe {
        sys_bpf(
            BPF_OBJ_GET_INFO_BY_FD,
            &attr as *const BpfAttr,
            mem::size_of::<BpfAttrInfo>() as u32,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(info)
    }
}

pub unsafe trait Pod: Copy + 'static {}

unsafe impl Pod for u8 {}
unsafe impl Pod for u16 {}
unsafe impl Pod for u32 {}
unsafe impl Pod for u64 {}
unsafe impl Pod for i32 {}
unsafe impl Pod for i64 {}

/// Map lookup elem: returns Ok(true) if found, Ok(false) if ENOENT.
pub fn map_lookup_elem<K: Pod, V: Pod>(map_fd: RawFd, key: &K, out: &mut V) -> io::Result<bool> {
    let mut attr = BpfAttr {
        map_elem: BpfAttrMapElem {
            map_fd: map_fd as u32,
            pad0: 0,
            key: key as *const K as u64,
            value: out as *mut V as u64,
            flags: 0,
        },
    };

    let ret = unsafe {
        sys_bpf(
            BPF_MAP_LOOKUP_ELEM,
            &attr as *const BpfAttr,
            mem::size_of::<BpfAttrMapElem>() as u32,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(code) if code == libc::ENOENT => Ok(false),
            _ => Err(e),
        }
    } else {
        Ok(true)
    }
}

/// Per-CPU map lookup: user must provide buffer sized `value_size * ncpu`.
///
/// 返回：Vec<V>，长度 ncpu。
pub fn map_lookup_percpu<K: Pod, V: Pod>(
    map_fd: RawFd,
    key: &K,
    ncpu: usize,
) -> io::Result<Vec<V>> {
    if ncpu == 0 {
        return Ok(Vec::new());
    }

    let mut vals: Vec<V> = Vec::with_capacity(ncpu);
    unsafe {
        // SAFETY: we will fill the buffer via bpf syscall; V is Pod.
        vals.set_len(ncpu);
    }

    let mut attr = BpfAttr {
        map_elem: BpfAttrMapElem {
            map_fd: map_fd as u32,
            pad0: 0,
            key: key as *const K as u64,
            value: vals.as_mut_ptr() as u64,
            flags: 0,
        },
    };

    let ret = unsafe {
        sys_bpf(
            BPF_MAP_LOOKUP_ELEM,
            &attr as *const BpfAttr,
            mem::size_of::<BpfAttrMapElem>() as u32,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(vals)
    }
}

/// Map update elem.
pub fn map_update_elem<K: Pod, V: Pod>(
    map_fd: RawFd,
    key: &K,
    val: &V,
    flags: u64,
) -> io::Result<()> {
    let mut attr = BpfAttr {
        map_elem: BpfAttrMapElem {
            map_fd: map_fd as u32,
            pad0: 0,
            key: key as *const K as u64,
            value: val as *const V as u64,
            flags,
        },
    };

    let ret = unsafe {
        sys_bpf(
            BPF_MAP_UPDATE_ELEM,
            &attr as *const BpfAttr,
            mem::size_of::<BpfAttrMapElem>() as u32,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Map delete elem: Ok(true) if deleted, Ok(false) if not found.
pub fn map_delete_elem<K: Pod>(map_fd: RawFd, key: &K) -> io::Result<bool> {
    let mut attr = BpfAttr {
        map_delete: BpfAttrMapDeleteElem {
            map_fd: map_fd as u32,
            pad0: 0,
            key: key as *const K as u64,
        },
    };

    let ret = unsafe {
        sys_bpf(
            BPF_MAP_DELETE_ELEM,
            &attr as *const BpfAttr,
            mem::size_of::<BpfAttrMapDeleteElem>() as u32,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(code) if code == libc::ENOENT => Ok(false),
            _ => Err(e),
        }
    } else {
        Ok(true)
    }
}

pub fn map_get_next_key<K: Pod>(
    map_fd: RawFd,
    key: Option<&K>,
    next_key: &mut K,
) -> io::Result<bool> {
    let key_ptr = match key {
        Some(k) => k as *const K as u64,
        None => 0u64,
    };

    let mut attr = BpfAttr {
        map_next_key: BpfAttrMapGetNextKey {
            map_fd: map_fd as u32,
            pad0: 0,
            key: key_ptr,
            next_key: next_key as *mut K as u64,
        },
    };

    let ret = unsafe {
        sys_bpf(
            BPF_MAP_GET_NEXT_KEY,
            &attr as *const BpfAttr,
            mem::size_of::<BpfAttrMapGetNextKey>() as u32,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(code) if code == libc::ENOENT => Ok(false),
            _ => Err(e),
        }
    } else {
        Ok(true)
    }
}

/// Count map entries by iterating keys.
///
/// 注意：对超大 map（百万级）频繁遍历会很重；调用方必须控制频率/条件。
pub fn map_count_entries<K: Pod>(map_fd: RawFd) -> io::Result<u64> {
    let mut cnt: u64 = 0;
    let mut cur: K = unsafe { mem::zeroed() };
    let mut next: K = unsafe { mem::zeroed() };

    let mut has = map_get_next_key::<K>(map_fd, None, &mut next)?;
    while has {
        cnt = cnt.saturating_add(1);
        cur = next;
        has = map_get_next_key::<K>(map_fd, Some(&cur), &mut next)?;
    }
    Ok(cnt)
}

/// Iterate map entries into Vec<(K,V)>.
///
/// 注意：只适用于容量可控的 map（白名单/黑名单可以接受；syn_state 可能很大不建议调用）。
pub fn map_dump<K: Pod, V: Pod>(map_fd: RawFd, max: usize) -> io::Result<Vec<(K, V)>> {
    let mut out: Vec<(K, V)> = Vec::new();
    out.reserve(max.min(4096));

    let mut cur: K = unsafe { mem::zeroed() };
    let mut next: K = unsafe { mem::zeroed() };

    let mut has = map_get_next_key::<K>(map_fd, None, &mut next)?;
    while has {
        let mut v: V = unsafe { mem::zeroed() };
        let found = map_lookup_elem::<K, V>(map_fd, &next, &mut v)?;
        if found {
            out.push((next, v));
            if out.len() >= max {
                break;
            }
        }

        cur = next;
        has = map_get_next_key::<K>(map_fd, Some(&cur), &mut next)?;
    }

    Ok(out)
}

/// Get number of online CPUs (best-effort).
pub fn cpu_count_online() -> usize {
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if n <= 0 {
        1
    } else {
        n as usize
    }
}

/// Read kernel version string (uname -r equivalent).
pub fn kernel_release() -> String {
    let mut uts: libc::utsname = unsafe { mem::zeroed() };
    let rc = unsafe { libc::uname(&mut uts as *mut libc::utsname) };
    if rc != 0 {
        return "unknown".to_string();
    }

    // SAFETY: uts.release is NUL-terminated char array.
    unsafe {
        let cstr = std::ffi::CStr::from_ptr(uts.release.as_ptr());
        cstr.to_string_lossy().to_string()
    }
}

/// Best-effort check: does bpffs path exist?
pub fn path_exists(p: &str) -> bool {
    std::fs::metadata(p).is_ok()
}

/// Open a file descriptor for bpffs pinned object using libc open (NOT BPF_OBJ_GET).
///
/// 仅用于存在性探测；真正操作必须使用 obj_get。
pub fn open_probe(p: &str) -> io::Result<RawFd> {
    let c = CString::new(p.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

/// Close fd best-effort.
pub fn close_fd_best_effort(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            let _ = libc::close(fd);
        }
    }
}

/// Poll a fd for readability with timeout_ms.
pub fn poll_readable(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout_ms) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        Err(e)
    } else if rc == 0 {
        Ok(false)
    } else {
        Ok((pfd.revents & libc::POLLIN) != 0)
    }
}

/// mmap wrapper.
pub unsafe fn mmap_shared(fd: RawFd, len: usize, prot: i32, offset: usize) -> io::Result<*mut u8> {
    // SAFETY: caller provides valid fd and parameters; kernel returns shared mapping or MAP_FAILED.
    let p = libc::mmap(
        ptr::null_mut(),
        len,
        prot,
        libc::MAP_SHARED,
        fd,
        offset as libc::off_t,
    );
    if p == libc::MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(p as *mut u8)
    }
}

/// munmap wrapper.
pub unsafe fn munmap(p: *mut u8, len: usize) {
    // SAFETY: p/len must be a live mapping created by mmap.
    let _ = libc::munmap(p as *mut libc::c_void, len);
}

/// Get system page size.
pub fn page_size() -> usize {
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n <= 0 {
        4096
    } else {
        n as usize
    }
}
