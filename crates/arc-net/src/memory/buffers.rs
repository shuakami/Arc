use std::io;

pub const INVALID_BUF: u16 = u16::MAX;

pub struct FixedBuffers {
    mem: Vec<u8>,
    buf_size: usize,
    free: Vec<u16>,
    // 0 = free, 1 = allocated.
    state: Vec<u8>,
    // Intrusive refcount for zero-copy split ownership.
    refs: Vec<u32>,
}

impl FixedBuffers {
    pub fn new(buf_count: usize, buf_size: usize) -> io::Result<Self> {
        if buf_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buf_count must be > 0",
            ));
        }
        if buf_count > (INVALID_BUF as usize) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buf_count exceeds u16::MAX (io_uring buf_index limit)",
            ));
        }
        if buf_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buf_size must be > 0",
            ));
        }

        let total = buf_count.checked_mul(buf_size).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "buf_count * buf_size overflow")
        })?;

        let mut mem = vec![0u8; total];

        // Touch pages early to reduce runtime page faults (best-effort).
        for byte in mem.iter_mut().step_by(4096) {
            *byte = 0;
        }

        let mut free = Vec::with_capacity(buf_count);
        for i in (0..buf_count).rev() {
            free.push(i as u16);
        }
        let state = vec![0u8; buf_count];
        let refs = vec![0u32; buf_count];

        Ok(Self {
            mem,
            buf_size,
            free,
            state,
            refs,
        })
    }

    #[inline]
    pub fn buf_size(&self) -> usize {
        self.buf_size
    }

    #[inline]
    pub fn buf_count(&self) -> usize {
        self.mem.len() / self.buf_size
    }

    #[inline]
    pub fn alloc(&mut self) -> Option<u16> {
        while let Some(idx) = self.free.pop() {
            let i = idx as usize;
            if i >= self.state.len() {
                eprintln!("buffers: invalid free-list index on alloc: {idx}");
                continue;
            }
            if self.state[i] != 0 {
                eprintln!("buffers: detected premature reuse of idx={idx}, skipping entry");
                continue;
            }
            self.state[i] = 1;
            self.refs[i] = 1;
            return Some(idx);
        }
        None
    }

    #[inline]
    pub fn free(&mut self, idx: u16) {
        self.release(idx);
    }

    #[inline]
    pub fn retain(&mut self, idx: u16) {
        debug_assert!(idx != INVALID_BUF);
        let i = idx as usize;
        if i >= self.state.len() {
            eprintln!("buffers: invalid retain idx={idx}");
            return;
        }
        if self.state[i] == 0 {
            eprintln!("buffers: retain on free idx={idx}");
            return;
        }
        let cur = self.refs[i];
        if cur == 0 {
            eprintln!("buffers: invalid refcount state for idx={idx}");
            return;
        }
        self.refs[i] = cur.saturating_add(1);
    }

    #[inline]
    pub fn release(&mut self, idx: u16) {
        debug_assert!(idx != INVALID_BUF);
        let i = idx as usize;
        if i >= self.state.len() {
            eprintln!("buffers: invalid release idx={idx}");
            return;
        }
        if self.state[i] == 0 {
            eprintln!("buffers: double free detected for idx={idx}");
            return;
        }
        let cur = self.refs[i];
        if cur == 0 {
            eprintln!("buffers: invalid refcount state for idx={idx}");
            return;
        }
        if cur > 1 {
            self.refs[i] = cur - 1;
            return;
        }
        self.refs[i] = 0;
        self.state[i] = 0;
        self.free.push(idx);
    }

    #[inline]
    pub fn ptr(&mut self, idx: u16) -> *mut u8 {
        debug_assert!(idx != INVALID_BUF);
        unsafe { self.mem.as_mut_ptr().add(idx as usize * self.buf_size) }
    }

    #[inline]
    pub fn ptr_at(&mut self, idx: u16, off: u32) -> *mut u8 {
        debug_assert!(idx != INVALID_BUF);
        let base = idx as usize * self.buf_size;
        unsafe { self.mem.as_mut_ptr().add(base + off as usize) }
    }

    #[inline]
    pub fn slice(&self, idx: u16, off: u32, len: u32) -> &[u8] {
        debug_assert!(idx != INVALID_BUF);
        let base = idx as usize * self.buf_size + off as usize;
        let end = base + len as usize;
        &self.mem[base..end]
    }

    pub fn iovecs(&mut self) -> Vec<libc::iovec> {
        let mut v = Vec::with_capacity(self.buf_count());
        let base = self.mem.as_mut_ptr();

        for i in 0..self.buf_count() {
            let p = unsafe { base.add(i * self.buf_size) };
            v.push(libc::iovec {
                iov_base: p as *mut libc::c_void,
                iov_len: self.buf_size,
            });
        }

        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retain_release_is_refcounted() {
        let mut bufs = FixedBuffers::new(4, 64).expect("create buffers");
        let id = bufs.alloc().expect("alloc first");
        assert_eq!(id, 0);

        bufs.retain(id);
        bufs.release(id);

        let id2 = bufs.alloc().expect("alloc second");
        assert_eq!(id2, 1, "buffer should not be reusable until final release");

        bufs.release(id);
        bufs.free(id2);

        let id3 = bufs.alloc().expect("alloc third");
        assert_eq!(id3, 1);
        let id4 = bufs.alloc().expect("alloc fourth");
        assert_eq!(id4, 0, "released buffer should become reusable");
    }
}
