use std::io;
use std::mem::MaybeUninit;
use std::ptr;

use crate::op;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub idx: u32,
    pub gen: u32,
}

pub struct Slab<T> {
    entries: Vec<MaybeUninit<T>>,
    gens: Vec<u32>,
    in_use: Vec<u8>,
    free: Vec<u32>,
}

impl<T> Slab<T> {
    pub fn new(capacity: usize) -> io::Result<Self> {
        if capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "slab capacity must be > 0",
            ));
        }
        if capacity > (op::MAX_IDX as usize) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "slab capacity exceeds user_data index encoding (24-bit)",
            ));
        }

        let mut entries: Vec<MaybeUninit<T>> = Vec::with_capacity(capacity);
        entries.resize_with(capacity, MaybeUninit::uninit);

        let gens = vec![0u32; capacity];
        let in_use = vec![0u8; capacity];

        let mut free = Vec::with_capacity(capacity);
        for i in (0..capacity).rev() {
            free.push(i as u32);
        }

        Ok(Self {
            entries,
            gens,
            in_use,
            free,
        })
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }

    #[inline]
    pub fn alloc(&mut self) -> Option<Key> {
        let idx = self.free.pop()?;
        let i = idx as usize;

        // Bump generation in 24-bit space; keep it non-zero.
        let mut g = (self.gens[i].wrapping_add(1)) & op::MAX_GEN;
        if g == 0 {
            g = 1;
        }
        self.gens[i] = g;
        self.in_use[i] = 1;

        Some(Key { idx, gen: g })
    }

    /// Safety: `key` must be freshly allocated via `alloc()` and not yet written.
    #[inline]
    pub unsafe fn write(&mut self, key: Key, val: T) {
        let i = key.idx as usize;
        debug_assert!(i < self.entries.len());
        debug_assert!(self.in_use[i] != 0);
        debug_assert!(self.gens[i] == key.gen);

        ptr::write(self.entries[i].as_mut_ptr(), val);
    }

    #[inline]
    pub fn get_mut(&mut self, key: Key) -> Option<&mut T> {
        let i = key.idx as usize;
        if i >= self.entries.len() {
            return None;
        }
        if self.in_use[i] == 0 {
            return None;
        }
        if self.gens[i] != key.gen {
            return None;
        }

        Some(unsafe { &mut *self.entries[i].as_mut_ptr() })
    }

    /// Snapshot all currently in-use keys.
    ///
    /// This allocates and is intended for non-hot paths, e.g. graceful-shutdown force close.
    pub fn active_keys(&self) -> Vec<Key> {
        let mut out = Vec::new();
        out.reserve(self.entries.len().saturating_sub(self.free.len()));
        for (idx, in_use) in self.in_use.iter().enumerate() {
            if *in_use != 0 {
                out.push(Key {
                    idx: idx as u32,
                    gen: self.gens[idx],
                });
            }
        }
        out
    }

    pub fn cancel_alloc(&mut self, key: Key) {
        let i = key.idx as usize;
        if i >= self.entries.len() {
            return;
        }
        if self.in_use[i] == 0 {
            return;
        }
        if self.gens[i] != key.gen {
            return;
        }

        self.in_use[i] = 0;
        self.free.push(key.idx);
    }

    pub fn free(&mut self, key: Key) {
        let i = key.idx as usize;
        if i >= self.entries.len() {
            return;
        }
        if self.in_use[i] == 0 {
            return;
        }
        if self.gens[i] != key.gen {
            return;
        }

        unsafe {
            ptr::drop_in_place(self.entries[i].as_mut_ptr());
        }
        self.in_use[i] = 0;
        self.free.push(key.idx);
    }
}

#[cfg(test)]
mod tests {
    use super::Slab;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn cancel_alloc_does_not_drop_uninitialized_slot() {
        let mut slab = Slab::<DropCounter>::new(1).expect("new slab");
        let drops = Arc::new(AtomicUsize::new(0));

        let k1 = slab.alloc().expect("alloc k1");
        slab.cancel_alloc(k1);
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        let k2 = slab.alloc().expect("alloc k2");
        unsafe {
            slab.write(k2, DropCounter(drops.clone()));
        }
        slab.free(k2);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn free_drops_once() {
        let mut slab = Slab::<DropCounter>::new(1).expect("new slab");
        let drops = Arc::new(AtomicUsize::new(0));

        let k = slab.alloc().expect("alloc");
        unsafe {
            slab.write(k, DropCounter(drops.clone()));
        }
        slab.free(k);
        slab.free(k);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}
