use crossbeam_utils::CachePadded;
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct SpscRing<T> {
    buf: Box<[UnsafeCell<MaybeUninit<T>>]>,
    mask: usize,
    head: CachePadded<AtomicUsize>,
    tail: CachePadded<AtomicUsize>,
}

impl<T> SpscRing<T> {
    /// Create a ring with capacity rounded up to next power-of-two.
    ///
    /// Minimum capacity is 2.
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(2).next_power_of_two();
        let mut v: Vec<UnsafeCell<MaybeUninit<T>>> = Vec::with_capacity(cap);
        for _ in 0..cap {
            v.push(UnsafeCell::new(MaybeUninit::uninit()));
        }
        Self {
            buf: v.into_boxed_slice(),
            mask: cap - 1,
            head: CachePadded::new(AtomicUsize::new(0)),
            tail: CachePadded::new(AtomicUsize::new(0)),
        }
    }

    /// Capacity of the ring.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Current depth (approx exact for SPSC).
    pub fn len(&self) -> usize {
        let h = self.head.load(Ordering::Relaxed);
        let t = self.tail.load(Ordering::Relaxed);
        h.wrapping_sub(t)
    }

    /// Push an item. Returns Err(item) when full (no blocking).
    #[inline]
    pub fn push(&self, item: T) -> Result<(), T> {
        let h = self.head.load(Ordering::Relaxed);
        let t = self.tail.load(Ordering::Acquire);
        if h.wrapping_sub(t) == self.capacity() {
            return Err(item);
        }
        let idx = h & self.mask;

        // SAFETY:
        // - Single producer writes to slot `idx` only when it is free.
        // - Consumer reads only after head is advanced with Release.
        unsafe {
            (*self.buf[idx].get()).write(item);
        }

        self.head.store(h.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Pop an item (consumer only).
    #[inline]
    pub fn pop(&self) -> Option<T> {
        let t = self.tail.load(Ordering::Relaxed);
        let h = self.head.load(Ordering::Acquire);
        if t == h {
            return None;
        }
        let idx = t & self.mask;

        // SAFETY:
        // - Single consumer reads from slot `idx` only when it is initialized (t < h).
        // - Producer will not overwrite this slot until tail is advanced with Release.
        let item = unsafe { (*self.buf[idx].get()).assume_init_read() };

        self.tail.store(t.wrapping_add(1), Ordering::Release);
        Some(item)
    }
}

impl<T> Drop for SpscRing<T> {
    fn drop(&mut self) {
        // Drain any remaining items to drop them properly.
        let mut t = self.tail.load(Ordering::Relaxed);
        let h = self.head.load(Ordering::Relaxed);
        while t != h {
            let idx = t & self.mask;
            // SAFETY:
            // - We are in Drop, no concurrent access is allowed.
            // - Slots between tail..head are initialized.
            unsafe {
                (*self.buf[idx].get()).assume_init_drop();
            }
            t = t.wrapping_add(1);
        }
    }
}

// SAFETY:
// - The ring is SPSC. Producer/consumer synchronization is done via atomics.
// - `T: Send` is required because items move across threads (producer -> consumer).
unsafe impl<T: Send> Send for SpscRing<T> {}
unsafe impl<T: Send> Sync for SpscRing<T> {}
