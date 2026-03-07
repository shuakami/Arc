use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

#[repr(align(64))]
struct AlignedUsize(AtomicUsize);

impl AlignedUsize {
    const fn new(v: usize) -> Self {
        Self(AtomicUsize::new(v))
    }
}

pub struct SpscQueue<T, const N: usize> {
    buf: [UnsafeCell<MaybeUninit<T>>; N],
    head: AlignedUsize,
    tail: AlignedUsize,
    mask: usize,
}

unsafe impl<T: Send, const N: usize> Send for SpscQueue<T, N> {}
unsafe impl<T: Send, const N: usize> Sync for SpscQueue<T, N> {}

pub struct Producer<'a, T, const N: usize> {
    q: &'a SpscQueue<T, N>,
}

pub struct Consumer<'a, T, const N: usize> {
    q: &'a SpscQueue<T, N>,
}

impl<T, const N: usize> SpscQueue<T, N> {
    pub fn new() -> Self {
        assert!(N >= 2, "SpscQueue N must be >= 2");
        assert!(N.is_power_of_two(), "SpscQueue N must be a power of two");

        let buf: [UnsafeCell<MaybeUninit<T>>; N] =
            std::array::from_fn(|_| UnsafeCell::new(MaybeUninit::uninit()));

        Self {
            buf,
            head: AlignedUsize::new(0),
            tail: AlignedUsize::new(0),
            mask: N - 1,
        }
    }

    pub fn split(&self) -> (Producer<'_, T, N>, Consumer<'_, T, N>) {
        (Producer { q: self }, Consumer { q: self })
    }
}

impl<'a, T, const N: usize> Producer<'a, T, N> {
    #[inline]
    pub fn push(&self, value: T) -> Result<(), T> {
        let tail = self.q.tail.0.load(Ordering::Relaxed);
        let next = (tail + 1) & self.q.mask;
        let head = self.q.head.0.load(Ordering::Acquire);

        if next == head {
            return Err(value);
        }

        unsafe {
            (*self.q.buf[tail].get()).write(value);
        }

        self.q.tail.0.store(next, Ordering::Release);
        Ok(())
    }
}

impl<'a, T, const N: usize> Consumer<'a, T, N> {
    #[inline]
    pub fn pop(&self) -> Option<T> {
        let head = self.q.head.0.load(Ordering::Relaxed);
        let tail = self.q.tail.0.load(Ordering::Acquire);

        if head == tail {
            return None;
        }

        let v = unsafe { (*self.q.buf[head].get()).as_ptr().read() };
        let next = (head + 1) & self.q.mask;
        self.q.head.0.store(next, Ordering::Release);
        Some(v)
    }
}
