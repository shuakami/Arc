#[derive(Debug, Clone)]
pub struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    /// Create a new RNG.
    ///
    /// `seed` must be non-zero; zero is mapped to a fixed constant.
    pub fn new(seed: u64) -> Self {
        let seed = if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        };
        Self { state: seed }
    }

    /// Next random `u64`.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        // xorshift64* (Marsaglia)
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform-ish range generator in `[0, upper)`.
    ///
    /// Uses rejection sampling to reduce modulo bias.
    #[inline]
    pub fn gen_range(&mut self, upper: u64) -> u64 {
        if upper <= 1 {
            return 0;
        }

        let zone = u64::MAX - (u64::MAX % upper);
        loop {
            let v = self.next_u64();
            if v < zone {
                return v % upper;
            }
        }
    }
}
