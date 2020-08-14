/// A pseudo-random number generator
#[derive(Debug)]
pub struct MersenneTwister {
    mt: Vec<usize>,
    index: usize,
    lower_mask: usize,
    upper_mask: usize,
    w: usize,
    n: usize,
    m: usize,
    r: usize,
    a: usize,
    u: usize,
    d: usize,
    s: usize,
    b: usize,
    t: usize,
    c: usize,
    l: usize,
    f: usize,
}

impl MersenneTwister {
    /// Constructs a new Mersenne Twister
    fn new(w: usize, n: usize, m: usize, r: usize, a: usize, u: usize, d: usize, s: usize, b: usize, t: usize, c: usize, l: usize, f: usize) -> Self {
        let mt = vec![0; n];
        let index = n + 1;
        let lower_mask = (1 << r) - 1;
        let upper_mask = lower_bits(!lower_mask, w);
        MersenneTwister { mt, index, lower_mask, upper_mask, w, n, m, r, a, u, d, s, b, t, c, l, f }
    }

    /// Seeds the Mersenne Twister with a given seed
    pub fn seed(&mut self, seed: usize) {
        self.index = self.n;
        self.mt[0] = seed;
        for i in 1..self.n {
            self.mt[i] = lower_bits(self.f * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.w - 2))) + i, self.w)
        }
    }

    /// Gets a usize out of the pseudo-random number generator
    fn extract_number(&mut self) -> usize {
        if self.index >= self.n {
            if self.index > self.n {
                panic!("Generator was never seeded")
            }
            self.twist()
        }

        let mut y = self.mt[self.index];
        y ^= (y >> self.u) & self.d;
        y ^= (y << self.s) & self.b;
        y ^= (y << self.t) & self.c;
        y ^= y >> self.l;

        self.index += 1;
        lower_bits(y, self.w)
    }

    /// Gets a u32 out of the pseudo-random number generator
    pub fn extract_u32(&mut self) -> u32 {
        self.extract_number() as u32
    }

    /// Gets a u64 out of the pseudo-random number generator
    pub fn extract_u64(&mut self) -> u64 {
        self.extract_number() as u64
    }

    /// Twists up the Twister
    fn twist(&mut self) {
        for i in 0..self.n {
            let x = (self.mt[i] & self.upper_mask)
            + (self.mt[(i+1) % self.n] & self.lower_mask);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= self.a;
            }
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ x_a;
        }
        self.index = 0
    }
}

/// Discards the upper bits and returns the lower `lower_amount` bits in `value`.
fn lower_bits(value: usize, lower_amount: usize) -> usize {
    value & ((1 << lower_amount) - 1)
}

/// Returns a 32-bit variant of the Mersenne Twister
pub fn mt19937() -> MersenneTwister {
    MersenneTwister::new(32, 624, 397, 31, 0x9908BDF, 11, 0xFFFFFFFF, 7, 0x9D2C5680, 15, 0xEFC60000, 18, 1812433253)
}

/// Returns a 64-bit variant of the Mersenne Twister
pub fn mt19937_64() -> MersenneTwister {
    MersenneTwister::new(64, 312, 156, 31, 0xB5026F5AA96619E9, 29, 0x5555555555555555, 17, 0x71D67FFFEDA60000, 37, 0xFFF7EEE000000000, 43, 6364136223846793005)
}

#[test]
fn test_mt19937() {
    let mut mt = mt19937();
    mt.seed(12);
    let result = mt.extract_u32();
    mt.seed(12);
    assert_eq!(result, mt.extract_u32());
}