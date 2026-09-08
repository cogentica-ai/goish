// math/rand — pseudo-random number generation.
//
// goish ships both APIs:
//   * legacy v1 (Go 1.0+) — `Source` / `Source64` / `NewSource` /
//     `New` / `Rand` — mounted at this path so ports written against
//     the v1 API (e.g. `oklog/ulid/v2`) compile unchanged.
//   * v2 (Go 1.22+) — `goish::math::rand::v2`, mounted as a sub-mod.
//
// Reference: math/rand/{rand.go,rng.go,normal.go,exp.go}
//            math/rand/v2/
//
// The v1 generator implemented here is the additive lagged-Fibonacci
// generator (ALFG) — lags 273 and 607, modulo 2^63 — exactly as
// shipped in Go's math/rand. The seed table `RNG_COOKED` and the
// Ziggurat tables (`KN`/`WN`/`FN`, `KE`/`WE`/`FE`) are carbon copies
// of Go 1.25.5's. Output is bit-identical to Go for the same seed
// across `Int63`, `Uint64`, `Uint32`, `Int31`, `Float64`, `Float32`,
// `Int63n`, `Int31n`, `Intn`, `Perm`, `Shuffle`, `Read`, `NormFloat64`,
// `ExpFloat64`. This is a test-enforced invariant.

// goishlint:ignore GOISH015 — `Rand`'s methods come from four Go files at once — rand.go for the
//     bounded and float forms, normal.go for NormFloat64, exp.go for ExpFloat64, rng.go for the
//     ALFG behind them — so a per-Go-file split would have to split one `impl Rand` block across
//     four modules and widen every private field to `pub(crate)` to do it. The anchors below
//     already carry the per-function provenance that the split exists to provide, and
//     rand_ref_smoke pins the whole generated sequence against Go.
#![allow(non_snake_case)]

pub mod v2;

mod rng_cooked;
mod ziggurat;

extern crate alloc;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::errors::error;
use crate::goslice::slice;
use crate::io;
use crate::nilval::Nil;
use crate::runtime::spin::SpinLock;
use crate::types::{byte, int};
#[allow(non_camel_case_types)]
type int32 = i32;
#[allow(non_camel_case_types)]
type int64 = i64;

// ─── ALFG constants (rng.go:14-20) ───────────────────────────────────

const RNG_LEN: usize = 607;
const RNG_TAP: usize = 273;
const RNG_MASK: u64 = (1u64 << 63) - 1;
const INT32_MAX: i32 = i32::MAX; // 2^31 - 1 = 2147483647

// ─── Source / Source64 traits — Go's `math/rand` interfaces ──────────

/// A Source represents a source of uniformly-distributed pseudo-random
/// int64 values in the range `[0, 1<<63)`. Not safe for concurrent use.
#[goish::interface]
pub trait Source: Send + Sync {
    fn Int63(&mut self) -> int64;
    fn Seed(&mut self, seed: int64);
}

/// A Source64 is a [Source] that can also generate uniformly-distributed
/// pseudo-random uint64 values in the range `[0, 1<<64)` directly.
pub trait Source64: Source {
    fn Uint64(&mut self) -> u64;
}

// ─── rngSource — Go's `*rngSource` (rng.go:180) ──────────────────────
//
// Additive Lagged-Fibonacci, lags 273 and 607, mod 2^63. State is the
// 607-element ring `vec` plus the two read indices `tap` and `feed`.

#[derive(Clone)]
#[allow(non_camel_case_types)]
pub struct rngSource {
    tap: i32,            // index into vec; Go stores as int
    feed: i32,           // index into vec; Go stores as int
    vec: [i64; RNG_LEN], // current feedback register
}

impl Default for rngSource {
    fn default() -> Self {
        Self {
            tap: 0,
            feed: 0,
            vec: [0; RNG_LEN],
        }
    }
}

// go: sdk 1.25.5 math/rand/rng.go:187-201 seedrand
/// `seedrand x[n+1] = 48271 * x[n] mod (2^31 - 1)` — rng.go:187.
///
/// Park-Miller LCG written in branch-free split form to avoid
/// `int32` multiplication overflow on the inner step.
#[inline]
fn seedrand(x: i32) -> i32 {
    const A: i32 = 48271;
    const Q: i32 = 44488;
    const R: i32 = 3399;
    let hi = x / Q;
    let lo = x % Q;
    let mut x = A.wrapping_mul(lo).wrapping_sub(R.wrapping_mul(hi));
    if x < 0 {
        x = x.wrapping_add(INT32_MAX);
    }
    x
}

impl Source for rngSource {
    // go: sdk 1.25.5 math/rand/rng.go:233-235 rngSource.Int63
    /// Int63 — rng.go:233.
    fn Int63(&mut self) -> int64 {
        (self.Uint64() & RNG_MASK) as int64
    }

    // go: sdk 1.25.5 math/rand/rng.go:204-230 rngSource.Seed
    /// Seed — rng.go:204. Initializes the 607-cell ring using the
    /// Park-Miller LCG warmed up for 20 cycles, then XOR-folds three
    /// LCG draws into each cell and XORs with the cooked seed table.
    fn Seed(&mut self, seed: int64) {
        self.tap = 0;
        self.feed = (RNG_LEN - RNG_TAP) as i32;

        let mut seed = seed.rem_euclid(INT32_MAX as i64);
        if seed < 0 {
            seed += INT32_MAX as i64;
        }
        if seed == 0 {
            seed = 89482311;
        }

        let mut x: i32 = seed as i32;
        // Warm-up: i = -20..0
        for _ in 0..20 {
            x = seedrand(x);
        }
        // Fill ring: i = 0..rngLen
        for i in 0..RNG_LEN {
            x = seedrand(x);
            let mut u: i64 = (x as i64) << 40;
            x = seedrand(x);
            u ^= (x as i64) << 20;
            x = seedrand(x);
            u ^= x as i64;
            u ^= rng_cooked::RNG_COOKED[i];
            self.vec[i] = u;
        }
    }
}

impl Source64 for rngSource {
    // go: sdk 1.25.5 math/rand/rng.go:238-252 rngSource.Uint64
    /// Uint64 — rng.go:238. The ring-buffer feedback step:
    /// `vec[feed] = vec[feed] + vec[tap]`, with both indices decremented
    /// modulo 607.
    fn Uint64(&mut self) -> u64 {
        self.tap -= 1;
        if self.tap < 0 {
            self.tap += RNG_LEN as i32;
        }
        self.feed -= 1;
        if self.feed < 0 {
            self.feed += RNG_LEN as i32;
        }
        // Wrapping add — Go's int64 addition is two's-complement modulo.
        let x = (self.vec[self.feed as usize]).wrapping_add(self.vec[self.tap as usize]);
        self.vec[self.feed as usize] = x;
        x as u64
    }
}

// go: sdk 1.25.5 math/rand/rand.go:51-53 NewSource
/// NewSource returns a new pseudo-random Source seeded with `seed`.
/// The returned Source implements Source64.
pub fn NewSource(seed: int64) -> Box<dyn Source64 + Send + Sync> {
    let mut s = rngSource::default();
    s.Seed(seed);
    Box::new(s)
}

// ─── Rand wrapper — `*Rand` in Go (rand.go:62) ───────────────────────

/// A Rand is a source of random numbers, wrapping a Source.
///
/// Per Go's design, the user's `*Rand` mutates the underlying source.
/// In goish we pass `&mut Rand` through methods (effects-analysis
/// upstream wraps consumers accordingly).
pub struct Rand {
    src: Box<dyn Source64 + Send + Sync>,
    // Sub-byte stash for `Read` (matches Go's readVal/readPos).
    read_val: int64,
    read_pos: i8,
}

// go: sdk 1.25.5 math/rand/rand.go:78-81 New
/// New returns a new Rand that uses random values from `src`.
///
/// In Go, `New` accepts `Source` and stashes a `Source64` if the
/// underlying type implements it. Goish requires `Source64` directly
/// for simplicity (every concrete Source on goish-v1 implements both).
pub fn New(src: Box<dyn Source64 + Send + Sync>) -> Rand {
    Rand {
        src,
        read_val: 0,
        read_pos: 0,
    }
}

impl Rand {
    // go: sdk 1.25.5 math/rand/rand.go:96-96 Rand.Int63
    /// `Int63` — rand.go:96.
    pub fn Int63(&mut self) -> int64 {
        self.src.Int63()
    }

    // go: sdk 1.25.5 math/rand/rand.go:99-99 Rand.Uint32
    /// `Uint32` — rand.go:99.
    pub fn Uint32(&mut self) -> u32 {
        (self.src.Int63() >> 31) as u32
    }

    // go: sdk 1.25.5 math/rand/rand.go:102-107 Rand.Uint64
    /// `Uint64` — rand.go:102. When the underlying source is a Source64
    /// (always the case in goish), delegate; otherwise fall through to
    /// the two-Int63 composition. We keep both paths even though only
    /// the s64 path is reachable, so future Source-only impls compile.
    pub fn Uint64(&mut self) -> u64 {
        self.src.Uint64()
    }

    // go: sdk 1.25.5 math/rand/rand.go:110-110 Rand.Int31
    /// `Int31` — rand.go:110.
    pub fn Int31(&mut self) -> int32 {
        (self.src.Int63() >> 32) as int32
    }

    // go: sdk 1.25.5 math/rand/rand.go:113-116 Rand.Int
    /// `Int` — rand.go:113. Clears the sign bit; on 64-bit Go `int` is
    /// `int64`, matching goish's `int = i64`.
    pub fn Int(&mut self) -> int {
        let u = self.src.Int63() as u64;
        ((u << 1) >> 1) as int
    }

    // go: sdk 1.25.5 math/rand/rand.go:85-93 Rand.Seed
    /// `Seed` — rand.go:85. Resets the sub-byte read buffer too.
    pub fn Seed(&mut self, seed: int64) {
        self.src.Seed(seed);
        self.read_pos = 0;
    }

    // go: sdk 1.25.5 math/rand/rand.go:120-133 Rand.Int63n
    /// `Int63n` — rand.go:120. Rejection sampling; panics on n<=0.
    pub fn Int63n(&mut self, n: int64) -> int64 {
        if n <= 0 {
            panic!("invalid argument to Int63n");
        }
        // Power-of-two fast path
        if n & (n - 1) == 0 {
            return self.src.Int63() & (n - 1);
        }
        let max = ((1u64 << 63) - 1 - (1u64 << 63) % (n as u64)) as i64;
        let mut v = self.src.Int63();
        while v > max {
            v = self.src.Int63();
        }
        v % n
    }

    // go: sdk 1.25.5 math/rand/rand.go:137-150 Rand.Int31n
    /// `Int31n` — rand.go:137. Rejection sampling; panics on n<=0.
    pub fn Int31n(&mut self, n: int32) -> int32 {
        if n <= 0 {
            panic!("invalid argument to Int31n");
        }
        if n & (n - 1) == 0 {
            return self.Int31() & (n - 1);
        }
        let max = ((1u32 << 31) - 1 - (1u32 << 31) % (n as u32)) as i32;
        let mut v = self.Int31();
        while v > max {
            v = self.Int31();
        }
        v % n
    }

    /// `int31n` — rand.go:161 (unexported in Go). Faster Lemire-style
    /// reduction; only used internally by `Shuffle` so the value
    /// stream stays Go-compatible. Caller must ensure `n > 0`.
    fn int31n_fast(&mut self, n: i32) -> i32 {
        let mut v = self.Uint32();
        let mut prod = (v as u64) * (n as u64);
        let mut low = prod as u32;
        if low < n as u32 {
            // `uint32(-n) % uint32(n)`: in Go, `-n` on int32 truncates.
            let thresh = (n as u32).wrapping_neg() % (n as u32);
            while low < thresh {
                v = self.Uint32();
                prod = (v as u64) * (n as u64);
                low = prod as u32;
            }
        }
        (prod >> 32) as i32
    }

    // go: sdk 1.25.5 math/rand/rand.go:178-186 Rand.Intn
    /// `Intn` — rand.go:178.
    pub fn Intn(&mut self, n: int) -> int {
        if n <= 0 {
            panic!("invalid argument to Intn");
        }
        if n <= (1i64 << 31) - 1 {
            self.Int31n(n as int32) as int
        } else {
            self.Int63n(n as int64) as int
        }
    }

    // go: sdk 1.25.5 math/rand/rand.go:189-212 Rand.Float64
    /// `Float64` — rand.go:189. Uses Go 1's exact divisor (1<<63) and
    /// resamples on the 1/2^53 chance of rounding up to 1.0, preserving
    /// the canonical value stream.
    pub fn Float64(&mut self) -> f64 {
        loop {
            let f = (self.src.Int63() as f64) / ((1u64 << 63) as f64);
            if f != 1.0 {
                return f;
            }
            // Resample; the branch is taken O(never).
        }
    }

    // go: sdk 1.25.5 math/rand/rand.go:215-225 Rand.Float32
    /// `Float32` — rand.go:215.
    pub fn Float32(&mut self) -> f32 {
        loop {
            let f = self.Float64() as f32;
            if f != 1.0 {
                return f;
            }
        }
    }

    // go: sdk 1.25.5 math/rand/rand.go:229-242 Rand.Perm
    /// `Perm` — rand.go:229. Returns a permutation of `[0,n)`.
    pub fn Perm(&mut self, n: int) -> slice<int> {
        let mut m: slice<int> = crate::make!([]int, n);
        // i=0..n; the i==0 iteration is intentional (preserves Go 1's
        // value stream).
        for i in 0..n {
            let j = self.Intn(i + 1);
            m[i] = m[j];
            m[j] = i;
        }
        m
    }

    // go: sdk 1.25.5 math/rand/rand.go:247-267 Rand.Shuffle
    /// `Shuffle` — rand.go:247. Fisher-Yates; uses Int63n for the very
    /// large head, then int31n_fast for the tail (matches Go's split).
    pub fn Shuffle<F>(&mut self, n: int, mut swap: F)
    where
        F: FnMut(int, int),
    {
        if n < 0 {
            panic!("invalid argument to Shuffle");
        }
        let mut i = n - 1;
        while i > (1i64 << 31) - 1 - 1 {
            let j = self.Int63n((i + 1) as int64);
            swap(i, j);
            i -= 1;
        }
        while i > 0 {
            let j = self.int31n_fast((i + 1) as i32) as int;
            swap(i, j);
            i -= 1;
        }
    }

    // go: sdk 1.25.5 math/rand/rand.go:272-280 Rand.Read
    /// `Read` — rand.go:272. Always returns (len(p), nil). Pulls 8
    /// random bytes per Int63() call; preserves leftover bytes in
    /// `read_val`/`read_pos` across calls.
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let n = crate::builtin::len(&*p) as usize;
        let mut pos = self.read_pos;
        let mut val = self.read_val;
        for i in 0..n {
            if pos == 0 {
                val = self.src.Int63();
                pos = 7;
            }
            p[i as int] = (val as u8) as byte;
            val >>= 8;
            pos -= 1;
        }
        self.read_pos = pos;
        self.read_val = val;
        (n as int, Nil.into())
    }

    // go: sdk 1.25.5 math/rand/normal.go:37-65 Rand.NormFloat64
    /// `NormFloat64` — normal.go:37. Ziggurat (Marsaglia & Tsang 2000).
    pub fn NormFloat64(&mut self) -> f64 {
        const RN: f64 = 3.442619855899;
        loop {
            let j = self.Uint32() as i32; // possibly negative
            let i = (j & 0x7F) as usize;
            let x = (j as f64) * (ziggurat::WN[i] as f64);
            // absInt32(j) < kn[i]
            let abs_j = if j < 0 {
                (j as i32).wrapping_neg() as u32
            } else {
                j as u32
            };
            if abs_j < ziggurat::KN[i] {
                return x;
            }
            if i == 0 {
                // Base strip — sample from the tail.
                let mut x_t;
                loop {
                    x_t = -libm::log(self.Float64()) * (1.0 / RN);
                    let y = -libm::log(self.Float64());
                    if y + y >= x_t * x_t {
                        break;
                    }
                }
                if j > 0 {
                    return RN + x_t;
                }
                return -RN - x_t;
            }
            // fn[i] + Float32(Float64()) * (fn[i-1] - fn[i])  <
            //   Float32(math.Exp(-0.5 * x * x))
            let lhs =
                ziggurat::FN[i] + (self.Float64() as f32) * (ziggurat::FN[i - 1] - ziggurat::FN[i]);
            let rhs = libm::exp(-0.5 * x * x) as f32;
            if lhs < rhs {
                return x;
            }
        }
    }

    // go: sdk 1.25.5 math/rand/exp.go:30-45 Rand.ExpFloat64
    /// `ExpFloat64` — exp.go:30. Ziggurat (Marsaglia & Tsang 2000).
    pub fn ExpFloat64(&mut self) -> f64 {
        const RE: f64 = 7.69711747013104972;
        loop {
            let j = self.Uint32();
            let i = (j & 0xFF) as usize;
            let x = (j as f64) * (ziggurat::WE[i] as f64);
            if j < ziggurat::KE[i] {
                return x;
            }
            if i == 0 {
                return RE - libm::log(self.Float64());
            }
            let lhs =
                ziggurat::FE[i] + (self.Float64() as f32) * (ziggurat::FE[i - 1] - ziggurat::FE[i]);
            let rhs = libm::exp(-x) as f32;
            if lhs < rhs {
                return x;
            }
        }
    }
}

impl io::Reader for Rand {
    // go: sdk 1.25.5 math/rand/rand.go:272-280 Rand.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Rand::Read(self, p)
    }
}

// ─── Top-level (`globalRand`) convenience functions (rand.go:304+) ───
//
// Go ships a process-wide locked Source seeded from runtime entropy.
// goish-v1 keeps the same shape: a single locked `rngSource`, lazily
// initialized on first use (seeded with 1 to match the pre-Go-1.20
// default; users wanting non-determinism call `Seed(time::UnixNano())`
// explicitly). The lock is goish's SpinLock — adequate since math/rand
// is documented as not for security-sensitive work.

struct GlobalState {
    src: rngSource,
    read_val: int64,
    read_pos: i8,
}

static GLOBAL: SpinLock<Option<GlobalState>> = SpinLock::new(None);
static GLOBAL_INIT: AtomicBool = AtomicBool::new(false);

fn with_global<R>(f: impl FnOnce(&mut GlobalState) -> R) -> R {
    let mut guard = GLOBAL.lock();
    if !GLOBAL_INIT.load(Ordering::Acquire) {
        let mut s = rngSource::default();
        s.Seed(1);
        *guard = Some(GlobalState {
            src: s,
            read_val: 0,
            read_pos: 0,
        });
        GLOBAL_INIT.store(true, Ordering::Release);
    }
    f(guard.as_mut().expect("global rand state initialized"))
}

/// `rand.Seed` — rand.go:400. Re-seeds the package-global generator.
pub fn Seed(seed: int64) {
    with_global(|g| {
        g.src.Seed(seed);
        g.read_pos = 0;
    });
}

// go: sdk 1.25.5 math/rand/rand.go:434-434 Int63
pub fn Int63() -> int64 {
    with_global(|g| g.src.Int63())
}

// go: sdk 1.25.5 math/rand/rand.go:438-438 Uint32
pub fn Uint32() -> u32 {
    with_global(|g| (g.src.Int63() >> 31) as u32)
}

// go: sdk 1.25.5 math/rand/rand.go:442-442 Uint64
pub fn Uint64() -> u64 {
    with_global(|g| g.src.Uint64())
}

// go: sdk 1.25.5 math/rand/rand.go:446-446 Int31
pub fn Int31() -> int32 {
    with_global(|g| (g.src.Int63() >> 32) as int32)
}

// go: sdk 1.25.5 math/rand/rand.go:449-449 Int
pub fn Int() -> int {
    with_global(|g| {
        let u = g.src.Int63() as u64;
        ((u << 1) >> 1) as int
    })
}

// go: sdk 1.25.5 math/rand/rand.go:454-454 Int63n
pub fn Int63n(n: int64) -> int64 {
    // Build a transient Rand over a borrow-shaped wrapper so the
    // rejection-sampling loop reuses the same locked source.
    if n <= 0 {
        panic!("invalid argument to Int63n");
    }
    with_global(|g| {
        if n & (n - 1) == 0 {
            return g.src.Int63() & (n - 1);
        }
        let max = ((1u64 << 63) - 1 - (1u64 << 63) % (n as u64)) as i64;
        let mut v = g.src.Int63();
        while v > max {
            v = g.src.Int63();
        }
        v % n
    })
}

// go: sdk 1.25.5 math/rand/rand.go:459-459 Int31n
pub fn Int31n(n: int32) -> int32 {
    if n <= 0 {
        panic!("invalid argument to Int31n");
    }
    with_global(|g| {
        if n & (n - 1) == 0 {
            return ((g.src.Int63() >> 32) as int32) & (n - 1);
        }
        let max = ((1u32 << 31) - 1 - (1u32 << 31) % (n as u32)) as i32;
        let mut v = (g.src.Int63() >> 32) as int32;
        while v > max {
            v = (g.src.Int63() >> 32) as int32;
        }
        v % n
    })
}

// go: sdk 1.25.5 math/rand/rand.go:464-464 Intn
pub fn Intn(n: int) -> int {
    if n <= 0 {
        panic!("invalid argument to Intn");
    }
    if n <= (1i64 << 31) - 1 {
        Int31n(n as int32) as int
    } else {
        Int63n(n as int64) as int
    }
}

// go: sdk 1.25.5 math/rand/rand.go:468-468 Float64
pub fn Float64() -> f64 {
    with_global(|g| loop {
        let f = (g.src.Int63() as f64) / ((1u64 << 63) as f64);
        if f != 1.0 {
            return f;
        }
    })
}

// go: sdk 1.25.5 math/rand/rand.go:472-472 Float32
pub fn Float32() -> f32 {
    loop {
        let f = Float64() as f32;
        if f != 1.0 {
            return f;
        }
    }
}

// go: sdk 1.25.5 math/rand/rand.go:476-476 Perm
pub fn Perm(n: int) -> slice<int> {
    let mut m: slice<int> = crate::make!([]int, n);
    for i in 0..n {
        let j = Intn(i + 1);
        m[i] = m[j];
        m[j] = i;
    }
    m
}

// go: sdk 1.25.5 math/rand/rand.go:481-481 Shuffle
pub fn Shuffle<F>(n: int, mut swap: F)
where
    F: FnMut(int, int),
{
    if n < 0 {
        panic!("invalid argument to Shuffle");
    }
    let mut i = n - 1;
    while i > (1i64 << 31) - 1 - 1 {
        let j = Int63n((i + 1) as int64);
        swap(i, j);
        i -= 1;
    }
    // For the tail we use the same Lemire reduction as Rand::int31n_fast,
    // operating on the locked global source directly to keep the value
    // stream stable.
    while i > 0 {
        let j = with_global(|g| {
            let n = (i + 1) as i32;
            let mut v = (g.src.Int63() >> 31) as u32; // == Uint32()
            let mut prod = (v as u64) * (n as u64);
            let mut low = prod as u32;
            if low < n as u32 {
                let thresh = (n as u32).wrapping_neg() % (n as u32);
                while low < thresh {
                    v = (g.src.Int63() >> 31) as u32;
                    prod = (v as u64) * (n as u64);
                    low = prod as u32;
                }
            }
            (prod >> 32) as i64
        });
        swap(i, j);
        i -= 1;
    }
}

// go: sdk 1.25.5 math/rand/rand.go:489-489 Read
pub fn Read(p: &mut slice<byte>) -> (int, error) {
    let n = crate::builtin::len(&*p) as usize;
    with_global(|g| {
        let mut pos = g.read_pos;
        let mut val = g.read_val;
        for i in 0..n {
            if pos == 0 {
                val = g.src.Int63();
                pos = 7;
            }
            p[i as int] = (val as u8) as byte;
            val >>= 8;
            pos -= 1;
        }
        g.read_pos = pos;
        g.read_val = val;
    });
    (n as int, Nil.into())
}

// go: sdk 1.25.5 math/rand/rand.go:499-499 NormFloat64
pub fn NormFloat64() -> f64 {
    // Construct a transient borrow-Rand-like view over the global. The
    // Ziggurat loop is identical to Rand::NormFloat64 — we just inline
    // here to avoid holding the global lock across the loop body.
    //
    // To keep value-stream identical to Go, every Uint32 and Float64
    // call must observe the same locked source, in order. We do that by
    // taking the lock for one draw at a time.
    const RN: f64 = 3.442619855899;
    loop {
        let j = Uint32() as i32;
        let i = (j & 0x7F) as usize;
        let x = (j as f64) * (ziggurat::WN[i] as f64);
        let abs_j = if j < 0 {
            (j as i32).wrapping_neg() as u32
        } else {
            j as u32
        };
        if abs_j < ziggurat::KN[i] {
            return x;
        }
        if i == 0 {
            let mut x_t;
            loop {
                x_t = -libm::log(Float64()) * (1.0 / RN);
                let y = -libm::log(Float64());
                if y + y >= x_t * x_t {
                    break;
                }
            }
            if j > 0 {
                return RN + x_t;
            }
            return -RN - x_t;
        }
        let lhs = ziggurat::FN[i] + (Float64() as f32) * (ziggurat::FN[i - 1] - ziggurat::FN[i]);
        let rhs = libm::exp(-0.5 * x * x) as f32;
        if lhs < rhs {
            return x;
        }
    }
}

// go: sdk 1.25.5 math/rand/rand.go:508-508 ExpFloat64
pub fn ExpFloat64() -> f64 {
    const RE: f64 = 7.69711747013104972;
    loop {
        let j = Uint32();
        let i = (j & 0xFF) as usize;
        let x = (j as f64) * (ziggurat::WE[i] as f64);
        if j < ziggurat::KE[i] {
            return x;
        }
        if i == 0 {
            return RE - libm::log(Float64());
        }
        let lhs = ziggurat::FE[i] + (Float64() as f32) * (ziggurat::FE[i - 1] - ziggurat::FE[i]);
        let rhs = libm::exp(-x) as f32;
        if lhs < rhs {
            return x;
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────
