// math/rand/v2 — pseudo-random number generation.
//
// Reference: /share/go/src/math/rand/v2/{rand.go,pcg.go}
//
// Slim deviations:
//   * No globalRand / runtime.rand binding. Top-level convenience
//     functions (Int64, Float64, Shuffle, …) are NOT exposed; users
//     must construct an explicit PCG / Rand. This avoids the runtime
//     fastrand hook and keeps `no_std` builds self-contained.
//   * Source is a Rust trait `Source` rather than a Go interface —
//     callers either pass `&mut PCG` directly, or wrap their own
//     impl. `Rand<S>` is generic over the source.
//   * Only PCG ported (not ChaCha8). PCG matches Go output bit-for-bit
//     for the same seed pair.
//   * MarshalBinary / AppendBinary / UnmarshalBinary on PCG ported.
//   * Perm() not ported — the closure-based Shuffle pattern doesn't
//     compose cleanly with Rust's borrow rules. Callers can build the
//     permutation directly: `for i in (1..n).rev() { let j = r.IntN(i+1); … }`.
//   * `is32bit` constant elided — goish-v1 is 64-bit only.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::math::bits;
use crate::types::{byte, int};

// ─── Source trait (rand.go:29) ───────────────────────────────────────

/// `rand.Source` — uniform uint64 source.
pub trait Source {
    fn Uint64(&mut self) -> u64;
}

// ─── PCG (pcg.go:18) ─────────────────────────────────────────────────

/// `rand.PCG` — 128-bit-state PCG generator. A zero PCG is equivalent
/// to `NewPCG(0, 0)`.
pub struct PCG {
    hi: u64,
    lo: u64,
}

/// `rand.NewPCG(seed1, seed2)` — pcg.go:24.
pub fn NewPCG(seed1: u64, seed2: u64) -> PCG {
    PCG { hi: seed1, lo: seed2 }
}

impl PCG {
    /// `Seed` — pcg.go:29.
    pub fn Seed(&mut self, seed1: u64, seed2: u64) {
        self.hi = seed1;
        self.lo = seed2;
    }

    /// `AppendBinary` — pcg.go:35.
    pub fn AppendBinary(&self, mut b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, "pcg:"...)
        let mut v: Vec<byte> = b.__into_vec();
        v.extend_from_slice(b"pcg:");
        // Go: b = byteorder.BEAppendUint64(b, p.hi)
        v.extend_from_slice(&self.hi.to_be_bytes());
        v.extend_from_slice(&self.lo.to_be_bytes());
        b = slice::__from_vec(v);
        (b, errors::nil)
    }

    /// `MarshalBinary` — pcg.go:43.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        let buf: slice<byte> = slice::__from_vec(Vec::with_capacity(20));
        self.AppendBinary(buf)
    }

    /// `UnmarshalBinary` — pcg.go:50.
    pub fn UnmarshalBinary(&mut self, data: &slice<byte>) -> error {
        let raw: &[byte] = data;
        if raw.len() != 20 || &raw[..4] != b"pcg:" {
            return errors::Wrap(ErrUnmarshalPCGImpl);
        }
        let mut hi_bytes = [0u8; 8];
        let mut lo_bytes = [0u8; 8];
        hi_bytes.copy_from_slice(&raw[4..12]);
        lo_bytes.copy_from_slice(&raw[12..20]);
        self.hi = u64::from_be_bytes(hi_bytes);
        self.lo = u64::from_be_bytes(lo_bytes);
        errors::nil
    }

    /// `next` — pcg.go:59. Returns (hi, lo) of the new state.
    fn next(&mut self) -> (u64, u64) {
        // Go: const (mulHi = …; mulLo = …; incHi = …; incLo = …)
        const MUL_HI: u64 = 2549297995355413924;
        const MUL_LO: u64 = 4865540595714422341;
        const INC_HI: u64 = 6364136223846793005;
        const INC_LO: u64 = 1442695040888963407;

        // Go: hi, lo = bits.Mul64(p.lo, mulLo)
        let (mut hi, mut lo) = bits::Mul64(self.lo, MUL_LO);
        // Go: hi += p.hi*mulLo + p.lo*mulHi
        hi = hi
            .wrapping_add(self.hi.wrapping_mul(MUL_LO))
            .wrapping_add(self.lo.wrapping_mul(MUL_HI));
        // Go: lo, c := bits.Add64(lo, incLo, 0)
        let (lo2, c) = bits::Add64(lo, INC_LO, 0);
        lo = lo2;
        // Go: hi, _ = bits.Add64(hi, incHi, c)
        let (hi2, _) = bits::Add64(hi, INC_HI, c);
        hi = hi2;
        self.lo = lo;
        self.hi = hi;
        (hi, lo)
    }
}

impl Source for PCG {
    /// `Uint64` — pcg.go:86. DXSM output.
    fn Uint64(&mut self) -> u64 {
        let (mut hi, lo) = self.next();
        // Go: const cheapMul = 0xda942042e4dd58b5
        const CHEAP_MUL: u64 = 0xda942042e4dd58b5;
        hi ^= hi >> 32;
        hi = hi.wrapping_mul(CHEAP_MUL);
        hi ^= hi >> 48;
        hi = hi.wrapping_mul(lo | 1);
        hi
    }
}

// ─── ErrUnmarshalPCG (pcg.go:47) ─────────────────────────────────────

struct ErrUnmarshalPCGImpl;
impl errors::ErrorTrait for ErrUnmarshalPCGImpl {
    fn Error(&self) -> string {
        string::from_static("invalid PCG encoding")
    }
}

// ─── Rand (rand.go:34) ───────────────────────────────────────────────

/// `rand.Rand` — random-number generator over a `Source`.
pub struct Rand<S: Source> {
    src: S,
}

/// `rand.New(src)` — rand.go:40.
pub fn New<S: Source>(src: S) -> Rand<S> {
    Rand { src }
}

impl<S: Source> Rand<S> {
    /// `Int64` — rand.go:45 — non-negative 63-bit integer.
    pub fn Int64(&mut self) -> i64 {
        // Go: int64(r.src.Uint64() &^ (1 << 63))
        (self.src.Uint64() & !(1u64 << 63)) as i64
    }

    /// `Uint32` — rand.go:48.
    pub fn Uint32(&mut self) -> u32 {
        (self.src.Uint64() >> 32) as u32
    }

    /// `Uint64` — rand.go:51.
    pub fn Uint64(&mut self) -> u64 {
        self.src.Uint64()
    }

    /// `Int32` — rand.go:54.
    pub fn Int32(&mut self) -> i32 {
        (self.src.Uint64() >> 33) as i32
    }

    /// `Int` — rand.go:57.
    pub fn Int(&mut self) -> int {
        // Go: int(uint(r.src.Uint64()) << 1 >> 1)
        ((self.src.Uint64() << 1) >> 1) as int
    }

    /// `Uint` — rand.go:60.
    pub fn Uint(&mut self) -> u64 {
        self.src.Uint64()
    }

    /// `Int64N(n)` — rand.go:64.
    pub fn Int64N(&mut self, n: i64) -> i64 {
        if n <= 0 {
            panic!("invalid argument to Int64N");
        }
        self.uint64n(n as u64) as i64
    }

    /// `Uint64N(n)` — rand.go:73.
    pub fn Uint64N(&mut self, n: u64) -> u64 {
        if n == 0 {
            panic!("invalid argument to Uint64N");
        }
        self.uint64n(n)
    }

    /// `uint64n` — rand.go:81. (No 32-bit fallback — goish is 64-bit-only.)
    fn uint64n(&mut self, n: u64) -> u64 {
        // Go: if n&(n-1) == 0 { return r.Uint64() & (n - 1) }
        if n & (n.wrapping_sub(1)) == 0 {
            return self.Uint64() & (n - 1);
        }
        // Go: hi, lo := bits.Mul64(r.Uint64(), n)
        let (mut hi, mut lo) = bits::Mul64(self.Uint64(), n);
        if lo < n {
            // Go: thresh := -n % n
            let thresh = (n.wrapping_neg()) % n;
            while lo < thresh {
                let (h2, l2) = bits::Mul64(self.Uint64(), n);
                hi = h2;
                lo = l2;
            }
        }
        let _ = lo;
        hi
    }

    /// `Int32N(n)` — rand.go:171.
    pub fn Int32N(&mut self, n: i32) -> i32 {
        if n <= 0 {
            panic!("invalid argument to Int32N");
        }
        self.uint64n(n as u64) as i32
    }

    /// `Uint32N(n)` — rand.go:180.
    pub fn Uint32N(&mut self, n: u32) -> u32 {
        if n == 0 {
            panic!("invalid argument to Uint32N");
        }
        self.uint64n(n as u64) as u32
    }

    /// `IntN(n)` — rand.go:191.
    pub fn IntN(&mut self, n: int) -> int {
        if n <= 0 {
            panic!("invalid argument to IntN");
        }
        self.uint64n(n as u64) as int
    }

    /// `UintN(n)` — rand.go:200.
    pub fn UintN(&mut self, n: u64) -> u64 {
        if n == 0 {
            panic!("invalid argument to UintN");
        }
        self.uint64n(n)
    }

    /// `Float64` — rand.go:208 — half-open [0.0, 1.0).
    pub fn Float64(&mut self) -> f64 {
        // Go: float64(r.Uint64()<<11>>11) / (1 << 53)
        ((self.Uint64() << 11) >> 11) as f64 / (1u64 << 53) as f64
    }

    /// `Float32` — rand.go:214 — half-open [0.0, 1.0).
    pub fn Float32(&mut self) -> f32 {
        ((self.Uint32() << 8) >> 8) as f32 / (1u32 << 24) as f32
    }

    /// `Shuffle(n, swap)` — rand.go:233. Fisher-Yates.
    pub fn Shuffle<F: FnMut(int, int)>(&mut self, n: int, mut swap: F) {
        if n < 0 {
            panic!("invalid argument to Shuffle");
        }
        // Go: for i := n - 1; i > 0; i-- { j := int(r.uint64n(uint64(i + 1))); swap(i, j) }
        let mut i = n - 1;
        while i > 0 {
            let j = self.uint64n((i + 1) as u64) as int;
            swap(i, j);
            i -= 1;
        }
    }
}
