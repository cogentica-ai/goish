// math/rand — pseudo-random number generation.
//
// goish ships both APIs:
//   * legacy v1 (Go 1.0+) — `Source` / `Source64` / `NewSource` /
//     `New` / `Rand` — mounted at this path so ports written against
//     the v1 API (e.g. `oklog/ulid/v2`) compile unchanged.
//   * v2 (Go 1.22+) — `goish::math::rand::v2`, mounted as a sub-mod.
//
// Reference: /share/go/src/math/rand/{rand.go,rng.go}
//            /share/go/src/math/rand/v2/
//
// The legacy generator here uses a SplitMix64 → 2-PCG-XSH-RR pipeline
// rather than Go's lagged-Fibonacci with the 607-element cooked seed
// table. It satisfies the API contract (`Source` + `Source64`) and the
// io.Reader-via-Read shape callers depend on, but the byte-for-byte
// output stream does NOT match Go's `math/rand`. Code that depends on
// reproducing Go-specific PRNG output should use a faithful port.

#![allow(non_snake_case)]

pub mod v2;

extern crate alloc;
use alloc::boxed::Box;

use crate::errors::error;
use crate::goslice::slice;
use crate::io;
use crate::nilval::Nil;
use crate::types::{byte, int};
type int32 = i32;
type int64 = i64;

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

// ─── Default Source implementation ────────────────────────────────────
//
// PCG-XSH-RR-style step plus SplitMix64 seed expansion. NOT a port of
// the lagged-Fibonacci `*rngSource`; output stream differs from Go's.

#[derive(Clone, Copy, Default)]
pub struct rngSource {
    state: u64,
    inc: u64,
}

#[inline]
fn pcg_step(state: &mut u64, inc: u64) -> u32 {
    let oldstate = *state;
    *state = oldstate
        .wrapping_mul(6364136223846793005)
        .wrapping_add(inc);
    let xorshifted = (((oldstate >> 18) ^ oldstate) >> 27) as u32;
    let rot = (oldstate >> 59) as u32;
    xorshifted.rotate_right(rot)
}

#[inline]
fn splitmix64(z: &mut u64) -> u64 {
    *z = z.wrapping_add(0x9E3779B97F4A7C15);
    let mut x = *z;
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D049BB133111EB);
    x ^ (x >> 31)
}

impl Source for rngSource {
    fn Int63(&mut self) -> int64 {
        (self.Uint64() & 0x7FFF_FFFF_FFFF_FFFF) as int64
    }
    fn Seed(&mut self, seed: int64) {
        let mut z = seed as u64;
        self.state = splitmix64(&mut z);
        self.inc = splitmix64(&mut z) | 1;
        // Burn one step so back-to-back seeds with adjacent values
        // produce visibly different first outputs.
        let _ = pcg_step(&mut self.state, self.inc);
    }
}

impl Source64 for rngSource {
    fn Uint64(&mut self) -> u64 {
        let hi = pcg_step(&mut self.state, self.inc) as u64;
        let lo = pcg_step(&mut self.state, self.inc) as u64;
        (hi << 32) | lo
    }
}

/// NewSource returns a new pseudo-random Source seeded with `seed`.
pub fn NewSource(seed: int64) -> Box<dyn Source64 + Send + Sync> {
    let mut s = rngSource::default();
    s.Seed(seed);
    Box::new(s)
}

// ─── Rand wrapper — `*Rand` in Go, by-value here ──────────────────────

/// A Rand is a source of random numbers, wrapping a Source.
///
/// Per Go's design, `Rand` is a value type but in goish we expose
/// `Rand` directly (callers wrap in `Box<dyn io::Reader>` themselves
/// when needed for interface-storage).
pub struct Rand {
    src: Box<dyn Source64 + Send + Sync>,
    // Sub-byte stash for `Read` (matches Go's readVal/readPos).
    read_val: int64,
    read_pos: i8,
}

/// New returns a new Rand that uses random values from `src`.
///
/// In Go, `New` accepts `Source` and stashes a `Source64` if the
/// underlying type implements it. Goish requires `Source64` directly
/// for simplicity (every concrete Source on goish-v1 implements both).
pub fn New(src: Box<dyn Source64 + Send + Sync>) -> Rand {
    Rand { src, read_val: 0, read_pos: 0 }
}

impl Rand {
    pub fn Int63(&mut self) -> int64 {
        self.src.Int63()
    }
    pub fn Uint32(&mut self) -> u32 {
        (self.src.Int63() >> 31) as u32
    }
    pub fn Uint64(&mut self) -> u64 {
        self.src.Uint64()
    }
    pub fn Int31(&mut self) -> int32 {
        (self.src.Int63() >> 32) as int32
    }
    pub fn Int(&mut self) -> int {
        let u = self.src.Int63() as u64;
        ((u << 1) >> 1) as int
    }
    pub fn Seed(&mut self, seed: int64) {
        self.src.Seed(seed);
        self.read_pos = 0;
    }
    /// Read generates len(p) random bytes into p. Always returns
    /// (len(p), nil). Mirrors the sub-byte stash semantic of Go's Read.
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
}

impl io::Reader for Rand {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Rand::Read(self, p)
    }
}
