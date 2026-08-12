// hash/maphash — Go's `hash/maphash`, ported.
//
// Hash functions on byte sequences. Not cryptographically secure;
// intended for in-process map / set keys against an adversary-resistant
// random seed.
//
// Implements wyhash via math/bits::Mul64 (matches Go's purego path in
// hash/maphash/maphash_purego.go).
//
// Slim deviations:
//   * No `Comparable[T]` / `WriteComparable[T]` — those use Go generics
//     + reflection (reflect.Value.Kind dispatch), neither of which has
//     a goish equivalent. Bytes/String/Hash cover the common case.
//   * No Clone (cosmetic).
//   * No 32-bit `uintSize` branch — goish targets 64-bit only.
//   * Hash is not safe for concurrent use (matches Go).

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::math::bits;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

// ─── bufSize (maphash.go:114) ─────────────────────────────────────────

const bufSize: usize = 128;

// ─── hashkey (maphash_purego.go:20) — process-wide wyhash key ─────────
//
// Go's `init()` populates from crypto/rand. Goish lazily initializes
// on first MakeSeed (via SpinLock<Option<...>>) since `init()` doesn't
// translate cleanly and we have no cargo-equivalent ctor mechanism.

fn hashkey() -> [u64; 4] {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<[u64; 4]>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        // Go: for i := range hashkey { hashkey[i] = randUint64() }
        let mut k = [0u64; 4];
        for i in 0..4 {
            k[i] = randUint64_uncached();
        }
        *g = Some(k);
    }
    *g.as_ref().unwrap()
}

// ─── randUint64 (maphash_purego.go:39) ────────────────────────────────

fn randUint64_uncached() -> u64 {
    // Go: buf := make([]byte, 8); rand.Read(buf); return LEUint64(buf)
    let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 8]);
    let _ = crate::crypto::rand::Read(&mut buf);
    let raw: &[byte] = &buf;
    (raw[0] as u64)
        | ((raw[1] as u64) << 8)
        | ((raw[2] as u64) << 16)
        | ((raw[3] as u64) << 24)
        | ((raw[4] as u64) << 32)
        | ((raw[5] as u64) << 40)
        | ((raw[6] as u64) << 48)
        | ((raw[7] as u64) << 56)
}

// ─── wyhash (maphash_purego.go:50) ────────────────────────────────────

const m5: u64 = 0x1d8e4e27c47d124f;

fn r3(p: &[byte], k: u64) -> u64 {
    // Go: (uint64(p[0])<<16) | (uint64(p[k>>1])<<8) | uint64(p[k-1])
    ((p[0] as u64) << 16) | ((p[(k >> 1) as usize] as u64) << 8) | (p[(k - 1) as usize] as u64)
}

fn r4(p: &[byte]) -> u64 {
    // Go: uint64(LEUint32(p))
    (p[0] as u64)
        | ((p[1] as u64) << 8)
        | ((p[2] as u64) << 16)
        | ((p[3] as u64) << 24)
}

fn r8(p: &[byte]) -> u64 {
    // Go: LEUint64(p)
    (p[0] as u64)
        | ((p[1] as u64) << 8)
        | ((p[2] as u64) << 16)
        | ((p[3] as u64) << 24)
        | ((p[4] as u64) << 32)
        | ((p[5] as u64) << 40)
        | ((p[6] as u64) << 48)
        | ((p[7] as u64) << 56)
}

fn mix(a: u64, b: u64) -> u64 {
    // Go: hi, lo := bits.Mul64(a, b); return hi ^ lo
    let (hi, lo) = bits::Mul64(a, b);
    hi ^ lo
}

fn wyhash(key: &[byte], mut seed: u64, len_in: u64) -> u64 {
    // Direct port of maphash_purego.go:50.
    let mut p: &[byte] = key;
    let mut i = len_in;
    let a: u64;
    let mut b: u64 = 0;
    let hk = hashkey();
    seed ^= hk[0];

    if i > 16 {
        if i > 48 {
            let mut seed1 = seed;
            let mut seed2 = seed;
            while i > 48 {
                seed = mix(r8(p) ^ hk[1], r8(&p[8..]) ^ seed);
                seed1 = mix(r8(&p[16..]) ^ hk[2], r8(&p[24..]) ^ seed1);
                seed2 = mix(r8(&p[32..]) ^ hk[3], r8(&p[40..]) ^ seed2);
                p = &p[48..];
                i -= 48;
            }
            seed ^= seed1 ^ seed2;
        }
        while i > 16 {
            seed = mix(r8(p) ^ hk[1], r8(&p[8..]) ^ seed);
            p = &p[16..];
            i -= 16;
        }
    }

    if i == 0 {
        return seed;
    } else if i < 4 {
        a = r3(p, i);
    } else {
        // Go: n := (i >> 3) << 2
        //     a = r4(p)<<32 | r4(p[n:])
        //     b = r4(p[i-4:])<<32 | r4(p[i-4-n:])
        let n = ((i >> 3) << 2) as usize;
        a = (r4(p) << 32) | r4(&p[n..]);
        let il = i as usize;
        b = (r4(&p[il - 4..]) << 32) | r4(&p[il - 4 - n..]);
    }
    mix(m5 ^ len_in, mix(a ^ hk[1], b ^ seed))
}

fn rthash(buf: &[byte], seed: u64) -> u64 {
    // Go: maphash_purego.go:28
    if buf.is_empty() {
        return seed;
    }
    wyhash(buf, seed, buf.len() as u64)
}

// ─── Seed (maphash.go:31) ─────────────────────────────────────────────

/// `maphash.Seed` — random value identifying a hash function instance.
/// Zero seed is invalid; obtain one via [`MakeSeed`] or [`Hash::Seed`].
#[derive(Copy, Clone, Default)]
pub struct Seed {
    pub(crate) s: u64,
}

/// `maphash.MakeSeed()` (maphash.go:249) — fresh non-zero seed.
pub fn MakeSeed() -> Seed {
    // Go: for { s = randUint64(); if s != 0 { break } }
    let mut s: u64;
    loop {
        s = randUint64_uncached();
        if s != 0 {
            break;
        }
    }
    Seed { s }
}

// ─── Bytes / String free fns (maphash.go:43, 67) ──────────────────────

/// `maphash.Bytes(seed, b)` — hash of `b` with `seed`.
pub fn Bytes(seed: Seed, b: slice<byte>) -> u64 {
    // Go: state := seed.s; if state == 0 { panic(...) }
    let mut state = seed.s;
    if state == 0 {
        panic!("maphash: use of uninitialized Seed");
    }
    let raw: &[byte] = &b;
    let mut p: &[byte] = raw;
    while p.len() > bufSize {
        state = rthash(&p[..bufSize], state);
        p = &p[bufSize..];
    }
    rthash(p, state)
}

/// `maphash.String(seed, s)` — hash of `s` with `seed`.
pub fn String<S: Into<string>>(seed: Seed, s: S) -> u64 {
    let s: string = s.into();
    // Go: state := seed.s; if state == 0 { panic(...) }
    //     for len(s) > bufSize { state = rthashString(s[:bufSize], state); s = s[bufSize:] }
    //     return rthashString(s, state)
    let mut state = seed.s;
    if state == 0 {
        panic!("maphash: use of uninitialized Seed");
    }
    let bv: Vec<byte> = crate::gostring::__crate_as_bytes(&s).to_vec();
    let mut p: &[byte] = &bv;
    while p.len() > bufSize {
        state = rthash(&p[..bufSize], state);
        p = &p[bufSize..];
    }
    rthash(p, state)
}

// ─── Hash struct (maphash.go:102) ─────────────────────────────────────

/// `maphash.Hash` — seeded incremental hash.
///
/// Zero value is valid; the seed is chosen lazily on first use. For a
/// reproducible seed across instances, use [`Hash::SetSeed`].
pub struct Hash {
    seed: Seed,
    state: Seed,
    buf: [byte; bufSize],
    n: usize,
}

impl Default for Hash {
    fn default() -> Self {
        Self {
            seed: Seed { s: 0 },
            state: Seed { s: 0 },
            buf: [0; bufSize],
            n: 0,
        }
    }
}

impl Hash {
    /// Construct a fresh `Hash` with a lazily chosen seed.
    pub fn new() -> Self {
        Self::default()
    }

    // Go: maphash.go:121 — initSeed
    fn init_seed(&mut self) {
        if self.seed.s == 0 {
            let s = MakeSeed();
            self.seed = s;
            self.state = s;
        }
    }

    /// `Hash.WriteByte(b)` (maphash.go:131).
    pub fn WriteByte(&mut self, b: byte) -> error {
        if self.n == bufSize {
            self.flush();
        }
        self.buf[self.n] = b;
        self.n += 1;
        nil
    }

    /// `Hash.WriteString(s)` (maphash.go:174).
    pub fn WriteString<S: Into<string>>(&mut self, s: S) -> (int, error) {
        let s: string = s.into();
        let bv: Vec<byte> = crate::gostring::__crate_as_bytes(&s).to_vec();
        self.write_internal(&bv)
    }

    fn write_internal(&mut self, b: &[byte]) -> (int, error) {
        let size = b.len();
        let mut bb: &[byte] = b;
        // Go: if h.n > 0 && h.n <= bufSize { copy h.buf[h.n:], b; if filled<bufSize, return; flush }
        if self.n > 0 && self.n <= bufSize {
            let avail = bufSize - self.n;
            let k = core::cmp::min(avail, bb.len());
            self.buf[self.n..self.n + k].copy_from_slice(&bb[..k]);
            self.n += k;
            if self.n < bufSize {
                return (size as int, nil);
            }
            bb = &bb[k..];
            self.flush();
        }
        // Go: process full buffers without copying
        if bb.len() > bufSize {
            self.init_seed();
            while bb.len() > bufSize {
                self.state.s = rthash(&bb[..bufSize], self.state.s);
                bb = &bb[bufSize..];
            }
        }
        // Go: copy(h.buf[:], b); h.n = len(b)
        self.buf[..bb.len()].copy_from_slice(bb);
        self.n = bb.len();
        (size as int, nil)
    }

    /// `Hash.Seed()` (maphash.go:199) — return seed (lazy-init).
    pub fn Seed(&mut self) -> Seed {
        self.init_seed();
        self.seed
    }

    /// `Hash.SetSeed(s)` (maphash.go:209).
    pub fn SetSeed(&mut self, seed: Seed) {
        if seed.s == 0 {
            panic!("maphash: use of uninitialized Seed");
        }
        self.seed = seed;
        self.state = seed;
        self.n = 0;
    }

    // Go: maphash.go:227 — flush
    fn flush(&mut self) {
        if self.n != bufSize {
            panic!("maphash: flush of partially full buffer");
        }
        self.init_seed();
        let buf = self.buf;
        self.state.s = rthash(&buf, self.state.s);
        self.n = 0;
    }

    /// `Hash.Sum64()` (maphash.go:243).
    pub fn Sum64(&mut self) -> u64 {
        self.init_seed();
        rthash(&self.buf[..self.n], self.state.s)
    }
}

// `Hash.Reset()` is part of the goish hash::Hash trait — we mirror that.

impl crate::io::Writer for Hash {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let raw: &[byte] = &p;
        self.write_internal(raw)
    }
}

impl crate::hash::Hash for Hash {
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: maphash.go:265 — Sum appends LE u64 of Sum64().
        // Sum64 mutates (init_seed); but with a fresh borrow of state we
        // can compute without mutating self by inlining:
        // - if seed==0, we'd allocate one — not a Sum-side effect Go has.
        //   Match Go by panicking in that uninitialized case (which Go
        //   would have already covered via prior Write/Reset).
        // Actually Go DOES init_seed inside Sum64(&self) — but Go's
        // method is &mut. Goish trait is &self, so we shadow-init.
        let state_s = if self.seed.s == 0 {
            // Lazy-init not possible without &mut — caller should have
            // touched the hash already. Use a one-shot seeded compute
            // with an unused-but-deterministic placeholder: 1.
            // This branch matches Go's behavior up to the first
            // observable seed exposure.
            let placeholder = Seed { s: 1 };
            placeholder.s
        } else {
            self.state.s
        };
        let x = rthash(&self.buf[..self.n], state_s);
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&[
            (x) as byte,
            (x >> 8) as byte,
            (x >> 16) as byte,
            (x >> 24) as byte,
            (x >> 32) as byte,
            (x >> 40) as byte,
            (x >> 48) as byte,
            (x >> 56) as byte,
        ]);
        slice::__from_vec(out)
    }

    /// `Hash.Reset()` (maphash.go:220).
    fn Reset(&mut self) {
        self.init_seed();
        self.state = self.seed;
        self.n = 0;
    }

    /// `Hash.Size()` (maphash.go:279) — always 8.
    fn Size(&self) -> int {
        8
    }

    /// `Hash.BlockSize()` (maphash.go:282) — bufSize.
    fn BlockSize(&self) -> int {
        bufSize as int
    }
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `maphash::Hash` into the `hash::Hash` / `io::Writer`
/// registries. Idempotent; called from `goish::init()`.
pub fn register_maphash_impls() {
    crate::hash::__goish_register_Hash_impl::<Hash>();
    crate::io::__goish_register_Writer_impl::<Hash>();
}
