// hash/adler32 — Go's `hash/adler32`, ported.
//
// Adler-32 checksum (RFC 1950): two sums accumulated per byte. s1 is
// the sum of all bytes; s2 is the sum of all s1 values. Both modulo
// 65521. s1 is initialized to 1, s2 to zero. The checksum is stored
// as `s2*65536 + s1` in big-endian order.
// (Go: hash/adler32/adler32.go)
//
// Slim deviations:
//   * No MarshalBinary / UnmarshalBinary / AppendBinary / Clone
//     (cosmetic state save/restore; not needed for HTTP work).
//   * `New()` returns `Digest` directly (a value with the Hash32
//     trait), not `hash.Hash32` interface — call sites use generics
//     or trait objects when interface dispatch is needed.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Hash, Hash32};
use crate::io;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

// ─── Constants (Go: adler32.go:22-32) ─────────────────────────────────

// Go: mod = 65521 — the largest prime less than 65536.
const MOD: u32 = 65521;
// Go: nmax = 5552 — largest n such that the per-block accumulator fits in u32.
const NMAX: usize = 5552;

/// `adler32.Size` (adler32.go:32) — checksum length in bytes.
pub const Size: int = 4;

// ─── Digest (Go: adler32.go:36) ───────────────────────────────────────
//
// Go: `type digest uint32` — low 16 bits are s1, high 16 bits are s2.
// We use a newtype struct over u32 so we can hang trait impls on it.

/// `adler32` digest — partial Adler-32 evaluation.
#[derive(Clone, Copy)]
pub struct Digest(u32);

/// `adler32.New()` (adler32.go:45) — return a new Adler-32 digest.
pub fn New() -> Digest {
    // Go: d := new(digest); d.Reset(); return d
    let mut d = Digest(0);
    d.Reset();
    d
}

// Go: update(d digest, p []byte) digest (adler32.go:87)
fn update(d: u32, mut p: &[byte]) -> u32 {
    // Go: s1, s2 := uint32(d&0xffff), uint32(d>>16)
    let mut s1: u32 = d & 0xffff;
    let mut s2: u32 = d >> 16;
    // Go: for len(p) > 0
    while !p.is_empty() {
        // Go: var q []byte
        //     if len(p) > nmax { p, q = p[:nmax], p[nmax:] }
        let mut q: &[byte] = &[];
        if p.len() > NMAX {
            q = &p[NMAX..];
            p = &p[..NMAX];
        }
        // Go: for len(p) >= 4 { unrolled four-byte step }
        while p.len() >= 4 {
            s1 = s1.wrapping_add(p[0] as u32);
            s2 = s2.wrapping_add(s1);
            s1 = s1.wrapping_add(p[1] as u32);
            s2 = s2.wrapping_add(s1);
            s1 = s1.wrapping_add(p[2] as u32);
            s2 = s2.wrapping_add(s1);
            s1 = s1.wrapping_add(p[3] as u32);
            s2 = s2.wrapping_add(s1);
            p = &p[4..];
        }
        // Go: for _, x := range p { s1 += uint32(x); s2 += s1 }
        for x in p.iter() {
            s1 = s1.wrapping_add(*x as u32);
            s2 = s2.wrapping_add(s1);
        }
        // Go: s1 %= mod; s2 %= mod
        s1 %= MOD;
        s2 %= MOD;
        // Go: p = q
        p = q;
    }
    // Go: return digest(s2<<16 | s1)
    (s2 << 16) | s1
}

/// `adler32.Checksum(data)` (adler32.go:129) — Adler-32 of `data`.
pub fn Checksum(data: slice<byte>) -> u32 {
    // Go: return uint32(update(1, data))
    let raw: &[byte] = &data;
    update(1, raw)
}

// ─── Hash trait impls for Digest (Go: adler32.go:38-126) ──────────────

impl io::Writer for Digest {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: *d = update(*d, p); return len(p), nil
        let raw: &[byte] = &p;
        self.0 = update(self.0, raw);
        (raw.len() as int, nil)
    }
}

impl Hash for Digest {
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: append(in, byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
        let s = self.0;
        let mut out: Vec<byte> = b.__into_vec();
        out.push((s >> 24) as byte);
        out.push((s >> 16) as byte);
        out.push((s >> 8) as byte);
        out.push(s as byte);
        slice::__from_vec(out)
    }
    fn Reset(&mut self) {
        // Go: *d = 1
        self.0 = 1;
    }
    fn Size(&self) -> int {
        Size
    }
    fn BlockSize(&self) -> int {
        // Go: return 4
        4
    }
}

impl Hash32 for Digest {
    fn Sum32(&self) -> u32 {
        // Go: return uint32(*d)
        self.0
    }
}
