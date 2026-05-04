// hash/fnv — Go's `hash/fnv`, ported. FNV-1 and FNV-1a, 32-bit and
// 64-bit variants. Non-cryptographic hash by Fowler-Noll-Vo.
//
// (Go: hash/fnv/fnv.go)
//
// Slim deviations:
//   * 128-bit variants (sum128, sum128a) need bits.Mul64; not yet
//     ported. Implementations TBD when math/bits.Mul64 lands.
//   * encoding.BinaryMarshaler / AppendBinary / UnmarshalBinary not
//     yet ported (cosmetic — internal-state save/restore).

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Hash, Hash32, Hash64};
use crate::io;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

// ─── Constants (Go: fnv.go:31) ────────────────────────────────────────

const offset32: u32 = 2166136261;
const offset64: u64 = 14695981039346656037;
const prime32: u32 = 16777619;
const prime64: u64 = 1099511628211;

// ─── sum32 — FNV-1 32-bit (Go: fnv.go:23) ─────────────────────────────

#[derive(Clone, Copy)]
pub struct sum32(u32);

/// `fnv.New32()` (fnv.go:44) — returns a new 32-bit FNV-1 hash.
pub fn New32() -> sum32 {
    // Go: var s sum32 = offset32
    sum32(offset32)
}

impl io::Writer for sum32 {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: hash := *s
        //     for _, c := range data { hash *= prime32; hash ^= sum32(c) }
        //     *s = hash
        //     return len(data), nil
        let raw: &[byte] = &p;
        let mut h: u32 = self.0;
        for c in raw.iter() {
            h = h.wrapping_mul(prime32);
            h ^= *c as u32;
        }
        self.0 = h;
        (raw.len() as int, nil)
    }
}

impl Hash for sum32 {
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: byteorder.BEAppendUint32(in, v)
        BEAppendUint32(b, self.0)
    }
    fn Reset(&mut self) {
        self.0 = offset32;
    }
    fn Size(&self) -> int {
        4
    }
    fn BlockSize(&self) -> int {
        1
    }
}

impl Hash32 for sum32 {
    fn Sum32(&self) -> u32 {
        self.0
    }
}

// ─── sum32a — FNV-1a 32-bit (Go: fnv.go:24) ───────────────────────────

#[derive(Clone, Copy)]
pub struct sum32a(u32);

/// `fnv.New32a()` (fnv.go:51) — returns a new 32-bit FNV-1a hash.
pub fn New32a() -> sum32a {
    sum32a(offset32)
}

impl io::Writer for sum32a {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: hash := *s
        //     for _, c := range data { hash ^= sum32a(c); hash *= prime32 }
        //     *s = hash
        let raw: &[byte] = &p;
        let mut h: u32 = self.0;
        for c in raw.iter() {
            h ^= *c as u32;
            h = h.wrapping_mul(prime32);
        }
        self.0 = h;
        (raw.len() as int, nil)
    }
}

impl Hash for sum32a {
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        BEAppendUint32(b, self.0)
    }
    fn Reset(&mut self) {
        self.0 = offset32;
    }
    fn Size(&self) -> int {
        4
    }
    fn BlockSize(&self) -> int {
        1
    }
}

impl Hash32 for sum32a {
    fn Sum32(&self) -> u32 {
        self.0
    }
}

// ─── sum64 — FNV-1 64-bit (Go: fnv.go:25) ─────────────────────────────

#[derive(Clone, Copy)]
pub struct sum64(u64);

/// `fnv.New64()` (fnv.go:58) — returns a new 64-bit FNV-1 hash.
pub fn New64() -> sum64 {
    sum64(offset64)
}

impl io::Writer for sum64 {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: for _, c := range data { hash *= prime64; hash ^= sum64(c) }
        let raw: &[byte] = &p;
        let mut h: u64 = self.0;
        for c in raw.iter() {
            h = h.wrapping_mul(prime64);
            h ^= *c as u64;
        }
        self.0 = h;
        (raw.len() as int, nil)
    }
}

impl Hash for sum64 {
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        BEAppendUint64(b, self.0)
    }
    fn Reset(&mut self) {
        self.0 = offset64;
    }
    fn Size(&self) -> int {
        8
    }
    fn BlockSize(&self) -> int {
        1
    }
}

impl Hash64 for sum64 {
    fn Sum64(&self) -> u64 {
        self.0
    }
}

// ─── sum64a — FNV-1a 64-bit (Go: fnv.go:26) ───────────────────────────

#[derive(Clone, Copy)]
pub struct sum64a(u64);

/// `fnv.New64a()` (fnv.go:65) — returns a new 64-bit FNV-1a hash.
pub fn New64a() -> sum64a {
    sum64a(offset64)
}

impl io::Writer for sum64a {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: for _, c := range data { hash ^= sum64a(c); hash *= prime64 }
        let raw: &[byte] = &p;
        let mut h: u64 = self.0;
        for c in raw.iter() {
            h ^= *c as u64;
            h = h.wrapping_mul(prime64);
        }
        self.0 = h;
        (raw.len() as int, nil)
    }
}

impl Hash for sum64a {
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        BEAppendUint64(b, self.0)
    }
    fn Reset(&mut self) {
        self.0 = offset64;
    }
    fn Size(&self) -> int {
        8
    }
    fn BlockSize(&self) -> int {
        1
    }
}

impl Hash64 for sum64a {
    fn Sum64(&self) -> u64 {
        self.0
    }
}

// ─── Big-endian uint append helpers (Go: internal/byteorder.BEAppendUint*) ─
//
// fnv.go uses byteorder.BEAppendUint32 / BEAppendUint64. encoding/binary
// has BigEndian.PutUint{32,64} but those take Rust &mut [u8]; the
// goish public-API rule wants slice<byte> in/out. Inline the appends
// here so the public Sum signature stays clean.

fn BEAppendUint32(dst: slice<byte>, v: u32) -> slice<byte> {
    let mut out: Vec<byte> = dst.__into_vec();
    out.push((v >> 24) as byte);
    out.push((v >> 16) as byte);
    out.push((v >> 8) as byte);
    out.push(v as byte);
    slice::__from_vec(out)
}

fn BEAppendUint64(dst: slice<byte>, v: u64) -> slice<byte> {
    let mut out: Vec<byte> = dst.__into_vec();
    out.push((v >> 56) as byte);
    out.push((v >> 48) as byte);
    out.push((v >> 40) as byte);
    out.push((v >> 32) as byte);
    out.push((v >> 24) as byte);
    out.push((v >> 16) as byte);
    out.push((v >> 8) as byte);
    out.push(v as byte);
    slice::__from_vec(out)
}
