// go: file hash/adler32/adler32.go decls: digest.Reset, New, digest.Size, digest.BlockSize, digest.AppendBinary, digest.MarshalBinary, digest.UnmarshalBinary, digest.Clone, update, digest.Write, digest.Sum32, digest.Sum, Checksum
//
// The `decls:` manifest above lists adler32.go's funcs and methods
// only. GOISH017 matches a manifest entry against Rust `fn` items, so
// naming the file's consts and types there would report every one of
// them as a dropped port. They are not dropped — `mod`, `nmax`,
// `Size`, `digest`, `magic` and `marshaledSize` each carry their own
// `// go: sdk` anchor below.
//
// hash/adler32/adler32.go — the Adler-32 checksum, RFC 1950.
//
// Two sums accumulated per byte: s1 is the sum of all bytes, s2 the
// sum of all s1 values, both modulo 65521. s1 starts at 1, s2 at 0,
// and the checksum is `s2*65536 + s1` in big-endian order. The whole
// digest is one uint32: s1 in the low half, s2 in the high half.
//
// The modulo reduction is what `nmax` is for. Go defers it and lets
// both sums run unreduced for up to 5552 bytes — the largest block for
// which `255*n*(n+1)/2 + (n+1)*(mod-1)` still fits in a uint32 — then
// reduces once per block. That bound is RFC 1950's, and this port
// reproduces the constant rather than re-deriving it.
//
// Deviations from Go, each forced by a Rust distinction:
//
//   * `mod` is a Rust keyword, so the constant is spelled `r#mod`. The
//     name is Go's; only the escape is Rust's.
//   * Go's `type digest uint32` is a defined type over uint32; goish
//     spells it as a newtype struct, which is what lets the trait
//     impls hang off it.
//   * `New` returns the concrete `digest` rather than Go's
//     `hash.Hash32` interface, as every goish hash package does.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use crate::convert::uint32 as touint32;
use crate::encoding;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Cloner, Hash, Hash32};
use crate::internal::byteorder;
use crate::io;
use crate::types::{byte, int, uint32};

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

// go: sdk 1.25.5 hash/adler32/adler32.go:22-29 mod
// goishlint:ignore GOISH021 mod — Go's name is `mod`, which is a Rust
//     keyword; the const below carries it as the raw identifier
//     `r#mod`, and GOISH021 matches on the bare spelling. The anchor
//     above is the real check: it names `mod` and cites its line range.
/// `adler32.mod` — the largest prime that is less than 65536.
const r#mod: uint32 = 65521;

// go: sdk 1.25.5 hash/adler32/adler32.go:22-29 nmax
/// `adler32.nmax` — the largest n such that
/// `255*n*(n+1)/2 + (n+1)*(mod-1) <= 2^32-1`. Mentioned in RFC 1950
/// (search for "5552").
const nmax: usize = 5552;

// go: sdk 1.25.5 hash/adler32/adler32.go:32-32 Size
/// `adler32.Size` — the size of an Adler-32 checksum in bytes.
pub const Size: int = 4;

// go: sdk 1.25.5 hash/adler32/adler32.go:36-36 digest
/// `adler32.digest` — the partial evaluation of a checksum. The low 16
/// bits are s1, the high 16 bits are s2.
#[derive(Clone, Copy)]
pub struct digest(uint32);

// go: sdk 1.25.5 hash/adler32/adler32.go:45-49 New
/// `adler32.New()` — a new `hash.Hash32` computing the Adler-32
/// checksum. Its `Sum` method lays the value out in big-endian byte
/// order. The result also implements `encoding.BinaryMarshaler` /
/// `encoding.BinaryUnmarshaler`, so a running hash can be saved and
/// resumed.
pub fn New() -> digest {
    // Go: d := new(digest); d.Reset(); return d
    let mut d = digest(0);
    <digest as Hash>::Reset(&mut d);
    return d;
}

// go: sdk 1.25.5 hash/adler32/adler32.go:55-58 magic
const magic: &[byte] = b"adl\x01";

// go: sdk 1.25.5 hash/adler32/adler32.go:55-58 marshaledSize
///
/// Go types this `int`; goish keeps it `usize` because every use is a
/// buffer length compared against `len(b)`.
const marshaledSize: usize = magic.len() + 4;

impl digest {
    // go: sdk 1.25.5 hash/adler32/adler32.go:60-64 digest.AppendBinary
    /// `(*digest).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, magic...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(magic);
        // Go: b = byteorder.BEAppendUint32(b, uint32(*d)); return b, nil
        return (
            byteorder::BEAppendUint32(slice::__from_vec(out), self.0),
            nil,
        );
    }

    // go: sdk 1.25.5 hash/adler32/adler32.go:66-68 digest.MarshalBinary
    /// `(*digest).MarshalBinary()` — the digest's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return d.AppendBinary(make([]byte, 0, marshaledSize))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 hash/adler32/adler32.go:70-79 digest.UnmarshalBinary
    /// `(*digest).UnmarshalBinary(b)` — restore state produced by
    /// [`digest::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic) || string(b[:len(magic)]) != magic
        if raw.len() < magic.len() || &raw[..magic.len()] != magic {
            return crate::errors::New("hash/adler32: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize
        if raw.len() != marshaledSize {
            return crate::errors::New("hash/adler32: invalid hash state size");
        }
        // Go: *d = digest(byteorder.BEUint32(b[len(magic):])); return nil
        self.0 = byteorder::BEUint32(slice::__from_vec(raw[magic.len()..].to_vec()));
        return nil;
    }

    // go: sdk 1.25.5 hash/adler32/adler32.go:81-84 digest.Clone
    /// `(*digest).Clone()` — an independent copy of this digest's
    /// state. Never fails, so the error is always nil, as in Go.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = *self;
        return (Box::new(r), nil);
    }
}

// go: sdk 1.25.5 hash/adler32/adler32.go:87-114 update
/// `adler32.update(d, p)` — add `p` to the running checksum `d`.
///
/// Takes a borrowed `&[byte]`: the block loop walks a cursor forward
/// (Go's `p, q = p[:nmax], p[nmax:]` and `p = p[4:]`), and re-wrapping
/// a goish slice per step would allocate inside the hot loop. It is
/// unexported, so no goish API surface sees the borrow.
fn update(d: digest, p: &[byte]) -> digest {
    // Go: s1, s2 := uint32(d&0xffff), uint32(d>>16)
    let mut s1: uint32 = d.0 & 0xffff;
    let mut s2: uint32 = d.0 >> 16;
    let mut p: &[byte] = p;
    // Go: for len(p) > 0
    while !p.is_empty() {
        // Go: var q []byte
        //     if len(p) > nmax { p, q = p[:nmax], p[nmax:] }
        let mut q: &[byte] = &[];
        if p.len() > nmax {
            q = &p[nmax..];
            p = &p[..nmax];
        }
        // Go: for len(p) >= 4 — the unrolled four-byte step.
        while p.len() >= 4 {
            s1 = s1.wrapping_add(touint32(p[0]));
            s2 = s2.wrapping_add(s1);
            s1 = s1.wrapping_add(touint32(p[1]));
            s2 = s2.wrapping_add(s1);
            s1 = s1.wrapping_add(touint32(p[2]));
            s2 = s2.wrapping_add(s1);
            s1 = s1.wrapping_add(touint32(p[3]));
            s2 = s2.wrapping_add(s1);
            // Go: p = p[4:]
            p = &p[4..];
        }
        // Go: for _, x := range p { s1 += uint32(x); s2 += s1 }
        let mut i: usize = 0;
        while i < p.len() {
            s1 = s1.wrapping_add(touint32(p[i]));
            s2 = s2.wrapping_add(s1);
            i += 1;
        }
        // Go: s1 %= mod; s2 %= mod
        s1 %= r#mod;
        s2 %= r#mod;
        // Go: p = q
        p = q;
    }
    // Go: return digest(s2<<16 | s1)
    return digest((s2 << 16) | s1);
}

// go: sdk 1.25.5 hash/adler32/adler32.go:129-129 Checksum
/// `adler32.Checksum(data)` — the Adler-32 checksum of `data`.
pub fn Checksum(data: slice<byte>) -> uint32 {
    // Go: return uint32(update(1, data))
    let raw: &[byte] = &data;
    return update(digest(1), raw).0;
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `digest` into the `hash` / `io` / `encoding` registries.
/// Idempotent; called from `goish::init()`.
pub fn register_adler32_impls() {
    crate::hash::__goish_register_Hash_impl::<digest>();
    crate::hash::__goish_register_Cloner_impl::<digest>();
    crate::io::__goish_register_Writer_impl::<digest>();
    encoding::__goish_register_BinaryMarshaler_impl::<digest>();
    encoding::__goish_register_BinaryAppender_impl::<digest>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<digest>();
}

// ─── hash.Hash32 / hash.Cloner / encoding interface impls ─────────────
//
// Go's `digest` satisfies these structurally. goish's interfaces are
// nominal, so each impl is spelled out; the marshaling ones forward to
// the inherent methods above.

impl io::Writer for digest {
    // go: sdk 1.25.5 hash/adler32/adler32.go:116-119 digest.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: *d = update(*d, p); return len(p), nil
        let raw: &[byte] = &p;
        *self = update(*self, raw);
        return (int::try_from(raw.len()).unwrap_or(0), nil);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Hash for digest {
    // go: sdk 1.25.5 hash/adler32/adler32.go:123-126 digest.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: s := uint32(*d)
        let s = self.0;
        // Go: return append(in, byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(&s.to_be_bytes());
        return slice::__from_vec(out);
    }
    // go: sdk 1.25.5 hash/adler32/adler32.go:38-38 digest.Reset
    fn Reset(&mut self) {
        // Go: *d = 1
        self.0 = 1;
    }
    // go: sdk 1.25.5 hash/adler32/adler32.go:51-51 digest.Size
    fn Size(&self) -> int {
        return Size;
    }
    // go: sdk 1.25.5 hash/adler32/adler32.go:53-53 digest.BlockSize
    fn BlockSize(&self) -> int {
        return 4;
    }
}

impl Hash32 for digest {
    // go: sdk 1.25.5 hash/adler32/adler32.go:121-121 digest.Sum32
    fn Sum32(&self) -> uint32 {
        // Go: return uint32(*d)
        return self.0;
    }
}

impl Cloner for digest {
    // go: sdk 1.25.5 hash/adler32/adler32.go:81-84 digest.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return digest::Clone(self);
    }
}

impl encoding::BinaryMarshaler for digest {
    // go: sdk 1.25.5 hash/adler32/adler32.go:66-68 digest.MarshalBinary
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return digest::MarshalBinary(self);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl encoding::BinaryAppender for digest {
    // go: sdk 1.25.5 hash/adler32/adler32.go:60-64 digest.AppendBinary
    fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        return digest::AppendBinary(self, b);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl encoding::BinaryUnmarshaler for digest {
    // go: sdk 1.25.5 hash/adler32/adler32.go:70-79 digest.UnmarshalBinary
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error {
        return digest::UnmarshalBinary(self, data);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `io::Writer::__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}
