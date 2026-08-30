// go: file hash/fnv/fnv.go decls: New32, New32a, New64, New64a, New128, New128a, sum32.Reset, sum32a.Reset, sum64.Reset, sum64a.Reset, sum128.Reset, sum128a.Reset, sum32.Sum32, sum32a.Sum32, sum64.Sum64, sum64a.Sum64, sum32.Write, sum32a.Write, sum64.Write, sum64a.Write, sum128.Write, sum128a.Write, sum32.Size, sum32a.Size, sum64.Size, sum64a.Size, sum128.Size, sum128a.Size, sum32.BlockSize, sum32a.BlockSize, sum64.BlockSize, sum64a.BlockSize, sum128.BlockSize, sum128a.BlockSize, sum32.Sum, sum32a.Sum, sum64.Sum, sum64a.Sum, sum128.Sum, sum128a.Sum, sum32.AppendBinary, sum32a.AppendBinary, sum64.AppendBinary, sum64a.AppendBinary, sum128.AppendBinary, sum128a.AppendBinary, sum32.MarshalBinary, sum32a.MarshalBinary, sum64.MarshalBinary, sum64a.MarshalBinary, sum128.MarshalBinary, sum128a.MarshalBinary, sum32.UnmarshalBinary, sum32a.UnmarshalBinary, sum64.UnmarshalBinary, sum64a.UnmarshalBinary, sum128.UnmarshalBinary, sum128a.UnmarshalBinary, sum32.Clone, sum32a.Clone, sum64.Clone, sum64a.Clone, sum128.Clone, sum128a.Clone
//
// The `decls:` manifest above lists fnv.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the file's consts and types there would report every one of them as
// a dropped port. They are not dropped — the six `sum*` types, the
// eight offset/prime constants and the nine magic/size constants each
// carry their own `// go: sdk` anchor below.
//
// hash/fnv/fnv.go — FNV-1 and FNV-1a, by Fowler, Noll and Vo.
//
// Six digests, three widths, two variants. FNV-1 multiplies then xors;
// FNV-1a xors then multiplies. That one transposition is the whole
// difference between the `a` and non-`a` types, and Go writes each of
// the twelve loops out rather than sharing them — so does this port.
//
// The 128-bit pair is the only one that is not a single machine word.
// Go carries it as `[2]uint64` and does the multiply by hand out of
// `bits.Mul64` plus two shifted partial products, because 0x13b and
// the bit at 1<<88 (`prime128Shift`, applied to the low word) are all
// that is nonzero in the 128-bit prime. goish reproduces that
// arithmetic verbatim, with one Rust adjustment noted at the call
// site: Go's `<<` binds tighter than `+`, Rust's binds looser, so the
// shifted term needs parentheses it does not need in Go.
//
// Deviations from Go:
//
//   * Each `type sumN uintM` becomes a newtype struct, which is what
//     lets the trait impls hang off it.
//   * Every `New*` returns its concrete type rather than Go's
//     `hash.Hash32` / `hash.Hash64` / `hash.Hash` interface, as every
//     goish hash package does.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use crate::convert::{uint32 as touint32, uint64 as touint64};
use crate::encoding;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Cloner, Hash, Hash32, Hash64};
use crate::internal::byteorder;
use crate::io;
use crate::math::bits;
use crate::types::{byte, int, uint32, uint64};

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

// go: sdk 1.25.5 hash/fnv/fnv.go:22-29 sum32
/// `fnv.sum32` — the FNV-1 32-bit digest.
#[derive(Clone, Copy)]
pub struct sum32(uint32);

// go: sdk 1.25.5 hash/fnv/fnv.go:22-29 sum32a
/// `fnv.sum32a` — the FNV-1a 32-bit digest.
#[derive(Clone, Copy)]
pub struct sum32a(uint32);

// go: sdk 1.25.5 hash/fnv/fnv.go:22-29 sum64
/// `fnv.sum64` — the FNV-1 64-bit digest.
#[derive(Clone, Copy)]
pub struct sum64(uint64);

// go: sdk 1.25.5 hash/fnv/fnv.go:22-29 sum64a
/// `fnv.sum64a` — the FNV-1a 64-bit digest.
#[derive(Clone, Copy)]
pub struct sum64a(uint64);

// go: sdk 1.25.5 hash/fnv/fnv.go:22-29 sum128
/// `fnv.sum128` — the FNV-1 128-bit digest: `[0]` is the high
/// half, `[1]` the low half.
#[derive(Clone, Copy)]
pub struct sum128([uint64; 2]);

// go: sdk 1.25.5 hash/fnv/fnv.go:22-29 sum128a
/// `fnv.sum128a` — the FNV-1a 128-bit digest; see [`sum128`].
#[derive(Clone, Copy)]
pub struct sum128a([uint64; 2]);

// go: sdk 1.25.5 hash/fnv/fnv.go:31-40 offset32
/// `fnv.offset32` — the FNV-1/1a 32-bit offset basis.
const offset32: uint32 = 2166136261;

// go: sdk 1.25.5 hash/fnv/fnv.go:31-40 offset64
/// `fnv.offset64` — the FNV-1/1a 64-bit offset basis.
const offset64: uint64 = 14695981039346656037;

// go: sdk 1.25.5 hash/fnv/fnv.go:31-40 offset128Lower
/// `fnv.offset128Lower` — the low half of the 128-bit offset basis.
const offset128Lower: uint64 = 0x62b821756295c58d;

// go: sdk 1.25.5 hash/fnv/fnv.go:31-40 offset128Higher
/// `fnv.offset128Higher` — the high half of the 128-bit offset basis.
const offset128Higher: uint64 = 0x6c62272e07bb0142;

// go: sdk 1.25.5 hash/fnv/fnv.go:31-40 prime32
/// `fnv.prime32` — the FNV 32-bit prime.
const prime32: uint32 = 16777619;

// go: sdk 1.25.5 hash/fnv/fnv.go:31-40 prime64
/// `fnv.prime64` — the FNV 64-bit prime.
const prime64: uint64 = 1099511628211;

// go: sdk 1.25.5 hash/fnv/fnv.go:31-40 prime128Lower
/// `fnv.prime128Lower` — the nonzero low bits of the 128-bit prime.
const prime128Lower: uint64 = 0x13b;

// go: sdk 1.25.5 hash/fnv/fnv.go:31-40 prime128Shift
/// `fnv.prime128Shift` — the 128-bit prime's high bit, as a shift of the low word.
const prime128Shift: uint32 = 24;

// go: sdk 1.25.5 hash/fnv/fnv.go:44-47 New32
/// `fnv.New32()` — a new 32-bit FNV-1 `hash.Hash32`. Its `Sum` method
/// lays the value out in big-endian byte order.
pub fn New32() -> sum32 {
    // Go: var s sum32 = offset32
    return sum32(offset32);
}

// go: sdk 1.25.5 hash/fnv/fnv.go:51-54 New32a
/// `fnv.New32a()` — a new 32-bit FNV-1a `hash.Hash32`. Its `Sum` method
/// lays the value out in big-endian byte order.
pub fn New32a() -> sum32a {
    // Go: var s sum32a = offset32
    return sum32a(offset32);
}

// go: sdk 1.25.5 hash/fnv/fnv.go:58-61 New64
/// `fnv.New64()` — a new 64-bit FNV-1 `hash.Hash64`. Its `Sum` method
/// lays the value out in big-endian byte order.
pub fn New64() -> sum64 {
    // Go: var s sum64 = offset64
    return sum64(offset64);
}

// go: sdk 1.25.5 hash/fnv/fnv.go:65-68 New64a
/// `fnv.New64a()` — a new 64-bit FNV-1a `hash.Hash64`. Its `Sum` method
/// lays the value out in big-endian byte order.
pub fn New64a() -> sum64a {
    // Go: var s sum64a = offset64
    return sum64a(offset64);
}

// go: sdk 1.25.5 hash/fnv/fnv.go:72-77 New128
/// `fnv.New128()` — a new 128-bit FNV-1 `hash.Hash`. Its `Sum` method
/// lays the value out in big-endian byte order.
pub fn New128() -> sum128 {
    // Go: var s sum128; s[0] = offset128Higher; s[1] = offset128Lower
    return sum128([offset128Higher, offset128Lower]);
}

// go: sdk 1.25.5 hash/fnv/fnv.go:81-86 New128a
/// `fnv.New128a()` — a new 128-bit FNV-1a `hash.Hash`. Its `Sum` method
/// lays the value out in big-endian byte order.
pub fn New128a() -> sum128a {
    // Go: var s sum128a; s[0] = offset128Higher; s[1] = offset128Lower
    return sum128a([offset128Higher, offset128Lower]);
}

// go: sdk 1.25.5 hash/fnv/fnv.go:210-220 magic32
const magic32: &[byte] = b"fnv\x01";
// go: sdk 1.25.5 hash/fnv/fnv.go:210-220 magic32a
const magic32a: &[byte] = b"fnv\x02";
// go: sdk 1.25.5 hash/fnv/fnv.go:210-220 magic64
const magic64: &[byte] = b"fnv\x03";
// go: sdk 1.25.5 hash/fnv/fnv.go:210-220 magic64a
const magic64a: &[byte] = b"fnv\x04";
// go: sdk 1.25.5 hash/fnv/fnv.go:210-220 magic128
const magic128: &[byte] = b"fnv\x05";
// go: sdk 1.25.5 hash/fnv/fnv.go:210-220 magic128a
const magic128a: &[byte] = b"fnv\x06";

// go: sdk 1.25.5 hash/fnv/fnv.go:210-220 marshaledSize32
///
/// Go types this `int`; goish keeps it `usize` because every use is a
/// buffer length compared against `len(b)`.
const marshaledSize32: usize = magic32.len() + 4;

// go: sdk 1.25.5 hash/fnv/fnv.go:210-220 marshaledSize64
///
/// Go types this `int`; goish keeps it `usize` because every use is a
/// buffer length compared against `len(b)`.
const marshaledSize64: usize = magic64.len() + 8;

// go: sdk 1.25.5 hash/fnv/fnv.go:210-220 marshaledSize128
///
/// Go types this `int`; goish keeps it `usize` because every use is a
/// buffer length compared against `len(b)`.
const marshaledSize128: usize = magic128.len() + 8 * 2;

impl sum32 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:222-226 sum32.AppendBinary
    /// `(*sum32).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, magic32...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(magic32);
        // Go: b = byteorder.BEAppendUint32(b, uint32(*s)); return b, nil
        return (
            byteorder::BEAppendUint32(slice::__from_vec(out), self.0),
            nil,
        );
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:228-230 sum32.MarshalBinary
    /// `(*sum32).MarshalBinary()` — the digest's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return s.AppendBinary(make([]byte, 0, marshaledSize32))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize32);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:284-293 sum32.UnmarshalBinary
    /// `(*sum32).UnmarshalBinary(b)` — restore state produced by
    /// [`sum32::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic32) || string(b[:len(magic32)]) != magic32
        if raw.len() < magic32.len() || &raw[..magic32.len()] != magic32 {
            return crate::errors::New("hash/fnv: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize32
        if raw.len() != marshaledSize32 {
            return crate::errors::New("hash/fnv: invalid hash state size");
        }
        // Go: *s = sum32(byteorder.BEUint32(b[4:])); return nil
        self.0 = byteorder::BEUint32(slice::__from_vec(raw[4..].to_vec()));
        return nil;
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:352-355 sum32.Clone
    /// `(*sum32).Clone()` — an independent copy of this digest's state.
    /// Never fails, so the error is always nil, as in Go.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = *self;
        return (Box::new(r), nil);
    }
}

impl sum32a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:232-236 sum32a.AppendBinary
    /// `(*sum32a).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, magic32a...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(magic32a);
        // Go: b = byteorder.BEAppendUint32(b, uint32(*s)); return b, nil
        return (
            byteorder::BEAppendUint32(slice::__from_vec(out), self.0),
            nil,
        );
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:238-240 sum32a.MarshalBinary
    /// `(*sum32a).MarshalBinary()` — the digest's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return s.AppendBinary(make([]byte, 0, marshaledSize32))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize32);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:295-304 sum32a.UnmarshalBinary
    /// `(*sum32a).UnmarshalBinary(b)` — restore state produced by
    /// [`sum32a::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic32a) || string(b[:len(magic32a)]) != magic32a
        if raw.len() < magic32a.len() || &raw[..magic32a.len()] != magic32a {
            return crate::errors::New("hash/fnv: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize32
        if raw.len() != marshaledSize32 {
            return crate::errors::New("hash/fnv: invalid hash state size");
        }
        // Go: *s = sum32a(byteorder.BEUint32(b[4:])); return nil
        self.0 = byteorder::BEUint32(slice::__from_vec(raw[4..].to_vec()));
        return nil;
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:357-360 sum32a.Clone
    /// `(*sum32a).Clone()` — an independent copy of this digest's state.
    /// Never fails, so the error is always nil, as in Go.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = *self;
        return (Box::new(r), nil);
    }
}

impl sum64 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:242-246 sum64.AppendBinary
    /// `(*sum64).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, magic64...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(magic64);
        // Go: b = byteorder.BEAppendUint64(b, uint64(*s)); return b, nil
        return (
            byteorder::BEAppendUint64(slice::__from_vec(out), self.0),
            nil,
        );
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:248-250 sum64.MarshalBinary
    /// `(*sum64).MarshalBinary()` — the digest's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return s.AppendBinary(make([]byte, 0, marshaledSize64))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize64);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:306-315 sum64.UnmarshalBinary
    /// `(*sum64).UnmarshalBinary(b)` — restore state produced by
    /// [`sum64::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic64) || string(b[:len(magic64)]) != magic64
        if raw.len() < magic64.len() || &raw[..magic64.len()] != magic64 {
            return crate::errors::New("hash/fnv: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize64
        if raw.len() != marshaledSize64 {
            return crate::errors::New("hash/fnv: invalid hash state size");
        }
        // Go: *s = sum64(byteorder.BEUint64(b[4:])); return nil
        self.0 = byteorder::BEUint64(slice::__from_vec(raw[4..].to_vec()));
        return nil;
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:362-365 sum64.Clone
    /// `(*sum64).Clone()` — an independent copy of this digest's state.
    /// Never fails, so the error is always nil, as in Go.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = *self;
        return (Box::new(r), nil);
    }
}

impl sum64a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:252-256 sum64a.AppendBinary
    /// `(*sum64a).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, magic64a...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(magic64a);
        // Go: b = byteorder.BEAppendUint64(b, uint64(*s)); return b, nil
        return (
            byteorder::BEAppendUint64(slice::__from_vec(out), self.0),
            nil,
        );
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:258-260 sum64a.MarshalBinary
    /// `(*sum64a).MarshalBinary()` — the digest's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return s.AppendBinary(make([]byte, 0, marshaledSize64))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize64);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:317-326 sum64a.UnmarshalBinary
    /// `(*sum64a).UnmarshalBinary(b)` — restore state produced by
    /// [`sum64a::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic64a) || string(b[:len(magic64a)]) != magic64a
        if raw.len() < magic64a.len() || &raw[..magic64a.len()] != magic64a {
            return crate::errors::New("hash/fnv: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize64
        if raw.len() != marshaledSize64 {
            return crate::errors::New("hash/fnv: invalid hash state size");
        }
        // Go: *s = sum64a(byteorder.BEUint64(b[4:])); return nil
        self.0 = byteorder::BEUint64(slice::__from_vec(raw[4..].to_vec()));
        return nil;
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:367-370 sum64a.Clone
    /// `(*sum64a).Clone()` — an independent copy of this digest's state.
    /// Never fails, so the error is always nil, as in Go.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = *self;
        return (Box::new(r), nil);
    }
}

impl sum128 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:262-267 sum128.AppendBinary
    /// `(*sum128).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, magic128...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(magic128);
        // Go: b = byteorder.BEAppendUint64(b, s[0])
        let acc = byteorder::BEAppendUint64(slice::__from_vec(out), self.0[0]);
        // Go: b = byteorder.BEAppendUint64(b, s[1]); return b, nil
        return (byteorder::BEAppendUint64(acc, self.0[1]), nil);
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:269-271 sum128.MarshalBinary
    /// `(*sum128).MarshalBinary()` — the digest's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return s.AppendBinary(make([]byte, 0, marshaledSize128))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize128);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:328-338 sum128.UnmarshalBinary
    /// `(*sum128).UnmarshalBinary(b)` — restore state produced by
    /// [`sum128::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic128) || string(b[:len(magic128)]) != magic128
        if raw.len() < magic128.len() || &raw[..magic128.len()] != magic128 {
            return crate::errors::New("hash/fnv: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize128
        if raw.len() != marshaledSize128 {
            return crate::errors::New("hash/fnv: invalid hash state size");
        }
        // Go: s[0] = byteorder.BEUint64(b[4:]); s[1] = byteorder.BEUint64(b[12:])
        self.0[0] = byteorder::BEUint64(slice::__from_vec(raw[4..12].to_vec()));
        self.0[1] = byteorder::BEUint64(slice::__from_vec(raw[12..].to_vec()));
        return nil;
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:372-375 sum128.Clone
    /// `(*sum128).Clone()` — an independent copy of this digest's state.
    /// Never fails, so the error is always nil, as in Go.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = *self;
        return (Box::new(r), nil);
    }
}

impl sum128a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:273-278 sum128a.AppendBinary
    /// `(*sum128a).AppendBinary(b)` — append the marshaled state to `b`.
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: b = append(b, magic128a...)
        let mut out: Vec<byte> = b.__into_vec();
        out.extend_from_slice(magic128a);
        // Go: b = byteorder.BEAppendUint64(b, s[0])
        let acc = byteorder::BEAppendUint64(slice::__from_vec(out), self.0[0]);
        // Go: b = byteorder.BEAppendUint64(b, s[1]); return b, nil
        return (byteorder::BEAppendUint64(acc, self.0[1]), nil);
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:280-282 sum128a.MarshalBinary
    /// `(*sum128a).MarshalBinary()` — the digest's internal state.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        // Go: return s.AppendBinary(make([]byte, 0, marshaledSize128))
        let buf: Vec<byte> = Vec::with_capacity(marshaledSize128);
        return self.AppendBinary(slice::__from_vec(buf));
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:340-350 sum128a.UnmarshalBinary
    /// `(*sum128a).UnmarshalBinary(b)` — restore state produced by
    /// [`sum128a::MarshalBinary`].
    pub fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        let raw: &[byte] = &b;
        // Go: if len(b) < len(magic128a) || string(b[:len(magic128a)]) != magic128a
        if raw.len() < magic128a.len() || &raw[..magic128a.len()] != magic128a {
            return crate::errors::New("hash/fnv: invalid hash state identifier");
        }
        // Go: if len(b) != marshaledSize128
        if raw.len() != marshaledSize128 {
            return crate::errors::New("hash/fnv: invalid hash state size");
        }
        // Go: s[0] = byteorder.BEUint64(b[4:]); s[1] = byteorder.BEUint64(b[12:])
        self.0[0] = byteorder::BEUint64(slice::__from_vec(raw[4..12].to_vec()));
        self.0[1] = byteorder::BEUint64(slice::__from_vec(raw[12..].to_vec()));
        return nil;
    }

    // go: sdk 1.25.5 hash/fnv/fnv.go:377-380 sum128a.Clone
    /// `(*sum128a).Clone()` — an independent copy of this digest's state.
    /// Never fails, so the error is always nil, as in Go.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *d; return &r, nil
        let r = *self;
        return (Box::new(r), nil);
    }
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register the six FNV digests into the `hash` / `io` / `encoding`
/// registries. Idempotent; called from `goish::init()`.
pub fn register_fnv_impls() {
    crate::hash::__goish_register_Hash_impl::<sum32>();
    crate::hash::__goish_register_Cloner_impl::<sum32>();
    crate::io::__goish_register_Writer_impl::<sum32>();
    encoding::__goish_register_BinaryMarshaler_impl::<sum32>();
    encoding::__goish_register_BinaryAppender_impl::<sum32>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<sum32>();
    crate::hash::__goish_register_Hash_impl::<sum32a>();
    crate::hash::__goish_register_Cloner_impl::<sum32a>();
    crate::io::__goish_register_Writer_impl::<sum32a>();
    encoding::__goish_register_BinaryMarshaler_impl::<sum32a>();
    encoding::__goish_register_BinaryAppender_impl::<sum32a>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<sum32a>();
    crate::hash::__goish_register_Hash_impl::<sum64>();
    crate::hash::__goish_register_Cloner_impl::<sum64>();
    crate::io::__goish_register_Writer_impl::<sum64>();
    encoding::__goish_register_BinaryMarshaler_impl::<sum64>();
    encoding::__goish_register_BinaryAppender_impl::<sum64>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<sum64>();
    crate::hash::__goish_register_Hash_impl::<sum64a>();
    crate::hash::__goish_register_Cloner_impl::<sum64a>();
    crate::io::__goish_register_Writer_impl::<sum64a>();
    encoding::__goish_register_BinaryMarshaler_impl::<sum64a>();
    encoding::__goish_register_BinaryAppender_impl::<sum64a>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<sum64a>();
    crate::hash::__goish_register_Hash_impl::<sum128>();
    crate::hash::__goish_register_Cloner_impl::<sum128>();
    crate::io::__goish_register_Writer_impl::<sum128>();
    encoding::__goish_register_BinaryMarshaler_impl::<sum128>();
    encoding::__goish_register_BinaryAppender_impl::<sum128>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<sum128>();
    crate::hash::__goish_register_Hash_impl::<sum128a>();
    crate::hash::__goish_register_Cloner_impl::<sum128a>();
    crate::io::__goish_register_Writer_impl::<sum128a>();
    encoding::__goish_register_BinaryMarshaler_impl::<sum128a>();
    encoding::__goish_register_BinaryAppender_impl::<sum128a>();
    encoding::__goish_register_BinaryUnmarshaler_impl::<sum128a>();
}

// ─── hash / encoding interface impls ──────────────────────────────────
//
// Go's digests satisfy these structurally. goish's interfaces are
// nominal, so each impl is spelled out; the marshaling ones forward
// to the inherent methods above.

impl io::Writer for sum32 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:100-108 sum32.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: hash := *s
        let raw: &[byte] = &p;
        let mut h: uint32 = self.0;
        let mut i: usize = 0;
        // Go: for _, c := range data
        while i < raw.len() {
            // Go: hash *= prime32; hash ^= sum32(c)
            h = h.wrapping_mul(prime32);
            h ^= touint32(raw[i]);
            i += 1;
        }
        // Go: *s = hash
        self.0 = h;
        // Go: return len(data), nil
        let raw: &[byte] = &p;
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

impl Hash for sum32 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:180-183 sum32.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: v := uint32(*s); return byteorder.BEAppendUint32(in, v)
        return byteorder::BEAppendUint32(b, self.0);
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:88-88 sum32.Reset
    fn Reset(&mut self) {
        // Go: *s = offset32
        self.0 = offset32;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:166-166 sum32.Size
    fn Size(&self) -> int {
        return 4;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:173-173 sum32.BlockSize
    fn BlockSize(&self) -> int {
        return 1;
    }
}

impl Hash32 for sum32 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:95-95 sum32.Sum32
    fn Sum32(&self) -> uint32 {
        // Go: return uint32(*s)
        return self.0;
    }
}

impl Cloner for sum32 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:352-355 sum32.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return sum32::Clone(self);
    }
}

impl encoding::BinaryMarshaler for sum32 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:228-230 sum32.MarshalBinary
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return sum32::MarshalBinary(self);
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

impl encoding::BinaryAppender for sum32 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:222-226 sum32.AppendBinary
    fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        return sum32::AppendBinary(self, b);
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

impl encoding::BinaryUnmarshaler for sum32 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:284-293 sum32.UnmarshalBinary
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error {
        return sum32::UnmarshalBinary(self, data);
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

impl io::Writer for sum32a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:110-118 sum32a.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: hash := *s
        let raw: &[byte] = &p;
        let mut h: uint32 = self.0;
        let mut i: usize = 0;
        // Go: for _, c := range data
        while i < raw.len() {
            // Go: hash ^= sum32a(c); hash *= prime32
            h ^= touint32(raw[i]);
            h = h.wrapping_mul(prime32);
            i += 1;
        }
        // Go: *s = hash
        self.0 = h;
        // Go: return len(data), nil
        let raw: &[byte] = &p;
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

impl Hash for sum32a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:185-188 sum32a.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: v := uint32(*s); return byteorder.BEAppendUint32(in, v)
        return byteorder::BEAppendUint32(b, self.0);
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:89-89 sum32a.Reset
    fn Reset(&mut self) {
        // Go: *s = offset32
        self.0 = offset32;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:167-167 sum32a.Size
    fn Size(&self) -> int {
        return 4;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:174-174 sum32a.BlockSize
    fn BlockSize(&self) -> int {
        return 1;
    }
}

impl Hash32 for sum32a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:96-96 sum32a.Sum32
    fn Sum32(&self) -> uint32 {
        // Go: return uint32(*s)
        return self.0;
    }
}

impl Cloner for sum32a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:357-360 sum32a.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return sum32a::Clone(self);
    }
}

impl encoding::BinaryMarshaler for sum32a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:238-240 sum32a.MarshalBinary
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return sum32a::MarshalBinary(self);
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

impl encoding::BinaryAppender for sum32a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:232-236 sum32a.AppendBinary
    fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        return sum32a::AppendBinary(self, b);
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

impl encoding::BinaryUnmarshaler for sum32a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:295-304 sum32a.UnmarshalBinary
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error {
        return sum32a::UnmarshalBinary(self, data);
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

impl io::Writer for sum64 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:120-128 sum64.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: hash := *s
        let raw: &[byte] = &p;
        let mut h: uint64 = self.0;
        let mut i: usize = 0;
        // Go: for _, c := range data
        while i < raw.len() {
            // Go: hash *= prime64; hash ^= sum64(c)
            h = h.wrapping_mul(prime64);
            h ^= touint64(raw[i]);
            i += 1;
        }
        // Go: *s = hash
        self.0 = h;
        // Go: return len(data), nil
        let raw: &[byte] = &p;
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

impl Hash for sum64 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:190-193 sum64.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: v := uint64(*s); return byteorder.BEAppendUint64(in, v)
        return byteorder::BEAppendUint64(b, self.0);
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:90-90 sum64.Reset
    fn Reset(&mut self) {
        // Go: *s = offset64
        self.0 = offset64;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:168-168 sum64.Size
    fn Size(&self) -> int {
        return 8;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:175-175 sum64.BlockSize
    fn BlockSize(&self) -> int {
        return 1;
    }
}

impl Hash64 for sum64 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:97-97 sum64.Sum64
    fn Sum64(&self) -> uint64 {
        // Go: return uint64(*s)
        return self.0;
    }
}

impl Cloner for sum64 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:362-365 sum64.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return sum64::Clone(self);
    }
}

impl encoding::BinaryMarshaler for sum64 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:248-250 sum64.MarshalBinary
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return sum64::MarshalBinary(self);
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

impl encoding::BinaryAppender for sum64 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:242-246 sum64.AppendBinary
    fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        return sum64::AppendBinary(self, b);
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

impl encoding::BinaryUnmarshaler for sum64 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:306-315 sum64.UnmarshalBinary
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error {
        return sum64::UnmarshalBinary(self, data);
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

impl io::Writer for sum64a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:130-138 sum64a.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: hash := *s
        let raw: &[byte] = &p;
        let mut h: uint64 = self.0;
        let mut i: usize = 0;
        // Go: for _, c := range data
        while i < raw.len() {
            // Go: hash ^= sum64a(c); hash *= prime64
            h ^= touint64(raw[i]);
            h = h.wrapping_mul(prime64);
            i += 1;
        }
        // Go: *s = hash
        self.0 = h;
        // Go: return len(data), nil
        let raw: &[byte] = &p;
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

impl Hash for sum64a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:195-198 sum64a.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: v := uint64(*s); return byteorder.BEAppendUint64(in, v)
        return byteorder::BEAppendUint64(b, self.0);
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:91-91 sum64a.Reset
    fn Reset(&mut self) {
        // Go: *s = offset64
        self.0 = offset64;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:169-169 sum64a.Size
    fn Size(&self) -> int {
        return 8;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:176-176 sum64a.BlockSize
    fn BlockSize(&self) -> int {
        return 1;
    }
}

impl Hash64 for sum64a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:98-98 sum64a.Sum64
    fn Sum64(&self) -> uint64 {
        // Go: return uint64(*s)
        return self.0;
    }
}

impl Cloner for sum64a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:367-370 sum64a.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return sum64a::Clone(self);
    }
}

impl encoding::BinaryMarshaler for sum64a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:258-260 sum64a.MarshalBinary
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return sum64a::MarshalBinary(self);
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

impl encoding::BinaryAppender for sum64a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:252-256 sum64a.AppendBinary
    fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        return sum64a::AppendBinary(self, b);
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

impl encoding::BinaryUnmarshaler for sum64a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:317-326 sum64a.UnmarshalBinary
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error {
        return sum64a::UnmarshalBinary(self, data);
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

impl io::Writer for sum128 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:140-151 sum128.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let raw: &[byte] = &p;
        let mut i: usize = 0;
        // Go: for _, c := range data
        while i < raw.len() {
            // Go: s0, s1 := bits.Mul64(prime128Lower, s[1])
            let (s0, s1) = bits::Mul64(prime128Lower, self.0[1]);
            // Go: s0 += s[1]<<prime128Shift + prime128Lower*s[0]
            // Go's `<<` binds tighter than `+`, Rust's binds looser,
            // so the shifted term is parenthesized here.
            let s0 = s0
                .wrapping_add(self.0[1] << prime128Shift)
                .wrapping_add(prime128Lower.wrapping_mul(self.0[0]));
            // Go: s[1] = s1; s[0] = s0
            self.0[1] = s1;
            self.0[0] = s0;
            // Go: s[1] ^= uint64(c)
            self.0[1] ^= touint64(raw[i]);
            i += 1;
        }
        // Go: return len(data), nil
        let raw: &[byte] = &p;
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

impl Hash for sum128 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:200-203 sum128.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: ret := byteorder.BEAppendUint64(in, s[0])
        let ret = byteorder::BEAppendUint64(b, self.0[0]);
        // Go: return byteorder.BEAppendUint64(ret, s[1])
        return byteorder::BEAppendUint64(ret, self.0[1]);
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:92-92 sum128.Reset
    fn Reset(&mut self) {
        // Go: s[0] = offset128Higher; s[1] = offset128Lower
        self.0[0] = offset128Higher;
        self.0[1] = offset128Lower;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:170-170 sum128.Size
    fn Size(&self) -> int {
        return 16;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:177-177 sum128.BlockSize
    fn BlockSize(&self) -> int {
        return 1;
    }
}

impl Cloner for sum128 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:372-375 sum128.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return sum128::Clone(self);
    }
}

impl encoding::BinaryMarshaler for sum128 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:269-271 sum128.MarshalBinary
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return sum128::MarshalBinary(self);
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

impl encoding::BinaryAppender for sum128 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:262-267 sum128.AppendBinary
    fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        return sum128::AppendBinary(self, b);
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

impl encoding::BinaryUnmarshaler for sum128 {
    // go: sdk 1.25.5 hash/fnv/fnv.go:328-338 sum128.UnmarshalBinary
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error {
        return sum128::UnmarshalBinary(self, data);
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

impl io::Writer for sum128a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:153-164 sum128a.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let raw: &[byte] = &p;
        let mut i: usize = 0;
        // Go: for _, c := range data
        while i < raw.len() {
            // Go: s[1] ^= uint64(c)
            self.0[1] ^= touint64(raw[i]);
            // Go: s0, s1 := bits.Mul64(prime128Lower, s[1])
            let (s0, s1) = bits::Mul64(prime128Lower, self.0[1]);
            // Go: s0 += s[1]<<prime128Shift + prime128Lower*s[0]
            // Go's `<<` binds tighter than `+`, Rust's binds looser,
            // so the shifted term is parenthesized here.
            let s0 = s0
                .wrapping_add(self.0[1] << prime128Shift)
                .wrapping_add(prime128Lower.wrapping_mul(self.0[0]));
            // Go: s[1] = s1; s[0] = s0
            self.0[1] = s1;
            self.0[0] = s0;
            i += 1;
        }
        // Go: return len(data), nil
        let raw: &[byte] = &p;
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

impl Hash for sum128a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:205-208 sum128a.Sum
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: ret := byteorder.BEAppendUint64(in, s[0])
        let ret = byteorder::BEAppendUint64(b, self.0[0]);
        // Go: return byteorder.BEAppendUint64(ret, s[1])
        return byteorder::BEAppendUint64(ret, self.0[1]);
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:93-93 sum128a.Reset
    fn Reset(&mut self) {
        // Go: s[0] = offset128Higher; s[1] = offset128Lower
        self.0[0] = offset128Higher;
        self.0[1] = offset128Lower;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:171-171 sum128a.Size
    fn Size(&self) -> int {
        return 16;
    }
    // go: sdk 1.25.5 hash/fnv/fnv.go:178-178 sum128a.BlockSize
    fn BlockSize(&self) -> int {
        return 1;
    }
}

impl Cloner for sum128a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:377-380 sum128a.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return sum128a::Clone(self);
    }
}

impl encoding::BinaryMarshaler for sum128a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:280-282 sum128a.MarshalBinary
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return sum128a::MarshalBinary(self);
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

impl encoding::BinaryAppender for sum128a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:273-278 sum128a.AppendBinary
    fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        return sum128a::AppendBinary(self, b);
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

impl encoding::BinaryUnmarshaler for sum128a {
    // go: sdk 1.25.5 hash/fnv/fnv.go:340-350 sum128a.UnmarshalBinary
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error {
        return sum128a::UnmarshalBinary(self, data);
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
