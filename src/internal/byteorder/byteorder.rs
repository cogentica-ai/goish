// go: file internal/byteorder/byteorder.go decls: LEUint16, LEPutUint16, LEAppendUint16, LEUint32, LEPutUint32, LEAppendUint32, LEUint64, LEPutUint64, LEAppendUint64, BEUint16, BEPutUint16, BEAppendUint16, BEUint32, BEPutUint32, BEAppendUint32, BEUint64, BEPutUint64, BEAppendUint64
//
// internal/byteorder — decode and encode little- and big-endian integer
// types from/to byte slices.
//
// Go writes each shift/mask by hand and relies on the compiler to fuse
// them into a single `MOVBE`/`BSWAP`; goish reaches for the equivalent
// `to_be_bytes` / `from_be_bytes` intrinsics, which lower to the same
// instructions without the `as byte` casts goish bans (AGENTS.md §2a).
// The bounds-check hints Go writes as `_ = b[n]` are the slicing itself
// here — `b[..N]` panics identically on a short slice.
//
// Signatures take `slice<byte>` per AGENTS.md §3; the `*Put*` forms take
// `&mut slice<byte>` because Go writes through the caller's slice.

#![allow(non_snake_case)]

use crate::goslice::slice;
use crate::types::{byte, uint16, uint32, uint64};

extern crate alloc;
use alloc::vec::Vec;

// ─── little endian ────────────────────────────────────────────────────

// go: sdk 1.25.5 internal/byteorder/byteorder.go:9-12 LEUint16
/// `byteorder.LEUint16(b)` — decode `b[0:2]` little-endian.
pub fn LEUint16(b: slice<byte>) -> uint16 {
    let raw: &[byte] = &b;
    return uint16::from_le_bytes([raw[0], raw[1]]);
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:14-18 LEPutUint16
/// `byteorder.LEPutUint16(b, v)` — encode `v` little-endian into `b[0:2]`.
pub fn LEPutUint16(b: &mut slice<byte>, v: uint16) {
    let raw: &mut [byte] = b;
    raw[..2].copy_from_slice(&v.to_le_bytes());
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:20-25 LEAppendUint16
/// `byteorder.LEAppendUint16(b, v)` — append `v` little-endian to `b`.
pub fn LEAppendUint16(b: slice<byte>, v: uint16) -> slice<byte> {
    let mut out: Vec<byte> = b.__into_vec();
    out.extend_from_slice(&v.to_le_bytes());
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:27-30 LEUint32
/// `byteorder.LEUint32(b)` — decode `b[0:4]` little-endian.
pub fn LEUint32(b: slice<byte>) -> uint32 {
    let raw: &[byte] = &b;
    return uint32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:32-38 LEPutUint32
/// `byteorder.LEPutUint32(b, v)` — encode `v` little-endian into `b[0:4]`.
pub fn LEPutUint32(b: &mut slice<byte>, v: uint32) {
    let raw: &mut [byte] = b;
    raw[..4].copy_from_slice(&v.to_le_bytes());
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:40-47 LEAppendUint32
/// `byteorder.LEAppendUint32(b, v)` — append `v` little-endian to `b`.
pub fn LEAppendUint32(b: slice<byte>, v: uint32) -> slice<byte> {
    let mut out: Vec<byte> = b.__into_vec();
    out.extend_from_slice(&v.to_le_bytes());
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:49-53 LEUint64
/// `byteorder.LEUint64(b)` — decode `b[0:8]` little-endian.
pub fn LEUint64(b: slice<byte>) -> uint64 {
    let raw: &[byte] = &b;
    return uint64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]);
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:55-65 LEPutUint64
/// `byteorder.LEPutUint64(b, v)` — encode `v` little-endian into `b[0:8]`.
pub fn LEPutUint64(b: &mut slice<byte>, v: uint64) {
    let raw: &mut [byte] = b;
    raw[..8].copy_from_slice(&v.to_le_bytes());
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:67-78 LEAppendUint64
/// `byteorder.LEAppendUint64(b, v)` — append `v` little-endian to `b`.
pub fn LEAppendUint64(b: slice<byte>, v: uint64) -> slice<byte> {
    let mut out: Vec<byte> = b.__into_vec();
    out.extend_from_slice(&v.to_le_bytes());
    return slice::__from_vec(out);
}

// ─── big endian ───────────────────────────────────────────────────────

// go: sdk 1.25.5 internal/byteorder/byteorder.go:80-83 BEUint16
/// `byteorder.BEUint16(b)` — decode `b[0:2]` big-endian.
pub fn BEUint16(b: slice<byte>) -> uint16 {
    let raw: &[byte] = &b;
    return uint16::from_be_bytes([raw[0], raw[1]]);
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:85-89 BEPutUint16
/// `byteorder.BEPutUint16(b, v)` — encode `v` big-endian into `b[0:2]`.
pub fn BEPutUint16(b: &mut slice<byte>, v: uint16) {
    let raw: &mut [byte] = b;
    raw[..2].copy_from_slice(&v.to_be_bytes());
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:91-96 BEAppendUint16
/// `byteorder.BEAppendUint16(b, v)` — append `v` big-endian to `b`.
pub fn BEAppendUint16(b: slice<byte>, v: uint16) -> slice<byte> {
    let mut out: Vec<byte> = b.__into_vec();
    out.extend_from_slice(&v.to_be_bytes());
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:98-101 BEUint32
/// `byteorder.BEUint32(b)` — decode `b[0:4]` big-endian.
pub fn BEUint32(b: slice<byte>) -> uint32 {
    let raw: &[byte] = &b;
    return uint32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:103-109 BEPutUint32
/// `byteorder.BEPutUint32(b, v)` — encode `v` big-endian into `b[0:4]`.
pub fn BEPutUint32(b: &mut slice<byte>, v: uint32) {
    let raw: &mut [byte] = b;
    raw[..4].copy_from_slice(&v.to_be_bytes());
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:111-118 BEAppendUint32
/// `byteorder.BEAppendUint32(b, v)` — append `v` big-endian to `b`.
pub fn BEAppendUint32(b: slice<byte>, v: uint32) -> slice<byte> {
    let mut out: Vec<byte> = b.__into_vec();
    out.extend_from_slice(&v.to_be_bytes());
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:120-124 BEUint64
/// `byteorder.BEUint64(b)` — decode `b[0:8]` big-endian.
pub fn BEUint64(b: slice<byte>) -> uint64 {
    let raw: &[byte] = &b;
    return uint64::from_be_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]);
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:126-136 BEPutUint64
/// `byteorder.BEPutUint64(b, v)` — encode `v` big-endian into `b[0:8]`.
pub fn BEPutUint64(b: &mut slice<byte>, v: uint64) {
    let raw: &mut [byte] = b;
    raw[..8].copy_from_slice(&v.to_be_bytes());
}

// go: sdk 1.25.5 internal/byteorder/byteorder.go:138-149 BEAppendUint64
/// `byteorder.BEAppendUint64(b, v)` — append `v` big-endian to `b`.
pub fn BEAppendUint64(b: slice<byte>, v: uint64) -> slice<byte> {
    let mut out: Vec<byte> = b.__into_vec();
    out.extend_from_slice(&v.to_be_bytes());
    return slice::__from_vec(out);
}
