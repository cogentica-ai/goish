// go: file encoding/asn1/marshal.go decls: base128IntLength, appendBase128Int, appendLength, lengthLength, appendTagAndLength
//
// The DER *encoding* side of encoding/asn1. goish's asn1 has been
// parse-only; this is the first slice of the other half.
//
// Scope, stated plainly: these are the five non-reflective primitives —
// tag/length and base-128 integer encoding. Everything above them in Go's
// marshal.go (the `encoder` interface and its dozen implementations,
// `makeField`, `makeBody`, and `Marshal` itself) is reflection-driven and
// is NOT here. This file is the foundation those need, not a usable
// `Marshal`.
//
// Why it lands separately: `crypto/x509/pkix` — and behind it
// `crypto/x509` and `crypto/tls`, ~415 functions — is gated on
// `asn1.Marshal`. Every byte those emit is laid down by the functions
// below, so getting them checked against Go first means the reflective
// layer can be built on something already known to be right rather than
// debugged as one piece.
//
// Deviations from marshal[go] @ Go 1.25.5:
//
//   * Go's `dst = append(dst, …)` grows and returns the slice. goish's
//     `slice<T>` has no in-place append, so each function takes and
//     returns `slice<byte>` — the same signature Go has — with a `Vec`
//     scratch buffer inside, converted at the return site (AGENTS.md §3).
//   * Go's `tagAndLength` is unexported; goish's is `TagAndLength`, public
//     because ParseTagAndLength already returns it.

#![allow(non_snake_case)]

extern crate alloc;

use super::TagAndLength;
use crate::goslice::slice;
use crate::types::{byte, int};
use crate::{byte as tobyte, int64, uint};
use alloc::vec::Vec;

// go: sdk 1.25.5 encoding/asn1/marshal.go:166-177 base128IntLength
/// The number of bytes `n` occupies in base-128 (7 bits per byte) form.
pub fn base128IntLength(n: int64) -> int {
    if n == 0 {
        return 1;
    }

    let mut l: int = 0;
    let mut i = n;
    while i > 0 {
        l += 1;
        i >>= 7;
    }

    return l;
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:179-193 appendBase128Int
/// Append `n` to `dst` in base-128 form, high bit set on every byte but
/// the last. Used for OID components and for tag numbers >= 31.
pub fn appendBase128Int(dst: slice<byte>, n: int64) -> slice<byte> {
    let l = base128IntLength(n);
    let mut out: Vec<byte> = dst.__into_vec();

    let mut i = l - 1;
    while i >= 0 {
        let mut o = tobyte(n >> uint(i * 7));
        o &= 0x7f;
        if i != 0 {
            o |= 0x80;
        }
        out.push(o);
        i -= 1;
    }

    return slice::__from_vec(out);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:239-246 lengthLength
/// The number of bytes the long-form length encoding of `i` occupies.
pub fn lengthLength(i: int) -> int {
    let mut numBytes: int = 1;
    let mut i = i;
    while i > 255 {
        numBytes += 1;
        i >>= 8;
    }
    return numBytes;
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:229-237 appendLength
/// Append `i` big-endian in exactly `lengthLength(i)` bytes.
pub fn appendLength(dst: slice<byte>, i: int) -> slice<byte> {
    let mut n = lengthLength(i);
    let mut out: Vec<byte> = dst.__into_vec();

    while n > 0 {
        out.push(tobyte(i >> uint((n - 1) * 8)));
        n -= 1;
    }

    return slice::__from_vec(out);
}

// go: sdk 1.25.5 encoding/asn1/marshal.go:248-271 appendTagAndLength
/// Append the identifier and length octets described by `t`.
pub fn appendTagAndLength(dst: slice<byte>, t: &TagAndLength) -> slice<byte> {
    let mut b: byte = tobyte(t.class) << 6;
    if t.isCompound {
        b |= 0x20;
    }
    let mut dst = dst;
    if t.tag >= 31 {
        b |= 0x1f;
        dst = push(dst, b);
        dst = appendBase128Int(dst, int64(t.tag));
    } else {
        b |= tobyte(t.tag);
        dst = push(dst, b);
    }

    if t.length >= 128 {
        let l = lengthLength(t.length);
        dst = push(dst, 0x80 | tobyte(l));
        dst = appendLength(dst, t.length);
    } else {
        dst = push(dst, tobyte(t.length));
    }

    return dst;
}

// go: none — goish idiom: Go writes `dst = append(dst, b)`; `slice<T>` has
// no in-place append, so the one-byte case gets a name.
fn push(dst: slice<byte>, b: byte) -> slice<byte> {
    let mut v: Vec<byte> = dst.__into_vec();
    v.push(b);
    return slice::__from_vec(v);
}
