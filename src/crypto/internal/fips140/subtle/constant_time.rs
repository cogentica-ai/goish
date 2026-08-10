// go: file crypto/internal/fips140/subtle/constant_time.go decls: ConstantTimeCompare, ConstantTimeLessOrEqBytes, ConstantTimeSelect, ConstantTimeByteEq, ConstantTimeEq, ConstantTimeCopy, ConstantTimeLessOrEq

#![allow(non_snake_case)]

use crate::convert::{byte as tobyte, int as toint, int32, uint32, uint64};
use crate::goslice::slice;
use crate::math::bits;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/internal/fips140/subtle/constant_time.go:16-28 ConstantTimeCompare
/// Return 1 if `x` and `y` have equal contents, 0 otherwise. Time taken is a
/// function of length only. Mismatched lengths return 0 immediately.
pub fn ConstantTimeCompare(x: &slice<byte>, y: &slice<byte>) -> int {
    // Go: if len(x) != len(y) { return 0 }
    if x.len() != y.len() {
        return 0;
    }
    // Go: var v byte
    let mut v: byte = 0;
    // Go: for i := 0; i < len(x); i++ { v |= x[i] ^ y[i] }
    let n = x.len();
    for i in 0..n {
        v |= x[toint(i)] ^ y[toint(i)];
    }
    // Go: return ConstantTimeByteEq(v, 0)
    return ConstantTimeByteEq(v, 0);
}

// go: sdk 1.25.5 crypto/internal/fips140/subtle/constant_time.go:34-59 ConstantTimeLessOrEqBytes
/// Return 1 if `x <= y`, 0 otherwise. Big-endian (lexicographical) compare,
/// constant-time in the contents. Mismatched lengths return 0.
pub fn ConstantTimeLessOrEqBytes(x: &slice<byte>, y: &slice<byte>) -> int {
    // Go: if len(x) != len(y) { return 0 }
    if x.len() != y.len() {
        return 0;
    }
    // Go: constant-time subtraction chain y - x; no borrow at the end ⇒ x <= y.
    let mut b: u64 = 0;
    let mut len = x.len();
    let xb_raw: &[byte] = x;
    let yb_raw: &[byte] = y;
    // Go: for len(x) > 8 { ... }
    while len > 8 {
        let off = len - 8;
        let x0 = read_be_u64(&xb_raw[off..len]);
        let y0 = read_be_u64(&yb_raw[off..len]);
        let (_d, nb) = bits::Sub64(y0, x0, b);
        b = nb;
        len -= 8;
    }
    // Go: if len(x) > 0 { ... zero-padded final block ... }
    if len > 0 {
        let mut xb = [0u8; 8];
        let mut yb = [0u8; 8];
        let pad = 8 - len;
        xb[pad..].copy_from_slice(&xb_raw[..len]);
        yb[pad..].copy_from_slice(&yb_raw[..len]);
        let x0 = u64::from_be_bytes(xb);
        let y0 = u64::from_be_bytes(yb);
        let (_d, nb) = bits::Sub64(y0, x0, b);
        b = nb;
    }
    // Go: return int(b ^ 1)
    return toint(b ^ 1);
}

// go: sdk 1.25.5 crypto/internal/fips140/subtle/constant_time.go:63 ConstantTimeSelect
/// Return `x` if `v == 1` and `y` if `v == 0`. Undefined for other `v`.
pub fn ConstantTimeSelect(v: int, x: int, y: int) -> int {
    // Go: return ^(v-1)&x | (v-1)&y
    return !(v - 1) & x | (v - 1) & y;
}

// go: sdk 1.25.5 crypto/internal/fips140/subtle/constant_time.go:66-68 ConstantTimeByteEq
/// Return 1 if `x == y`, 0 otherwise.
pub fn ConstantTimeByteEq(x: u8, y: u8) -> int {
    // Go: return int((uint32(x^y) - 1) >> 31)
    return toint(uint32(x ^ y).wrapping_sub(1) >> 31);
}

// go: sdk 1.25.5 crypto/internal/fips140/subtle/constant_time.go:71-73 ConstantTimeEq
/// Return 1 if `x == y`, 0 otherwise.
pub fn ConstantTimeEq(x: i32, y: i32) -> int {
    // Go: return int((uint64(uint32(x^y)) - 1) >> 63)
    return toint(uint64(uint32(x ^ y)).wrapping_sub(1) >> 63);
}

// go: sdk 1.25.5 crypto/internal/fips140/subtle/constant_time.go:78-88 ConstantTimeCopy
/// Copy `y` into `x` if `v == 1`; leave `x` unchanged if `v == 0`.
/// Panics on length mismatch. Undefined for other `v`.
pub fn ConstantTimeCopy(v: int, x: &mut slice<byte>, y: &slice<byte>) {
    // Go: if len(x) != len(y) { panic("subtle: slices have different lengths") }
    if x.len() != y.len() {
        panic!("subtle: slices have different lengths");
    }
    // Go: xmask := byte(v - 1); ymask := byte(^(v - 1))
    let xmask: byte = tobyte(v - 1);
    let ymask: byte = tobyte(!(v - 1));
    // Go: for i := 0; i < len(x); i++ { x[i] = x[i]&xmask | y[i]&ymask }
    let n = x.len();
    for i in 0..n {
        let xi = x[toint(i)];
        x[toint(i)] = xi & xmask | y[toint(i)] & ymask;
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/subtle/constant_time.go:92-96 ConstantTimeLessOrEq
/// Return 1 if `x <= y`, 0 otherwise. Undefined if `x` or `y` is negative
/// or greater than 2**31 - 1.
pub fn ConstantTimeLessOrEq(x: int, y: int) -> int {
    // Go: x32 := int32(x); y32 := int32(y)
    let x32 = int32(x);
    let y32 = int32(y);
    // Go: return int(((x32 - y32 - 1) >> 31) & 1)
    return toint((x32.wrapping_sub(y32).wrapping_sub(1) >> 31) & 1);
}

// go: none — byteorder.BEUint64 inlined; goish has no crypto/internal/
// fips140deps/byteorder package yet (Wave C).
#[inline]
fn read_be_u64(b: &[byte]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&b[..8]);
    return u64::from_be_bytes(buf);
}
