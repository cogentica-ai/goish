// crypto/subtle — constant-time helpers for cryptographic code.
//
// Reference: /share/go/src/crypto/subtle/constant_time.go +
//            /share/go/src/crypto/internal/fips140/subtle/constant_time.go +
//            /share/go/src/crypto/subtle/xor.go
//
// The upstream `crypto/subtle` package re-exports thin wrappers around
// `crypto/internal/fips140/subtle`. Goish does not have FIPS internals,
// so we inline the implementations here verbatim.
//
// Slim deviations (documented per function):
//   * `XORBytes` does not support `dst` aliasing `x` or `y` because Rust's
//     borrow checker forbids passing `&mut` and `&` to the same backing
//     storage. Go callers that explicitly XOR-into-self will need to use
//     a temporary buffer. (Common AEAD/HMAC usage doesn't overlap.)

#![allow(non_snake_case)]

extern crate alloc;

use crate::goslice::slice;
use crate::math::bits;
use crate::types::{byte, int};

// ─── ConstantTimeCompare (constant_time.go:15) ───────────────────────────────

/// `subtle.ConstantTimeCompare(x, y)` — return 1 if `x` and `y` have equal
/// contents and 0 otherwise. The time taken is a function of the length of
/// the slices and is independent of the contents. If the lengths of `x` and
/// `y` do not match, returns 0 immediately.
pub fn ConstantTimeCompare(x: &slice<byte>, y: &slice<byte>) -> int {
    // Go: constant_time.go:17 — if len(x) != len(y) { return 0 }
    if x.len() != y.len() {
        return 0;
    }

    // Go: constant_time.go:21 — var v byte
    let mut v: byte = 0;

    // Go: constant_time.go:23 — for i := 0; i < len(x); i++ { v |= x[i] ^ y[i] }
    let n = x.len();
    for i in 0..n {
        v |= x[i as int] ^ y[i as int];
    }

    // Go: constant_time.go:27 — return ConstantTimeByteEq(v, 0)
    ConstantTimeByteEq(v, 0)
}

// ─── ConstantTimeLessOrEqBytes (constant_time.go:34) ─────────────────────────

/// `subtle.ConstantTimeLessOrEqBytes(x, y)` — return 1 if `x <= y` and 0
/// otherwise. Big-endian / lexicographical comparison; constant-time by
/// length. If the lengths differ, returns 0.
pub fn ConstantTimeLessOrEqBytes(x: &slice<byte>, y: &slice<byte>) -> int {
    // Go: constant_time.go:35 — if len(x) != len(y) { return 0 }
    if x.len() != y.len() {
        return 0;
    }

    // Go: constant_time.go:41 — Do a constant-time subtraction chain y - x.
    // If there is no borrow at the end, then x <= y.
    let mut b: u64 = 0;
    let mut len = x.len();

    // Go: constant_time.go:42 — for len(x) > 8 { ... }
    let xb_raw: &[byte] = x;
    let yb_raw: &[byte] = y;
    while len > 8 {
        let off = len - 8;
        let x0 = read_be_u64(&xb_raw[off..len]);
        let y0 = read_be_u64(&yb_raw[off..len]);
        let (_d, nb) = bits::Sub64(y0, x0, b);
        b = nb;
        len -= 8;
    }

    // Go: constant_time.go:49 — final partial block, padded.
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

    // Go: constant_time.go:58 — return int(b ^ 1)
    (b ^ 1) as int
}

// ─── ConstantTimeSelect (constant_time.go:63) ────────────────────────────────

/// `subtle.ConstantTimeSelect(v, x, y)` — return `x` if `v == 1` and `y` if
/// `v == 0`. Behavior is undefined for any other `v`.
pub fn ConstantTimeSelect(v: int, x: int, y: int) -> int {
    // Go: constant_time.go:63 — return ^(v-1)&x | (v-1)&y
    !(v - 1) & x | (v - 1) & y
}

// ─── ConstantTimeByteEq (constant_time.go:66) ────────────────────────────────

/// `subtle.ConstantTimeByteEq(x, y)` — return 1 if `x == y` and 0 otherwise.
pub fn ConstantTimeByteEq(x: u8, y: u8) -> int {
    // Go: constant_time.go:67 — return int((uint32(x^y) - 1) >> 31)
    (((x ^ y) as u32).wrapping_sub(1) >> 31) as int
}

// ─── ConstantTimeEq (constant_time.go:71) ────────────────────────────────────

/// `subtle.ConstantTimeEq(x, y)` — return 1 if `x == y` and 0 otherwise.
pub fn ConstantTimeEq(x: i32, y: i32) -> int {
    // Go: constant_time.go:72 — return int((uint64(uint32(x^y)) - 1) >> 63)
    (((x ^ y) as u32 as u64).wrapping_sub(1) >> 63) as int
}

// ─── ConstantTimeCopy (constant_time.go:78) ──────────────────────────────────

/// `subtle.ConstantTimeCopy(v, x, y)` — copy `y` into `x` if `v == 1`. If
/// `v == 0`, `x` is left unchanged. Panics on length mismatch.
pub fn ConstantTimeCopy(v: int, x: &mut slice<byte>, y: &slice<byte>) {
    // Go: constant_time.go:79 — if len(x) != len(y) { panic(…) }
    if x.len() != y.len() {
        panic!("subtle: slices have different lengths");
    }

    // Go: constant_time.go:83-84 — xmask = byte(v - 1); ymask = byte(^(v - 1))
    let xmask: byte = (v - 1) as byte;
    let ymask: byte = !(v - 1) as byte;

    // Go: constant_time.go:85 — for i := 0; i < len(x); i++ { x[i] = x[i]&xmask | y[i]&ymask }
    let n = x.len();
    for i in 0..n {
        let xi = x[i as int];
        x[i as int] = xi & xmask | y[i as int] & ymask;
    }
}

// ─── ConstantTimeLessOrEq (constant_time.go:92) ──────────────────────────────

/// `subtle.ConstantTimeLessOrEq(x, y)` — return 1 if `x <= y` and 0
/// otherwise. Behavior is undefined if `x` or `y` are negative or
/// > 2**31 - 1.
pub fn ConstantTimeLessOrEq(x: int, y: int) -> int {
    // Go: constant_time.go:93 — x32 := int32(x); y32 := int32(y)
    let x32 = x as i32;
    let y32 = y as i32;
    // Go: constant_time.go:95 — return int(((x32 - y32 - 1) >> 31) & 1)
    ((x32.wrapping_sub(y32).wrapping_sub(1) >> 31) & 1) as int
}

// ─── XORBytes (xor.go:17 + fips140/subtle/xor_generic.go) ───────────────────

/// `subtle.XORBytes(dst, x, y)` — set `dst[i] = x[i] ^ y[i]` for all
/// `i < n = min(len(x), len(y))`, returning `n`. Panics if `len(dst) < n`.
///
/// Slim: Go's API accepts `dst == x` or `dst == y` (exact aliasing) but
/// nothing else. Rust's borrow rules forbid `&mut` aliasing with `&`, so
/// callers that need XOR-into-self must use a temporary. For HMAC-style
/// pad XOR (the prototypical caller), separate buffers are the norm.
pub fn XORBytes(dst: &mut slice<byte>, x: &slice<byte>, y: &slice<byte>) -> int {
    let n = if x.len() < y.len() { x.len() } else { y.len() };
    if dst.len() < n {
        panic!("subtle.XORBytes: dst too short");
    }
    for i in 0..n {
        dst[i as int] = x[i as int] ^ y[i as int];
    }
    n as int
}

// ─── helpers ─────────────────────────────────────────────────────────────────

#[inline]
fn read_be_u64(b: &[byte]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&b[..8]);
    u64::from_be_bytes(buf)
}
