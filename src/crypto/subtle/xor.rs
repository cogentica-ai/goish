// go: file crypto/subtle/xor.go decls: XORBytes

#![allow(non_snake_case)]

use crate::crypto::internal::fips140::subtle;
use crate::goslice::slice;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/subtle/xor.go:17-19 XORBytes
/// `XORBytes` sets `dst[i] = x[i] ^ y[i]` for all `i < n = min(len(x),
/// len(y))`, returning `n`. Panics if `dst` is shorter than `n`.
pub fn XORBytes(dst: &mut slice<byte>, x: &slice<byte>, y: &slice<byte>) -> int {
    // Go: return subtle.XORBytes(dst, x, y)
    return subtle::XORBytes(dst, x, y);
}
