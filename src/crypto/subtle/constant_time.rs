// go: file crypto/subtle/constant_time.go decls: ConstantTimeCompare, ConstantTimeSelect, ConstantTimeByteEq, ConstantTimeEq, ConstantTimeCopy, ConstantTimeLessOrEq
//
// Go 1.25 made crypto/subtle a thin re-export of the FIPS 140-3 module's
// implementation; each function here delegates verbatim, exactly as the
// Go file does.

#![allow(non_snake_case)]

use crate::crypto::internal::fips140::subtle;
use crate::goslice::slice;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/subtle/constant_time.go:15-17 ConstantTimeCompare
/// Return 1 if `x` and `y` have equal contents, 0 otherwise. Time taken is a
/// function of length only. Mismatched lengths return 0 immediately.
pub fn ConstantTimeCompare(x: &slice<byte>, y: &slice<byte>) -> int {
    // Go: return subtle.ConstantTimeCompare(x, y)
    return subtle::ConstantTimeCompare(x, y);
}

// go: sdk 1.25.5 crypto/subtle/constant_time.go:21-23 ConstantTimeSelect
/// Return `x` if `v == 1` and `y` if `v == 0`. Undefined for other `v`.
pub fn ConstantTimeSelect(v: int, x: int, y: int) -> int {
    // Go: return subtle.ConstantTimeSelect(v, x, y)
    return subtle::ConstantTimeSelect(v, x, y);
}

// go: sdk 1.25.5 crypto/subtle/constant_time.go:26-28 ConstantTimeByteEq
/// Return 1 if `x == y`, 0 otherwise.
pub fn ConstantTimeByteEq(x: u8, y: u8) -> int {
    // Go: return subtle.ConstantTimeByteEq(x, y)
    return subtle::ConstantTimeByteEq(x, y);
}

// go: sdk 1.25.5 crypto/subtle/constant_time.go:31-33 ConstantTimeEq
/// Return 1 if `x == y`, 0 otherwise.
pub fn ConstantTimeEq(x: i32, y: i32) -> int {
    // Go: return subtle.ConstantTimeEq(x, y)
    return subtle::ConstantTimeEq(x, y);
}

// go: sdk 1.25.5 crypto/subtle/constant_time.go:38-40 ConstantTimeCopy
/// Copy `y` into `x` if `v == 1`; leave `x` unchanged if `v == 0`.
/// Panics on length mismatch. Undefined for other `v`.
pub fn ConstantTimeCopy(v: int, x: &mut slice<byte>, y: &slice<byte>) {
    // Go: subtle.ConstantTimeCopy(v, x, y)
    subtle::ConstantTimeCopy(v, x, y);
}

// go: sdk 1.25.5 crypto/subtle/constant_time.go:44-46 ConstantTimeLessOrEq
/// Return 1 if `x <= y`, 0 otherwise. Undefined if `x` or `y` is negative
/// or greater than 2**31 - 1.
pub fn ConstantTimeLessOrEq(x: int, y: int) -> int {
    // Go: return subtle.ConstantTimeLessOrEq(x, y)
    return subtle::ConstantTimeLessOrEq(x, y);
}
