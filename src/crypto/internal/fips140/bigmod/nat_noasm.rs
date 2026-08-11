// go: file crypto/internal/fips140/bigmod/nat_noasm.go decls: addMulVVW1024, addMulVVW1536, addMulVVW2048
//
// The purego side of Go's build-tag pair — nat_asm.go declares the same
// three symbols as assembly. goish has no assembly, so this is the only
// side it can implement; see nistec for the same decision.
//
// Deviation: Go's signature is `(z, x *uint, y uint)` and it recovers the
// length with `unsafe.Slice(z, 1024/_W)`. The caller always has a slice
// of exactly that length already, so goish takes slices and asserts the
// length instead of reconstructing one from a raw pointer.

#![allow(non_snake_case, non_upper_case_globals)]

use super::nat::{addMulVVW, _W_usize};
use crate::types::uint;

// go: sdk 1.25.5 crypto/internal/fips140/bigmod/nat_noasm.go:11-13 addMulVVW1024
pub(super) fn addMulVVW1024(z: &mut [uint], x: &[uint], y: uint) -> uint {
    // Go: return addMulVVW(unsafe.Slice(z, 1024/_W), unsafe.Slice(x, 1024/_W), y)
    let n = 1024 / _W_usize;
    return addMulVVW(&mut z[..n], &x[..n], y);
}

// go: sdk 1.25.5 crypto/internal/fips140/bigmod/nat_noasm.go:15-17 addMulVVW1536
pub(super) fn addMulVVW1536(z: &mut [uint], x: &[uint], y: uint) -> uint {
    // Go: return addMulVVW(unsafe.Slice(z, 1536/_W), unsafe.Slice(x, 1536/_W), y)
    let n = 1536 / _W_usize;
    return addMulVVW(&mut z[..n], &x[..n], y);
}

// go: sdk 1.25.5 crypto/internal/fips140/bigmod/nat_noasm.go:19-21 addMulVVW2048
pub(super) fn addMulVVW2048(z: &mut [uint], x: &[uint], y: uint) -> uint {
    // Go: return addMulVVW(unsafe.Slice(z, 2048/_W), unsafe.Slice(x, 2048/_W), y)
    let n = 2048 / _W_usize;
    return addMulVVW(&mut z[..n], &x[..n], y);
}
