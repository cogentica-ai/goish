// go: file crypto/internal/fips140/alias/alias.go decls: AnyOverlap, InexactOverlap
//
// Memory aliasing tests. The crypto/cipher AEAD, Block, BlockMode and
// Stream interfaces all require that an implementation reject inexactly
// overlapping buffers, and these are the checks that implement it.
//
// Go reaches for `unsafe.Pointer`; goish uses `core::ptr::from_ref` plus
// `.addr()`, which is the same comparison without leaving strict
// provenance (and without an `as` cast, per AGENTS.md §2a).

#![allow(non_snake_case)]

use crate::goslice::slice;
use crate::types::byte;

// go: sdk 1.25.5 crypto/internal/fips140/alias/alias.go:12-16 AnyOverlap
/// `alias.AnyOverlap(x, y)` — whether `x` and `y` share memory at any
/// (not necessarily corresponding) index. Memory beyond the slice length
/// is ignored.
pub fn AnyOverlap(x: &slice<byte>, y: &slice<byte>) -> bool {
    let xr: &[byte] = x;
    let yr: &[byte] = y;
    // Go: return len(x) > 0 && len(y) > 0 &&
    //       uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
    //       uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
    if xr.is_empty() || yr.is_empty() {
        return false;
    }
    let x0 = core::ptr::from_ref(&xr[0]).addr();
    let xn = core::ptr::from_ref(&xr[xr.len() - 1]).addr();
    let y0 = core::ptr::from_ref(&yr[0]).addr();
    let yn = core::ptr::from_ref(&yr[yr.len() - 1]).addr();
    return x0 <= yn && y0 <= xn;
}

// go: sdk 1.25.5 crypto/internal/fips140/alias/alias.go:24-29 InexactOverlap
/// `alias.InexactOverlap(x, y)` — whether `x` and `y` share memory at any
/// *non-corresponding* index. `x` and `y` may have different lengths and
/// still not overlap inexactly.
pub fn InexactOverlap(x: &slice<byte>, y: &slice<byte>) -> bool {
    let xr: &[byte] = x;
    let yr: &[byte] = y;
    // Go: if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] { return false }
    if xr.is_empty() || yr.is_empty() {
        return false;
    }
    if core::ptr::from_ref(&xr[0]).addr() == core::ptr::from_ref(&yr[0]).addr() {
        return false;
    }
    // Go: return AnyOverlap(x, y)
    return AnyOverlap(x, y);
}
