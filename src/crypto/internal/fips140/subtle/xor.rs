// go: file crypto/internal/fips140/subtle/xor.go decls: XORBytes
//
// Deviation: no `alias.InexactOverlap` panic — goish `slice<T>` does not
// expose the pointer arithmetic that check needs, and Rust's borrow rules
// already forbid `&mut` aliasing a `&` argument, which is the case the
// check exists to catch.

#![allow(non_snake_case)]

use crate::convert::int as toint;
use crate::goslice::slice;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor.go:17-29 XORBytes
//
//   func XORBytes(dst, x, y []byte) int
/// `XORBytes` sets `dst[i] = x[i] ^ y[i]` for all `i < n = min(len(x),
/// len(y))`, returning `n`. Panics if `dst` is shorter than `n`.
pub fn XORBytes(dst: &mut slice<byte>, x: &slice<byte>, y: &slice<byte>) -> int {
    // Go: n := min(len(x), len(y))
    let n = if x.len() < y.len() { x.len() } else { y.len() };
    // Go: if n == 0 { return 0 }
    if n == 0 {
        return 0;
    }
    // Go: if n > len(dst) { panic("subtle.XORBytes: dst too short") }
    if n > dst.len() {
        panic!("subtle.XORBytes: dst too short");
    }
    // Go: xorBytes(&dst[0], &x[0], &y[0], n)  // arch-specific
    let xs: &[byte] = x;
    let ys: &[byte] = y;
    let xv = xs[..n].to_vec();
    let yv = ys[..n].to_vec();
    let ds: &mut [byte] = dst;
    super::xor_generic::xorBytes(&mut ds[..n], &xv, &yv, toint(n));
    // Go: return n
    return toint(n);
}
