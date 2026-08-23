// go: file crypto/internal/fips140/nistec/p224_sqrt.go decls: p224SqrtCandidate
//
// Deviations from p224_sqrt[go] @ Go 1.25.5:
//
//   * `var p224GG *[96]fiat.P224Element` guarded by a `sync.Once` becomes
//     a `goish::lazy::Lazy<Vec<P224Element>>` — Go's is a pointer to a
//     heap array, and `Vec` keeps the 3 KiB off the caller's stack.
//   * `fiat.P224Element` is `Copy`, so operands are by value; Go's
//     "r and x must not overlap" precondition is unrepresentable here,
//     which is strictly safer.
//
// goishlint:ignore GOISH021 — `p224GGOnce` is the `sync.Once` guard for
// `p224GG`; the `Lazy` below carries its own one-shot latch.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use super::fiat::P224Element;
use crate::goslice::slice;
use crate::lazy::Lazy;

// Go: p224_sqrt.go:12-13 — `var p224GG *[96]fiat.P224Element; var p224GGOnce sync.Once`
//
// p = q*2^n + 1 with q odd -> q = 2^128 - 1 and n = 96
// g^(2^n) = 1 -> g = 11 ^ q (where 11 is the smallest non-square)
// GG[j] = g^(2^j) for j = 0 to n-1
static p224GG: Lazy<Vec<P224Element>> = Lazy::new(|| {
    let mut gg: Vec<P224Element> = Vec::with_capacity(96);
    let mut i: usize = 0;
    while i < 96 {
        let mut e = P224Element::New();
        if i == 0 {
            let _ = e.SetBytes(slice::__from_vec(alloc::vec![
                0x6a, 0x0f, 0xec, 0x67, 0x85, 0x98, 0xa7, 0x92, 0x0c, 0x55, 0xb2, 0xd4, 0x0b, 0x2d,
                0x6f, 0xfb, 0xbe, 0xa3, 0xd8, 0xce, 0xf3, 0xfb, 0x36, 0x32, 0xdc, 0x69, 0x1b, 0x74
            ]));
        } else {
            e.Square(gg[i - 1]);
        }
        gg.push(e);
        i += 1;
    }
    return gg;
});

// go: sdk 1.25.5 crypto/internal/fips140/nistec/p224_sqrt.go:15-132 p224SqrtCandidate
/// Set r to a square root candidate for x.
pub(super) fn p224SqrtCandidate(r: &mut P224Element, x: P224Element) {
    // Since p = 1 mod 4, we can't use the exponentiation by (p + 1) / 4
    // like for the other primes. Instead, implement a variation of
    // Tonelli–Shanks. The constant-time implementation is adapted from
    // Thomas Pornin's ecGFp5.
    //
    // https://github.com/pornin/ecgfp5/blob/82325b965/rust/src/field.rs#L337-L385

    // r <- x^((q+1)/2) = x^(2^127)
    // v <- x^q = x^(2^128-1)

    // Compute x^(2^127-1) first.
    //
    // The sequence of 10 multiplications and 126 squarings is derived from
    // the following addition chain generated with
    // github.com/mmcloughlin/addchain v0.4.0.
    //
    //	_10      = 2*1
    //	_11      = 1 + _10
    //	_110     = 2*_11
    //	_111     = 1 + _110
    //	_111000  = _111 << 3
    //	_111111  = _111 + _111000
    //	_1111110 = 2*_111111
    //	_1111111 = 1 + _1111110
    //	x12      = _1111110 << 5 + _111111
    //	x24      = x12 << 12 + x12
    //	i36      = x24 << 7
    //	x31      = _1111111 + i36
    //	x48      = i36 << 17 + x24
    //	x96      = x48 << 48 + x48
    //	return     x96 << 31 + x31
    //
    let mut t0 = P224Element::New();
    let mut t1 = P224Element::New();

    r.Square(x);
    r.Mul(x, *r);
    r.Square(*r);
    r.Mul(x, *r);
    t0.Square(*r);
    let mut s: usize = 1;
    while s < 3 {
        t0.Square(t0);
        s += 1;
    }
    t0.Mul(*r, t0);
    t1.Square(t0);
    r.Mul(x, t1);
    let mut s: usize = 0;
    while s < 5 {
        t1.Square(t1);
        s += 1;
    }
    t0.Mul(t0, t1);
    t1.Square(t0);
    let mut s: usize = 1;
    while s < 12 {
        t1.Square(t1);
        s += 1;
    }
    t0.Mul(t0, t1);
    t1.Square(t0);
    let mut s: usize = 1;
    while s < 7 {
        t1.Square(t1);
        s += 1;
    }
    r.Mul(*r, t1);
    let mut s: usize = 0;
    while s < 17 {
        t1.Square(t1);
        s += 1;
    }
    t0.Mul(t0, t1);
    t1.Square(t0);
    let mut s: usize = 1;
    while s < 48 {
        t1.Square(t1);
        s += 1;
    }
    t0.Mul(t0, t1);
    let mut s: usize = 0;
    while s < 31 {
        t0.Square(t0);
        s += 1;
    }
    r.Mul(*r, t0);

    // v = x^(2^127-1)^2 * x
    let mut v = P224Element::New();
    v.Square(*r);
    v.Mul(v, x);

    // r = x^(2^127-1) * x
    r.Mul(*r, x);

    // for i = n-1 down to 1:
    //     w = v^(2^(i-1))
    //     if w == -1 then:
    //         v <- v*GG[n-i]
    //         r <- r*GG[n-i-1]

    let mut one = P224Element::New();
    one.One();
    let mut p224MinusOne = P224Element::New();
    p224MinusOne.Sub(P224Element::New(), one);

    let mut i: usize = 96 - 1;
    while i >= 1 {
        let mut w = P224Element::New();
        w.Set(v);
        let mut j: usize = 0;
        while j < i - 1 {
            w.Square(w);
            j += 1;
        }
        let cond = w.Equal(p224MinusOne);
        t0.Mul(v, p224GG[96 - i]);
        v.Select(t0, v, cond);
        t0.Mul(*r, p224GG[96 - i - 1]);
        r.Select(t0, *r, cond);
        i -= 1;
    }
}
