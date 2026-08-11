// go: file crypto/internal/fips140/edwards25519/field/fe_generic.go decls: mul, addMul, mul19, addMul19, addMul38, shiftRightBy51, feMulGeneric, feSquareGeneric, carryPropagate

#![allow(non_snake_case)]

use super::fe::{maskLow51Bits, Element};
use crate::math::bits;



/// `uint128` holds a 128-bit number as two 64-bit limbs, for use with
/// the bits.Mul64 and bits.Add64 intrinsics.
#[derive(Clone, Copy)]
pub(super) struct uint128 {
    pub(super) lo: u64,
    pub(super) hi: u64,
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/field/fe_generic.go:16-19 mul
/// `mul` returns a * b.
pub(super) fn mul(a: u64, b: u64) -> uint128 {
    let (hi, lo) = bits::Mul64(a, b);
    uint128 { lo, hi }
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/field/fe_generic.go:22-27 addMul
/// `addMul` returns v + a * b.
pub(super) fn addMul(v: uint128, a: u64, b: u64) -> uint128 {
    let (mut hi, lo0) = bits::Mul64(a, b);
    let (lo, c) = bits::Add64(lo0, v.lo, 0);
    let (hi2, _) = bits::Add64(hi, v.hi, c);
    hi = hi2;
    uint128 { lo, hi }
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/field/fe_generic.go:30-33 mul19
/// `mul19` returns v * 19.
pub(super) fn mul19(v: u64) -> u64 {
    // Using this approach seems to yield better optimizations than *19.
    v.wrapping_add((v.wrapping_add(v << 3)) << 1)
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/field/fe_generic.go:36-41 addMul19
/// `addMul19` returns v + 19 * a * b, where a and b are at most 52 bits.
pub(super) fn addMul19(v: uint128, a: u64, b: u64) -> uint128 {
    let (mut hi, lo0) = bits::Mul64(mul19(a), b);
    let (lo, c) = bits::Add64(lo0, v.lo, 0);
    let (hi2, _) = bits::Add64(hi, v.hi, c);
    hi = hi2;
    uint128 { lo, hi }
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/field/fe_generic.go:44-49 addMul38
/// `addMul38` returns v + 38 * a * b, where a and b are at most 52 bits.
pub(super) fn addMul38(v: uint128, a: u64, b: u64) -> uint128 {
    let (mut hi, lo0) = bits::Mul64(mul19(a), b.wrapping_mul(2));
    let (lo, c) = bits::Add64(lo0, v.lo, 0);
    let (hi2, _) = bits::Add64(hi, v.hi, c);
    hi = hi2;
    uint128 { lo, hi }
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/field/fe_generic.go:52-54 shiftRightBy51
/// `shiftRightBy51` returns a >> 51. a is assumed to be at most 115
/// bits.
pub(super) fn shiftRightBy51(a: uint128) -> u64 {
    (a.hi << (64 - 51)) | (a.lo >> 51)
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/field/fe_generic.go:56-184 feMulGeneric
/// `feMulGeneric` — portable 128-bit-product schoolbook multiply +
/// reduction. Sets v = a * b.
pub(super) fn feMulGeneric(v: &mut Element, a: &Element, b: &Element) {
    let a0 = a.l0;
    let a1 = a.l1;
    let a2 = a.l2;
    let a3 = a.l3;
    let a4 = a.l4;

    let b0 = b.l0;
    let b1 = b.l1;
    let b2 = b.l2;
    let b3 = b.l3;
    let b4 = b.l4;

    // r0 = a0×b0 + 19×(a1×b4 + a2×b3 + a3×b2 + a4×b1)
    let mut r0 = mul(a0, b0);
    r0 = addMul19(r0, a1, b4);
    r0 = addMul19(r0, a2, b3);
    r0 = addMul19(r0, a3, b2);
    r0 = addMul19(r0, a4, b1);

    // r1 = a0×b1 + a1×b0 + 19×(a2×b4 + a3×b3 + a4×b2)
    let mut r1 = mul(a0, b1);
    r1 = addMul(r1, a1, b0);
    r1 = addMul19(r1, a2, b4);
    r1 = addMul19(r1, a3, b3);
    r1 = addMul19(r1, a4, b2);

    // r2 = a0×b2 + a1×b1 + a2×b0 + 19×(a3×b4 + a4×b3)
    let mut r2 = mul(a0, b2);
    r2 = addMul(r2, a1, b1);
    r2 = addMul(r2, a2, b0);
    r2 = addMul19(r2, a3, b4);
    r2 = addMul19(r2, a4, b3);

    // r3 = a0×b3 + a1×b2 + a2×b1 + a3×b0 + 19×a4×b4
    let mut r3 = mul(a0, b3);
    r3 = addMul(r3, a1, b2);
    r3 = addMul(r3, a2, b1);
    r3 = addMul(r3, a3, b0);
    r3 = addMul19(r3, a4, b4);

    // r4 = a0×b4 + a1×b3 + a2×b2 + a3×b1 + a4×b0
    let mut r4 = mul(a0, b4);
    r4 = addMul(r4, a1, b3);
    r4 = addMul(r4, a2, b2);
    r4 = addMul(r4, a3, b1);
    r4 = addMul(r4, a4, b0);

    // After the multiplication, we need to reduce (carry) the five
    // coefficients to obtain a result with limbs that are at most
    // slightly larger than 2^51, to respect the Element invariant.
    let c0 = shiftRightBy51(r0);
    let c1 = shiftRightBy51(r1);
    let c2 = shiftRightBy51(r2);
    let c3 = shiftRightBy51(r3);
    let c4 = shiftRightBy51(r4);

    let rr0 = (r0.lo & maskLow51Bits).wrapping_add(mul19(c4));
    let rr1 = (r1.lo & maskLow51Bits).wrapping_add(c0);
    let rr2 = (r2.lo & maskLow51Bits).wrapping_add(c1);
    let rr3 = (r3.lo & maskLow51Bits).wrapping_add(c2);
    let rr4 = (r4.lo & maskLow51Bits).wrapping_add(c3);

    // Now all coefficients fit into 64-bit registers but are still too
    // large to be passed around as an Element. We therefore do one last
    // carry chain, where the carries will be small enough to fit in the
    // wiggle room above 2^51.
    v.l0 = (rr0 & maskLow51Bits).wrapping_add(mul19(rr4 >> 51));
    v.l1 = (rr1 & maskLow51Bits).wrapping_add(rr0 >> 51);
    v.l2 = (rr2 & maskLow51Bits).wrapping_add(rr1 >> 51);
    v.l3 = (rr3 & maskLow51Bits).wrapping_add(rr2 >> 51);
    v.l4 = (rr4 & maskLow51Bits).wrapping_add(rr3 >> 51);
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/field/fe_generic.go:186-257 feSquareGeneric
/// `feSquareGeneric` — portable squaring; sets v = a * a.
pub(super) fn feSquareGeneric(v: &mut Element, a: &Element) {
    let l0 = a.l0;
    let l1 = a.l1;
    let l2 = a.l2;
    let l3 = a.l3;
    let l4 = a.l4;

    // r0 = l0×l0 + 19×2×(l1×l4 + l2×l3)
    let mut r0 = mul(l0, l0);
    r0 = addMul38(r0, l1, l4);
    r0 = addMul38(r0, l2, l3);

    // r1 = 2×l0×l1 + 19×2×l2×l4 + 19×l3×l3
    let mut r1 = mul(l0.wrapping_mul(2), l1);
    r1 = addMul38(r1, l2, l4);
    r1 = addMul19(r1, l3, l3);

    // r2 = 2×l0×l2 + l1×l1 + 19×2×l3×l4
    let mut r2 = mul(l0.wrapping_mul(2), l2);
    r2 = addMul(r2, l1, l1);
    r2 = addMul38(r2, l3, l4);

    // r3 = 2×l0×l3 + 2×l1×l2 + 19×l4×l4
    let mut r3 = mul(l0.wrapping_mul(2), l3);
    r3 = addMul(r3, l1.wrapping_mul(2), l2);
    r3 = addMul19(r3, l4, l4);

    // r4 = 2×l0×l4 + 2×l1×l3 + l2×l2
    let mut r4 = mul(l0.wrapping_mul(2), l4);
    r4 = addMul(r4, l1.wrapping_mul(2), l3);
    r4 = addMul(r4, l2, l2);

    let c0 = shiftRightBy51(r0);
    let c1 = shiftRightBy51(r1);
    let c2 = shiftRightBy51(r2);
    let c3 = shiftRightBy51(r3);
    let c4 = shiftRightBy51(r4);

    let rr0 = (r0.lo & maskLow51Bits).wrapping_add(mul19(c4));
    let rr1 = (r1.lo & maskLow51Bits).wrapping_add(c0);
    let rr2 = (r2.lo & maskLow51Bits).wrapping_add(c1);
    let rr3 = (r3.lo & maskLow51Bits).wrapping_add(c2);
    let rr4 = (r4.lo & maskLow51Bits).wrapping_add(c3);

    v.l0 = (rr0 & maskLow51Bits).wrapping_add(mul19(rr4 >> 51));
    v.l1 = (rr1 & maskLow51Bits).wrapping_add(rr0 >> 51);
    v.l2 = (rr2 & maskLow51Bits).wrapping_add(rr1 >> 51);
    v.l3 = (rr3 & maskLow51Bits).wrapping_add(rr2 >> 51);
    v.l4 = (rr4 & maskLow51Bits).wrapping_add(rr3 >> 51);
}

impl Element {
    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/field/fe_generic.go:261-272 carryPropagate
    /// `carryPropagate` brings the limbs below 52 bits by applying the
    /// reduction identity (a * 2^255 + b = a * 19 + b) to the l4 carry.
    pub(super) fn carryPropagate(&mut self) -> &mut Element {
        // (l4>>51) is at most 64 - 51 = 13 bits, so (l4>>51)*19 is at
        // most 18 bits, and the final l0 will be at most 52 bits.
        // Similarly for the rest.
        let l0 = self.l0;
        self.l0 = (self.l0 & maskLow51Bits).wrapping_add(mul19(self.l4 >> 51));
        self.l4 = (self.l4 & maskLow51Bits).wrapping_add(self.l3 >> 51);
        self.l3 = (self.l3 & maskLow51Bits).wrapping_add(self.l2 >> 51);
        self.l2 = (self.l2 & maskLow51Bits).wrapping_add(self.l1 >> 51);
        self.l1 = (self.l1 & maskLow51Bits).wrapping_add(l0 >> 51);

        self
    }
}
