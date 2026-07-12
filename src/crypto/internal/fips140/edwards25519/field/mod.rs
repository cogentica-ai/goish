// crypto/internal/fips140/edwards25519/field — fast constant-time
// arithmetic modulo 2^255-19.
//
// Faithful port of Go 1.25.5
// crypto/internal/fips140/edwards25519/field/fe.go +
// fe_generic.go. The amd64/arm64 assembly (fe_amd64.s / fe_arm64.s)
// is NOT ported — goish always takes the portable generic path
// (feMulGeneric / feSquareGeneric).
//
// `Element` represents an element of the field GF(2^255-19) as five
// 51-bit uint64 limbs. Note that this is not a cryptographically
// secure group, and should only be used to interact with
// edwards25519.Point coordinates.
//
// goish notes:
//   * Go methods return `*Element` (the mutated receiver, for
//     chaining). goish returns `&mut Element` — same intent.
//   * All arguments and receivers are allowed to alias; mutating
//     methods snapshot their inputs before writing the receiver where
//     a `v.Multiply(v, v)` style call could otherwise corrupt data.
//   * The 5-limb storage `[u64; 5]` is internal — never appears in a
//     public signature. `SetBytes`/`Bytes` use `slice<byte>`.
//   * Constant-time discipline preserved verbatim: `Select`/`Swap` use
//     a uint64 mask, `Equal` reduces to subtle::ConstantTimeCompare.
//     No branch or array index on secret limb data.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use crate::crypto::subtle;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::math::bits;
use crate::types::{byte, int};
use alloc::vec::Vec;

// Side-effecting blank import in Go: `_ "crypto/internal/fips140/check"`.
// goish's `check` module is side-effect-free; referenced here only to
// mirror the import.
#[allow(unused_imports)]
use crate::crypto::internal::fips140::check as _check;

// ─── little-endian byte helpers (Go: fips140deps/byteorder) ───────────
// fe.go's SetBytes/Bytes do little-endian; tiny module-private helpers
// avoid pulling a heavy dep.

/// LEUint64 — decode a little-endian uint64 from an 8-byte window.
fn LEUint64(b: &[byte]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&b[0..8]);
    u64::from_le_bytes(arr)
}

/// LEPutUint64 — encode `x` little-endian into the first 8 bytes of `b`.
fn LEPutUint64(b: &mut [byte], x: u64) {
    let arr = x.to_le_bytes();
    b[0..8].copy_from_slice(&arr);
}

// ─── Element ──────────────────────────────────────────────────────────

/// `field.Element` — an element of GF(2^255-19).
///
/// An element t represents the integer
///     t.l0 + t.l1*2^51 + t.l2*2^102 + t.l3*2^153 + t.l4*2^204
///
/// Between operations, all limbs are expected to be lower than 2^52.
///
/// This type works similarly to math/big.Int, and all arguments and
/// receivers are allowed to alias. The zero value is a valid zero
/// element.
#[derive(Clone, Copy)]
pub struct Element {
    l0: u64,
    l1: u64,
    l2: u64,
    l3: u64,
    l4: u64,
}

/// `maskLow51Bits` — `(1 << 51) - 1`.
const maskLow51Bits: u64 = (1 << 51) - 1;

/// `feZero` — the additive identity.
const feZero: Element = Element { l0: 0, l1: 0, l2: 0, l3: 0, l4: 0 };

/// `feOne` — the multiplicative identity.
const feOne: Element = Element { l0: 1, l1: 0, l2: 0, l3: 0, l4: 0 };

impl Default for Element {
    /// The zero value is a valid zero element.
    fn default() -> Self {
        feZero
    }
}

impl Element {
    /// `new(Element)` — a fresh zero element.
    pub fn new() -> Self {
        feZero
    }

    /// `Zero` sets v = 0, and returns v.
    pub fn Zero(&mut self) -> &mut Element {
        *self = feZero;
        self
    }

    /// `One` sets v = 1, and returns v.
    pub fn One(&mut self) -> &mut Element {
        *self = feOne;
        self
    }

    /// `rawEqual` — bitwise (un-reduced) limb equality of v and u.
    /// Mirrors Go's `field.Element{}` struct comparison; used by
    /// edwards25519's `checkInitialized`, not a normalised field test.
    pub(crate) fn rawEqual(&self, u: &Element) -> bool {
        self.l0 == u.l0
            && self.l1 == u.l1
            && self.l2 == u.l2
            && self.l3 == u.l3
            && self.l4 == u.l4
    }

    /// `reduce` reduces v modulo 2^255 - 19 and returns it.
    fn reduce(&mut self) -> &mut Element {
        self.carryPropagate();

        // After the light reduction we now have a field element
        // representation v < 2^255 + 2^13 * 19, but need v < 2^255 - 19.

        // If v >= 2^255 - 19, then v + 19 >= 2^255, which would overflow
        // 2^255 - 1, generating a carry. That is, c will be 0 if
        // v < 2^255 - 19, and 1 otherwise.
        let mut c = (self.l0 + 19) >> 51;
        c = (self.l1 + c) >> 51;
        c = (self.l2 + c) >> 51;
        c = (self.l3 + c) >> 51;
        c = (self.l4 + c) >> 51;

        // If v < 2^255 - 19 and c = 0, this will be a no-op. Otherwise,
        // it's effectively applying the reduction identity to the carry.
        self.l0 = self.l0.wrapping_add(19u64.wrapping_mul(c));

        self.l1 = self.l1.wrapping_add(self.l0 >> 51);
        self.l0 &= maskLow51Bits;
        self.l2 = self.l2.wrapping_add(self.l1 >> 51);
        self.l1 &= maskLow51Bits;
        self.l3 = self.l3.wrapping_add(self.l2 >> 51);
        self.l2 &= maskLow51Bits;
        self.l4 = self.l4.wrapping_add(self.l3 >> 51);
        self.l3 &= maskLow51Bits;
        // no additional carry
        self.l4 &= maskLow51Bits;

        self
    }

    /// `Add` sets v = a + b, and returns v.
    pub fn Add(&mut self, a: &Element, b: &Element) -> &mut Element {
        self.l0 = a.l0.wrapping_add(b.l0);
        self.l1 = a.l1.wrapping_add(b.l1);
        self.l2 = a.l2.wrapping_add(b.l2);
        self.l3 = a.l3.wrapping_add(b.l3);
        self.l4 = a.l4.wrapping_add(b.l4);
        self.carryPropagate()
    }

    /// `Subtract` sets v = a - b, and returns v.
    pub fn Subtract(&mut self, a: &Element, b: &Element) -> &mut Element {
        // We first add 2 * p, to guarantee the subtraction won't
        // underflow, and then subtract b (which can be up to
        // 2^255 + 2^13 * 19).
        self.l0 = a.l0.wrapping_add(0xFFFFFFFFFFFDA).wrapping_sub(b.l0);
        self.l1 = a.l1.wrapping_add(0xFFFFFFFFFFFFE).wrapping_sub(b.l1);
        self.l2 = a.l2.wrapping_add(0xFFFFFFFFFFFFE).wrapping_sub(b.l2);
        self.l3 = a.l3.wrapping_add(0xFFFFFFFFFFFFE).wrapping_sub(b.l3);
        self.l4 = a.l4.wrapping_add(0xFFFFFFFFFFFFE).wrapping_sub(b.l4);
        self.carryPropagate()
    }

    /// `Negate` sets v = -a, and returns v.
    pub fn Negate(&mut self, a: &Element) -> &mut Element {
        self.Subtract(&feZero, a)
    }

    /// `Invert` sets v = 1/z mod p, and returns v.
    ///
    /// If z == 0, Invert returns v = 0.
    pub fn Invert(&mut self, z: &Element) -> &mut Element {
        // Inversion is implemented as exponentiation with exponent
        // p - 2. It uses the same sequence of 255 squarings and 11
        // multiplications as [Curve25519].
        let mut z2 = Element::new();
        let mut z9 = Element::new();
        let mut z11 = Element::new();
        let mut z2_5_0 = Element::new();
        let mut z2_10_0 = Element::new();
        let mut z2_20_0 = Element::new();
        let mut z2_50_0 = Element::new();
        let mut z2_100_0 = Element::new();
        let mut t = Element::new();

        z2.Square(z); // 2
        t.Square(&z2); // 4
        let tc = t;
        t.Square(&tc); // 8
        z9.Multiply(&t, z); // 9
        z11.Multiply(&z9, &z2); // 11
        t.Square(&z11); // 22
        z2_5_0.Multiply(&t, &z9); // 31 = 2^5 - 2^0

        t.Square(&z2_5_0); // 2^6 - 2^1
        for _ in 0..4 {
            let tc = t;
            t.Square(&tc); // 2^10 - 2^5
        }
        z2_10_0.Multiply(&t, &z2_5_0); // 2^10 - 2^0

        t.Square(&z2_10_0); // 2^11 - 2^1
        for _ in 0..9 {
            let tc = t;
            t.Square(&tc); // 2^20 - 2^10
        }
        z2_20_0.Multiply(&t, &z2_10_0); // 2^20 - 2^0

        t.Square(&z2_20_0); // 2^21 - 2^1
        for _ in 0..19 {
            let tc = t;
            t.Square(&tc); // 2^40 - 2^20
        }
        let tc = t;
        t.Multiply(&tc, &z2_20_0); // 2^40 - 2^0

        let tc = t;
        t.Square(&tc); // 2^41 - 2^1
        for _ in 0..9 {
            let tc = t;
            t.Square(&tc); // 2^50 - 2^10
        }
        z2_50_0.Multiply(&t, &z2_10_0); // 2^50 - 2^0

        t.Square(&z2_50_0); // 2^51 - 2^1
        for _ in 0..49 {
            let tc = t;
            t.Square(&tc); // 2^100 - 2^50
        }
        z2_100_0.Multiply(&t, &z2_50_0); // 2^100 - 2^0

        t.Square(&z2_100_0); // 2^101 - 2^1
        for _ in 0..99 {
            let tc = t;
            t.Square(&tc); // 2^200 - 2^100
        }
        let tc = t;
        t.Multiply(&tc, &z2_100_0); // 2^200 - 2^0

        let tc = t;
        t.Square(&tc); // 2^201 - 2^1
        for _ in 0..49 {
            let tc = t;
            t.Square(&tc); // 2^250 - 2^50
        }
        let tc = t;
        t.Multiply(&tc, &z2_50_0); // 2^250 - 2^0

        let tc = t;
        t.Square(&tc); // 2^251 - 2^1
        let tc = t;
        t.Square(&tc); // 2^252 - 2^2
        let tc = t;
        t.Square(&tc); // 2^253 - 2^3
        let tc = t;
        t.Square(&tc); // 2^254 - 2^4
        let tc = t;
        t.Square(&tc); // 2^255 - 2^5

        self.Multiply(&t, &z11) // 2^255 - 21
    }

    /// `Set` sets v = a, and returns v.
    pub fn Set(&mut self, a: &Element) -> &mut Element {
        *self = *a;
        self
    }

    /// `SetBytes` sets v to x, where x is a 32-byte little-endian
    /// encoding. If x is not of the right length, SetBytes returns an
    /// error and the receiver is unchanged.
    ///
    /// Consistent with RFC 7748, the most significant bit (the high bit
    /// of the last byte) is ignored, and non-canonical values
    /// (2^255-19 through 2^255-1) are accepted.
    pub fn SetBytes(&mut self, x: slice<byte>) -> error {
        if x.Len() != 32 {
            return errors::New("edwards25519: invalid field element input size");
        }
        let mut b = [0u8; 32];
        let mut i: int = 0;
        while i < 32 {
            b[i as usize] = x[i];
            i += 1;
        }

        // Bits 0:51 (bytes 0:8, bits 0:64, shift 0, mask 51).
        self.l0 = LEUint64(&b[0..8]);
        self.l0 &= maskLow51Bits;
        // Bits 51:102 (bytes 6:14, bits 48:112, shift 3, mask 51).
        self.l1 = LEUint64(&b[6..14]) >> 3;
        self.l1 &= maskLow51Bits;
        // Bits 102:153 (bytes 12:20, bits 96:160, shift 6, mask 51).
        self.l2 = LEUint64(&b[12..20]) >> 6;
        self.l2 &= maskLow51Bits;
        // Bits 153:204 (bytes 19:27, bits 152:216, shift 1, mask 51).
        self.l3 = LEUint64(&b[19..27]) >> 1;
        self.l3 &= maskLow51Bits;
        // Bits 204:255 (bytes 24:32, bits 192:256, shift 12, mask 51).
        // Note: not bytes 25:33, shift 4, to avoid overread.
        self.l4 = LEUint64(&b[24..32]) >> 12;
        self.l4 &= maskLow51Bits;

        errors::nil
    }

    /// `Bytes` returns the canonical 32-byte little-endian encoding of v.
    pub fn Bytes(&self) -> slice<byte> {
        let mut out = [0u8; 32];
        self.bytes(&mut out);
        let mut v: Vec<byte> = Vec::with_capacity(32);
        for &x in out.iter() {
            v.push(x);
        }
        slice::<byte>::__from_vec(v)
    }

    /// `bytes` packs the canonical encoding of v into `out`.
    fn bytes(&self, out: &mut [byte; 32]) {
        let mut t = *self;
        t.reduce();

        // Pack five 51-bit limbs into four 64-bit words:
        //
        //  255    204    153    102     51      0
        //    ├──l4──┼──l3──┼──l2──┼──l1──┼──l0──┤
        //   ├───u3───┼───u2───┼───u1───┼───u0───┤
        // 256      192      128       64        0
        let u0 = t.l1 << 51 | t.l0;
        let u1 = t.l2 << (102 - 64) | t.l1 >> (64 - 51);
        let u2 = t.l3 << (153 - 128) | t.l2 >> (128 - 102);
        let u3 = t.l4 << (204 - 192) | t.l3 >> (192 - 153);

        LEPutUint64(&mut out[0..8], u0);
        LEPutUint64(&mut out[8..16], u1);
        LEPutUint64(&mut out[16..24], u2);
        LEPutUint64(&mut out[24..32], u3);
    }

    /// `Equal` returns 1 if v and u are equal, and 0 otherwise.
    pub fn Equal(&self, u: &Element) -> int {
        let sa = u.Bytes();
        let sv = self.Bytes();
        subtle::ConstantTimeCompare(&sa, &sv)
    }

    /// `Select` sets v to a if cond == 1, and to b if cond == 0.
    pub fn Select(&mut self, a: &Element, b: &Element, cond: int) -> &mut Element {
        let m = mask64Bits(cond);
        self.l0 = (m & a.l0) | (!m & b.l0);
        self.l1 = (m & a.l1) | (!m & b.l1);
        self.l2 = (m & a.l2) | (!m & b.l2);
        self.l3 = (m & a.l3) | (!m & b.l3);
        self.l4 = (m & a.l4) | (!m & b.l4);
        self
    }

    /// `Swap` swaps v and u if cond == 1 or leaves them unchanged if
    /// cond == 0.
    pub fn Swap(&mut self, u: &mut Element, cond: int) {
        let m = mask64Bits(cond);
        let mut t = m & (self.l0 ^ u.l0);
        self.l0 ^= t;
        u.l0 ^= t;
        t = m & (self.l1 ^ u.l1);
        self.l1 ^= t;
        u.l1 ^= t;
        t = m & (self.l2 ^ u.l2);
        self.l2 ^= t;
        u.l2 ^= t;
        t = m & (self.l3 ^ u.l3);
        self.l3 ^= t;
        u.l3 ^= t;
        t = m & (self.l4 ^ u.l4);
        self.l4 ^= t;
        u.l4 ^= t;
    }

    /// `IsNegative` returns 1 if v is negative, and 0 otherwise.
    pub fn IsNegative(&self) -> int {
        int::from(self.Bytes()[0] & 1)
    }

    /// `Absolute` sets v to |u|, and returns v.
    pub fn Absolute(&mut self, u: &Element) -> &mut Element {
        let mut neg = Element::new();
        neg.Negate(u);
        let cond = u.IsNegative();
        self.Select(&neg, u, cond)
    }

    /// `Multiply` sets v = x * y, and returns v.
    pub fn Multiply(&mut self, x: &Element, y: &Element) -> &mut Element {
        // x and/or y may alias self; snapshot before writing.
        let xs = *x;
        let ys = *y;
        feMulGeneric(self, &xs, &ys);
        self
    }

    /// `Square` sets v = x * x, and returns v.
    pub fn Square(&mut self, x: &Element) -> &mut Element {
        // x may alias self; snapshot before writing.
        let xs = *x;
        feSquareGeneric(self, &xs);
        self
    }

    /// `Mult32` sets v = x * y, and returns v.
    pub fn Mult32(&mut self, x: &Element, y: u32) -> &mut Element {
        let (x0lo, x0hi) = mul51(x.l0, y);
        let (x1lo, x1hi) = mul51(x.l1, y);
        let (x2lo, x2hi) = mul51(x.l2, y);
        let (x3lo, x3hi) = mul51(x.l3, y);
        let (x4lo, x4hi) = mul51(x.l4, y);
        // carried over per the reduction identity
        self.l0 = x0lo.wrapping_add(19u64.wrapping_mul(x4hi));
        self.l1 = x1lo.wrapping_add(x0hi);
        self.l2 = x2lo.wrapping_add(x1hi);
        self.l3 = x3lo.wrapping_add(x2hi);
        self.l4 = x4lo.wrapping_add(x3hi);
        // The hi portions are going to be only 32 bits, plus any
        // previous excess, so we can skip the carry propagation.
        self
    }

    /// `Pow22523` set v = x^((p-5)/8), and returns v. (p-5)/8 is
    /// 2^252-3.
    ///
    /// `Multiply`/`Square` snapshot their `&Element` inputs internally,
    /// so callers may alias freely; Rust's borrow checker still forbids
    /// `t.Multiply(&t, ..)` syntactically, so where the receiver also
    /// appears as an argument we pass a copy taken before the call.
    pub fn Pow22523(&mut self, x: &Element) -> &mut Element {
        let mut t0 = Element::new();
        let mut t1 = Element::new();
        let mut t2 = Element::new();

        t0.Square(x); // x^2
        t1.Square(&t0); // x^4
        t1.Square(&t1.clone()); // x^8
        t1.Multiply(x, &t1.clone()); // x^9
        t0.Multiply(&t0.clone(), &t1); // x^11
        t0.Square(&t0.clone()); // x^22
        t0.Multiply(&t1, &t0.clone()); // x^31
        t1.Square(&t0); // x^62
        for _ in 1..5 {
            // x^992
            t1.Square(&t1.clone());
        }
        t0.Multiply(&t1, &t0.clone()); // x^1023 -> 1023 = 2^10 - 1
        t1.Square(&t0); // 2^11 - 2
        for _ in 1..10 {
            // 2^20 - 2^10
            t1.Square(&t1.clone());
        }
        t1.Multiply(&t1.clone(), &t0); // 2^20 - 1
        t2.Square(&t1); // 2^21 - 2
        for _ in 1..20 {
            // 2^40 - 2^20
            t2.Square(&t2.clone());
        }
        t1.Multiply(&t2, &t1.clone()); // 2^40 - 1
        t1.Square(&t1.clone()); // 2^41 - 2
        for _ in 1..10 {
            // 2^50 - 2^10
            t1.Square(&t1.clone());
        }
        t0.Multiply(&t1, &t0.clone()); // 2^50 - 1
        t1.Square(&t0); // 2^51 - 2
        for _ in 1..50 {
            // 2^100 - 2^50
            t1.Square(&t1.clone());
        }
        t1.Multiply(&t1.clone(), &t0); // 2^100 - 1
        t2.Square(&t1); // 2^101 - 2
        for _ in 1..100 {
            // 2^200 - 2^100
            t2.Square(&t2.clone());
        }
        t1.Multiply(&t2, &t1.clone()); // 2^200 - 1
        t1.Square(&t1.clone()); // 2^201 - 2
        for _ in 1..50 {
            // 2^250 - 2^50
            t1.Square(&t1.clone());
        }
        t0.Multiply(&t1, &t0.clone()); // 2^250 - 1
        t0.Square(&t0.clone()); // 2^251 - 2
        t0.Square(&t0.clone()); // 2^252 - 4
        self.Multiply(&t0, x) // 2^252 - 3 -> x^(2^252-3)
    }

    /// `SqrtRatio` sets r to the non-negative square root of the ratio
    /// of u and v.
    ///
    /// If u/v is square, SqrtRatio returns r and 1. If u/v is not
    /// square, SqrtRatio sets r according to Section 4.3 of
    /// draft-irtf-cfrg-ristretto255-decaf448-00, and returns r and 0.
    pub fn SqrtRatio(&mut self, u: &Element, v: &Element) -> int {
        let mut t0 = Element::new();

        // r = (u * v3) * (u * v7)^((p-5)/8)
        let mut v2 = Element::new();
        v2.Square(v);
        t0.Multiply(&v2, v);
        let mut uv3 = Element::new();
        uv3.Multiply(u, &t0);
        t0.Square(&v2);
        let mut uv7 = Element::new();
        uv7.Multiply(&uv3, &t0);
        t0.Pow22523(&uv7);
        let mut rr = Element::new();
        rr.Multiply(&uv3, &t0);

        t0.Square(&rr);
        let mut chk = Element::new();
        chk.Multiply(v, &t0); // check = v * r^2

        let mut uNeg = Element::new();
        uNeg.Negate(u);
        let correctSignSqrt = chk.Equal(u);
        let flippedSignSqrt = chk.Equal(&uNeg);
        t0.Multiply(&uNeg, &sqrtM1);
        let flippedSignSqrtI = chk.Equal(&t0);

        let mut rPrime = Element::new();
        rPrime.Multiply(&rr, &sqrtM1); // r_prime = SQRT_M1 * r
        // r = CT_SELECT(r_prime IF flipped_sign_sqrt | flipped_sign_sqrt_i ELSE r)
        let rrc = rr;
        rr.Select(&rPrime, &rrc, flippedSignSqrt | flippedSignSqrtI);

        self.Absolute(&rr); // Choose the nonnegative square root.
        correctSignSqrt | flippedSignSqrt
    }

    /// `carryPropagate` brings the limbs below 52 bits by applying the
    /// reduction identity (a * 2^255 + b = a * 19 + b) to the l4 carry.
    fn carryPropagate(&mut self) -> &mut Element {
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

/// `mask64Bits` returns 0xffffffffffffffff if cond is 1, and 0
/// otherwise.
fn mask64Bits(cond: int) -> u64 {
    // Go: ^(uint64(cond) - 1). With cond == 1 this is ^0 == all-ones;
    // with cond == 0 it is ^(u64::MAX) == 0.
    let c = u64::from_ne_bytes((cond as i64).to_ne_bytes());
    !c.wrapping_sub(1)
}

/// `mul51` returns lo + hi * 2^51 = a * b.
fn mul51(a: u64, b: u32) -> (u64, u64) {
    let (mh, ml) = bits::Mul64(a, u64::from(b));
    let lo = ml & maskLow51Bits;
    let hi = (mh << 13) | (ml >> 51);
    (lo, hi)
}

/// `sqrtM1` is 2^((p-1)/4), which squared is equal to -1 by Euler's
/// Criterion.
const sqrtM1: Element = Element {
    l0: 1718705420411056,
    l1: 234908883556509,
    l2: 2233514472574048,
    l3: 2117202627021982,
    l4: 765476049583133,
};

// ─── fe_generic.go ────────────────────────────────────────────────────

/// `uint128` holds a 128-bit number as two 64-bit limbs, for use with
/// the bits.Mul64 and bits.Add64 intrinsics.
#[derive(Clone, Copy)]
struct uint128 {
    lo: u64,
    hi: u64,
}

/// `mul` returns a * b.
fn mul(a: u64, b: u64) -> uint128 {
    let (hi, lo) = bits::Mul64(a, b);
    uint128 { lo, hi }
}

/// `addMul` returns v + a * b.
fn addMul(v: uint128, a: u64, b: u64) -> uint128 {
    let (mut hi, lo0) = bits::Mul64(a, b);
    let (lo, c) = bits::Add64(lo0, v.lo, 0);
    let (hi2, _) = bits::Add64(hi, v.hi, c);
    hi = hi2;
    uint128 { lo, hi }
}

/// `mul19` returns v * 19.
fn mul19(v: u64) -> u64 {
    // Using this approach seems to yield better optimizations than *19.
    v.wrapping_add((v.wrapping_add(v << 3)) << 1)
}

/// `addMul19` returns v + 19 * a * b, where a and b are at most 52 bits.
fn addMul19(v: uint128, a: u64, b: u64) -> uint128 {
    let (mut hi, lo0) = bits::Mul64(mul19(a), b);
    let (lo, c) = bits::Add64(lo0, v.lo, 0);
    let (hi2, _) = bits::Add64(hi, v.hi, c);
    hi = hi2;
    uint128 { lo, hi }
}

/// `addMul38` returns v + 38 * a * b, where a and b are at most 52 bits.
fn addMul38(v: uint128, a: u64, b: u64) -> uint128 {
    let (mut hi, lo0) = bits::Mul64(mul19(a), b.wrapping_mul(2));
    let (lo, c) = bits::Add64(lo0, v.lo, 0);
    let (hi2, _) = bits::Add64(hi, v.hi, c);
    hi = hi2;
    uint128 { lo, hi }
}

/// `shiftRightBy51` returns a >> 51. a is assumed to be at most 115
/// bits.
fn shiftRightBy51(a: uint128) -> u64 {
    (a.hi << (64 - 51)) | (a.lo >> 51)
}

/// `feMulGeneric` — portable 128-bit-product schoolbook multiply +
/// reduction. Sets v = a * b.
fn feMulGeneric(v: &mut Element, a: &Element, b: &Element) {
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

/// `feSquareGeneric` — portable squaring; sets v = a * a.
fn feSquareGeneric(v: &mut Element, a: &Element) {
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
