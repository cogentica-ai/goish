// go: file crypto/internal/fips140/edwards25519/scalar.go decls: NewScalar, isReduced, MultiplyAdd, Add, Subtract, Negate, Multiply, Set, SetUniformBytes, setShortBytes, SetCanonicalBytes, SetBytesWithClamping, Bytes, bytes, Equal, nonAdjacentForm, signedRadix16

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use super::scalar_fiat::*;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::math::bits;
use crate::types::{byte, int};
use alloc::vec::Vec;

// ════════════════════════════════════════════════════════════════════
//  scalar.go — the public Scalar type.
// ════════════════════════════════════════════════════════════════════

/// A `Scalar` is an integer modulo
///
///     l = 2^252 + 27742317777372353535851937790883648493
///
/// which is the prime order of the edwards25519 group.
///
/// This type works similarly to math/big.Int, and all arguments and
/// receivers are allowed to alias. The zero value is a valid zero
/// element.
#[derive(Clone, Copy)]
pub struct Scalar {
    /// s is the scalar in the Montgomery domain, in the format of the
    /// fiat-crypto implementation.
    s: fiatScalarMontgomeryDomainFieldElement,
}

impl Default for Scalar {
    // go: none — Go gets the zero Scalar from `Scalar{}`; Rust needs the
    // Default impl spelled.
    /// The zero value is a valid zero element.
    fn default() -> Self {
        Scalar { s: [0, 0, 0, 0] }
    }
}

/// scalarTwo168 — 2^168 mod l, encoded as a
/// fiatScalarMontgomeryDomainFieldElement (little-endian 4-limb value
/// in the 2^256 Montgomery domain).
const scalarTwo168: Scalar = Scalar {
    s: [
        0x5b8ab432eac74798,
        0x38afddd6de59d5d7,
        0xa2c131b399411b7c,
        0x6329a7ed9ce5a30,
    ],
};

/// scalarTwo336 — 2^336 mod l, encoded as a
/// fiatScalarMontgomeryDomainFieldElement.
const scalarTwo336: Scalar = Scalar {
    s: [
        0xbd3d108e2b35ecc5,
        0x5c3a3718bdf9c90b,
        0x63aa97a331b4f2ee,
        0x3d217f5be65cb5c,
    ],
};

/// scalarMinusOneBytes — l - 1 in little endian.
const scalarMinusOneBytes: [u8; 32] = [
    236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 16,
];

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:58-60 NewScalar
/// `NewScalar` returns a new zero Scalar.
pub fn NewScalar() -> Scalar {
    Scalar::default()
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:178-200 isReduced
/// `isReduced` returns whether the given scalar in 32-byte little
/// endian encoded form is reduced modulo l.
fn isReduced(s: &[byte]) -> bool {
    if s.len() != 32 {
        return false;
    }

    let s0 = LEUint64(&s[0..8]);
    let s1 = LEUint64(&s[8..16]);
    let s2 = LEUint64(&s[16..24]);
    let s3 = LEUint64(&s[24..32]);

    let l0 = LEUint64(&scalarMinusOneBytes[0..8]);
    let l1 = LEUint64(&scalarMinusOneBytes[8..16]);
    let l2 = LEUint64(&scalarMinusOneBytes[16..24]);
    let l3 = LEUint64(&scalarMinusOneBytes[24..32]);

    // Constant-time subtraction chain scalarMinusOneBytes - s. A borrow
    // at the end means s > scalarMinusOneBytes.
    let (_, b) = bits::Sub64(l0, s0, 0);
    let (_, b) = bits::Sub64(l1, s1, b);
    let (_, b) = bits::Sub64(l2, s2, b);
    let (_, b) = bits::Sub64(l3, s3, b);
    b == 0
}

impl Scalar {
    // go: none — Go writes `&Scalar{}`; this is that constructor.
    /// `new(Scalar)` — a fresh zero Scalar.
    pub fn new() -> Self {
        Scalar::default()
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:64-68 MultiplyAdd
    /// `MultiplyAdd` sets s = x * y + z mod l, and returns s. It is
    /// equivalent to using Multiply and then Add.
    pub fn MultiplyAdd(&mut self, x: &Scalar, y: &Scalar, z: &Scalar) -> &mut Scalar {
        // Snapshot z in case it aliases s.
        let zCopy = *z;
        self.Multiply(x, y);
        let sCopy = *self;
        self.Add(&sCopy, &zCopy)
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:71-75 Add
    /// `Add` sets s = x + y mod l, and returns s.
    pub fn Add(&mut self, x: &Scalar, y: &Scalar) -> &mut Scalar {
        // s = 1 * x + y mod l
        let (xs, ys) = (x.s, y.s);
        fiatScalarAdd(&mut self.s, &xs, &ys);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:78-82 Subtract
    /// `Subtract` sets s = x - y mod l, and returns s.
    pub fn Subtract(&mut self, x: &Scalar, y: &Scalar) -> &mut Scalar {
        // s = -1 * y + x mod l
        let (xs, ys) = (x.s, y.s);
        fiatScalarSub(&mut self.s, &xs, &ys);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:85-89 Negate
    /// `Negate` sets s = -x mod l, and returns s.
    pub fn Negate(&mut self, x: &Scalar) -> &mut Scalar {
        // s = -1 * x + 0 mod l
        let xs = x.s;
        fiatScalarOpp(&mut self.s, &xs);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:92-96 Multiply
    /// `Multiply` sets s = x * y mod l, and returns s.
    pub fn Multiply(&mut self, x: &Scalar, y: &Scalar) -> &mut Scalar {
        // s = x * y + 0 mod l
        let (xs, ys) = (x.s, y.s);
        fiatScalarMul(&mut self.s, &xs, &ys);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:99-102 Set
    /// `Set` sets s = x, and returns s.
    pub fn Set(&mut self, x: &Scalar) -> &mut Scalar {
        *self = *x;
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:110-133 SetUniformBytes
    /// `SetUniformBytes` sets s = x mod l, where x is a 64-byte
    /// little-endian integer. If x is not of the right length,
    /// SetUniformBytes returns an error and the receiver is unchanged.
    ///
    /// SetUniformBytes can be used to set s to a uniformly distributed
    /// value given 64 uniformly distributed random bytes.
    pub fn SetUniformBytes(&mut self, x: slice<byte>) -> error {
        if x.Len() != 64 {
            return errors::New("edwards25519: invalid SetUniformBytes input length");
        }

        // We have a value x of 512 bits, but fiatScalarFromBytes expects
        // an input lower than l (a little over 252 bits). Interpret x as
        //     x = a + b * 2^168 + c * 2^336  mod l
        // and reduce with two multiplications and two additions.
        let mut buf = [0u8; 64];
        let mut i: int = 0;
        while i < 64 {
            buf[i as usize] = x[i];
            i += 1;
        }

        self.setShortBytes(&buf[0..21]);
        let mut t = Scalar::default();
        t.setShortBytes(&buf[21..42]);
        let tIn = t;
        t.Multiply(&tIn, &scalarTwo168);
        let sCopy = *self;
        self.Add(&sCopy, &t);
        t.setShortBytes(&buf[42..64]);
        let tIn2 = t;
        t.Multiply(&tIn2, &scalarTwo336);
        let sCopy2 = *self;
        self.Add(&sCopy2, &t);

        errors::nil
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:145-154 setShortBytes
    /// `setShortBytes` sets s = x mod l, where x is a little-endian
    /// integer shorter than 32 bytes.
    fn setShortBytes(&mut self, x: &[byte]) -> &mut Scalar {
        if x.len() >= 32 {
            panic!("edwards25519: internal error: setShortBytes called with a long string");
        }
        let mut buf = [0u8; 32];
        buf[0..x.len()].copy_from_slice(x);
        let mut nm: fiatScalarNonMontgomeryDomainFieldElement = [0, 0, 0, 0];
        fiatScalarFromBytes(&mut nm, &buf);
        fiatScalarToMontgomery(&mut self.s, &nm);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:159-171 SetCanonicalBytes
    /// `SetCanonicalBytes` sets s = x, where x is a 32-byte
    /// little-endian encoding of s, and returns s via the receiver. If
    /// x is not a canonical encoding of s, SetCanonicalBytes returns an
    /// error and the receiver is unchanged.
    pub fn SetCanonicalBytes(&mut self, x: slice<byte>) -> error {
        if x.Len() != 32 {
            return errors::New("invalid scalar length");
        }
        let mut buf = [0u8; 32];
        let mut i: int = 0;
        while i < 32 {
            buf[i as usize] = x[i];
            i += 1;
        }
        if !isReduced(&buf) {
            return errors::New("invalid scalar encoding");
        }

        let mut nm: fiatScalarNonMontgomeryDomainFieldElement = [0, 0, 0, 0];
        fiatScalarFromBytes(&mut nm, &buf);
        fiatScalarToMontgomery(&mut self.s, &nm);

        errors::nil
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:213-230 SetBytesWithClamping
    /// `SetBytesWithClamping` applies the buffer pruning described in
    /// RFC 8032, Section 5.1.5 (also known as clamping) and sets s to
    /// the result. The input must be 32 bytes, and it is not modified.
    /// If x is not of the right length, SetBytesWithClamping returns an
    /// error and the receiver is unchanged.
    ///
    /// Note that since Scalar values are always reduced modulo the
    /// prime order of the curve, the resulting value will not preserve
    /// any of the cofactor-clearing properties that clamping is meant
    /// to provide. It will however work as expected as long as it is
    /// applied to points on the prime order subgroup, like in Ed25519.
    pub fn SetBytesWithClamping(&mut self, x: slice<byte>) -> error {
        if x.Len() != 32 {
            return errors::New("edwards25519: invalid SetBytesWithClamping input length");
        }

        // We need the wide reduction from SetUniformBytes, since
        // clamping sets the 2^254 bit, making the value higher than the
        // order.
        let mut wideBytes = [0u8; 64];
        let mut i: int = 0;
        while i < 32 {
            wideBytes[i as usize] = x[i];
            i += 1;
        }
        wideBytes[0] &= 248;
        wideBytes[31] &= 63;
        wideBytes[31] |= 64;

        let mut v: Vec<byte> = Vec::with_capacity(64);
        for &b in wideBytes.iter() {
            v.push(b);
        }
        self.SetUniformBytes(slice::<byte>::__from_vec(v))
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:233-238 Bytes
    /// `Bytes` returns the canonical 32-byte little-endian encoding of s.
    pub fn Bytes(&self) -> slice<byte> {
        let mut encoded = [0u8; 32];
        self.bytes(&mut encoded);
        let mut v: Vec<byte> = Vec::with_capacity(32);
        for &x in encoded.iter() {
            v.push(x);
        }
        slice::<byte>::__from_vec(v)
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:240-245 bytes
    /// `bytes` packs the canonical encoding of s into `out`.
    fn bytes(&self, out: &mut [byte; 32]) {
        let mut ss: fiatScalarNonMontgomeryDomainFieldElement = [0, 0, 0, 0];
        fiatScalarFromMontgomery(&mut ss, &self.s);
        fiatScalarToBytes(out, &ss);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:248-260 Equal
    /// `Equal` returns 1 if s and t are equal, and 0 otherwise.
    pub fn Equal(&self, t: &Scalar) -> int {
        let mut diff: fiatScalarMontgomeryDomainFieldElement = [0, 0, 0, 0];
        fiatScalarSub(&mut diff, &self.s, &t.s);
        let mut nonzero: u64 = 0;
        fiatScalarNonzero(&mut nonzero, &diff);
        nonzero |= nonzero >> 32;
        nonzero |= nonzero >> 16;
        nonzero |= nonzero >> 8;
        nonzero |= nonzero >> 4;
        nonzero |= nonzero >> 2;
        nonzero |= nonzero >> 1;
        let r: u64 = (!nonzero) & 1;
        int::try_from(r).unwrap()
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:265-328 nonAdjacentForm
    /// `nonAdjacentForm` computes a width-w non-adjacent form for this
    /// scalar.
    ///
    /// w must be between 2 and 8, or nonAdjacentForm will panic.
    ///
    /// Used by edwards25519.Point scalar multiplication.
    pub(crate) fn nonAdjacentForm(&self, w: u32) -> [i8; 256] {
        // Adapted from curve25519-dalek; see scalar.go for the doc link.
        let b = self.Bytes();
        if b[31] > 127 {
            panic!("scalar has high bit set illegally");
        }
        if w < 2 {
            panic!("w must be at least 2 by the definition of NAF");
        } else if w > 8 {
            panic!("NAF digits must fit in int8");
        }

        let mut naf: [i8; 256] = [0; 256];
        let mut digits: [u64; 5] = [0; 5];

        let mut bb = [0u8; 32];
        let mut k: int = 0;
        while k < 32 {
            bb[k as usize] = b[k];
            k += 1;
        }
        for i in 0..4usize {
            digits[i] = LEUint64(&bb[i * 8..i * 8 + 8]);
        }

        let width: u64 = 1u64 << w;
        let windowMask: u64 = width - 1;

        let mut pos: u32 = 0;
        let mut carry: u64 = 0;
        while pos < 256 {
            let indexU64: u32 = pos / 64;
            let indexBit: u32 = pos % 64;
            let bitBuf: u64;
            if indexBit < 64 - w {
                // This window's bits are contained in a single u64.
                bitBuf = digits[indexU64 as usize] >> indexBit;
            } else {
                // Combine the current 64 bits with bits from the next 64.
                bitBuf = (digits[indexU64 as usize] >> indexBit)
                    | (digits[1 + indexU64 as usize] << (64 - indexBit));
            }

            // Add carry into the current window.
            let window: u64 = carry + (bitBuf & windowMask);

            if window & 1 == 0 {
                // If the window value is even, preserve the carry.
                pos += 1;
                continue;
            }

            if window < width / 2 {
                carry = 0;
                naf[pos as usize] = i8x(window);
            } else {
                carry = 1;
                naf[pos as usize] = i8x(window).wrapping_sub(i8x(width));
            }

            pos += w;
        }
        naf
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/scalar.go:330-352 signedRadix16
    /// `signedRadix16` — recentered radix-16 digits of the scalar.
    ///
    /// Used by edwards25519.Point scalar multiplication.
    pub(crate) fn signedRadix16(&self) -> [i8; 64] {
        let b = self.Bytes();
        if b[31] > 127 {
            panic!("scalar has high bit set illegally");
        }

        let mut digits: [i8; 64] = [0; 64];

        // Compute unsigned radix-16 digits:
        for i in 0..32usize {
            let bi: int = int::try_from(i).unwrap();
            digits[2 * i] = i8x(u64::from(b[bi] & 15));
            digits[2 * i + 1] = i8x(u64::from((b[bi] >> 4) & 15));
        }

        // Recenter coefficients:
        for i in 0..63usize {
            let carry: i8 = (digits[i] + 8) >> 4;
            digits[i] -= carry << 4;
            digits[i + 1] += carry;
        }

        digits
    }
}

// go: none — Go's `int8(x)` conversion; goish spells the narrowing
// once rather than at every call site in nonAdjacentForm.
/// `i8x` — Go's `int8(x)` truncating conversion. Keeps the low 8 bits
/// reinterpreted as a signed byte; goish forbids `as`.
fn i8x(x: u64) -> i8 {
    let lo: u8 = u8::try_from(x & 0xff).unwrap();
    i8::from_le_bytes([lo])
}

// ─── polymorphic nil (AGENTS.md §6) ──────────────────────────────────

impl From<crate::nilval::Nil> for Scalar {
    // go: none — the polymorphic-nil conversion (AGENTS.md §6).
    fn from(_: crate::nilval::Nil) -> Self {
        Scalar::default()
    }
}
