// go: file crypto/elliptic/params.go decls: CurveParams.Params, CurveParams.polynomial, CurveParams.IsOnCurve, zForAffine, CurveParams.affineFromJacobian, CurveParams.Add, CurveParams.addJacobian, CurveParams.Double, CurveParams.doubleJacobian, CurveParams.ScalarMult, CurveParams.ScalarBaseMult, matchesSpecificCurve
//
// Deviations from params[go] @ Go 1.25.5:
//
//   * Go's `new(big.Int).Mul(x, y)` allocates a result and freely aliases
//     the receiver with an operand (`x3.Mul(x3, x3)`). goish's
//     `Int::Mul(&mut self, x, y)` cannot take `&self` and `&mut self` at
//     once, so the `new(big.Int).Op(…)` idiom is spelled through the
//     `mul`/`add`/`sub`/`lsh`/`modp` helpers at the bottom of this file
//     and in-place aliasing goes through an explicit clone. The
//     allocation pattern differs; the arithmetic does not.
//   * `matchesSpecificCurve` compares `params == c.Params()` by *pointer*
//     in Go. goish's `Params()` returns an owned `CurveParams`, so the
//     comparison is by value across every field. That is strictly
//     narrower than Go's: a CurveParams equal in all of P, N, B, Gx, Gy,
//     BitSize and Name *is* the curve, whereas Go would reject an
//     identical copy allocated separately. No caller can observe the
//     difference except by constructing a duplicate of a NIST curve, in
//     which case dispatching to the constant-time implementation is the
//     better answer anyway.
//   * Methods returning `(*big.Int, *big.Int)` return `(Int, Int)`.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::goslice::slice;
use crate::math::big::Int;
use crate::string;
use crate::types::{byte, int, uint};

use super::elliptic::{panicIfNotOnCurve, Curve};
use super::nistec::{p224, p256, p384, p521};

// Go: params.go:5-17
//   type CurveParams struct { P, N, B, Gx, Gy *big.Int; BitSize int; Name string }
/// Contains the parameters of an elliptic curve and also provides a
/// generic, non-constant time implementation of [Curve].
///
/// The generic Curve implementation is deprecated, and using custom curves
/// (those not returned by [P224], [P256], [P384], and [P521]) is not
/// guaranteed to provide any security property.
#[derive(Clone, Default)]
pub struct CurveParams {
    /// the order of the underlying field
    pub P: Int,
    /// the order of the base point
    pub N: Int,
    /// the constant of the curve equation
    pub B: Int,
    /// (x,y) of the base point
    pub Gx: Int,
    pub Gy: Int,
    /// the size of the underlying field
    pub BitSize: int,
    /// the canonical name of the curve
    pub Name: string,
}

// CurveParams operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1² and y = y1/z1³. The greatest speedups come when the
// whole calculation can be performed within the transform (as in
// ScalarMult and ScalarBaseMult). But even for Add and Double, it's faster
// to apply and reverse the transform than to operate in affine
// coordinates.

impl CurveParams {
    // go: sdk 1.25.5 crypto/elliptic/params.go:24-26 CurveParams.Params
    pub fn Params(&self) -> CurveParams {
        return self.clone();
    }

    // go: sdk 1.25.5 crypto/elliptic/params.go:36-48 CurveParams.polynomial
    /// Return x³ - 3x + b.
    pub(super) fn polynomial(&self, x: &Int) -> Int {
        let mut x3 = mul(x, x);
        x3 = mul(&x3, x);

        let mut threeX = lsh(x, 1);
        threeX = add(&threeX, x);

        x3 = sub(&x3, &threeX);
        x3 = add(&x3, &self.B);
        x3 = modp(&x3, &self.P);

        return x3;
    }

    // go: sdk 1.25.5 crypto/elliptic/params.go:56-73 CurveParams.IsOnCurve
    /// Implements [Curve::IsOnCurve].
    ///
    /// Deprecated: the [CurveParams] methods are deprecated and are not
    /// guaranteed to provide any security property.
    pub fn IsOnCurve(&self, x: &Int, y: &Int) -> bool {
        // If there is a dedicated constant-time implementation for this
        // curve operation, use that instead of the generic one.
        let (specific, ok) = matchesSpecificCurve(self);
        if ok {
            return specific.unwrap().IsOnCurve(x, y);
        }

        if x.Sign() < 0 || x.Cmp(&self.P) >= 0 || y.Sign() < 0 || y.Cmp(&self.P) >= 0 {
            return false;
        }

        // y² = x³ - 3x + b
        let mut y2 = mul(y, y);
        y2 = modp(&y2, &self.P);

        return self.polynomial(x).Cmp(&y2) == 0;
    }

    // go: sdk 1.25.5 crypto/elliptic/params.go:88-102 CurveParams.affineFromJacobian
    /// Reverse the Jacobian transform. If the point is ∞ it returns 0, 0.
    fn affineFromJacobian(&self, x: &Int, y: &Int, z: &Int) -> (Int, Int) {
        if z.Sign() == 0 {
            return (Int::default(), Int::default());
        }

        let mut zinv = Int::default();
        zinv.ModInverse(z, &self.P);
        let mut zinvsq = mul(&zinv, &zinv);

        let mut xOut = mul(x, &zinvsq);
        xOut = modp(&xOut, &self.P);
        zinvsq = mul(&zinvsq, &zinv);
        let mut yOut = mul(y, &zinvsq);
        yOut = modp(&yOut, &self.P);
        return (xOut, yOut);
    }

    // go: sdk 1.25.5 crypto/elliptic/params.go:110-122 CurveParams.Add
    /// Implements [Curve::Add].
    ///
    /// Deprecated: the [CurveParams] methods are deprecated and are not
    /// guaranteed to provide any security property.
    pub fn Add(&self, x1: &Int, y1: &Int, x2: &Int, y2: &Int) -> (Int, Int) {
        // If there is a dedicated constant-time implementation for this
        // curve operation, use that instead of the generic one.
        let (specific, ok) = matchesSpecificCurve(self);
        if ok {
            return specific.unwrap().Add(x1, y1, x2, y2);
        }
        panicIfNotOnCurve(self as &(dyn Curve + Send + Sync), x1, y1);
        panicIfNotOnCurve(self as &(dyn Curve + Send + Sync), x2, y2);

        let z1 = zForAffine(x1, y1);
        let z2 = zForAffine(x2, y2);
        let (x3, y3, z3) = self.addJacobian(x1, y1, &z1, x2, y2, &z2);
        return self.affineFromJacobian(&x3, &y3, &z3);
    }

    // go: sdk 1.25.5 crypto/elliptic/params.go:126-200 CurveParams.addJacobian
    /// Take two points in Jacobian coordinates, (x1, y1, z1) and
    /// (x2, y2, z2), and return their sum, also in Jacobian form.
    fn addJacobian(
        &self,
        x1: &Int,
        y1: &Int,
        z1: &Int,
        x2: &Int,
        y2: &Int,
        z2: &Int,
    ) -> (Int, Int, Int) {
        // See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
        let mut x3 = Int::default();
        let mut y3 = Int::default();
        let mut z3 = Int::default();
        if z1.Sign() == 0 {
            x3.Set(x2);
            y3.Set(y2);
            z3.Set(z2);
            return (x3, y3, z3);
        }
        if z2.Sign() == 0 {
            x3.Set(x1);
            y3.Set(y1);
            z3.Set(z1);
            return (x3, y3, z3);
        }

        let mut z1z1 = mul(z1, z1);
        z1z1 = modp(&z1z1, &self.P);
        let mut z2z2 = mul(z2, z2);
        z2z2 = modp(&z2z2, &self.P);

        let mut u1 = mul(x1, &z2z2);
        u1 = modp(&u1, &self.P);
        let mut u2 = mul(x2, &z1z1);
        u2 = modp(&u2, &self.P);
        let mut h = sub(&u2, &u1);
        let xEqual = h.Sign() == 0;
        if h.Sign() == -1 {
            h = add(&h, &self.P);
        }
        let mut i = lsh(&h, 1);
        i = mul(&i, &i);
        let j = mul(&h, &i);

        let mut s1 = mul(y1, z2);
        s1 = mul(&s1, &z2z2);
        s1 = modp(&s1, &self.P);
        let mut s2 = mul(y2, z1);
        s2 = mul(&s2, &z1z1);
        s2 = modp(&s2, &self.P);
        let mut r = sub(&s2, &s1);
        if r.Sign() == -1 {
            r = add(&r, &self.P);
        }
        let yEqual = r.Sign() == 0;
        if xEqual && yEqual {
            return self.doubleJacobian(x1, y1, z1);
        }
        r = lsh(&r, 1);
        let mut v = mul(&u1, &i);

        x3.Set(&r);
        x3 = mul(&x3, &x3);
        x3 = sub(&x3, &j);
        x3 = sub(&x3, &v);
        x3 = sub(&x3, &v);
        x3 = modp(&x3, &self.P);

        y3.Set(&r);
        v = sub(&v, &x3);
        y3 = mul(&y3, &v);
        s1 = mul(&s1, &j);
        s1 = lsh(&s1, 1);
        y3 = sub(&y3, &s1);
        y3 = modp(&y3, &self.P);

        z3 = add(z1, z2);
        z3 = mul(&z3, &z3);
        z3 = sub(&z3, &z1z1);
        z3 = sub(&z3, &z2z2);
        z3 = mul(&z3, &h);
        z3 = modp(&z3, &self.P);

        return (x3, y3, z3);
    }

    // go: sdk 1.25.5 crypto/elliptic/params.go:208-218 CurveParams.Double
    /// Implements [Curve::Double].
    ///
    /// Deprecated: the [CurveParams] methods are deprecated and are not
    /// guaranteed to provide any security property.
    pub fn Double(&self, x1: &Int, y1: &Int) -> (Int, Int) {
        // If there is a dedicated constant-time implementation for this
        // curve operation, use that instead of the generic one.
        let (specific, ok) = matchesSpecificCurve(self);
        if ok {
            return specific.unwrap().Double(x1, y1);
        }
        panicIfNotOnCurve(self as &(dyn Curve + Send + Sync), x1, y1);

        let z1 = zForAffine(x1, y1);
        let (x3, y3, z3) = self.doubleJacobian(x1, y1, &z1);
        return self.affineFromJacobian(&x3, &y3, &z3);
    }

    // go: sdk 1.25.5 crypto/elliptic/params.go:222-279 CurveParams.doubleJacobian
    /// Take a point in Jacobian coordinates, (x, y, z), and return its
    /// double, also in Jacobian form.
    fn doubleJacobian(&self, x: &Int, y: &Int, z: &Int) -> (Int, Int, Int) {
        // See https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
        let mut delta = mul(z, z);
        delta = modp(&delta, &self.P);
        let mut gamma = mul(y, y);
        gamma = modp(&gamma, &self.P);
        let mut alpha = sub(x, &delta);
        if alpha.Sign() == -1 {
            alpha = add(&alpha, &self.P);
        }
        let mut alpha2 = add(x, &delta);
        alpha = mul(&alpha, &alpha2);
        alpha2.Set(&alpha);
        alpha = lsh(&alpha, 1);
        alpha = add(&alpha, &alpha2);

        // Go: `beta := alpha2.Mul(x, gamma)` — beta and alpha2 are the same
        // object, and alpha2 is dead from here on.
        let mut beta = mul(x, &gamma);

        let mut x3 = mul(&alpha, &alpha);
        let mut beta8 = lsh(&beta, 3);
        beta8 = modp(&beta8, &self.P);
        x3 = sub(&x3, &beta8);
        if x3.Sign() == -1 {
            x3 = add(&x3, &self.P);
        }
        x3 = modp(&x3, &self.P);

        let mut z3 = add(y, z);
        z3 = mul(&z3, &z3);
        z3 = sub(&z3, &gamma);
        if z3.Sign() == -1 {
            z3 = add(&z3, &self.P);
        }
        z3 = sub(&z3, &delta);
        if z3.Sign() == -1 {
            z3 = add(&z3, &self.P);
        }
        z3 = modp(&z3, &self.P);

        beta = lsh(&beta, 2);
        beta = sub(&beta, &x3);
        if beta.Sign() == -1 {
            beta = add(&beta, &self.P);
        }
        // Go: `y3 := alpha.Mul(alpha, beta)` — alpha is dead from here on.
        let mut y3 = mul(&alpha, &beta);

        gamma = mul(&gamma, &gamma);
        gamma = lsh(&gamma, 3);
        gamma = modp(&gamma, &self.P);

        y3 = sub(&y3, &gamma);
        if y3.Sign() == -1 {
            y3 = add(&y3, &self.P);
        }
        y3 = modp(&y3, &self.P);

        return (x3, y3, z3);
    }

    // go: sdk 1.25.5 crypto/elliptic/params.go:287-309 CurveParams.ScalarMult
    /// Implements [Curve::ScalarMult].
    ///
    /// Deprecated: the [CurveParams] methods are deprecated and are not
    /// guaranteed to provide any security property.
    pub fn ScalarMult(&self, Bx: &Int, By: &Int, k: &slice<byte>) -> (Int, Int) {
        // If there is a dedicated constant-time implementation for this
        // curve operation, use that instead of the generic one.
        let (specific, ok) = matchesSpecificCurve(self);
        if ok {
            return specific.unwrap().ScalarMult(Bx, By, k);
        }
        panicIfNotOnCurve(self as &(dyn Curve + Send + Sync), Bx, By);

        let mut Bz = Int::default();
        Bz.SetInt64(1);
        let mut x = Int::default();
        let mut y = Int::default();
        let mut z = Int::default();

        for (_, b) in crate::range!(k) {
            let mut byte = *b;
            let mut bitNum: int = 0;
            while bitNum < 8 {
                let (nx, ny, nz) = self.doubleJacobian(&x, &y, &z);
                x = nx;
                y = ny;
                z = nz;
                if byte & 0x80 == 0x80 {
                    let (nx, ny, nz) = self.addJacobian(Bx, By, &Bz, &x, &y, &z);
                    x = nx;
                    y = ny;
                    z = nz;
                }
                byte <<= 1;
                bitNum += 1;
            }
        }

        return self.affineFromJacobian(&x, &y, &z);
    }

    // go: sdk 1.25.5 crypto/elliptic/params.go:317-325 CurveParams.ScalarBaseMult
    /// Implements [Curve::ScalarBaseMult].
    ///
    /// Deprecated: the [CurveParams] methods are deprecated and are not
    /// guaranteed to provide any security property.
    pub fn ScalarBaseMult(&self, k: &slice<byte>) -> (Int, Int) {
        // If there is a dedicated constant-time implementation for this
        // curve operation, use that instead of the generic one.
        let (specific, ok) = matchesSpecificCurve(self);
        if ok {
            return specific.unwrap().ScalarBaseMult(k);
        }

        let Gx = self.Gx.clone();
        let Gy = self.Gy.clone();
        return self.ScalarMult(&Gx, &Gy, k);
    }
}

// go: sdk 1.25.5 crypto/elliptic/params.go:78-84 zForAffine
/// Return a Jacobian Z value for the affine point (x, y). If x and y are
/// zero, it assumes that they represent the point at infinity because
/// (0, 0) is not on any of the curves handled here.
fn zForAffine(x: &Int, y: &Int) -> Int {
    let mut z = Int::default();
    if x.Sign() != 0 || y.Sign() != 0 {
        z.SetInt64(1);
    }
    return z;
}

// go: sdk 1.25.5 crypto/elliptic/params.go:327-334 matchesSpecificCurve
pub(super) fn matchesSpecificCurve(
    params: &CurveParams,
) -> (Option<&'static (dyn Curve + Send + Sync)>, bool) {
    let all: [&'static (dyn Curve + Send + Sync); 4] = [p224(), p256(), p384(), p521()];
    for c in all {
        if sameParams(params, &c.Params()) {
            return (Some(c), true);
        }
    }
    return (None, false);
}

// go: none — Go compares `params == c.Params()` by pointer. `big::Int`
// implements `PartialEq` only against `nil`, so equality here is spelled
// field by field with `Cmp`.
fn sameParams(a: &CurveParams, b: &CurveParams) -> bool {
    return a.BitSize == b.BitSize
        && a.Name == b.Name
        && a.P.Cmp(&b.P) == 0
        && a.N.Cmp(&b.N) == 0
        && a.B.Cmp(&b.B) == 0
        && a.Gx.Cmp(&b.Gx) == 0
        && a.Gy.Cmp(&b.Gy) == 0;
}

// go: none — Go's `new(big.Int).Mul(x, y)`. goish's `Int::Mul` takes
// `&mut self`, so the allocate-and-multiply idiom needs a name.
fn mul(x: &Int, y: &Int) -> Int {
    let mut z = Int::default();
    z.Mul(x, y);
    return z;
}

// go: none — `new(big.Int).Add(x, y)`.
fn add(x: &Int, y: &Int) -> Int {
    let mut z = Int::default();
    z.Add(x, y);
    return z;
}

// go: none — `new(big.Int).Sub(x, y)`.
fn sub(x: &Int, y: &Int) -> Int {
    let mut z = Int::default();
    z.Sub(x, y);
    return z;
}

// go: none — `new(big.Int).Lsh(x, n)`.
fn lsh(x: &Int, n: uint) -> Int {
    let mut z = Int::default();
    z.Lsh(x, n);
    return z;
}

// go: none — `z.Mod(z, p)`, which aliases receiver and operand.
fn modp(x: &Int, p: &Int) -> Int {
    let mut z = Int::default();
    z.Mod(x, p);
    return z;
}

// go: none — Go's `*CurveParams` satisfies `Curve` structurally. Rust
// needs the impl written out, forwarding to the inherent methods above,
// plus the two Any hooks every `#[goish::interface]` concrete impl
// overrides so `cast!` can reach the type.
impl Curve for CurveParams {
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn Params(&self) -> CurveParams {
        return CurveParams::Params(self);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn IsOnCurve(&self, x: &Int, y: &Int) -> bool {
        return CurveParams::IsOnCurve(self, x, y);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn Add(&self, x1: &Int, y1: &Int, x2: &Int, y2: &Int) -> (Int, Int) {
        return CurveParams::Add(self, x1, y1, x2, y2);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn Double(&self, x1: &Int, y1: &Int) -> (Int, Int) {
        return CurveParams::Double(self, x1, y1);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn ScalarMult(&self, x1: &Int, y1: &Int, k: &slice<byte>) -> (Int, Int) {
        return CurveParams::ScalarMult(self, x1, y1, k);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn ScalarBaseMult(&self, k: &slice<byte>) -> (Int, Int) {
        return CurveParams::ScalarBaseMult(self, k);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}
