// crypto/internal/fips140/edwards25519 — the edwards25519 curve, used
// by crypto/ed25519.
//
// Faithful port of Go 1.25.5's
// crypto/internal/fips140/edwards25519. The `field` sub-package
// (GF(2^255-19) arithmetic) and `scalar` (mod-l arithmetic) are
// submodules; this package root holds `Point` (extended coordinates),
// the internal coordinate types, addition / doubling formulae, and
// constant- / variable-time scalar multiplication.
//
// goish notes:
//   * Go methods return `*Point` for chaining; goish returns
//     `&mut Self`. All arguments and receivers may alias — mutating
//     methods snapshot their inputs before writing the receiver where
//     a `p.Add(p, q)` style call could otherwise corrupt data.
//   * Go's `(*Point).SetBytes` returns `(*Point, error)`; goish returns
//     `error`, with the receiver itself as the result (matching the
//     `field::Element` / `scalar::Scalar` convention).
//   * `Point`'s internal `field::Element` coordinates never appear in a
//     public signature. `SetBytes` / `Bytes` use `slice<byte>`.
//   * Go's `incomparable` (`[0]func()`) exists to make `Point` reject
//     `==`. Rust needs no such marker: `Point` simply does not derive
//     `PartialEq`, and `Equal` is the only comparison.
//     goishlint:ignore GOISH021 incomparable — no Rust equivalent needed
//   * Go's package-level `var feOne` is built once at init. goish has no
//     lazily-initialised immutable static, so `SetBytes` constructs it
//     locally — the same value, at the only call site that reads it.
//     goishlint:ignore GOISH021 feOne — function-local, see above
//   * Go precomputes the fixed-base `basepointTable` lazily via
//     `sync.Once`. goish has no process-wide mutable static here, so
//     `ScalarBaseMult` / `VarTimeDoubleScalarBaseMult` build the table
//     on each call. The table values are identical; only the one-time
//     amortisation is dropped (noted, behaviour is unchanged).
//   * Constant-time discipline preserved verbatim: `SelectInto` is a
//     branch-free masked select over every table entry; only
//     `VarTimeDoubleScalarBaseMult` (and the NAF tables) is variable
//     time, exactly as in Go.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use super::field;
use super::scalar::*;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::types::{byte, int};
use field::Element;

// ─── ConstantTimeByteEq (Go: crypto/internal/fips140/subtle) ──────────
// edwards25519 needs only this one subtle primitive; ported inline.

/// `ConstantTimeByteEq` returns 1 if x == y and 0 otherwise.
fn ConstantTimeByteEq(x: u8, y: u8) -> int {
    let v = u32::from(x ^ y).wrapping_sub(1) >> 31;
    int::from(v)
}

// ─── coordinate types ─────────────────────────────────────────────────

/// `projP1xP1` — a point in P1xP1 (completed) coordinates.
#[derive(Clone, Copy, Default)]
struct projP1xP1 {
    X: Element,
    Y: Element,
    Z: Element,
    T: Element,
}

/// `projP2` — a point in P2 (projective) coordinates.
#[derive(Clone, Copy, Default)]
struct projP2 {
    X: Element,
    Y: Element,
    Z: Element,
}

/// `Point` represents a point on the edwards25519 curve.
///
/// This type works similarly to math/big.Int, and all arguments and
/// receivers are allowed to alias.
///
/// The point is internally represented in extended coordinates
/// (X, Y, Z, T) where x = X/Z, y = Y/Z, and xy = T/Z per
/// https://eprint.iacr.org/2008/522.
///
/// The zero value is NOT valid, and it may be used only as a receiver.
#[derive(Clone, Copy, Default)]
pub struct Point {
    x: Element,
    y: Element,
    z: Element,
    t: Element,
}

/// `projCached` — a cached point for variable-base addition.
#[derive(Clone, Copy, Default)]
struct projCached {
    YplusX: Element,
    YminusX: Element,
    Z: Element,
    T2d: Element,
}

/// `affineCached` — a cached affine point for fixed-base addition.
#[derive(Clone, Copy, Default)]
struct affineCached {
    YplusX: Element,
    YminusX: Element,
    T2d: Element,
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:41-47 checkInitialized
/// `checkInitialized` panics if any point has a zero-valued (x, y).
fn checkInitialized(points: &[&Point]) {
    let zero = Element::new();
    for p in points {
        if p.x.rawEqual(&zero) && p.y.rawEqual(&zero) {
            panic!("edwards25519: use of uninitialized Point");
        }
    }
}

// ─── constructors ─────────────────────────────────────────────────────

impl projP2 {
    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:59-64 projP2.Zero
    /// `Zero` sets v to the identity in P2 coordinates.
    fn Zero(&mut self) -> &mut projP2 {
        self.X.Zero();
        self.Y.One();
        self.Z.One();
        self
    }
}

/// `identityBytes` — the encoding of the point at infinity.
const identityBytes: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// `generatorBytes` — the encoding of the canonical curve basepoint.
const generatorBytes: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// `fixed_bytes` — wrap a 32-byte literal as a `slice<byte>`.
fn fixed_bytes(b: &[u8; 32]) -> slice<byte> {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(32);
    for &x in b.iter() {
        v.push(x);
    }
    slice::<byte>::__from_vec(v)
}

/// `identity` — a fresh Point set to the point at infinity.
fn identity() -> Point {
    let mut p = Point::default();
    let err = p.SetBytes(fixed_bytes(&identityBytes));
    if err != crate::nil {
        panic!("edwards25519: bad identity encoding");
    }
    p
}

/// `generator` — a fresh Point set to the canonical curve basepoint.
fn generator() -> Point {
    let mut p = Point::default();
    let err = p.SetBytes(fixed_bytes(&generatorBytes));
    if err != crate::nil {
        panic!("edwards25519: bad generator encoding");
    }
    p
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:72-74 NewIdentityPoint
/// `NewIdentityPoint` returns a new Point set to the identity.
pub fn NewIdentityPoint() -> Point {
    identity()
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:85-87 NewGeneratorPoint
/// `NewGeneratorPoint` returns a new Point set to the canonical generator.
pub fn NewGeneratorPoint() -> Point {
    generator()
}

impl projCached {
    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:89-95 projCached.Zero
    /// `Zero` sets v to the identity in cached coordinates.
    fn Zero(&mut self) -> &mut projCached {
        self.YplusX.One();
        self.YminusX.One();
        self.Z.One();
        self.T2d.Zero();
        self
    }
}

impl affineCached {
    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:97-102 affineCached.Zero
    /// `Zero` sets v to the identity in affine cached coordinates.
    fn Zero(&mut self) -> &mut affineCached {
        self.YplusX.One();
        self.YminusX.One();
        self.T2d.Zero();
        self
    }
}

// ─── curve constant d ─────────────────────────────────────────────────

/// `dBytes` — the encoding of the curve constant `d`.
const dBytes: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];

/// `d` — the curve constant in the edwards25519 equation.
fn d() -> Element {
    let mut e = Element::new();
    let err = e.SetBytes(fixed_bytes(&dBytes));
    if err != crate::nil {
        panic!("edwards25519: bad d encoding");
    }
    e
}

/// `d2` — 2*d.
fn d2() -> Element {
    let dd = d();
    let mut e = Element::new();
    e.Add(&dd, &dd);
    e
}

// ─── assignments ──────────────────────────────────────────────────────

impl Point {
    /// `new(Point)` — a fresh (uninitialised) zero Point.
    pub fn new() -> Self {
        Point::default()
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:107-110 Point.Set
    /// `Set` sets v = u, and returns v.
    pub fn Set(&mut self, u: &Point) -> &mut Point {
        *self = *u;
        self
    }

    // ─── encoding ─────────────────────────────────────────────────────

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:116-121 Point.Bytes
    /// `Bytes` returns the canonical 32-byte encoding of v, according to
    /// RFC 8032, Section 5.1.2.
    pub fn Bytes(&self) -> slice<byte> {
        checkInitialized(&[self]);

        let mut zInv = Element::new();
        let mut x = Element::new();
        let mut y = Element::new();
        zInv.Invert(&self.z); // zInv = 1 / Z
        x.Multiply(&self.x, &zInv); // x = X / Z
        y.Multiply(&self.y, &zInv); // y = Y / Z

        let mut buf = [0u8; 32];
        let out = copyFieldElement(&mut buf, &y);
        let neg = x.IsNegative();
        let signbit: u8 = u8::try_from(neg).unwrap() << 7;
        out[31] |= signbit;

        let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(32);
        for &b in out.iter() {
            v.push(b);
        }
        slice::<byte>::__from_vec(v)
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:145-187 Point.SetBytes
    /// `SetBytes` sets v = x, where x is a 32-byte encoding of v. If x
    /// does not represent a valid point on the curve, SetBytes returns
    /// an error and the receiver is unchanged. Otherwise SetBytes
    /// returns nil and v is the decoded point.
    ///
    /// Note that SetBytes accepts all non-canonical encodings of valid
    /// points. That is, it follows decoding rules that match most
    /// implementations in the ecosystem rather than RFC 8032.
    pub fn SetBytes(&mut self, x: slice<byte>) -> error {
        // -x² + y² = 1 + dx²y²
        // x² + dx²y² = x²(dy² + 1) = y² - 1
        // x² = (y² - 1) / (dy² + 1)

        let mut y = Element::new();
        let err = y.SetBytes(x.clone());
        if err != crate::nil {
            return errors::New("edwards25519: invalid point encoding length");
        }

        let feOne = {
            let mut e = Element::new();
            e.One();
            e
        };

        // u = y² - 1
        let mut y2 = Element::new();
        y2.Square(&y);
        let mut u = Element::new();
        u.Subtract(&y2, &feOne);

        // v = dy² + 1
        let dd = d();
        let mut vv = Element::new();
        vv.Multiply(&y2, &dd);
        let vvCopy = vv;
        vv.Add(&vvCopy, &feOne);

        // x = +√(u/v)
        let mut xx = Element::new();
        let wasSquare = xx.SqrtRatio(&u, &vv);
        if wasSquare == 0 {
            return errors::New("edwards25519: invalid point encoding");
        }

        // Select the negative square root if the sign bit is set.
        let mut xxNeg = Element::new();
        xxNeg.Negate(&xx);
        let xxPos = xx;
        let signbit = int::from(x[31] >> 7);
        xx.Select(&xxNeg, &xxPos, signbit);

        self.x.Set(&xx);
        self.y.Set(&y);
        self.z.One();
        self.t.Multiply(&xx, &y); // xy = T / Z

        errors::nil
    }

    // ─── conversions ──────────────────────────────────────────────────

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:210-216 Point.fromP1xP1
    /// `fromP1xP1` sets v from a P1xP1 point.
    fn fromP1xP1(&mut self, p: &projP1xP1) -> &mut Point {
        self.x.Multiply(&p.X, &p.T);
        self.y.Multiply(&p.Y, &p.Z);
        self.z.Multiply(&p.Z, &p.T);
        self.t.Multiply(&p.X, &p.Y);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:218-224 Point.fromP2
    /// `fromP2` sets v from a P2 point.
    fn fromP2(&mut self, p: &projP2) -> &mut Point {
        self.x.Multiply(&p.X, &p.Z);
        self.y.Multiply(&p.Y, &p.Z);
        self.z.Square(&p.Z);
        self.t.Multiply(&p.X, &p.Y);
        self
    }

    // ─── (re)addition and subtraction ─────────────────────────────────

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:258-263 Point.Add
    /// `Add` sets v = p + q, and returns v.
    pub fn Add(&mut self, p: &Point, q: &Point) -> &mut Point {
        checkInitialized(&[p, q]);
        let mut qCached = projCached::default();
        qCached.FromP3(q);
        let mut result = projP1xP1::default();
        result.Add(p, &qCached);
        self.fromP1xP1(&result)
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:266-271 Point.Subtract
    /// `Subtract` sets v = p - q, and returns v.
    pub fn Subtract(&mut self, p: &Point, q: &Point) -> &mut Point {
        checkInitialized(&[p, q]);
        let mut qCached = projCached::default();
        qCached.FromP3(q);
        let mut result = projP1xP1::default();
        result.Sub(p, &qCached);
        self.fromP1xP1(&result)
    }

    // ─── negation ─────────────────────────────────────────────────────

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:374-381 Point.Negate
    /// `Negate` sets v = -p, and returns v.
    pub fn Negate(&mut self, p: &Point) -> &mut Point {
        checkInitialized(&[p]);
        // Snapshot p in case it aliases the receiver.
        let pCopy = *p;
        self.x.Negate(&pCopy.x);
        self.y.Set(&pCopy.y);
        self.z.Set(&pCopy.z);
        self.t.Negate(&pCopy.t);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:384-394 Point.Equal
    /// `Equal` returns 1 if v is equivalent to u, and 0 otherwise.
    pub fn Equal(&self, u: &Point) -> int {
        checkInitialized(&[self, u]);

        let mut t1 = Element::new();
        let mut t2 = Element::new();
        let mut t3 = Element::new();
        let mut t4 = Element::new();
        t1.Multiply(&self.x, &u.z);
        t2.Multiply(&u.x, &self.z);
        t3.Multiply(&self.y, &u.z);
        t4.Multiply(&u.y, &self.z);

        t1.Equal(&t2) & t3.Equal(&t4)
    }

    /// `MultByCofactor` sets v = 8 * p, and returns v.
    pub fn MultByCofactor(&mut self, p: &Point) -> &mut Point {
        checkInitialized(&[p]);
        let mut result = projP1xP1::default();
        let mut pp = projP2::default();
        pp.FromP3(p);
        result.Double(&pp);
        let r0 = result;
        pp.FromP1xP1(&r0);
        result.Double(&pp);
        let r1 = result;
        pp.FromP1xP1(&r1);
        result.Double(&pp);
        self.fromP1xP1(&result)
    }
}

// ─── coordinate conversions ───────────────────────────────────────────

impl projP2 {
    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:196-201 projP2.FromP1xP1
    /// `FromP1xP1` sets v from a P1xP1 point.
    fn FromP1xP1(&mut self, p: &projP1xP1) -> &mut projP2 {
        self.X.Multiply(&p.X, &p.T);
        self.Y.Multiply(&p.Y, &p.Z);
        self.Z.Multiply(&p.Z, &p.T);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:203-208 projP2.FromP3
    /// `FromP3` sets v from an extended-coordinate Point.
    fn FromP3(&mut self, p: &Point) -> &mut projP2 {
        self.X.Set(&p.x);
        self.Y.Set(&p.y);
        self.Z.Set(&p.z);
        self
    }
}

impl projCached {
    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:234-240 projCached.FromP3
    /// `FromP3` sets v from an extended-coordinate Point.
    fn FromP3(&mut self, p: &Point) -> &mut projCached {
        self.YplusX.Add(&p.y, &p.x);
        self.YminusX.Subtract(&p.y, &p.x);
        self.Z.Set(&p.z);
        self.T2d.Multiply(&p.t, &d2());
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:399-405 projCached.Select
    /// `Select` sets v to a if cond == 1 and to b if cond == 0.
    fn Select(&mut self, a: &projCached, b: &projCached, cond: int) -> &mut projCached {
        self.YplusX.Select(&a.YplusX, &b.YplusX, cond);
        self.YminusX.Select(&a.YminusX, &b.YminusX, cond);
        self.Z.Select(&a.Z, &b.Z, cond);
        self.T2d.Select(&a.T2d, &b.T2d, cond);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:416-420 projCached.CondNeg
    /// `CondNeg` negates v if cond == 1 and leaves it unchanged otherwise.
    fn CondNeg(&mut self, cond: int) -> &mut projCached {
        // Snapshot YminusX before the swap aliases it.
        let mut ymx = self.YminusX;
        self.YplusX.Swap(&mut ymx, cond);
        self.YminusX = ymx;
        let mut negT2d = Element::new();
        negT2d.Negate(&self.T2d);
        let t2dCopy = self.T2d;
        self.T2d.Select(&negT2d, &t2dCopy, cond);
        self
    }
}

impl affineCached {
    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:242-253 affineCached.FromP3
    /// `FromP3` sets v from an extended-coordinate Point.
    fn FromP3(&mut self, p: &Point) -> &mut affineCached {
        self.YplusX.Add(&p.y, &p.x);
        self.YminusX.Subtract(&p.y, &p.x);
        self.T2d.Multiply(&p.t, &d2());

        let mut invZ = Element::new();
        invZ.Invert(&p.z);
        let ypx = self.YplusX;
        self.YplusX.Multiply(&ypx, &invZ);
        let ymx = self.YminusX;
        self.YminusX.Multiply(&ymx, &invZ);
        let t2d = self.T2d;
        self.T2d.Multiply(&t2d, &invZ);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:408-413 affineCached.Select
    /// `Select` sets v to a if cond == 1 and to b if cond == 0.
    fn Select(&mut self, a: &affineCached, b: &affineCached, cond: int) -> &mut affineCached {
        self.YplusX.Select(&a.YplusX, &b.YplusX, cond);
        self.YminusX.Select(&a.YminusX, &b.YminusX, cond);
        self.T2d.Select(&a.T2d, &b.T2d, cond);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:423-427 affineCached.CondNeg
    /// `CondNeg` negates v if cond == 1 and leaves it unchanged otherwise.
    fn CondNeg(&mut self, cond: int) -> &mut affineCached {
        let mut ymx = self.YminusX;
        self.YplusX.Swap(&mut ymx, cond);
        self.YminusX = ymx;
        let mut negT2d = Element::new();
        negT2d.Negate(&self.T2d);
        let t2dCopy = self.T2d;
        self.T2d.Select(&negT2d, &t2dCopy, cond);
        self
    }
}

// ─── group addition / doubling formulae ───────────────────────────────

impl projP1xP1 {
    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:273-291 projP1xP1.Add
    /// `Add` sets v = p + q (q in cached coordinates).
    fn Add(&mut self, p: &Point, q: &projCached) -> &mut projP1xP1 {
        let mut YplusX = Element::new();
        let mut YminusX = Element::new();
        let mut PP = Element::new();
        let mut MM = Element::new();
        let mut TT2d = Element::new();
        let mut ZZ2 = Element::new();

        YplusX.Add(&p.y, &p.x);
        YminusX.Subtract(&p.y, &p.x);

        PP.Multiply(&YplusX, &q.YplusX);
        MM.Multiply(&YminusX, &q.YminusX);
        TT2d.Multiply(&p.t, &q.T2d);
        ZZ2.Multiply(&p.z, &q.Z);

        let zz2Copy = ZZ2;
        ZZ2.Add(&zz2Copy, &zz2Copy);

        self.X.Subtract(&PP, &MM);
        self.Y.Add(&PP, &MM);
        self.Z.Add(&ZZ2, &TT2d);
        self.T.Subtract(&ZZ2, &TT2d);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:293-311 projP1xP1.Sub
    /// `Sub` sets v = p - q (q in cached coordinates).
    fn Sub(&mut self, p: &Point, q: &projCached) -> &mut projP1xP1 {
        let mut YplusX = Element::new();
        let mut YminusX = Element::new();
        let mut PP = Element::new();
        let mut MM = Element::new();
        let mut TT2d = Element::new();
        let mut ZZ2 = Element::new();

        YplusX.Add(&p.y, &p.x);
        YminusX.Subtract(&p.y, &p.x);

        PP.Multiply(&YplusX, &q.YminusX); // flipped sign
        MM.Multiply(&YminusX, &q.YplusX); // flipped sign
        TT2d.Multiply(&p.t, &q.T2d);
        ZZ2.Multiply(&p.z, &q.Z);

        let zz2Copy = ZZ2;
        ZZ2.Add(&zz2Copy, &zz2Copy);

        self.X.Subtract(&PP, &MM);
        self.Y.Add(&PP, &MM);
        self.Z.Subtract(&ZZ2, &TT2d); // flipped sign
        self.T.Add(&ZZ2, &TT2d); // flipped sign
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:313-330 projP1xP1.AddAffine
    /// `AddAffine` sets v = p + q (q in affine cached coordinates).
    fn AddAffine(&mut self, p: &Point, q: &affineCached) -> &mut projP1xP1 {
        let mut YplusX = Element::new();
        let mut YminusX = Element::new();
        let mut PP = Element::new();
        let mut MM = Element::new();
        let mut TT2d = Element::new();
        let mut Z2 = Element::new();

        YplusX.Add(&p.y, &p.x);
        YminusX.Subtract(&p.y, &p.x);

        PP.Multiply(&YplusX, &q.YplusX);
        MM.Multiply(&YminusX, &q.YminusX);
        TT2d.Multiply(&p.t, &q.T2d);

        Z2.Add(&p.z, &p.z);

        self.X.Subtract(&PP, &MM);
        self.Y.Add(&PP, &MM);
        self.Z.Add(&Z2, &TT2d);
        self.T.Subtract(&Z2, &TT2d);
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:332-349 projP1xP1.SubAffine
    /// `SubAffine` sets v = p - q (q in affine cached coordinates).
    fn SubAffine(&mut self, p: &Point, q: &affineCached) -> &mut projP1xP1 {
        let mut YplusX = Element::new();
        let mut YminusX = Element::new();
        let mut PP = Element::new();
        let mut MM = Element::new();
        let mut TT2d = Element::new();
        let mut Z2 = Element::new();

        YplusX.Add(&p.y, &p.x);
        YminusX.Subtract(&p.y, &p.x);

        PP.Multiply(&YplusX, &q.YminusX); // flipped sign
        MM.Multiply(&YminusX, &q.YplusX); // flipped sign
        TT2d.Multiply(&p.t, &q.T2d);

        Z2.Add(&p.z, &p.z);

        self.X.Subtract(&PP, &MM);
        self.Y.Add(&PP, &MM);
        self.Z.Subtract(&Z2, &TT2d); // flipped sign
        self.T.Add(&Z2, &TT2d); // flipped sign
        self
    }

    // go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:353-369 projP1xP1.Double
    /// `Double` sets v = 2 * p (p in P2 coordinates).
    fn Double(&mut self, p: &projP2) -> &mut projP1xP1 {
        let mut XX = Element::new();
        let mut YY = Element::new();
        let mut ZZ2 = Element::new();
        let mut XplusYsq = Element::new();

        XX.Square(&p.X);
        YY.Square(&p.Y);
        ZZ2.Square(&p.Z);
        let zz2Copy = ZZ2;
        ZZ2.Add(&zz2Copy, &zz2Copy);
        XplusYsq.Add(&p.X, &p.Y);
        let xpyCopy = XplusYsq;
        XplusYsq.Square(&xpyCopy);

        self.Y.Add(&YY, &XX);
        self.Z.Subtract(&YY, &XX);

        let vy = self.Y;
        self.X.Subtract(&XplusYsq, &vy);
        let vz = self.Z;
        self.T.Subtract(&ZZ2, &vz);
        self
    }
}

// ─── lookup tables (Go: tables.go) ─────────────────────────────────────

/// `projLookupTable` — a dynamic table for variable-base constant-time
/// scalar muls.
struct projLookupTable {
    points: [projCached; 8],
}

/// `affineLookupTable` — a precomputed table for fixed-base
/// constant-time scalar muls.
struct affineLookupTable {
    points: [affineCached; 8],
}

/// `nafLookupTable5` — a dynamic table for variable-base, variable-time
/// scalar muls.
struct nafLookupTable5 {
    points: [projCached; 8],
}

/// `nafLookupTable8` — a precomputed table for fixed-base,
/// variable-time scalar muls.
struct nafLookupTable8 {
    points: [affineCached; 64],
}

impl projLookupTable {
    /// `FromP3` builds a lookup table at runtime (fast).
    fn FromP3(&mut self, q: &Point) {
        // v.points[i] = (i+1)*Q, i.e. Q, 2Q, ..., 8Q.
        self.points[0].FromP3(q);
        let mut tmpP3 = Point::default();
        let mut tmpP1xP1 = projP1xP1::default();
        for i in 0..7usize {
            let prev = self.points[i];
            tmpP1xP1.Add(q, &prev);
            tmpP3.fromP1xP1(&tmpP1xP1);
            self.points[i + 1].FromP3(&tmpP3);
        }
    }

    /// `SelectInto` sets dest to x*Q for -8 <= x <= 8, in constant time.
    fn SelectInto(&self, dest: &mut projCached, x: i8) {
        // Compute xabs = |x|.
        let xmask = x >> 7;
        let xabs: u8 = ((x.wrapping_add(xmask)) ^ xmask).to_le_bytes()[0];

        dest.Zero();
        for j in 1..=8i32 {
            // Set dest = j*Q if |x| = j.
            let cond = ConstantTimeByteEq(xabs, u8::try_from(j).unwrap());
            let destCopy = *dest;
            dest.Select(
                &self.points[usize::try_from(j - 1).unwrap()],
                &destCopy,
                cond,
            );
        }
        // Now dest = |x|*Q, conditionally negate to get x*Q.
        dest.CondNeg(int::from(xmask & 1));
    }
}

impl affineLookupTable {
    /// `FromP3` builds the table from q (not optimised for speed).
    fn FromP3(&mut self, q: &Point) {
        self.points[0].FromP3(q);
        let mut tmpP3 = Point::default();
        let mut tmpP1xP1 = projP1xP1::default();
        for i in 0..7usize {
            let prev = self.points[i];
            tmpP1xP1.AddAffine(q, &prev);
            tmpP3.fromP1xP1(&tmpP1xP1);
            self.points[i + 1].FromP3(&tmpP3);
        }
    }

    /// `SelectInto` sets dest to x*Q for -8 <= x <= 8, in constant time.
    fn SelectInto(&self, dest: &mut affineCached, x: i8) {
        let xmask = x >> 7;
        let xabs: u8 = ((x.wrapping_add(xmask)) ^ xmask).to_le_bytes()[0];

        dest.Zero();
        for j in 1..=8i32 {
            let cond = ConstantTimeByteEq(xabs, u8::try_from(j).unwrap());
            let destCopy = *dest;
            dest.Select(
                &self.points[usize::try_from(j - 1).unwrap()],
                &destCopy,
                cond,
            );
        }
        dest.CondNeg(int::from(xmask & 1));
    }
}

impl nafLookupTable5 {
    /// `FromP3` builds a lookup table at runtime (fast).
    fn FromP3(&mut self, q: &Point) {
        // v.points[i] = (2*i+1)*Q, i.e. Q, 3Q, 5Q, ..., 15Q.
        self.points[0].FromP3(q);
        let mut q2 = Point::default();
        q2.Add(q, q);
        let mut tmpP3 = Point::default();
        let mut tmpP1xP1 = projP1xP1::default();
        for i in 0..7usize {
            let prev = self.points[i];
            tmpP1xP1.Add(&q2, &prev);
            tmpP3.fromP1xP1(&tmpP1xP1);
            self.points[i + 1].FromP3(&tmpP3);
        }
    }

    /// `SelectInto` returns x*Q for odd 0 < x < 2^4 (variable time).
    fn SelectInto(&self, dest: &mut projCached, x: i8) {
        let idx = usize::try_from(x / 2).unwrap();
        *dest = self.points[idx];
    }
}

impl nafLookupTable8 {
    /// `FromP3` builds the table from q (not optimised for speed).
    fn FromP3(&mut self, q: &Point) {
        self.points[0].FromP3(q);
        let mut q2 = Point::default();
        q2.Add(q, q);
        let mut tmpP3 = Point::default();
        let mut tmpP1xP1 = projP1xP1::default();
        for i in 0..63usize {
            let prev = self.points[i];
            tmpP1xP1.AddAffine(&q2, &prev);
            tmpP3.fromP1xP1(&tmpP1xP1);
            self.points[i + 1].FromP3(&tmpP3);
        }
    }

    /// `SelectInto` returns x*Q for odd 0 < x < 2^7 (variable time).
    fn SelectInto(&self, dest: &mut affineCached, x: i8) {
        let idx = usize::try_from(x / 2).unwrap();
        *dest = self.points[idx];
    }
}

/// `basepointTable` builds the set of 32 affineLookupTables, where
/// table i is generated from 256^i * basepoint.
///
/// Go precomputes this lazily via `sync.Once`; goish rebuilds it on
/// each call (same values, only the one-time caching is dropped).
fn basepointTable() -> alloc::boxed::Box<[affineLookupTable; 32]> {
    let mut table: alloc::vec::Vec<affineLookupTable> = alloc::vec::Vec::with_capacity(32);
    for _ in 0..32 {
        table.push(affineLookupTable {
            points: [affineCached::default(); 8],
        });
    }
    let mut p = NewGeneratorPoint();
    for i in 0..32usize {
        table[i].FromP3(&p);
        for _ in 0..8 {
            let pCopy = p;
            p.Add(&pCopy, &pCopy);
        }
    }
    let boxed: alloc::boxed::Box<[affineLookupTable]> = table.into_boxed_slice();
    // SAFETY-free: length is exactly 32 by construction.
    alloc::boxed::Box::<[affineLookupTable; 32]>::try_from(boxed)
        .unwrap_or_else(|_| panic!("edwards25519: basepointTable length mismatch"))
}

/// `basepointNafTable` builds the nafLookupTable8 for the basepoint.
fn basepointNafTable() -> alloc::boxed::Box<nafLookupTable8> {
    let mut t = alloc::boxed::Box::new(nafLookupTable8 {
        points: [affineCached::default(); 64],
    });
    t.FromP3(&NewGeneratorPoint());
    t
}

// ─── scalar multiplication (Go: scalarmult.go) ─────────────────────────

impl Point {
    /// `ScalarBaseMult` sets v = x * B, where B is the canonical
    /// generator, and returns v.
    ///
    /// The scalar multiplication is done in constant time.
    pub fn ScalarBaseMult(&mut self, x: &Scalar) -> &mut Point {
        let basepointTable = basepointTable();

        // Write x = sum(x_i * 16^i) so x*B = sum(B*x_i*16^i).
        let digits = x.signedRadix16();

        let mut multiple = affineCached::default();
        let mut tmp1 = projP1xP1::default();
        let mut tmp2 = projP2::default();

        // Accumulate the odd components first.
        self.Set(&NewIdentityPoint());
        let mut i = 1usize;
        while i < 64 {
            basepointTable[i / 2].SelectInto(&mut multiple, digits[i]);
            tmp1.AddAffine(self, &multiple);
            self.fromP1xP1(&tmp1);
            i += 2;
        }

        // Multiply by 16.
        tmp2.FromP3(self);
        tmp1.Double(&tmp2);
        let t1a = tmp1;
        tmp2.FromP1xP1(&t1a);
        tmp1.Double(&tmp2);
        let t1b = tmp1;
        tmp2.FromP1xP1(&t1b);
        tmp1.Double(&tmp2);
        let t1c = tmp1;
        tmp2.FromP1xP1(&t1c);
        tmp1.Double(&tmp2);
        self.fromP1xP1(&tmp1);

        // Accumulate the even components.
        let mut i = 0usize;
        while i < 64 {
            basepointTable[i / 2].SelectInto(&mut multiple, digits[i]);
            tmp1.AddAffine(self, &multiple);
            self.fromP1xP1(&tmp1);
            i += 2;
        }

        self
    }

    /// `ScalarMult` sets v = x * q, and returns v.
    ///
    /// The scalar multiplication is done in constant time.
    pub fn ScalarMult(&mut self, x: &Scalar, q: &Point) -> &mut Point {
        checkInitialized(&[q]);

        let mut table = projLookupTable {
            points: [projCached::default(); 8],
        };
        table.FromP3(q);

        // Write x = sum(x_i * 16^i) so x*Q = sum(Q*x_i*16^i).
        let digits = x.signedRadix16();

        // Unwrap the first loop iteration to skip computing 16*identity.
        let mut multiple = projCached::default();
        let mut tmp1 = projP1xP1::default();
        let mut tmp2 = projP2::default();
        table.SelectInto(&mut multiple, digits[63]);

        self.Set(&NewIdentityPoint());
        tmp1.Add(self, &multiple); // tmp1 = x_63*Q
        let mut i: int = 62;
        while i >= 0 {
            let ti = usize::try_from(i).unwrap();
            tmp2.FromP1xP1(&tmp1);
            tmp1.Double(&tmp2);
            let t1a = tmp1;
            tmp2.FromP1xP1(&t1a);
            tmp1.Double(&tmp2);
            let t1b = tmp1;
            tmp2.FromP1xP1(&t1b);
            tmp1.Double(&tmp2);
            let t1c = tmp1;
            tmp2.FromP1xP1(&t1c);
            tmp1.Double(&tmp2);
            self.fromP1xP1(&tmp1);
            table.SelectInto(&mut multiple, digits[ti]);
            tmp1.Add(self, &multiple);
            i -= 1;
        }
        self.fromP1xP1(&tmp1);
        self
    }

    /// `VarTimeDoubleScalarBaseMult` sets v = a * A + b * B, where B is
    /// the canonical generator, and returns v.
    ///
    /// Execution time depends on the inputs.
    pub fn VarTimeDoubleScalarBaseMult(&mut self, a: &Scalar, A: &Point, b: &Scalar) -> &mut Point {
        checkInitialized(&[A]);

        let basepointNafTable = basepointNafTable();
        let mut aTable = nafLookupTable5 {
            points: [projCached::default(); 8],
        };
        aTable.FromP3(A);
        // The basepoint is fixed, so use a wider NAF / bigger table.
        let aNaf = a.nonAdjacentForm(5);
        let bNaf = b.nonAdjacentForm(8);

        // Find the first nonzero coefficient.
        let mut i: int = 255;
        let mut j: int = i;
        while j >= 0 {
            let ji = usize::try_from(j).unwrap();
            if aNaf[ji] != 0 || bNaf[ji] != 0 {
                break;
            }
            j -= 1;
        }
        i = j;

        let mut multA = projCached::default();
        let mut multB = affineCached::default();
        let mut tmp1 = projP1xP1::default();
        let mut tmp2 = projP2::default();
        tmp2.Zero();

        // Move from high to low bits, doubling at each step.
        while i >= 0 {
            let ii = usize::try_from(i).unwrap();
            tmp1.Double(&tmp2);

            // Only update v if we have a nonzero coeff to add in.
            if aNaf[ii] > 0 {
                self.fromP1xP1(&tmp1);
                aTable.SelectInto(&mut multA, aNaf[ii]);
                tmp1.Add(self, &multA);
            } else if aNaf[ii] < 0 {
                self.fromP1xP1(&tmp1);
                aTable.SelectInto(&mut multA, -aNaf[ii]);
                tmp1.Sub(self, &multA);
            }

            if bNaf[ii] > 0 {
                self.fromP1xP1(&tmp1);
                basepointNafTable.SelectInto(&mut multB, bNaf[ii]);
                tmp1.AddAffine(self, &multB);
            } else if bNaf[ii] < 0 {
                self.fromP1xP1(&tmp1);
                basepointNafTable.SelectInto(&mut multB, -bNaf[ii]);
                tmp1.SubAffine(self, &multB);
            }

            tmp2.FromP1xP1(&tmp1);
            i -= 1;
        }

        self.fromP2(&tmp2);
        self
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/edwards25519/edwards25519.go:189-192 copyFieldElement
//
// Go returns `buf[:]`, a slice aliasing the caller's array, so that
// `bytes` can then set the sign bit in place. goish returns the same
// borrow, which the compiler can check.
fn copyFieldElement<'a>(buf: &'a mut [u8; 32], v: &Element) -> &'a mut [u8; 32] {
    let vb = v.Bytes();
    let mut i: int = 0;
    while i < 32 {
        buf[i as usize] = vb[i];
        i += 1;
    }
    return buf;
}
