// go: file crypto/elliptic/elliptic.go decls: GenerateKey, Marshal, MarshalCompressed, Unmarshal, UnmarshalCompressed, panicIfNotOnCurve, initAll, P224, P256, P384, P521
//
// Package elliptic implements the standard NIST P-224, P-256, P-384, and
// P-521 elliptic curves over prime fields.
//
// Direct use of this package is deprecated, beyond the [P224], [P256],
// [P384], and [P521] values necessary to use [crypto/ecdsa]. Most other
// uses should migrate to the more efficient and safer [crypto/ecdh].
//
// Deviations from elliptic[go] @ Go 1.25.5:
//
//   * `Curve` and `unmarshaler` are `#[goish::interface]` traits. Go's
//     `Params() *CurveParams` returns a pointer that callers compare by
//     identity; interface methods must return owned values here, so
//     `Params()` clones and `matchesSpecificCurve` compares by value
//     across every field (see params.rs).
//   * `P224()` and friends return `&'static (dyn Curve + Send + Sync)`
//     rather than a boxed interface value, which preserves Go's documented
//     "multiple invocations return the same value, so it can be used for
//     equality checks".
//   * `Unmarshal` returns `x = nil` for "not a point". `Int` has no nil,
//     so the goish signature adds an `ok`.
//   * `UnmarshalCompressed`'s generic path calls `y.ModSqrt(y, p)` and
//     tests the returned pointer for nil. goish's `ModSqrt` returns
//     `&mut Self` and cannot express that, so the residue is verified
//     directly: y² must equal the polynomial. Same acceptance set.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::goslice::slice;
use crate::io;
use crate::lazy::Lazy;
use crate::math::big::Int;
use crate::{byte, int};
use crate::error;

use super::nistec::{fillInto, initAllCurves, p224, p256, p384, p521};
use super::params::CurveParams;

// Go: elliptic.go:20-66
//   type Curve interface { Params; IsOnCurve; Add; Double; ScalarMult; ScalarBaseMult }
/// A short-form Weierstrass curve with a=-3.
///
/// The behavior of Add, Double, and ScalarMult when the input is not a
/// point on the curve is undefined.
///
/// Note that the conventional point at infinity (0, 0) is not considered
/// on the curve, although it can be returned by Add, Double, ScalarMult,
/// or ScalarBaseMult (but not the [Unmarshal] or [UnmarshalCompressed]
/// functions).
// GOISH022 reports `goish::int` on the line below. It is a false
// positive on the attribute-macro path — the same one drbg/rand.rs
// carries — and the rule is non-fatal, so it is left visible rather than
// suppressed with a comment that would look like a real waiver.
#[goish::interface]
pub trait Curve {
    /// Return the parameters for the curve.
    fn Params(&self) -> CurveParams;
    /// Report whether the given (x,y) lies on the curve.
    fn IsOnCurve(&self, x: &Int, y: &Int) -> bool;
    /// Return the sum of (x1,y1) and (x2,y2).
    fn Add(&self, x1: &Int, y1: &Int, x2: &Int, y2: &Int) -> (Int, Int);
    /// Return 2*(x,y).
    fn Double(&self, x1: &Int, y1: &Int) -> (Int, Int);
    /// Return k*(x,y) where k is an integer in big-endian form.
    fn ScalarMult(&self, x1: &Int, y1: &Int, k: &slice<byte>) -> (Int, Int);
    /// Return k*G, where G is the base point of the group and k is an
    /// integer in big-endian form.
    fn ScalarBaseMult(&self, k: &slice<byte>) -> (Int, Int);
}

// Go: elliptic.go:68 — `var mask = []byte{0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f}`
static mask: Lazy<slice<byte>> = Lazy::new(|| {
    return slice::__from_vec(alloc::vec![0xff, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f]);
});

// go: sdk 1.25.5 crypto/elliptic/elliptic.go:70-101 GenerateKey
// goishlint:ignore GOISH023 — Go's `for x == nil { … }`; Rust spells the
// same loop as `loop { … }`, which parses as the tail expression.
/// Return a public/private key pair. The private key is generated using
/// the given reader, which must return random data.
///
/// Deprecated: for ECDH, use the GenerateKey methods of the [crypto/ecdh]
/// package; for ECDSA, use the GenerateKey function of the crypto/ecdsa
/// package.
pub fn GenerateKey(
    curve: &(dyn Curve + Send + Sync + 'static),
    rand: &mut (dyn io::Reader + Send + Sync + 'static),
) -> (slice<byte>, Int, Int, error) {
    let params = curve.Params();
    let N = params.N.clone();
    let bitSize = N.BitLen();
    let byteLen = ((bitSize + 7) / 8) as usize;

    loop {
        let mut priv_ = slice::__from_vec(alloc::vec![0u8; byteLen]);
        let (_, err) = io::ReadFull(rand, &mut priv_);
        if err != crate::nil {
            return (priv_, Int::default(), Int::default(), err);
        }
        {
            let m: &[byte] = &mask;
            let p: &mut [byte] = &mut priv_;
            // We have to mask off any excess bits in the case that the size
            // of the underlying field is not a whole number of bytes.
            p[0] &= m[(bitSize % 8) as usize];
            // This is because, in tests, rand will return all zeros and we
            // don't want to get the point at infinity and loop forever.
            p[1] ^= 0x42;
        }

        // If the scalar is out of range, sample another random number.
        let mut s = Int::default();
        s.SetBytes(priv_.clone());
        if s.Cmp(&N) >= 0 {
            continue;
        }

        let (x, y) = curve.ScalarBaseMult(&priv_);
        return (priv_, x, y, crate::nil.into());
    }
}

// go: sdk 1.25.5 crypto/elliptic/elliptic.go:103-121 Marshal
/// Convert a point on the curve into the uncompressed form specified in
/// SEC 1, Version 2.0, Section 2.3.3. If the point is not on the curve (or
/// is the conventional point at infinity), the behavior is undefined.
///
/// Deprecated: for ECDH, use the crypto/ecdh package.
pub fn Marshal(curve: &(dyn Curve + Send + Sync + 'static), x: &Int, y: &Int) -> slice<byte> {
    panicIfNotOnCurve(curve, x, y);

    let byteLen = ((curve.Params().BitSize + 7) / 8) as usize;

    let mut ret: Vec<byte> = alloc::vec![0u8; 1 + 2 * byteLen];
    ret[0] = 4; // uncompressed point

    fillInto(&mut ret[1..1 + byteLen], x);
    fillInto(&mut ret[1 + byteLen..1 + 2 * byteLen], y);

    return slice::__from_vec(ret);
}

// go: sdk 1.25.5 crypto/elliptic/elliptic.go:123-133 MarshalCompressed
/// Convert a point on the curve into the compressed form specified in
/// SEC 1, Version 2.0, Section 2.3.3. If the point is not on the curve (or
/// is the conventional point at infinity), the behavior is undefined.
pub fn MarshalCompressed(
    curve: &(dyn Curve + Send + Sync + 'static),
    x: &Int,
    y: &Int,
) -> slice<byte> {
    panicIfNotOnCurve(curve, x, y);
    let byteLen = ((curve.Params().BitSize + 7) / 8) as usize;
    let mut compressed: Vec<byte> = alloc::vec![0u8; 1 + byteLen];
    compressed[0] = byte(y.Bit(0)) | 2;
    fillInto(&mut compressed[1..], x);
    return slice::__from_vec(compressed);
}

// Go: elliptic.go:135-142
//   type unmarshaler interface { Unmarshal(…); UnmarshalCompressed(…) }
/// Implemented by curves with their own constant-time Unmarshal.
///
/// There isn't an equivalent interface for Marshal/MarshalCompressed
/// because that doesn't involve any mathematical operations, only
/// FillBytes and Bit.
// GOISH022 false positive on the attribute path; see the note above.
#[goish::interface]
pub trait unmarshaler {
    fn Unmarshal(&self, data: &slice<byte>) -> (Int, Int, bool);
    fn UnmarshalCompressed(&self, data: &slice<byte>) -> (Int, Int, bool);
}

// go: sdk 1.25.5 crypto/elliptic/elliptic.go:147-175 Unmarshal
/// Convert a point, serialized by [Marshal], into an x, y pair. It is an
/// error if the point is not in uncompressed form, is not on the curve, or
/// is the point at infinity. On error, the returned `ok` is false.
///
/// Deprecated: for ECDH, use the crypto/ecdh package.
pub fn Unmarshal(
    curve: &(dyn Curve + Send + Sync + 'static),
    data: &slice<byte>,
) -> (Int, Int, bool) {
    let (c, ok) = goish::cast!(curve, unmarshaler);
    if ok {
        return c.Unmarshal(data);
    }

    let params = curve.Params();
    let byteLen = ((params.BitSize + 7) / 8) as usize;
    let raw: &[byte] = data;
    if raw.len() != 1 + 2 * byteLen {
        return (Int::default(), Int::default(), false);
    }
    if raw[0] != 4 {
        // uncompressed form
        return (Int::default(), Int::default(), false);
    }
    let p = params.P.clone();
    let mut x = Int::default();
    x.SetBytes(slice::__from_vec(raw[1..1 + byteLen].to_vec()));
    let mut y = Int::default();
    y.SetBytes(slice::__from_vec(raw[1 + byteLen..].to_vec()));
    if x.Cmp(&p) >= 0 || y.Cmp(&p) >= 0 {
        return (Int::default(), Int::default(), false);
    }
    if !curve.IsOnCurve(&x, &y) {
        return (Int::default(), Int::default(), false);
    }
    return (x, y, true);
}

// go: sdk 1.25.5 crypto/elliptic/elliptic.go:177-210 UnmarshalCompressed
/// Convert a point, serialized by [MarshalCompressed], into an x, y pair.
/// It is an error if the point is not in compressed form, is not on the
/// curve, or is the point at infinity. On error, the returned `ok` is
/// false.
pub fn UnmarshalCompressed(
    curve: &(dyn Curve + Send + Sync + 'static),
    data: &slice<byte>,
) -> (Int, Int, bool) {
    let (c, ok) = goish::cast!(curve, unmarshaler);
    if ok {
        return c.UnmarshalCompressed(data);
    }

    let params = curve.Params();
    let byteLen = ((params.BitSize + 7) / 8) as usize;
    let raw: &[byte] = data;
    if raw.len() != 1 + byteLen {
        return (Int::default(), Int::default(), false);
    }
    if raw[0] != 2 && raw[0] != 3 {
        // compressed form
        return (Int::default(), Int::default(), false);
    }
    let p = params.P.clone();
    let mut x = Int::default();
    x.SetBytes(slice::__from_vec(raw[1..].to_vec()));
    if x.Cmp(&p) >= 0 {
        return (Int::default(), Int::default(), false);
    }
    // y² = x³ - 3x + b
    let y2 = params.polynomial(&x);
    let mut y = Int::default();
    y.ModSqrt(&y2, &p);
    // Go tests `y == nil` here; goish's ModSqrt cannot return nil, so the
    // residue is checked instead — y is a square root exactly when y² ≡ y2.
    let mut check = Int::default();
    let yc = y.clone();
    check.Mul(&yc, &yc);
    let mut checkMod = Int::default();
    checkMod.Mod(&check, &p);
    if checkMod.Cmp(&y2) != 0 {
        return (Int::default(), Int::default(), false);
    }
    if byte(y.Bit(0)) != raw[0] & 1 {
        let yc = y.clone();
        y.Neg(&yc);
        let yc = y.clone();
        y.Mod(&yc, &p);
    }
    if !curve.IsOnCurve(&x, &y) {
        return (Int::default(), Int::default(), false);
    }
    return (x, y, true);
}

// go: sdk 1.25.5 crypto/elliptic/elliptic.go:212-222 panicIfNotOnCurve
pub(super) fn panicIfNotOnCurve(curve: &(dyn Curve + Send + Sync + 'static), x: &Int, y: &Int) {
    // (0, 0) is the point at infinity by convention. It's ok to operate on
    // it, although IsOnCurve is documented to return false for it.
    if x.Sign() == 0 && y.Sign() == 0 {
        return;
    }

    if !curve.IsOnCurve(x, y) {
        panic!("crypto/elliptic: attempted operation on invalid point");
    }
}

// Go: elliptic.go:224 — `var initonce sync.Once`
static initonce: AtomicBool = AtomicBool::new(false);

// go: sdk 1.25.5 crypto/elliptic/elliptic.go:226-231 initAll
fn initAll() {
    initAllCurves();
}

// go: none — Go's `initonce.Do(initAll)`; no_std has no sync.Once, so an
// AtomicBool latch stands in, the same shape the fips140 CASTs use.
fn initOnceDo() {
    if initonce.swap(true, Ordering::SeqCst) {
        return;
    }
    initAll();
}

// go: sdk 1.25.5 crypto/elliptic/elliptic.go:233-243 P224
/// Return a [Curve] which implements NIST P-224 (FIPS 186-3, section
/// D.2.2), also known as secp224r1. The CurveParams.Name of this [Curve]
/// is "P-224".
pub fn P224() -> &'static (dyn Curve + Send + Sync) {
    initOnceDo();
    return p224();
}

// go: sdk 1.25.5 crypto/elliptic/elliptic.go:245-256 P256
/// Return a [Curve] which implements NIST P-256 (FIPS 186-3, section
/// D.2.3), also known as secp256r1 or prime256v1.
pub fn P256() -> &'static (dyn Curve + Send + Sync) {
    initOnceDo();
    return p256();
}

// go: sdk 1.25.5 crypto/elliptic/elliptic.go:258-268 P384
/// Return a [Curve] which implements NIST P-384 (FIPS 186-3, section
/// D.2.4), also known as secp384r1.
pub fn P384() -> &'static (dyn Curve + Send + Sync) {
    initOnceDo();
    return p384();
}

// go: sdk 1.25.5 crypto/elliptic/elliptic.go:270-280 P521
/// Return a [Curve] which implements NIST P-521 (FIPS 186-3, section
/// D.2.5), also known as secp521r1.
pub fn P521() -> &'static (dyn Curve + Send + Sync) {
    initOnceDo();
    return p521();
}

// Keep the `int` import honest: BitSize and BitLen are both one.
const _: int = 0;

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register the concrete `Curve` implementations. Idempotent; called
/// from `goish::init()`.
pub fn register_elliptic_impls() {
    __goish_register_Curve_impl::<crate::crypto::elliptic::params::CurveParams>();
}
