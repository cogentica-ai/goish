// go: file crypto/elliptic/nistec.go decls: initP224, initP256, initP384, initP521, nistCurve.Params, nistCurve.IsOnCurve, nistCurve.pointFromAffine, nistCurve.pointToAffine, nistCurve.Add, nistCurve.Double, nistCurve.normalizeScalar, nistCurve.ScalarMult, nistCurve.ScalarBaseMult, nistCurve.Unmarshal, nistCurve.UnmarshalCompressed, bigFromDecimal, bigFromHex
//
// Deviations from nistec[go] @ Go 1.25.5:
//
//   * `nistPoint[T any]` is a constraint interface; Rust has no type
//     unions, so it is a plain trait implemented for the four nistec point
//     types — the same treatment as the ecdh and ecdsa siblings.
//   * Go builds `p224` as a package-level `var` with only `newPoint` set
//     and fills `params` from `initP224`, driven by a `sync.Once` in
//     elliptic.go. goish builds the whole value in one `Lazy`, and
//     `initP224` forces it — the same one-time construction, reachable by
//     the same name.
//   * `Unmarshal`/`UnmarshalCompressed` return `(x, y *big.Int)` with
//     `x == nil` for "not a point". `Int` has no nil, so they return
//     `(Int, Int, bool)`.
//   * goish's nistec points mutate the receiver and return `error`, so
//     `p.Add(p1, p2)` and friends read accordingly.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::internal::fips140::nistec;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::lazy::Lazy;
use crate::math::big::Int;
use crate::string;
use crate::types::{byte, int};

use super::elliptic::{unmarshaler, Curve};
use super::params::CurveParams;

// Go: nistec.go:111-119
//   type nistPoint[T any] interface { … }
/// A generic constraint for the nistec Point types.
pub trait nistPoint: Copy + Sized + 'static {
    fn Bytes(&self) -> slice<byte>;
    fn SetBytes(&mut self, b: &slice<byte>) -> error;
    fn Add(&mut self, p1: Self, p2: Self) -> Self;
    fn Double(&mut self, p: Self) -> Self;
    fn ScalarMult(&mut self, q: Self, scalar: &slice<byte>) -> error;
    fn ScalarBaseMult(&mut self, scalar: &slice<byte>) -> error;
}

/// Pure forwarding to the inherent nistec methods. Go gets this from the
/// type union in the constraint.
macro_rules! __impl_nistpoint {
    ($($t:ty),* $(,)?) => {$(
        impl nistPoint for $t {
            fn Bytes(&self) -> slice<byte> {
                return <$t>::Bytes(self);
            }
            fn SetBytes(&mut self, b: &slice<byte>) -> error {
                return <$t>::SetBytes(self, b);
            }
            fn Add(&mut self, p1: Self, p2: Self) -> Self {
                <$t>::Add(self, p1, p2);
                return *self;
            }
            fn Double(&mut self, p: Self) -> Self {
                <$t>::Double(self, p);
                return *self;
            }
            fn ScalarMult(&mut self, q: Self, scalar: &slice<byte>) -> error {
                return <$t>::ScalarMult(self, q, scalar);
            }
            fn ScalarBaseMult(&mut self, scalar: &slice<byte>) -> error {
                return <$t>::ScalarBaseMult(self, scalar);
            }
        }
    )*};
}

__impl_nistpoint!(
    nistec::P224Point,
    nistec::P256Point,
    nistec::P384Point,
    nistec::P521Point,
);

// Go: nistec.go:96-109
//   type nistCurve[Point nistPoint[Point]] struct { newPoint func() Point; params *CurveParams }
/// A Curve implementation based on a nistec Point.
///
/// It's a wrapper that exposes the big.Int-based Curve interface and
/// encodes the legacy idiosyncrasies it requires, such as invalid and
/// infinity point handling.
///
/// To interact with the nistec package, points are encoded into and
/// decoded from properly formatted byte slices. All big.Int use is limited
/// to this package.
pub struct nistCurve<Point: nistPoint> {
    newPoint: fn() -> Point,
    params: CurveParams,
}

// Go: nistec.go:13-15 — `var p224 = &nistCurve[*nistec.P224Point]{…}`
static _p224: Lazy<nistCurve<nistec::P224Point>> = Lazy::new(|| nistCurve {
    newPoint: nistec::NewP224Point,
    params: CurveParams {
        Name: string::from_static("P-224"),
        BitSize: 224,
        // SP 800-186, Section 3.2.1.2
        P: bigFromDecimal("26959946667150639794667015087019630673557916260026308143510066298881"),
        N: bigFromDecimal("26959946667150639794667015087019625940457807714424391721682722368061"),
        B: bigFromHex("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4"),
        Gx: bigFromHex("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"),
        Gy: bigFromHex("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
    },
});

// go: none — Go's package-level `var p224`; goish reaches the Lazy through
// an accessor so the `&'static` coercion to `dyn Curve` has one home.
pub(super) fn p224() -> &'static (dyn Curve + Send + Sync) {
    return _p224.get();
}

// go: sdk 1.25.5 crypto/elliptic/nistec.go:17-28 initP224
fn initP224() {
    let _ = _p224.get();
}

// Go: nistec.go:30-32 — `var p256 = &nistCurve[*nistec.P256Point]{…}`
static _p256: Lazy<nistCurve<nistec::P256Point>> = Lazy::new(|| nistCurve {
    newPoint: nistec::NewP256Point,
    params: CurveParams {
        Name: string::from_static("P-256"),
        BitSize: 256,
        // SP 800-186, Section 3.2.1.3
        P: bigFromDecimal(
            "115792089210356248762697446949407573530086143415290314195533631308867097853951",
        ),
        N: bigFromDecimal(
            "115792089210356248762697446949407573529996955224135760342422259061068512044369",
        ),
        B: bigFromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
        Gx: bigFromHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        Gy: bigFromHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    },
});

// go: none — see p224.
pub(super) fn p256() -> &'static (dyn Curve + Send + Sync) {
    return _p256.get();
}

// go: sdk 1.25.5 crypto/elliptic/nistec.go:34-45 initP256
fn initP256() {
    let _ = _p256.get();
}

// Go: nistec.go:47-49 — `var p384 = &nistCurve[*nistec.P384Point]{…}`
static _p384: Lazy<nistCurve<nistec::P384Point>> = Lazy::new(|| {
    nistCurve {
    newPoint: nistec::NewP384Point,
    params: CurveParams {
        Name: string::from_static("P-384"),
        BitSize: 384,
        // SP 800-186, Section 3.2.1.4
        P: bigFromDecimal(
            "3940200619639447921227904010014361380507973927046544666794829340424572177149687032904726608825893800186160697311231\
9",
        ),
        N: bigFromDecimal(
            "3940200619639447921227904010014361380507973927046544666794690527962765939911326356939895630815229491355443365394264\
3",
        ),
        B: bigFromHex(
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        ),
        Gx: bigFromHex(
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        ),
        Gy: bigFromHex(
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
        ),
    },
}
});

// go: none — see p224.
pub(super) fn p384() -> &'static (dyn Curve + Send + Sync) {
    return _p384.get();
}

// go: sdk 1.25.5 crypto/elliptic/nistec.go:51-67 initP384
fn initP384() {
    let _ = _p384.get();
}

// Go: nistec.go:69-71 — `var p521 = &nistCurve[*nistec.P521Point]{…}`
static _p521: Lazy<nistCurve<nistec::P521Point>> = Lazy::new(|| {
    nistCurve {
    newPoint: nistec::NewP521Point,
    params: CurveParams {
        Name: string::from_static("P-521"),
        BitSize: 521,
        // SP 800-186, Section 3.2.1.5
        P: bigFromDecimal(
            "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480\
858037121987999716643812574028291115057151",
        ),
        N: bigFromDecimal(
            "6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363\
321113864768612440380340372808892707005449",
        ),
        B: bigFromHex(
            "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f\
1ef451fd46b503f00",
        ),
        Gx: bigFromHex(
            "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429\
bf97e7e31c2e5bd66",
        ),
        Gy: bigFromHex(
            "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24\
088be94769fd16650",
        ),
    },
}
});

// go: none — see p224.
pub(super) fn p521() -> &'static (dyn Curve + Send + Sync) {
    return _p521.get();
}

// go: sdk 1.25.5 crypto/elliptic/nistec.go:73-94 initP521
fn initP521() {
    let _ = _p521.get();
}

// go: none — Go's elliptic.go `initAll` calls the four; keeping them
// reachable from one place keeps the `sync.Once` shape intact.
pub(super) fn initAllCurves() {
    initP224();
    initP256();
    initP384();
    initP521();
}

impl<Point: nistPoint> nistCurve<Point> {
    // go: sdk 1.25.5 crypto/elliptic/nistec.go:121-123 nistCurve.Params
    pub fn Params(&self) -> CurveParams {
        return self.params.clone();
    }

    // go: sdk 1.25.5 crypto/elliptic/nistec.go:125-133 nistCurve.IsOnCurve
    pub fn IsOnCurve(&self, x: &Int, y: &Int) -> bool {
        // IsOnCurve is documented to reject (0, 0), the conventional point
        // at infinity, which however is accepted by pointFromAffine.
        if x.Sign() == 0 && y.Sign() == 0 {
            return false;
        }
        let (_, err) = self.pointFromAffine(x, y);
        return err == crate::nil;
    }

    // go: sdk 1.25.5 crypto/elliptic/nistec.go:135-155 nistCurve.pointFromAffine
    fn pointFromAffine(&self, x: &Int, y: &Int) -> (Point, error) {
        // (0, 0) is by convention the point at infinity, which can't be
        // represented in affine coordinates.
        if x.Sign() == 0 && y.Sign() == 0 {
            return ((self.newPoint)(), crate::nil.into());
        }
        // Reject values that would not get correctly encoded.
        if x.Sign() < 0 || y.Sign() < 0 {
            return ((self.newPoint)(), errors::New("negative coordinate"));
        }
        if x.BitLen() > self.params.BitSize || y.BitLen() > self.params.BitSize {
            return ((self.newPoint)(), errors::New("overflowing coordinate"));
        }
        // Encode the coordinates and let SetBytes reject invalid points.
        let byteLen = ((self.params.BitSize + 7) / 8) as usize;
        let mut buf: Vec<byte> = alloc::vec![0u8; 1 + 2 * byteLen];
        buf[0] = 4; // uncompressed point
        fillInto(&mut buf[1..1 + byteLen], x);
        fillInto(&mut buf[1 + byteLen..1 + 2 * byteLen], y);
        let mut p = (self.newPoint)();
        let err = p.SetBytes(&slice::__from_vec(buf));
        return (p, err);
    }

    // go: sdk 1.25.5 crypto/elliptic/nistec.go:157-168 nistCurve.pointToAffine
    fn pointToAffine(&self, p: Point) -> (Int, Int) {
        let out = p.Bytes();
        let raw: &[byte] = &out;
        if raw.len() == 1 && raw[0] == 0 {
            // This is the encoding of the point at infinity, which the
            // affine coordinates API represents as (0, 0) by convention.
            return (Int::default(), Int::default());
        }
        let byteLen = ((self.params.BitSize + 7) / 8) as usize;
        let mut x = Int::default();
        x.SetBytes(slice::__from_vec(raw[1..1 + byteLen].to_vec()));
        let mut y = Int::default();
        y.SetBytes(slice::__from_vec(raw[1 + byteLen..].to_vec()));
        return (x, y);
    }

    // go: sdk 1.25.5 crypto/elliptic/nistec.go:170-180 nistCurve.Add
    pub fn Add(&self, x1: &Int, y1: &Int, x2: &Int, y2: &Int) -> (Int, Int) {
        let (mut p1, err) = self.pointFromAffine(x1, y1);
        if err != crate::nil {
            panic!("crypto/elliptic: Add was called on an invalid point");
        }
        let (p2, err) = self.pointFromAffine(x2, y2);
        if err != crate::nil {
            panic!("crypto/elliptic: Add was called on an invalid point");
        }
        let a = p1;
        let sum = p1.Add(a, p2);
        return self.pointToAffine(sum);
    }

    // go: sdk 1.25.5 crypto/elliptic/nistec.go:182-188 nistCurve.Double
    pub fn Double(&self, x1: &Int, y1: &Int) -> (Int, Int) {
        let (mut p, err) = self.pointFromAffine(x1, y1);
        if err != crate::nil {
            panic!("crypto/elliptic: Double was called on an invalid point");
        }
        let a = p;
        let d = p.Double(a);
        return self.pointToAffine(d);
    }

    // go: sdk 1.25.5 crypto/elliptic/nistec.go:190-203 nistCurve.normalizeScalar
    /// Bring the scalar within the byte size of the order of the curve, as
    /// expected by the nistec scalar multiplication functions.
    fn normalizeScalar(&self, scalar: &slice<byte>) -> slice<byte> {
        let byteSize = ((self.params.N.BitLen() + 7) / 8) as usize;
        let raw: &[byte] = scalar;
        if raw.len() == byteSize {
            return scalar.clone();
        }
        let mut s = Int::default();
        s.SetBytes(scalar.clone());
        if raw.len() > byteSize {
            let t = s.clone();
            s.Mod(&t, &self.params.N);
        }
        let mut out: Vec<byte> = alloc::vec![0u8; byteSize];
        fillInto(&mut out, &s);
        return slice::__from_vec(out);
    }

    // go: sdk 1.25.5 crypto/elliptic/nistec.go:205-216 nistCurve.ScalarMult
    pub fn ScalarMult(&self, Bx: &Int, By: &Int, scalar: &slice<byte>) -> (Int, Int) {
        let (mut p, err) = self.pointFromAffine(Bx, By);
        if err != crate::nil {
            panic!("crypto/elliptic: ScalarMult was called on an invalid point");
        }
        let scalar = self.normalizeScalar(scalar);
        let q = p;
        let err = p.ScalarMult(q, &scalar);
        if err != crate::nil {
            panic!("crypto/elliptic: nistec rejected normalized scalar");
        }
        return self.pointToAffine(p);
    }

    // go: sdk 1.25.5 crypto/elliptic/nistec.go:218-225 nistCurve.ScalarBaseMult
    pub fn ScalarBaseMult(&self, scalar: &slice<byte>) -> (Int, Int) {
        let scalar = self.normalizeScalar(scalar);
        let mut p = (self.newPoint)();
        let err = p.ScalarBaseMult(&scalar);
        if err != crate::nil {
            panic!("crypto/elliptic: nistec rejected normalized scalar");
        }
        return self.pointToAffine(p);
    }

    // go: sdk 1.25.5 crypto/elliptic/nistec.go:227-243 nistCurve.Unmarshal
    pub fn Unmarshal(&self, data: &slice<byte>) -> (Int, Int, bool) {
        let raw: &[byte] = data;
        if raw.is_empty() || raw[0] != 4 {
            return (Int::default(), Int::default(), false);
        }
        // Use SetBytes to check that data encodes a valid point.
        let mut p = (self.newPoint)();
        let err = p.SetBytes(data);
        if err != crate::nil {
            return (Int::default(), Int::default(), false);
        }
        // We don't use pointToAffine because it involves an expensive field
        // inversion to convert from Jacobian to affine coordinates, which we
        // already have.
        let byteLen = ((self.params.BitSize + 7) / 8) as usize;
        let mut x = Int::default();
        x.SetBytes(slice::__from_vec(raw[1..1 + byteLen].to_vec()));
        let mut y = Int::default();
        y.SetBytes(slice::__from_vec(raw[1 + byteLen..].to_vec()));
        return (x, y, true);
    }

    // go: sdk 1.25.5 crypto/elliptic/nistec.go:245-254 nistCurve.UnmarshalCompressed
    pub fn UnmarshalCompressed(&self, data: &slice<byte>) -> (Int, Int, bool) {
        let raw: &[byte] = data;
        if raw.is_empty() || (raw[0] != 2 && raw[0] != 3) {
            return (Int::default(), Int::default(), false);
        }
        let mut p = (self.newPoint)();
        let err = p.SetBytes(data);
        if err != crate::nil {
            return (Int::default(), Int::default(), false);
        }
        let (x, y) = self.pointToAffine(p);
        return (x, y, true);
    }
}

// go: sdk 1.25.5 crypto/elliptic/nistec.go:256-262 bigFromDecimal
fn bigFromDecimal(s: &'static str) -> Int {
    let mut b = Int::default();
    let (_, ok) = b.SetString(s, 10);
    if !ok {
        panic!("crypto/elliptic: internal error: invalid encoding");
    }
    return b;
}

// go: sdk 1.25.5 crypto/elliptic/nistec.go:264-270 bigFromHex
fn bigFromHex(s: &'static str) -> Int {
    let mut b = Int::default();
    let (_, ok) = b.SetString(s, 16);
    if !ok {
        panic!("crypto/elliptic: internal error: invalid encoding");
    }
    return b;
}

// go: none — Go's `x.FillBytes(buf[a:b])` writes through a subslice view.
// goish's FillBytes returns a fresh slice, so the result is copied back
// into the caller's buffer.
pub(super) fn fillInto(dst: &mut [byte], v: &Int) {
    let filled = v.FillBytes(slice::__from_vec(alloc::vec![0u8; dst.len()]));
    let src: &[byte] = &filled;
    dst.copy_from_slice(src);
}

// Keep the `int` import honest: BitSize is one.
const _: int = 0;

// go: none — Go's `*nistCurve[Point]` satisfies `Curve` and `unmarshaler`
// structurally. Rust needs both impls written out, forwarding to the
// inherent methods above, plus the two Any hooks every
// `#[goish::interface]` concrete impl overrides so `cast!` can reach the
// type — which is exactly what elliptic.Unmarshal's type assertion needs.
impl<Point: nistPoint> Curve for nistCurve<Point> {
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn Params(&self) -> CurveParams {
        return nistCurve::<Point>::Params(self);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn IsOnCurve(&self, x: &Int, y: &Int) -> bool {
        return nistCurve::<Point>::IsOnCurve(self, x, y);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn Add(&self, x1: &Int, y1: &Int, x2: &Int, y2: &Int) -> (Int, Int) {
        return nistCurve::<Point>::Add(self, x1, y1, x2, y2);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn Double(&self, x1: &Int, y1: &Int) -> (Int, Int) {
        return nistCurve::<Point>::Double(self, x1, y1);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn ScalarMult(&self, x1: &Int, y1: &Int, k: &slice<byte>) -> (Int, Int) {
        return nistCurve::<Point>::ScalarMult(self, x1, y1, k);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn ScalarBaseMult(&self, k: &slice<byte>) -> (Int, Int) {
        return nistCurve::<Point>::ScalarBaseMult(self, k);
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

impl<Point: nistPoint> unmarshaler for nistCurve<Point> {
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn Unmarshal(&self, data: &slice<byte>) -> (Int, Int, bool) {
        return nistCurve::<Point>::Unmarshal(self, data);
    }
    // go: none — forwarding to the inherent method of the same
    // name; see the block-level note above.
    fn UnmarshalCompressed(&self, data: &slice<byte>) -> (Int, Int, bool) {
        return nistCurve::<Point>::UnmarshalCompressed(self, data);
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

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registry for the four concrete `nistCurve` instantiations. Go's
// `curve.(unmarshaler)` is structural and needs no such step; here the
// assertion in `elliptic::Unmarshal` misses without it, silently, and
// the caller gets the generic big.Int path instead of nistec.
// See AGENTS.md §9b.
pub(crate) fn register_nistec_unmarshalers() {
    crate::crypto::elliptic::elliptic::__goish_register_unmarshaler_impl::<nistCurve<nistec::P224Point>>();
    crate::crypto::elliptic::elliptic::__goish_register_unmarshaler_impl::<nistCurve<nistec::P256Point>>();
    crate::crypto::elliptic::elliptic::__goish_register_unmarshaler_impl::<nistCurve<nistec::P384Point>>();
    crate::crypto::elliptic::elliptic::__goish_register_unmarshaler_impl::<nistCurve<nistec::P521Point>>();
}
