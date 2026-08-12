// go: file crypto/internal/fips140/ecdsa/ecdsa.go decls: PrivateKey.Bytes, PrivateKey.PublicKey, PublicKey.Bytes, precomputeParams, P224, P256, P384, P521, NewPrivateKey, NewPublicKey, GenerateKey, randomPoint, Sign, SignDeterministic, bits2octets, signGeneric, inverse, hashToNat, rightShift, Verify, verifyGeneric
//
// Deviations from ecdsa[go] @ Go 1.25.5:
//
//   * `type Point[P any] interface { *nistec.P224Point | … }` is a
//     constraint interface with a type union; Rust has none, so it is a
//     plain trait implemented for the four nistec point types, and
//     `Curve[P Point[P]]` becomes `Curve<P: Point>`. Same shape as the
//     sibling crypto/internal/fips140/ecdh port.
//   * `precomputeParams(c *Curve[P], order []byte)` fills `c.N` and
//     `c.nMinus2` on a partially built `*Curve`. `bigmod::Modulus` has no
//     zero value in Rust, so the first parameter is the *set* of fields
//     Go's composite literal supplies and the completed Curve comes back
//     as the result. Two inputs in, the same two fields computed.
//   * `ordInverse func([]byte) ([]byte, error)` is nil for three of the
//     four curves. Rust `fn` pointers are not nullable, so the field is
//     an `Option`, and Go's `if c.ordInverse != nil` reads as a match.
//   * `var _P224 = sync.OnceValue(…)` becomes `goish::lazy::Lazy`, and
//     `P224()` returns `&'static Curve<…>` — Go's memoised pointer.
//   * Go's `H hash.Hash` type parameter collapses to the
//     `impl IntoHashFunc` factory used across the tree — a plain
//     function or a closure, which is what lets fips140hash.UnwrapNew's
//     captured constructor translate.
//   * Constructors returning `(*T, error)` return `(T, error)` with the
//     zero value on the error path.
//
// goishlint:ignore GOISH021 — `_P224`/`_P256`/`_P384`/`_P521` are the
// `sync.OnceValue` cells behind the four accessors; the `Lazy` statics
// below are those cells, named for the curve they memoise.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::internal::fips140;
use crate::crypto::internal::fips140::bigmod::{Modulus, Nat};
use crate::crypto::internal::fips140::drbg;
use crate::crypto::internal::fips140::nistec;
use crate::errors;
use crate::goslice::slice;
use crate::hash::IntoHashFunc;
use crate::io;
use crate::lazy::Lazy;
use crate::types::{byte, int};
use crate::error;

use super::cast::{fipsPCT, fipsSelfTest, fipsSelfTestDeterministic};
use super::ecdsa_noasm::{sign, verify};
use super::hmacdrbg::{hmacDRBG, newDRBG, personalizationString,
                      blockAlignedPersonalizationString};

// PrivateKey and PublicKey are not generic to make it possible to use them
// in other types without instantiating them with a specific point type.
// They are tied to one of the Curve types below through the curveID field.

// Go: ecdsa.go:23-26
//   type PrivateKey struct { pub PublicKey; d []byte }
#[derive(Clone)]
pub struct PrivateKey {
    // Go's fields are package-scoped; `pub(super)` is that scope here.
    pub(super) r#pub: PublicKey,
    /// bigmod.(*Nat).Bytes output (same length as the curve order)
    pub(super) d: slice<byte>,
}

impl PrivateKey {
    // go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:28-30 PrivateKey.Bytes
    pub fn Bytes(&self) -> slice<byte> {
        return self.d.clone();
    }

    // go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:32-34 PrivateKey.PublicKey
    pub fn PublicKey(&self) -> PublicKey {
        return self.r#pub.clone();
    }
}

// Go: ecdsa.go:36-39
//   type PublicKey struct { curve curveID; q []byte }
#[derive(Clone)]
pub struct PublicKey {
    pub(super) curve: curveID,
    /// uncompressed nistec Point.Bytes output
    pub(super) q: slice<byte>,
}

impl PublicKey {
    // go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:41-43 PublicKey.Bytes
    pub fn Bytes(&self) -> slice<byte> {
        return self.q.clone();
    }
}

// Go: ecdsa.go:45
//   type curveID string
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct curveID(&'static str);

// Go: ecdsa.go:47-52 — `const ( p224 curveID = "P-224"; … )`
const p224: curveID = curveID("P-224");
pub(super) const p256: curveID = curveID("P-256");
const p384: curveID = curveID("P-384");
const p521: curveID = curveID("P-521");

// Go: ecdsa.go:54-60
//   type Curve[P Point[P]] struct { curve curveID; newPoint func() P;
//                                   ordInverse func([]byte) ([]byte, error);
//                                   N *bigmod.Modulus; nMinus2 []byte }
pub struct Curve<P: Point> {
    pub(super) curve: curveID,
    newPoint: fn() -> P,
    ordInverse: Option<fn(&slice<byte>) -> (slice<byte>, error)>,
    pub N: Modulus,
    nMinus2: slice<byte>,
}

// go: none — the fields Go's `&Curve[P]{…}` composite literal sets before
// handing the value to precomputeParams. Rust cannot leave `N` unset, so
// the literal and the precompute step are separated by this type.
struct curveParams<P: Point> {
    curve: curveID,
    newPoint: fn() -> P,
    ordInverse: Option<fn(&slice<byte>) -> (slice<byte>, error)>,
}

// Go: ecdsa.go:62-71
//   type Point[P any] interface { *nistec.P224Point | … }
/// A generic constraint for the [nistec] Point types.
pub trait Point: Copy + Sized {
    fn Bytes(&self) -> slice<byte>;
    fn BytesX(&self) -> (slice<byte>, error);
    fn SetBytes(&mut self, b: &slice<byte>) -> error;
    fn ScalarMult(&mut self, q: Self, scalar: &slice<byte>) -> error;
    fn ScalarBaseMult(&mut self, scalar: &slice<byte>) -> error;
    fn Add(&mut self, p1: Self, p2: Self) -> Self;
}

/// Pure forwarding: every nistec point already has these as inherent
/// methods. Go gets it from the type union in the constraint.
macro_rules! __impl_point {
    ($($t:ty),* $(,)?) => {$(
        impl Point for $t {
            fn Bytes(&self) -> slice<byte> {
                return <$t>::Bytes(self);
            }
            fn BytesX(&self) -> (slice<byte>, error) {
                return <$t>::BytesX(self);
            }
            fn SetBytes(&mut self, b: &slice<byte>) -> error {
                return <$t>::SetBytes(self, b);
            }
            fn ScalarMult(&mut self, q: Self, scalar: &slice<byte>) -> error {
                return <$t>::ScalarMult(self, q, scalar);
            }
            fn ScalarBaseMult(&mut self, scalar: &slice<byte>) -> error {
                return <$t>::ScalarBaseMult(self, scalar);
            }
            fn Add(&mut self, p1: Self, p2: Self) -> Self {
                <$t>::Add(self, p1, p2);
                return *self;
            }
        }
    )*};
}

__impl_point!(
    nistec::P224Point,
    nistec::P256Point,
    nistec::P384Point,
    nistec::P521Point,
);

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:73-81 precomputeParams
fn precomputeParams<P: Point>(c: curveParams<P>, order: &slice<byte>) -> Curve<P> {
    let (N, err) = Modulus::NewModulus(order.clone());
    if err != crate::nil {
        panic!("ecdsa: internal error: invalid curve order");
    }
    let mut two = Nat::NewNat();
    let (_, _) = two.SetBytes(slice::__from_vec(alloc::vec![2u8]), &N);
    let mut nMinus2 = Nat::NewNat();
    nMinus2.ExpandFor(&N);
    nMinus2.Sub(&two, &N);
    let nMinus2 = nMinus2.Bytes(&N);
    return Curve {
        curve: c.curve,
        newPoint: c.newPoint,
        ordInverse: c.ordInverse,
        N,
        nMinus2,
    };
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:83-83 P224
pub fn P224() -> &'static Curve<nistec::P224Point> {
    return &_P224;
}

// Go: ecdsa.go:85-92 — `var _P224 = sync.OnceValue(func() *Curve[…] { … })`
static _P224: Lazy<Curve<nistec::P224Point>> = Lazy::new(|| {
    return precomputeParams(
        curveParams {
            curve: p224,
            newPoint: nistec::NewP224Point,
            ordInverse: None,
        },
        &p224Order,
    );
});

// Go: ecdsa.go:94-99 — `var p224Order = []byte{…}`
static p224Order: Lazy<slice<byte>> = Lazy::new(|| {
    return slice::__from_vec(alloc::vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x16,
        0xa2, 0xe0, 0xb8, 0xf0, 0x3e, 0x13, 0xdd, 0x29, 0x45, 0x5c, 0x5c, 0x2a, 0x3d,
    ]);
});

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:101-101 P256
pub fn P256() -> &'static Curve<nistec::P256Point> {
    return &_P256;
}

// Go: ecdsa.go:103-111 — `var _P256 = sync.OnceValue(func() *Curve[…] { … })`
static _P256: Lazy<Curve<nistec::P256Point>> = Lazy::new(|| {
    return precomputeParams(
        curveParams {
            curve: p256,
            newPoint: nistec::NewP256Point,
            ordInverse: Some(nistec::P256OrdInverse),
        },
        &p256Order,
    );
});

// Go: ecdsa.go:113-117 — `var p256Order = []byte{…}`
static p256Order: Lazy<slice<byte>> = Lazy::new(|| {
    return slice::__from_vec(alloc::vec![
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ]);
});

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:119-119 P384
pub fn P384() -> &'static Curve<nistec::P384Point> {
    return &_P384;
}

// Go: ecdsa.go:121-128 — `var _P384 = sync.OnceValue(func() *Curve[…] { … })`
static _P384: Lazy<Curve<nistec::P384Point>> = Lazy::new(|| {
    return precomputeParams(
        curveParams {
            curve: p384,
            newPoint: nistec::NewP384Point,
            ordInverse: None,
        },
        &p384Order,
    );
});

// Go: ecdsa.go:130-136 — `var p384Order = []byte{…}`
static p384Order: Lazy<slice<byte>> = Lazy::new(|| {
    return slice::__from_vec(alloc::vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37,
        0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc,
        0xc5, 0x29, 0x73,
    ]);
});

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:138-138 P521
pub fn P521() -> &'static Curve<nistec::P521Point> {
    return &_P521;
}

// Go: ecdsa.go:140-147 — `var _P521 = sync.OnceValue(func() *Curve[…] { … })`
static _P521: Lazy<Curve<nistec::P521Point>> = Lazy::new(|| {
    return precomputeParams(
        curveParams {
            curve: p521,
            newPoint: nistec::NewP521Point,
            ordInverse: None,
        },
        &p521Order,
    );
});

// Go: ecdsa.go:149-157 — `var p521Order = []byte{…}`
static p521Order: Lazy<slice<byte>> = Lazy::new(|| {
    return slice::__from_vec(alloc::vec![
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01,
        0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f,
        0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09,
    ]);
});

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:159-171 NewPrivateKey
pub fn NewPrivateKey<P: Point>(
    c: &Curve<P>,
    D: &slice<byte>,
    Q: &slice<byte>,
) -> (PrivateKey, error) {
    fips140::RecordApproved();
    let (pubKey, err) = NewPublicKey(c, Q);
    if err != crate::nil {
        return (zeroPrivateKey(), err);
    }
    let mut d = Nat::NewNat();
    let (_, err) = d.SetBytes(D.clone(), &c.N);
    if err != crate::nil {
        return (zeroPrivateKey(), err);
    }
    let priv_ = PrivateKey {
        r#pub: pubKey,
        d: d.Bytes(&c.N),
    };
    return (priv_, crate::nil.into());
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:173-182 NewPublicKey
pub fn NewPublicKey<P: Point>(c: &Curve<P>, Q: &slice<byte>) -> (PublicKey, error) {
    // SetBytes checks that Q is a valid point on the curve, and that its
    // coordinates are reduced modulo p, fulfilling the requirements of SP
    // 800-89, Section 5.3.2.
    let mut p = (c.newPoint)();
    let err = p.SetBytes(Q);
    if err != crate::nil {
        return (zeroPublicKey(), err);
    }
    return (
        PublicKey {
            curve: c.curve,
            q: Q.clone(),
        },
        crate::nil.into(),
    );
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:184-204 GenerateKey
/// Generate a new ECDSA private key pair for the specified curve.
pub fn GenerateKey<P: Point>(
    c: &Curve<P>,
    rand: &mut (dyn io::Reader + Send + Sync + 'static),
) -> (PrivateKey, error) {
    fips140::RecordApproved();

    let (k, Q, err) = randomPoint(c, |b: &mut slice<byte>| {
        return drbg::ReadWithReader(rand, b);
    });
    if err != crate::nil {
        return (zeroPrivateKey(), err);
    }

    let priv_ = PrivateKey {
        r#pub: PublicKey {
            curve: c.curve,
            q: Q.Bytes(),
        },
        d: k.Bytes(&c.N),
    };
    fipsPCT(c, &priv_);
    return (priv_, crate::nil.into());
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:206-251 randomPoint
// goishlint:ignore GOISH023 — the body is Go's `for { … }`, which only
// leaves through an explicit return; Rust spells that as `loop { … }`,
// which parses as the tail expression.
/// Return a random scalar and the corresponding point using a procedure
/// equivalent to FIPS 186-5, Appendix A.2.2 (ECDSA Key Pair Generation by
/// Rejection Sampling) and to Appendix A.3.2 (Per-Message Secret Number
/// Generation of Private Keys by Rejection Sampling) or Appendix A.3.3
/// (Per-Message Secret Number Generation for Deterministic ECDSA) followed
/// by Step 5 of Section 6.4.1.
pub(super) fn randomPoint<P: Point, F: FnMut(&mut slice<byte>) -> error>(
    c: &Curve<P>,
    mut generate: F,
) -> (Nat, P, error) {
    loop {
        let mut b = slice::__from_vec(alloc::vec![0u8; c.N.Size() as usize]);
        let err = generate(&mut b);
        if err != crate::nil {
            return (Nat::NewNat(), (c.newPoint)(), err);
        }

        // Take only the leftmost bits of the generated random value. This
        // is both necessary to increase the chance of the random value
        // being in the correct range and to match the specification. It's
        // unfortunate that we need to do a shift instead of a mask, but see
        // the comment on rightShift.
        //
        // These are the most dangerous lines in the package and maybe in
        // the library: a single bit of bias in the selection of nonces
        // would likely lead to key recovery, but no tests would fail. Look
        // but DO NOT TOUCH.
        let excess = b.Len() * 8 - c.N.BitLen();
        if excess > 0 {
            // Just to be safe, assert that this only happens for the one
            // curve that doesn't have a round number of bits.
            if c.curve != p521 {
                panic!("ecdsa: internal error: unexpectedly masking off bits");
            }
            b = rightShift(&b, excess);
        }

        // FIPS 186-5, Appendix A.4.2 makes us check x <= N - 2 and then
        // return x + 1. Note that it follows that 0 < x + 1 < N. Instead,
        // SetBytes checks that k < N, and we explicitly check 0 != k. Since
        // k can't be negative, this is strictly equivalent. None of this
        // matters anyway because the chance of selecting zero is
        // cryptographically negligible.
        let mut k = Nat::NewNat();
        let (_, err) = k.SetBytes(b, &c.N);
        if err == crate::nil && k.IsZero() == 0 {
            let mut p = (c.newPoint)();
            let err = p.ScalarBaseMult(&k.Bytes(&c.N));
            return (k, p, err);
        }

        if let Some(f) = testingOnlyRejectionSamplingLooped {
            f();
        }
    }
}

// Go: ecdsa.go:253-255 — `var testingOnlyRejectionSamplingLooped func()`
//
/// Called when rejection sampling in randomPoint rejects a candidate for
/// being higher than the modulus. Go's is a nil func var set only by
/// tests; Rust `fn` pointers are not nullable, so it is an `Option`.
const testingOnlyRejectionSamplingLooped: Option<fn()> = None;

// Go: ecdsa.go:257-261
//   type Signature struct { R, S []byte }
/// An ECDSA signature, where r and s are represented as big-endian byte
/// slices of the same length as the curve order.
#[derive(Clone)]
pub struct Signature {
    pub R: slice<byte>,
    pub S: slice<byte>,
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:263-293 Sign
/// Sign a hash (which shall be the result of hashing a larger message with
/// the hash function H) using the private key, priv. If the hash is longer
/// than the bit-length of the private key's curve order, the hash will be
/// truncated to that length.
pub fn Sign<P: Point>(
    c: &Curve<P>,
    h: impl IntoHashFunc,
    priv_: &PrivateKey,
    rand: &mut (dyn io::Reader + Send + Sync + 'static),
    hash: &slice<byte>,
) -> (Signature, error) {
    if priv_.r#pub.curve != c.curve {
        return (
            zeroSignature(),
            errors::New("ecdsa: private key does not match curve"),
        );
    }
    fips140::RecordApproved();
    fipsSelfTest();

    // Random ECDSA is dangerous, because a failure of the RNG would
    // immediately leak the private key. Instead, we use a "hedged"
    // approach, as specified in draft-irtf-cfrg-det-sigs-with-noise-04,
    // Section 4. This has also the advantage of closely resembling
    // Deterministic ECDSA.

    let mut Z = slice::__from_vec(alloc::vec![0u8; priv_.d.Len() as usize]);
    let err = drbg::ReadWithReader(rand, &mut Z);
    if err != crate::nil {
        return (zeroSignature(), err);
    }

    // See https://github.com/cfrg/draft-irtf-cfrg-det-sigs-with-noise/issues/6
    // for the FIPS compliance of this method. In short Z is entropy from
    // the main DRBG, of length 3/2 of security_strength, so the nonce is
    // optional per SP 800-90Ar1, Section 8.6.7, and the rest is a
    // personalization string, which per SP 800-90Ar1, Section 8.7.1 may
    // contain secret information.
    let mut drbg = newDRBG(
        h,
        &Z,
        &empty(),
        personalizationString::blockAligned(blockAlignedPersonalizationString(
            slice::__from_vec(alloc::vec![priv_.d.clone(), bits2octets(c, hash)]),
        )),
    );

    return sign(c, priv_, &mut drbg, hash);
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:295-308 SignDeterministic
/// Sign a hash (which shall be the result of hashing a larger message with
/// the hash function H) using the private key, priv. If the hash is longer
/// than the bit-length of the private key's curve order, the hash will be
/// truncated to that length. This applies Deterministic ECDSA as specified
/// in FIPS 186-5 and RFC 6979.
pub fn SignDeterministic<P: Point>(
    c: &Curve<P>,
    h: impl IntoHashFunc,
    priv_: &PrivateKey,
    hash: &slice<byte>,
) -> (Signature, error) {
    if priv_.r#pub.curve != c.curve {
        return (
            zeroSignature(),
            errors::New("ecdsa: private key does not match curve"),
        );
    }
    fips140::RecordApproved();
    fipsSelfTestDeterministic();
    // RFC 6979, Section 3.3
    let mut drbg = newDRBG(
        h,
        &priv_.d,
        &bits2octets(c, hash),
        personalizationString::nil,
    );
    return sign(c, priv_, &mut drbg, hash);
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:310-316 bits2octets
/// bits2octets as specified in FIPS 186-5, Appendix B.2.4 or RFC 6979,
/// Section 2.3.4. See RFC 6979, Section 3.5 for the rationale.
pub(super) fn bits2octets<P: Point>(c: &Curve<P>, hash: &slice<byte>) -> slice<byte> {
    let mut e = Nat::NewNat();
    hashToNat(c, &mut e, hash);
    return e.Bytes(&c.N);
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:318-366 signGeneric
pub(super) fn signGeneric<P: Point>(
    c: &Curve<P>,
    priv_: &PrivateKey,
    drbg: &mut hmacDRBG,
    hash: &slice<byte>,
) -> (Signature, error) {
    // FIPS 186-5, Section 6.4.1

    let (k, R, err) = randomPoint(c, |b: &mut slice<byte>| {
        drbg.Generate(b);
        return crate::nil.into();
    });
    if err != crate::nil {
        return (zeroSignature(), err);
    }

    // kInv = k⁻¹
    let mut kInv = Nat::NewNat();
    inverse(c, &mut kInv, &k);

    let (Rx, err) = R.BytesX();
    if err != crate::nil {
        return (zeroSignature(), err);
    }
    let mut r = Nat::NewNat();
    let (_, err) = r.SetOverflowingBytes(Rx, &c.N);
    if err != crate::nil {
        return (zeroSignature(), err);
    }

    // The spec wants us to retry here, but the chance of hitting this
    // condition on a large prime-order group like the NIST curves we
    // support is cryptographically negligible. If we hit it, something is
    // awfully wrong.
    if r.IsZero() == 1 {
        return (zeroSignature(), errors::New("ecdsa: internal error: r is zero"));
    }

    let mut e = Nat::NewNat();
    hashToNat(c, &mut e, hash);

    let mut s = Nat::NewNat();
    let (_, err) = s.SetBytes(priv_.d.clone(), &c.N);
    if err != crate::nil {
        return (zeroSignature(), err);
    }
    s.Mul(&r, &c.N);
    s.Add(&e, &c.N);
    s.Mul(&kInv, &c.N);

    // Again, the chance of this happening is cryptographically negligible.
    if s.IsZero() == 1 {
        return (zeroSignature(), errors::New("ecdsa: internal error: s is zero"));
    }

    return (
        Signature {
            R: r.Bytes(&c.N),
            S: s.Bytes(&c.N),
        },
        crate::nil.into(),
    );
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:368-385 inverse
/// Set kInv to the inverse of k modulo the order of the curve.
fn inverse<P: Point>(c: &Curve<P>, kInv: &mut Nat, k: &Nat) {
    if let Some(ordInverse) = c.ordInverse {
        let (kBytes, err) = ordInverse(&k.Bytes(&c.N));
        // Some platforms don't implement ordInverse, and always return an
        // error.
        if err == crate::nil {
            let (_, err) = kInv.SetBytes(kBytes, &c.N);
            if err != crate::nil {
                panic!("ecdsa: internal error: ordInverse produced an invalid value");
            }
            return;
        }
    }

    // Calculate the inverse of s in GF(N) using Fermat's method
    // (exponentiation modulo P - 2, per Euler's theorem)
    kInv.Exp(k, c.nMinus2.clone(), &c.N);
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:387-404 hashToNat
/// Set e to the left-most bits of hash, according to FIPS 186-5, Section
/// 6.4.1, point 2 and Section 6.4.2, point 3.
fn hashToNat<P: Point>(c: &Curve<P>, e: &mut Nat, hash: &slice<byte>) {
    // ECDSA asks us to take the left-most log2(N) bits of hash, and use
    // them as an integer modulo N. This is the absolute worst of all
    // worlds: we still have to reduce, because the result might still
    // overflow N, but to take the left-most bits for P-521 we have to do a
    // right shift.
    let mut hash = hash.clone();
    let size = c.N.Size();
    if hash.Len() >= size {
        let raw: &[byte] = &hash;
        hash = slice::__from_vec(raw[..size as usize].to_vec());
        let excess = hash.Len() * 8 - c.N.BitLen();
        if excess > 0 {
            hash = rightShift(&hash, excess);
        }
    }
    let (_, err) = e.SetOverflowingBytes(hash, &c.N);
    if err != crate::nil {
        panic!("ecdsa: internal error: truncated hash is too long");
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:406-423 rightShift
/// Implement the right shift necessary for bits2int, which takes the
/// leftmost bits of either the hash or HMAC_DRBG output.
///
/// Note how taking the rightmost bits would have been as easy as masking
/// the first byte, but we can't have nice things.
fn rightShift(b: &slice<byte>, shift: int) -> slice<byte> {
    if shift <= 0 || shift >= 8 {
        panic!("ecdsa: internal error: shift can only be by 1 to 7 bits");
    }
    let src: &[byte] = b;
    let mut out = src.to_vec();
    let mut i = out.len();
    while i > 0 {
        i -= 1;
        out[i] >>= shift;
        if i > 0 {
            out[i] |= out[i - 1] << (8 - shift);
        }
    }
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:425-439 Verify
/// Verify the signature, sig, of hash (which should be the result of
/// hashing a larger message) using the public key, pub. If the hash is
/// longer than the bit-length of the private key's curve order, the hash
/// will be truncated to that length.
///
/// The inputs are not considered confidential, and may leak through timing
/// side channels, or if an attacker has control of part of the inputs.
pub fn Verify<P: Point>(
    c: &Curve<P>,
    pubKey: &PublicKey,
    hash: &slice<byte>,
    sig: &Signature,
) -> error {
    if pubKey.curve != c.curve {
        return errors::New("ecdsa: public key does not match curve");
    }
    fips140::RecordApproved();
    fipsSelfTest();
    return verify(c, pubKey, hash, sig);
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdsa/ecdsa.go:441-496 verifyGeneric
pub(super) fn verifyGeneric<P: Point>(
    c: &Curve<P>,
    pubKey: &PublicKey,
    hash: &slice<byte>,
    sig: &Signature,
) -> error {
    // FIPS 186-5, Section 6.4.2

    let mut Q = (c.newPoint)();
    let err = Q.SetBytes(&pubKey.q);
    if err != crate::nil {
        return err;
    }

    let mut r = Nat::NewNat();
    let (_, err) = r.SetBytes(sig.R.clone(), &c.N);
    if err != crate::nil {
        return err;
    }
    if r.IsZero() == 1 {
        return errors::New("ecdsa: invalid signature: r is zero");
    }
    let mut s = Nat::NewNat();
    let (_, err) = s.SetBytes(sig.S.clone(), &c.N);
    if err != crate::nil {
        return err;
    }
    if s.IsZero() == 1 {
        return errors::New("ecdsa: invalid signature: s is zero");
    }

    let mut e = Nat::NewNat();
    hashToNat(c, &mut e, hash);

    // w = s⁻¹
    let mut w = Nat::NewNat();
    inverse(c, &mut w, &s);

    // p₁ = [e * s⁻¹]G
    e.Mul(&w, &c.N);
    let mut p1 = (c.newPoint)();
    let err = p1.ScalarBaseMult(&e.Bytes(&c.N));
    if err != crate::nil {
        return err;
    }
    // p₂ = [r * s⁻¹]Q
    w.Mul(&r, &c.N);
    let q = Q;
    let err = Q.ScalarMult(q, &w.Bytes(&c.N));
    if err != crate::nil {
        return err;
    }
    // BytesX returns an error for the point at infinity.
    let a = p1;
    let sum = p1.Add(a, Q);
    let (Rx, err) = sum.BytesX();
    if err != crate::nil {
        return err;
    }

    let mut v = Nat::NewNat();
    let (_, err) = v.SetOverflowingBytes(Rx, &c.N);
    if err != crate::nil {
        return err;
    }

    if v.Equal(&r) != 1 {
        return errors::New("ecdsa: signature did not verify");
    }
    return crate::nil.into();
}

// go: none — Go returns nil pointers on the error paths; goish returns
// values, so the error paths need zero ones.
fn zeroPrivateKey() -> PrivateKey {
    return PrivateKey {
        r#pub: zeroPublicKey(),
        d: empty(),
    };
}

// go: none — the same, for *PublicKey.
fn zeroPublicKey() -> PublicKey {
    return PublicKey {
        curve: curveID(""),
        q: empty(),
    };
}

// go: none — the zero values above, reachable from outside the package.
// crypto/ecdsa returns them on its own error paths, mirroring Go's nil
// `*PublicKey` / `*PrivateKey`.
impl Default for PublicKey {
    fn default() -> Self {
        return zeroPublicKey();
    }
}

// go: none — see the PublicKey impl above.
impl Default for PrivateKey {
    fn default() -> Self {
        return zeroPrivateKey();
    }
}

// go: none — the same, for *Signature.
fn zeroSignature() -> Signature {
    return Signature {
        R: empty(),
        S: empty(),
    };
}

// go: none — Go writes a bare `nil` []byte in the two places that pass an
// absent nonce or personalization string.
fn empty() -> slice<byte> {
    return slice::__from_vec(Vec::<byte>::new());
}
