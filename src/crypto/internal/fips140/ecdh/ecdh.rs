// go: file crypto/internal/fips140/ecdh/ecdh.go decls: PrivateKey.Bytes, PrivateKey.PublicKey, PublicKey.Bytes, P224, P256, P384, P521, GenerateKey, NewPrivateKey, NewPublicKey, ECDH, ecdh, isZero, isLess
//
// Deviations from ecdh[go] @ Go 1.25.5:
//
//   * Go's `type Point[P any] interface { *nistec.P224Point | … ; Bytes()
//     … }` is a *constraint* interface with a type union, not a runtime
//     one. Rust has no type unions, so it becomes a plain trait
//     implemented for the four nistec point types. `Curve[P Point[P]]`
//     follows as `Curve<P: Point>`.
//   * The trait's methods carry goish's nistec shapes — `SetBytes` and the
//     two scalar multiplications mutate the receiver and return `error`
//     rather than returning `(P, error)` — because that is what
//     `crypto/internal/fips140/nistec` exposes here.
//   * `type curveID string` becomes a newtype over `&'static str`: the
//     four values are compile-time constants compared only for equality,
//     and goish's `string` is `Arc<[u8]>`-backed and so not
//     const-constructible. It never appears in a signature.
//   * Go's methods returning `*PrivateKey` / `*PublicKey` plus an error
//     return the value plus an error here, with the zero value on the
//     error path.
//   * `PrivateKey.pub` keeps its Go name as the raw identifier `r#pub`.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::internal::fips140;
use crate::crypto::internal::fips140::drbg;
use crate::crypto::internal::fips140::nistec;
use crate::crypto::internal::fips140deps::byteorder;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::lazy::Lazy;
use crate::math::bits;
use crate::types::byte;
use crate::{error, uint64};

use super::cast::fipsSelfTest;

// PrivateKey and PublicKey are not generic to make it possible to use them
// in other types without instantiating them with a specific point type.
// They are tied to one of the Curve types below through the curveID field.

// All this is duplicated from crypto/internal/fips/ecdsa, but the standards
// are different and FIPS 140 does not allow reusing keys across them.

// Go: ecdh.go:25-28
//   type PrivateKey struct { pub PublicKey; d []byte }
#[derive(Clone)]
pub struct PrivateKey {
    // Go's fields are package-scoped; `pub(super)` is that scope here, so
    // cast.rs can build the known-answer key exactly as cast.go does.
    pub(super) r#pub: PublicKey,
    /// bigmod.(*Nat).Bytes output (fixed length)
    pub(super) d: slice<byte>,
}

impl PrivateKey {
    // go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:30-32 Bytes
    pub fn Bytes(&self) -> slice<byte> {
        return self.d.clone();
    }

    // go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:34-36 PublicKey
    pub fn PublicKey(&self) -> PublicKey {
        return self.r#pub.clone();
    }
}

// Go: ecdh.go:38-41
//   type PublicKey struct { curve curveID; q []byte }
#[derive(Clone)]
pub struct PublicKey {
    pub(super) curve: curveID,
    /// uncompressed nistec Point.Bytes output
    pub(super) q: slice<byte>,
}

impl PublicKey {
    // go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:43-45 Bytes
    pub fn Bytes(&self) -> slice<byte> {
        return self.q.clone();
    }
}

// Go: ecdh.go:47
//   type curveID string
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct curveID(&'static str);

// Go: ecdh.go:49-54 — `const ( p224 curveID = "P-224"; … )`
const p224: curveID = curveID("P-224");
pub(super) const p256: curveID = curveID("P-256");
const p384: curveID = curveID("P-384");
const p521: curveID = curveID("P-521");

// Go: ecdh.go:56-60
//   type Curve[P Point[P]] struct { curve curveID; newPoint func() P; N []byte }
pub struct Curve<P: Point> {
    curve: curveID,
    newPoint: fn() -> P,
    pub N: slice<byte>,
}

// Go: ecdh.go:62-70
//   type Point[P any] interface { *nistec.P224Point | … }
/// A generic constraint for the [nistec] Point types.
pub trait Point: Copy + Sized {
    fn Bytes(&self) -> slice<byte>;
    fn BytesX(&self) -> (slice<byte>, error);
    fn SetBytes(&mut self, b: &slice<byte>) -> error;
    fn ScalarMult(&mut self, q: Self, scalar: &slice<byte>) -> error;
    fn ScalarBaseMult(&mut self, scalar: &slice<byte>) -> error;
}

/// The four `impl Point` blocks below are pure forwarding: every nistec
/// point already has these methods as inherent ones with the same
/// signatures. Go gets this for free from the type union in the
/// constraint; Rust needs it spelled out once per type.
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
        }
    )*};
}

__impl_point!(
    nistec::P224Point,
    nistec::P256Point,
    nistec::P384Point,
    nistec::P521Point,
);

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:72-78 P224
pub fn P224() -> Curve<nistec::P224Point> {
    return Curve {
        curve: p224,
        newPoint: nistec::NewP224Point,
        N: p224Order.clone(),
    };
}

// Go: ecdh.go:80-85 — `var p224Order = []byte{…}`
static p224Order: Lazy<slice<byte>> = Lazy::new(|| {
    return slice::__from_vec(alloc::vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x16,
        0xa2, 0xe0, 0xb8, 0xf0, 0x3e, 0x13, 0xdd, 0x29, 0x45, 0x5c, 0x5c, 0x2a, 0x3d,
    ]);
});

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:87-93 P256
pub fn P256() -> Curve<nistec::P256Point> {
    return Curve {
        curve: p256,
        newPoint: nistec::NewP256Point,
        N: p256Order.clone(),
    };
}

// Go: ecdh.go:95-100 — `var p256Order = []byte{…}`
static p256Order: Lazy<slice<byte>> = Lazy::new(|| {
    return slice::__from_vec(alloc::vec![
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ]);
});

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:102-108 P384
pub fn P384() -> Curve<nistec::P384Point> {
    return Curve {
        curve: p384,
        newPoint: nistec::NewP384Point,
        N: p384Order.clone(),
    };
}

// Go: ecdh.go:110-117 — `var p384Order = []byte{…}`
static p384Order: Lazy<slice<byte>> = Lazy::new(|| {
    return slice::__from_vec(alloc::vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37,
        0x2d, 0xdf, 0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc,
        0xc5, 0x29, 0x73,
    ]);
});

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:119-125 P521
pub fn P521() -> Curve<nistec::P521Point> {
    return Curve {
        curve: p521,
        newPoint: nistec::NewP521Point,
        N: p521Order.clone(),
    };
}

// Go: ecdh.go:127-136 — `var p521Order = []byte{…}`
static p521Order: Lazy<slice<byte>> = Lazy::new(|| {
    return slice::__from_vec(alloc::vec![
        0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01,
        0x48, 0xf7, 0x09, 0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f,
        0xb7, 0x1e, 0x91, 0x38, 0x64, 0x09,
    ]);
});

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:138-187 GenerateKey
// goishlint:ignore GOISH023 — the body is Go's `for { … }`, which only
// leaves through an explicit return; Rust spells that unconditional loop
// as `loop { … }`, which parses as the tail expression.
/// Generate a new ECDSA private key pair for the specified curve.
pub fn GenerateKey<P: Point>(
    c: &Curve<P>,
    rand: &mut (dyn io::Reader + Send + Sync + 'static),
) -> (PrivateKey, error) {
    fips140::RecordApproved();
    // This procedure is equivalent to Key Pair Generation by Testing
    // Candidates, specified in NIST SP 800-56A Rev. 3, Section 5.6.1.2.2.

    loop {
        let mut key = slice::__from_vec(alloc::vec![0u8; c.N.Len() as usize]);
        let err = drbg::ReadWithReader(rand, &mut key);
        if err != crate::nil {
            return (zeroPrivateKey(), err);
        }
        {
            // In tests, rand will return all zeros and NewPrivateKey will
            // reject the zero key as it generates the identity as a public
            // key. This also makes this function consistent with
            // crypto/elliptic.GenerateKey.
            let k: &mut [byte] = &mut key;
            k[1] ^= 0x42;

            // Mask off any excess bits if the size of the underlying field
            // is not a whole number of bytes, which is only the case for
            // P-521.
            let n: &[byte] = &c.N;
            if c.curve == p521 && n[0] & 0b1111_1110 == 0 {
                k[0] &= 0b0000_0001;
            }
        }

        let (privateKey, err) = NewPrivateKey(c, &key);
        if err != crate::nil {
            continue;
        }

        // A "Pairwise Consistency Test" makes no sense if we just generated
        // the public key from an ephemeral private key. Moreover, there is
        // no way to check it aside from redoing the exact same computation
        // again. SP 800-56A Rev. 3, Section 5.6.2.1.4 acknowledges that, and
        // doesn't require it. However, ISO 19790:2012, Section 7.10.3.3 has
        // a blanket requirement for a PCT for all generated keys (AS10.35)
        // and FIPS 140-3 IG 10.3.A, Additional Comment 1 goes out of its way
        // to say that "the PCT shall be performed consistent [...], even if
        // the underlying standard does not require a PCT". So we do it. And
        // make ECDH nearly 50% slower (only) in FIPS mode.
        let newPoint = c.newPoint;
        let d = privateKey.d.clone();
        let q = privateKey.r#pub.q.clone();
        fips140::PCT("ECDH PCT", || {
            let mut p1 = newPoint();
            let err = p1.ScalarBaseMult(&d);
            if err != crate::nil {
                return err;
            }
            if !bytesEqual(&p1.Bytes(), &q) {
                return errors::New("crypto/ecdh: public key does not match private key");
            }
            return crate::nil.into();
        });

        return (privateKey, crate::nil.into());
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:189-214 NewPrivateKey
pub fn NewPrivateKey<P: Point>(c: &Curve<P>, key: &slice<byte>) -> (PrivateKey, error) {
    // SP 800-56A Rev. 3, Section 5.6.1.2.2 checks that c <= n – 2 and then
    // returns d = c + 1. Note that it follows that 0 < d < n. Equivalently,
    // we check that 0 < d < n, and return d.
    if key.Len() != c.N.Len() || isZero(key) || !isLess(key, &c.N) {
        return (
            zeroPrivateKey(),
            errors::New("crypto/ecdh: invalid private key"),
        );
    }

    let mut p = (c.newPoint)();
    let err = p.ScalarBaseMult(key);
    if err != crate::nil {
        // This is unreachable because the only error condition of
        // ScalarBaseMult is if the input is not the right size.
        panic!("crypto/ecdh: internal error: nistec ScalarBaseMult failed for a fixed-size input");
    }

    let publicKey = p.Bytes();
    if publicKey.Len() == 1 {
        // The encoding of the identity is a single 0x00 byte. This is
        // unreachable because the only scalar that generates the identity is
        // zero, which is rejected above.
        panic!("crypto/ecdh: internal error: public key is the identity element");
    }

    let raw: &[byte] = key;
    let k = PrivateKey {
        d: slice::__from_vec(raw.to_vec()),
        r#pub: PublicKey {
            curve: c.curve,
            q: publicKey,
        },
    };
    return (k, crate::nil.into());
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:216-231 NewPublicKey
pub fn NewPublicKey<P: Point>(c: &Curve<P>, key: &slice<byte>) -> (PublicKey, error) {
    let raw: &[byte] = key;
    // Reject the point at infinity and compressed encodings.
    if raw.is_empty() || raw[0] != 4 {
        return (
            zeroPublicKey(),
            errors::New("crypto/ecdh: invalid public key"),
        );
    }

    // SetBytes checks that x and y are in the interval [0, p - 1], and that
    // the point is on the curve. Along with the rejection of the point at
    // infinity (the identity element) above, this fulfills the requirements
    // of NIST SP 800-56A Rev. 3, Section 5.6.2.3.4.
    let mut p = (c.newPoint)();
    let err = p.SetBytes(key);
    if err != crate::nil {
        return (zeroPublicKey(), err);
    }

    return (
        PublicKey {
            curve: c.curve,
            q: slice::__from_vec(raw.to_vec()),
        },
        crate::nil.into(),
    );
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:233-237 ECDH
pub fn ECDH<P: Point>(c: &Curve<P>, k: &PrivateKey, peer: &PublicKey) -> (slice<byte>, error) {
    fipsSelfTest();
    fips140::RecordApproved();
    return ecdh(c, k, peer);
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:239-270 ecdh
pub(super) fn ecdh<P: Point>(
    c: &Curve<P>,
    k: &PrivateKey,
    peer: &PublicKey,
) -> (slice<byte>, error) {
    if c.curve != k.r#pub.curve {
        return (
            slice::__from_vec(Vec::<byte>::new()),
            errors::New("crypto/ecdh: mismatched curves"),
        );
    }
    if k.r#pub.curve != peer.curve {
        return (
            slice::__from_vec(Vec::<byte>::new()),
            errors::New("crypto/ecdh: mismatched curves"),
        );
    }

    // This applies the Shared Secret Computation of the Ephemeral Unified
    // Model scheme specified in NIST SP 800-56A Rev. 3, Section 6.1.2.2.

    // Per Section 5.6.2.3.4, Step 1, reject the identity element (0x00).
    if k.r#pub.q.Len() == 1 {
        return (
            slice::__from_vec(Vec::<byte>::new()),
            errors::New("crypto/ecdh: public key is the identity element"),
        );
    }

    // SetBytes checks that (x, y) are reduced modulo p, and that they are on
    // the curve, performing Steps 2-3 of Section 5.6.2.3.4.
    let mut p = (c.newPoint)();
    let err = p.SetBytes(&peer.q);
    if err != crate::nil {
        return (slice::__from_vec(Vec::<byte>::new()), err);
    }

    // Compute P according to Section 5.7.1.2.
    let q = p;
    let err = p.ScalarMult(q, &k.d);
    if err != crate::nil {
        return (slice::__from_vec(Vec::<byte>::new()), err);
    }

    // BytesX checks that the result is not the identity element, and returns
    // the x-coordinate of the result, performing Steps 2-5 of Section 5.7.1.2.
    return p.BytesX();
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:272-279 isZero
/// Report whether x is all zeroes in constant time.
fn isZero(x: &slice<byte>) -> bool {
    let mut acc: byte = 0;
    for (_, b) in crate::range!(x) {
        acc |= *b;
    }
    return acc == 0;
}

// go: sdk 1.25.5 crypto/internal/fips140/ecdh/ecdh.go:281-308 isLess
/// Report whether a < b, where a and b are big-endian buffers of the same
/// length and shorter than 72 bytes.
fn isLess(a: &slice<byte>, b: &slice<byte>) -> bool {
    if a.Len() != b.Len() {
        panic!("crypto/ecdh: internal error: mismatched isLess inputs");
    }

    // Copy the values into a fixed-size preallocated little-endian buffer.
    // 72 bytes is enough for every scalar in this package, and having a
    // fixed size lets us avoid heap allocations.
    if a.Len() > 72 {
        panic!("crypto/ecdh: internal error: isLess input too large");
    }
    let ar: &[byte] = a;
    let br: &[byte] = b;
    let mut bufA = [0u8; 72];
    let mut bufB = [0u8; 72];
    let mut i: usize = 0;
    while i < ar.len() {
        bufA[i] = ar[ar.len() - i - 1];
        bufB[i] = br[br.len() - i - 1];
        i += 1;
    }

    // Perform a subtraction with borrow.
    let mut borrow: uint64 = 0;
    let mut i: usize = 0;
    while i < bufA.len() {
        let limbA = byteorder::LEUint64(slice::__from_vec(bufA[i..].to_vec()));
        let limbB = byteorder::LEUint64(slice::__from_vec(bufB[i..].to_vec()));
        let (_, br2) = bits::Sub64(limbA, limbB, borrow);
        borrow = br2;
        i += 8;
    }

    // If there is a borrow at the end of the operation, then a < b.
    return borrow == 1;
}

// go: none — Go returns a nil *PrivateKey on the error paths; goish
// returns a value, so the error paths need a zero one.
fn zeroPrivateKey() -> PrivateKey {
    return PrivateKey {
        r#pub: zeroPublicKey(),
        d: slice::__from_vec(Vec::<byte>::new()),
    };
}

// go: none — the same, for *PublicKey.
fn zeroPublicKey() -> PublicKey {
    return PublicKey {
        curve: curveID(""),
        q: slice::__from_vec(Vec::<byte>::new()),
    };
}

// go: none — Go calls `bytes.Equal`; goish's crypto ports compare the
// borrowed backing directly rather than pulling in the bytes package.
pub(super) fn bytesEqual(a: &slice<byte>, b: &slice<byte>) -> bool {
    let ar: &[byte] = a;
    let br: &[byte] = b;
    return ar == br;
}
