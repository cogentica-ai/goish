// go: file crypto/ecdsa/ecdsa_legacy.go decls: generateLegacy, hashToInt, one, Sign, signLegacy, Verify, verifyLegacy, randFieldElement
//
// A math/big implementation of ECDSA that is only used for deprecated
// custom curves.
//
// Deviations from ecdsa_legacy[go] @ Go 1.25.5:
//
//   * `signLegacy` needs `math/rand/v2`.NewChaCha8 to build the hedged
//     CSPRNG from its seed. goish's math/rand/v2 ports PCG only (see that
//     package's header), so the function returns an error at exactly that
//     step rather than silently signing with weaker hedging. Everything
//     before and after the missing line is ported, so restoring it is a
//     one-line change once ChaCha8 lands. Nothing in goish signs with a
//     custom curve — the four NIST curves never reach this file.
//   * Go's `ModInverse` returns nil when no inverse exists; goish's leaves
//     the receiver unchanged. Both call sites here invert a value that is
//     non-zero and less than a prime order, so an inverse always exists
//     and the two behaviours cannot diverge.
//   * `for { … }` loops that Go exits with `break` become `loop { … }`.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use super::ecdsa::{encodeSignature, parseSignature, PrivateKey, PublicKey};
use crate::crypto::elliptic;
use crate::crypto::internal::fips140only;
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::io;
use crate::math::big::{Int, NewInt};
use crate::types::byte;
use crate::{int, uint};

// go: sdk 1.25.5 crypto/ecdsa/ecdsa_legacy.go:22-37 generateLegacy
pub(super) fn generateLegacy(
    c: &'static (dyn elliptic::Curve + Send + Sync),
    rand: &mut (dyn io::Reader + Send + Sync + 'static),
) -> (PrivateKey, error) {
    if fips140only::Enabled {
        return (
            zeroPrivateKey(),
            errors::New("crypto/ecdsa: use of custom curves is not allowed in FIPS 140-only mode"),
        );
    }

    let (k, err) = randFieldElement(c, rand);
    if err != nil {
        return (zeroPrivateKey(), err);
    }

    let (x, y) = c.ScalarBaseMult(&k.Bytes());
    return (
        PrivateKey {
            PublicKey: PublicKey {
                Curve: c,
                X: x,
                Y: y,
            },
            D: k,
        },
        nil,
    );
}

// go: sdk 1.25.5 crypto/ecdsa/ecdsa_legacy.go:39-55 hashToInt
/// Convert a hash value to an integer. Per FIPS 186-4, Section 6.4, we use
/// the left-most bits of the hash to match the bit-length of the order of
/// the curve. This also performs Step 5 of SEC 1, Version 2.0,
/// Section 4.1.3.
fn hashToInt(hash: &slice<byte>, c: &(dyn elliptic::Curve + Send + Sync)) -> Int {
    let orderBits = c.Params().N.BitLen();
    let orderBytes = (orderBits + 7) / 8;
    let raw: &[byte] = hash;
    let hash: &[byte] = if int(raw.len()) > orderBytes {
        &raw[..orderBytes as usize]
    } else {
        raw
    };

    let mut ret = Int::default();
    ret.SetBytes(slice::__from_vec(hash.to_vec()));
    let excess = int(hash.len()) * 8 - orderBits;
    if excess > 0 {
        let cur = ret.clone();
        ret.Rsh(&cur, uint(excess));
    }
    return ret;
}

goish::var! {
    errZeroParam: error = "zero parameter";
}

// go: sdk 1.25.5 crypto/ecdsa/ecdsa_legacy.go:64-81 Sign
/// Sign a hash (which should be the result of hashing a larger message)
/// using the private key, `priv`. If the hash is longer than the bit-length
/// of the private key's curve order, the hash will be truncated to that
/// length. Returns the signature as a pair of integers. Most applications
/// should use [`super::ecdsa::SignASN1`] instead of dealing directly with
/// r, s.
pub fn Sign(
    rand: &mut (dyn io::Reader + Send + Sync + 'static),
    priv_: &PrivateKey,
    hash: &slice<byte>,
) -> (Int, Int, error) {
    let (sig, err) = super::ecdsa::SignASN1(rand, priv_, hash);
    if err != nil {
        return (Int::default(), Int::default(), err);
    }

    let (rb, sb, err) = parseSignature(&sig);
    if err != nil {
        return (
            Int::default(),
            Int::default(),
            errors::New("invalid ASN.1 from SignASN1"),
        );
    }
    let mut r = Int::default();
    let mut s = Int::default();
    r.SetBytes(rb);
    s.SetBytes(sb);
    return (r, s, nil);
}

// go: sdk 1.25.5 crypto/ecdsa/ecdsa_legacy.go:83-135 signLegacy
pub(super) fn signLegacy(
    priv_: &PrivateKey,
    csprng: &mut (dyn io::Reader + Send + Sync + 'static),
    hash: &slice<byte>,
) -> (slice<byte>, error) {
    if fips140only::Enabled {
        return (
            empty(),
            errors::New("crypto/ecdsa: use of custom curves is not allowed in FIPS 140-only mode"),
        );
    }

    // A cheap version of hedged signatures, for the deprecated path.
    let mut seed: [byte; 32] = [0u8; 32];
    let mut seedSlice = slice::__from_vec(seed.to_vec());
    let (_, err) = io::ReadFull(csprng, &mut seedSlice);
    if err != nil {
        return (empty(), err);
    }
    let sr: &[byte] = &seedSlice;
    seed.copy_from_slice(sr);
    for (i, b) in crate::range!(&priv_.D.Bytes()) {
        seed[(i as usize) % 32] ^= *b;
    }
    for (i, b) in crate::range!(hash) {
        seed[(i as usize) % 32] ^= *b;
    }

    // Go: csprng = rand.NewChaCha8(seed)
    //
    // goish's math/rand/v2 ports PCG only. Erroring here is the honest
    // stop: the alternative is to keep signing from the caller's reader,
    // which silently drops the hedging this function exists to provide.
    let _ = seed;
    return (
        empty(),
        errors::New(
            "crypto/ecdsa: signing with a custom curve needs math/rand/v2.NewChaCha8, which goish has not ported",
        ),
    );
}

// go: sdk 1.25.5 crypto/ecdsa/ecdsa_legacy.go:137-152 Verify
/// Verify the signature in r, s of hash using the public key, `pub`. Its
/// return value records whether the signature is valid. Most applications
/// should use [`super::ecdsa::VerifyASN1`] instead of dealing directly with
/// r, s.
///
/// The inputs are not considered confidential, and may leak through timing
/// side channels, or if an attacker has control of part of the inputs.
pub fn Verify(pub_: &PublicKey, hash: &slice<byte>, r: &Int, s: &Int) -> bool {
    if r.Sign() <= 0 || s.Sign() <= 0 {
        return false;
    }
    let (sig, err) = encodeSignature(&r.Bytes(), &s.Bytes());
    if err != nil {
        return false;
    }
    return super::ecdsa::VerifyASN1(pub_, hash, &sig);
}

// go: sdk 1.25.5 crypto/ecdsa/ecdsa_legacy.go:155-194 verifyLegacy
pub(super) fn verifyLegacy(pub_: &PublicKey, hash: &slice<byte>, sig: &slice<byte>) -> bool {
    if fips140only::Enabled {
        panic!("crypto/ecdsa: use of custom curves is not allowed in FIPS 140-only mode");
    }

    let (rBytes, sBytes, err) = parseSignature(sig);
    if err != nil {
        return false;
    }
    let mut r = Int::default();
    let mut s = Int::default();
    r.SetBytes(rBytes);
    s.SetBytes(sBytes);

    let c = pub_.Curve;
    let N = c.Params().N;

    if r.Sign() <= 0 || s.Sign() <= 0 {
        return false;
    }
    if r.Cmp(&N) >= 0 || s.Cmp(&N) >= 0 {
        return false;
    }

    // SEC 1, Version 2.0, Section 4.1.4
    let mut e = hashToInt(hash, c);
    let mut w = Int::default();
    w.ModInverse(&s, &N);

    let mut u1 = Int::default();
    u1.Mul(&e, &w);
    let cur = u1.clone();
    u1.Mod(&cur, &N);
    let mut u2 = Int::default();
    u2.Mul(&r, &w);
    let cur = u2.clone();
    u2.Mod(&cur, &N);
    let _ = &mut e;

    let (x1, y1) = c.ScalarBaseMult(&u1.Bytes());
    let (x2, y2) = c.ScalarMult(&pub_.X, &pub_.Y, &u2.Bytes());
    let (mut x, y) = c.Add(&x1, &y1, &x2, &y2);

    if x.Sign() == 0 && y.Sign() == 0 {
        return false;
    }
    let cur = x.clone();
    x.Mod(&cur, &N);
    return x.Cmp(&r) == 0;
}

// go: sdk 1.25.5 crypto/ecdsa/ecdsa_legacy.go:196-196 one
//
// Go: `var one = new(big.Int).SetInt64(1)`. Go declares it at package
// scope; goish builds it on demand because
// `big::Int` has no const constructor. Unused by the ported paths, kept
// for completeness of the file.
#[allow(dead_code)]
fn one() -> Int {
    return NewInt(1);
}

// go: sdk 1.25.5 crypto/ecdsa/ecdsa_legacy.go:200-215 randFieldElement
// goishlint:ignore GOISH023 — Go's `for { … return … }`; Rust spells the
// same unbounded loop as `loop { … }`, which parses as a tail expression.
/// Return a random element of the order of the given curve using the
/// procedure given in FIPS 186-4, Appendix B.5.2.
fn randFieldElement(
    c: &(dyn elliptic::Curve + Send + Sync),
    rand: &mut (dyn io::Reader + Send + Sync + 'static),
) -> (Int, error) {
    loop {
        let N = c.Params().N;
        let mut b = slice::__from_vec(alloc::vec![0u8; ((N.BitLen() + 7) / 8) as usize]);
        let (_, err) = io::ReadFull(rand, &mut b);
        if err != nil {
            return (Int::default(), err);
        }
        let excess = b.Len() * 8 - N.BitLen();
        if excess > 0 {
            let raw: &mut [byte] = &mut b;
            raw[0] >>= excess;
        }
        let mut k = Int::default();
        k.SetBytes(b);
        if k.Sign() != 0 && k.Cmp(&N) < 0 {
            return (k, nil);
        }
    }
}

// go: none — Go writes `nil` for an absent `[]byte`.
fn empty() -> slice<byte> {
    return slice::__from_vec(Vec::<byte>::new());
}

// go: none — Go returns a nil `*PrivateKey` on error; goish pairs a zero
// value with the error, as ecdsa.rs does.
fn zeroPrivateKey() -> PrivateKey {
    return PrivateKey {
        PublicKey: PublicKey {
            Curve: elliptic::P256(),
            X: Int::default(),
            Y: Int::default(),
        },
        D: Int::default(),
    };
}
