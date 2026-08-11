// go: file crypto/internal/fips140/rsa/pkcs1v15.go decls: hashPrefixes, SignPKCS1v15, signPKCS1v15, pkcs1v15ConstructEM, VerifyPKCS1v15, verifyPKCS1v15, checkApprovedHashName
//
// Signing and verification using PKCS #1 v1.5 signatures.
//
// Deviations from pkcs1v15[go] @ Go 1.25.5:
//
//   * Go keys `hashPrefixes` by the hash function NAME as returned by
//     `crypto.Hash.String()` ("SHA-256", "MD5+SHA1", …), and the whole
//     file threads that `hash string` through. goish threads the
//     `crypto.Hash` identifier instead — the established goish idiom,
//     and the one thing `crypto/rsa` already had in hand — so
//     `hashPrefixes` is a match on the identifier rather than a
//     `map<string, slice<byte>>`. Every Go key has an entry, including
//     the two the identifier form makes easy to forget: `MD5+SHA1`
//     (TLS 1.0/1.1, deliberately EMPTY prefix) and `RIPEMD-160`.
//     Go's empty `hash string` sentinel — sign the digest directly with
//     no DigestInfo prefix — is `crypto.Hash(0)` here.

extern crate alloc;

use super::cast::fipsSelfTest;
use super::rsa::{
    checkPublicKey, decrypt, encrypt, nil_bytes, noCheck, read_with_reader,
    withCheck, ErrDecryption, ErrMessageTooLong, ErrVerification, PrivateKey, PublicKey,
};
use crate::bytes;
use crate::crypto::internal::fips140;
use crate::crypto::Hash as HashId;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int};
use alloc::vec::Vec;

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v15.go:25-40 hashPrefixes
/// `hashPrefixes` — the precomputed ASN.1 DER `DigestInfo` prefixes.
///
/// These are ASN1 DER structures:
///
/// ```text
/// DigestInfo ::= SEQUENCE {
///   digestAlgorithm AlgorithmIdentifier,
///   digest OCTET STRING
/// }
/// ```
///
/// For performance, we don't use the generic ASN1 encoder. Rather, we
/// precompute a prefix of the digest value that makes a valid ASN1 DER
/// string with the correct contents.
fn hashPrefixes(hash: HashId) -> Option<&'static [byte]> {
    const MD5_P: &[byte] = &[
        0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05,
        0x00, 0x04, 0x10,
    ];
    const SHA1_P: &[byte] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    const SHA224_P: &[byte] = &[
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
        0x05, 0x00, 0x04, 0x1c,
    ];
    const SHA256_P: &[byte] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA384_P: &[byte] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    const SHA512_P: &[byte] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];
    const SHA512_224_P: &[byte] = &[
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
        0x05, 0x00, 0x04, 0x1c,
    ];
    const SHA512_256_P: &[byte] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA3_224_P: &[byte] = &[
        0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07,
        0x05, 0x00, 0x04, 0x1c,
    ];
    const SHA3_256_P: &[byte] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA3_384_P: &[byte] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09,
        0x05, 0x00, 0x04, 0x30,
    ];
    const SHA3_512_P: &[byte] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a,
        0x05, 0x00, 0x04, 0x40,
    ];
    // A special TLS case which doesn't use an ASN1 prefix.
    const MD5SHA1_P: &[byte] = &[];
    const RIPEMD160_P: &[byte] = &[
        0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14,
    ];

    return match hash {
        x if x == crate::crypto::MD5 => Some(MD5_P),
        x if x == crate::crypto::SHA1 => Some(SHA1_P),
        x if x == crate::crypto::SHA224 => Some(SHA224_P),
        x if x == crate::crypto::SHA256 => Some(SHA256_P),
        x if x == crate::crypto::SHA384 => Some(SHA384_P),
        x if x == crate::crypto::SHA512 => Some(SHA512_P),
        x if x == crate::crypto::SHA512_224 => Some(SHA512_224_P),
        x if x == crate::crypto::SHA512_256 => Some(SHA512_256_P),
        x if x == crate::crypto::SHA3_224 => Some(SHA3_224_P),
        x if x == crate::crypto::SHA3_256 => Some(SHA3_256_P),
        x if x == crate::crypto::SHA3_384 => Some(SHA3_384_P),
        x if x == crate::crypto::SHA3_512 => Some(SHA3_512_P),
        x if x == crate::crypto::MD5SHA1 => Some(MD5SHA1_P),
        x if x == crate::crypto::RIPEMD160 => Some(RIPEMD160_P),
        _ => None,
    };
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v15.go:46-52 SignPKCS1v15
/// `SignPKCS1v15` calculates an RSASSA-PKCS1-v1.5 signature.
///
/// `hash` identifies the hash function used to produce `hashed`; pass
/// `crypto.Hash(0)` (Go's empty hash name) to indicate that the message
/// is signed directly.
pub fn SignPKCS1v15(
    priv_: &PrivateKey,
    hash: HashId,
    hashed: slice<byte>,
) -> (slice<byte>, error) {
    fipsSelfTest();
    fips140::RecordApproved();
    checkApprovedHashName(hash);

    return signPKCS1v15(priv_, hash, hashed);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v15.go:54-61 signPKCS1v15
pub(super) fn signPKCS1v15(
    priv_: &PrivateKey,
    hash: HashId,
    hashed: slice<byte>,
) -> (slice<byte>, error) {
    let (em, err) = pkcs1v15ConstructEM(&priv_.pub_, hash, hashed);
    if !err.IsNil() {
        return (nil_bytes(), err);
    }

    return decrypt(priv_, em, withCheck);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v15.go:63-87 pkcs1v15ConstructEM
fn pkcs1v15ConstructEM(
    pub_: &PublicKey,
    hash: HashId,
    hashed: slice<byte>,
) -> (slice<byte>, error) {
    // Special case: crypto.Hash(0) (Go's "") indicates that the data is
    // signed directly.
    let prefix: &[byte] = if hash != crate::crypto::Hash(0) {
        match hashPrefixes(hash) {
            Some(p) => p,
            None => {
                return (
                    nil_bytes(),
                    errors::New("crypto/rsa: unsupported hash function"),
                );
            }
        }
    } else {
        &[]
    };

    // EM = 0x00 || 0x01 || PS || 0x00 || T
    let k = usize::try_from(pub_.Size()).unwrap_or(0);
    let prefix_len = prefix.len();
    let hashed_v = hashed.to_vec();
    let hashed_len = hashed_v.len();
    if k < prefix_len + hashed_len + 2 + 8 + 1 {
        return (nil_bytes(), ErrMessageTooLong.into());
    }
    let mut em: Vec<byte> = alloc::vec![0u8; k];
    em[1] = 1;
    let mut i: usize = 2;
    while i < k - prefix_len - hashed_len - 1 {
        em[i] = 0xff;
        i += 1;
    }
    // copy(em[k-len(prefix)-len(hashed):], prefix)
    let pstart = k - prefix_len - hashed_len;
    let mut j: usize = 0;
    while j < prefix_len {
        em[pstart + j] = prefix[j];
        j += 1;
    }
    // copy(em[k-len(hashed):], hashed)
    let hstart = k - hashed_len;
    let mut j: usize = 0;
    while j < hashed_len {
        em[hstart + j] = hashed_v[j];
        j += 1;
    }
    return (slice::<byte>::__from_vec(em), errors::nil);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v15.go:93-99 VerifyPKCS1v15
/// `VerifyPKCS1v15` verifies an RSASSA-PKCS1-v1.5 signature.
///
/// `hash` identifies the hash function used to produce `hashed`, or
/// `crypto.Hash(0)` if the message was signed directly.
pub fn VerifyPKCS1v15(
    pub_: &PublicKey,
    hash: HashId,
    hashed: slice<byte>,
    sig: slice<byte>,
) -> error {
    fipsSelfTest();
    fips140::RecordApproved();
    checkApprovedHashName(hash);

    return verifyPKCS1v15(pub_, hash, hashed, sig);
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v15.go:101-129 verifyPKCS1v15
pub(super) fn verifyPKCS1v15(
    pub_: &PublicKey,
    hash: HashId,
    hashed: slice<byte>,
    sig: slice<byte>,
) -> error {
    let (fipsApproved, err) = checkPublicKey(pub_);
    if !err.IsNil() {
        return err;
    } else if !fipsApproved {
        fips140::RecordNonApproved();
    }

    // RFC 8017 Section 8.2.2: If the length of the signature S is not k
    // octets (where k is the length in octets of the RSA modulus n),
    // output "invalid signature" and stop.
    if pub_.Size() != sig.Len() {
        return ErrVerification.into();
    }

    let (em, err) = encrypt(pub_, sig);
    if !err.IsNil() {
        return ErrVerification.into();
    }

    let (expected, err) = pkcs1v15ConstructEM(pub_, hash, hashed);
    if !err.IsNil() {
        return ErrVerification.into();
    }
    if !bytes::Equal(em, expected) {
        return ErrVerification.into();
    }

    return errors::nil;
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/pkcs1v15.go:131-138 checkApprovedHashName
fn checkApprovedHashName(hash: HashId) {
    match hash {
        x if x == crate::crypto::SHA224
            || x == crate::crypto::SHA256
            || x == crate::crypto::SHA384
            || x == crate::crypto::SHA512
            || x == crate::crypto::SHA512_224
            || x == crate::crypto::SHA512_256
            || x == crate::crypto::SHA3_224
            || x == crate::crypto::SHA3_256
            || x == crate::crypto::SHA3_384
            || x == crate::crypto::SHA3_512 => {}
        _ => fips140::RecordNonApproved(),
    }
}
