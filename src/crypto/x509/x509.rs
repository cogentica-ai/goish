// go: file crypto/x509/x509.go decls: SignatureAlgorithm.isRSAPSS, SignatureAlgorithm.hashFunc, SignatureAlgorithm.String, PublicKeyAlgorithm.String, getSignatureAlgorithmFromAI, getPublicKeyAlgorithmFromOID, namedCurveFromOID, oidFromNamedCurve, oidFromECDHCurve, extKeyUsageFromOID, oidFromExtKeyUsage, InsecureAlgorithmError.Error, ConstraintViolationError.Error, Certificate.Equal, Certificate.hasSANExtension, Certificate.hasNameConstraints, Certificate.getSANExtension, UnhandledCriticalExtension.Error, oidInExtensions, isIA5String
//
// The X.509 type surface: the algorithm identifiers, the OID tables and
// the `Certificate` struct every other file in the package hangs on.
//
// **Partial port, and deliberately so.** x509.go is 2565 lines. What is
// here is the *parsing* half of its type surface — everything
// `parser.go` reads or writes. The *marshaling* half (CreateCertificate,
// buildCertExtensions, marshalSANs, signTBS, MarshalPKIXPublicKey and
// their helpers), the signature-checking half (CheckSignature,
// CheckSignatureFrom, checkSignature), and the CSR / CRL types
// (CertificateRequest, RevocationList and friends) are absent, not
// stubbed. Both halves are blocked on the same two things: Go builds
// certificates with `asn1.Marshal` of tagged structs, and reads the
// leftovers with `asn1.Unmarshal`, which goish does not have.
//
// Deviations from x509[go] @ Go 1.25.5:
//
//   * Go's package-level `var oidSignatureSHA256WithRSA =
//     asn1.ObjectIdentifier{…}` are heap slices; goish has no const
//     slice, so each is a function returning its ObjectIdentifier. Same
//     names, same values — the idiom `crypto/x509/pkix` already uses.
//   * `signatureAlgorithmDetails` is a slice of an *anonymous* struct in
//     Go. Rust has no anonymous struct type, so the row gets a name,
//     `signatureAlgorithmDetail`, with Go's field names verbatim.
//   * `Certificate.PublicKey` is Go's `any`; goish holds `goany::Any`.
//     The key is wrapped with `Any::new_fn`, not `Any::new`, because
//     `Any::new` demands `PartialEq` and none of `rsa.PublicKey`,
//     `ecdsa.PublicKey`, `ed25519.PublicKey` or `dsa.PublicKey` is
//     `==`-comparable in goish (Go spells their comparison as an
//     `Equal` method). `As::<T>()` sees through the wrapper, so
//     retrieval is unaffected; the only difference is that two
//     `Any`-wrapped keys never compare equal, which matches Go's
//     pointer-identity comparison of two separately parsed `*rsa.
//     PublicKey` values.
//   * `Certificate.URIs` is `slice<url::URL>` for Go's `[]*url.URL`, and
//     `PermittedIPRanges` / `ExcludedIPRanges` are `slice<net::IPNet>`
//     for `[]*net.IPNet` — goish models a Go pointer-to-struct as the
//     value throughout.
//   * `getSignatureAlgorithmFromAI`'s RSA-PSS branch is NOT ported: it
//     is `asn1.Unmarshal(ai.Parameters.FullBytes, &params)` into a
//     tagged `pssParameters` struct, and goish has no `asn1.Unmarshal`.
//     An RSA-PSS algorithm identifier therefore yields
//     `UnknownSignatureAlgorithm`, which is also what Go returns when
//     that Unmarshal fails. Everything before the `oidSignatureRSAPSS`
//     test is verbatim. This is a real gap, not a rounding: a
//     certificate *signed* with RSA-PSS parses, but reports its
//     signature algorithm as unknown.
//
// goishlint:ignore GOISH018 ParsePKIXPublicKey, marshalPublicKey, MarshalPKIXPublicKey, checkSignature, signaturePublicKeyAlgoMismatchError, CheckSignature, CheckSignatureFrom, CheckCRLSignature, reverseBitsInAByte, asn1BitLength, marshalSANs, buildCertExtensions, marshalKeyUsage, marshalExtKeyUsage, marshalBasicConstraints, marshalCertificatePolicies, buildCSRExtensions, subjectBytes, signingParamsForKey, signTBS, CreateCertificate, ParseCRL, ParseDERCRL, CreateCRL, newRawAttributes, parseRawAttributes, parseCSRExtensions, CreateCertificateRequest, ParseCertificateRequest, parseCertificateRequest, CreateRevocationList — the marshaling, signing and CSR/CRL halves; see the banner.
// goishlint:ignore GOISH019 pkixPublicKey, certificate, tbsCertificate, dsaAlgorithmParameters, validity, authKeyId, pssParameters, basicConstraints, policyInformation, authorityInfoAccess, distributionPoint, distributionPointName, CertificateRequest, tbsCertificateRequest, certificateRequest, RevocationListEntry, RevocationList, certificateList, tbsCertificateList — ASN.1 shapes that exist only to be handed to asn1.Marshal / asn1.Unmarshal, and types of the unported halves. `publicKeyInfo`, the one parser.go reads, is here.
// goishlint:ignore GOISH021 pkixPublicKey, certificate, tbsCertificate, dsaAlgorithmParameters, validity, authKeyId, pssParameters, basicConstraints, policyInformation, authorityInfoAccess, distributionPoint, distributionPointName, CertificateRequest, tbsCertificateRequest, certificateRequest, RevocationListEntry, RevocationList, certificateList, tbsCertificateList, emptyRawValue, pssParametersSHA256, pssParametersSHA384, pssParametersSHA512, oidSHA256, oidSHA384, oidSHA512, oidMGF1, x509usepolicies, x509sha256skid, pemCRLPrefix, pemType, emptyASN1Subject, oidExtensionRequest, x509v2Version, oidExtensionSubjectKeyId, oidExtensionKeyUsage, oidExtensionExtendedKeyUsage, oidExtensionBasicConstraints, oidExtensionCertificatePolicies, oidExtensionCRLDistributionPoints, publicKeyAlgoName, signatureAlgorithmDetails, extKeyUsageOIDs — the RSA-PSS parameter blobs and the marshaling-side extension OIDs, which land with the halves they belong to. The extension OIDs parser.go reads by name (SubjectAltName, NameConstraints, AuthorityInfoAccess, AuthorityKeyId, CRLNumber, ReasonCode) are here.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use super::oid::OID;
use crate::crypto;
use crate::crypto::ecdh;
use crate::crypto::elliptic;
use crate::crypto::x509::pkix;
use crate::encoding::asn1;
use crate::error;
use crate::errors;
use crate::goany::Any;
use crate::goslice::slice;
use crate::gostring::string;
use crate::math::big;
use crate::net;
use crate::net::url;
use crate::time;
use crate::int;
use crate::types::byte;
use crate::unicode;

// Go: x509.go:202-206
//   type publicKeyInfo struct {
//       Raw       asn1.RawContent
//       Algorithm pkix.AlgorithmIdentifier
//       PublicKey asn1.BitString
//   }
/// The SubjectPublicKeyInfo ASN.1 structure. `parsePublicKey` takes one.
#[derive(Clone, Default)]
pub(super) struct publicKeyInfo {
    pub Raw: asn1::RawContent,
    pub Algorithm: pkix::AlgorithmIdentifier,
    pub PublicKey: asn1::BitString,
}

// Go: x509.go:213 — `type SignatureAlgorithm int`
/// Identifies the algorithm a certificate's signature was produced with.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct SignatureAlgorithm(pub int);

// Go: x509.go:215-234 — the iota block.
pub const UnknownSignatureAlgorithm: SignatureAlgorithm = SignatureAlgorithm(0);
/// Unsupported.
pub const MD2WithRSA: SignatureAlgorithm = SignatureAlgorithm(1);
/// Only supported for signing, not verification.
pub const MD5WithRSA: SignatureAlgorithm = SignatureAlgorithm(2);
/// Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
pub const SHA1WithRSA: SignatureAlgorithm = SignatureAlgorithm(3);
pub const SHA256WithRSA: SignatureAlgorithm = SignatureAlgorithm(4);
pub const SHA384WithRSA: SignatureAlgorithm = SignatureAlgorithm(5);
pub const SHA512WithRSA: SignatureAlgorithm = SignatureAlgorithm(6);
/// Unsupported.
pub const DSAWithSHA1: SignatureAlgorithm = SignatureAlgorithm(7);
/// Unsupported.
pub const DSAWithSHA256: SignatureAlgorithm = SignatureAlgorithm(8);
/// Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
pub const ECDSAWithSHA1: SignatureAlgorithm = SignatureAlgorithm(9);
pub const ECDSAWithSHA256: SignatureAlgorithm = SignatureAlgorithm(10);
pub const ECDSAWithSHA384: SignatureAlgorithm = SignatureAlgorithm(11);
pub const ECDSAWithSHA512: SignatureAlgorithm = SignatureAlgorithm(12);
pub const SHA256WithRSAPSS: SignatureAlgorithm = SignatureAlgorithm(13);
pub const SHA384WithRSAPSS: SignatureAlgorithm = SignatureAlgorithm(14);
pub const SHA512WithRSAPSS: SignatureAlgorithm = SignatureAlgorithm(15);
pub const PureEd25519: SignatureAlgorithm = SignatureAlgorithm(16);

impl SignatureAlgorithm {
    // go: sdk 1.25.5 crypto/x509/x509.go:236-243 SignatureAlgorithm.isRSAPSS
    pub(super) fn isRSAPSS(&self) -> bool {
        for (_, details) in crate::range!(signatureAlgorithmDetails()) {
            if details.algo == *self {
                return details.isRSAPSS;
            }
        }
        return false;
    }

    // go: sdk 1.25.5 crypto/x509/x509.go:245-252 SignatureAlgorithm.hashFunc
    pub(super) fn hashFunc(&self) -> crypto::Hash {
        for (_, details) in crate::range!(signatureAlgorithmDetails()) {
            if details.algo == *self {
                return details.hash;
            }
        }
        return crypto::Hash(0);
    }

    // go: sdk 1.25.5 crypto/x509/x509.go:254-261 SignatureAlgorithm.String
    pub fn String(&self) -> string {
        for (_, details) in crate::range!(signatureAlgorithmDetails()) {
            if details.algo == *self {
                return details.name.clone();
            }
        }
        return crate::strconv::Itoa(self.0);
    }
}

// Go: x509.go:263 — `type PublicKeyAlgorithm int`
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct PublicKeyAlgorithm(pub int);

// Go: x509.go:265-271 — the iota block.
pub const UnknownPublicKeyAlgorithm: PublicKeyAlgorithm = PublicKeyAlgorithm(0);
pub const RSA: PublicKeyAlgorithm = PublicKeyAlgorithm(1);
/// Only supported for parsing.
pub const DSA: PublicKeyAlgorithm = PublicKeyAlgorithm(2);
pub const ECDSA: PublicKeyAlgorithm = PublicKeyAlgorithm(3);
pub const Ed25519: PublicKeyAlgorithm = PublicKeyAlgorithm(4);

// Go: x509.go:273-278 — `var publicKeyAlgoName = [...]string{…}`, a
// sparse array indexed by the PublicKeyAlgorithm value. goish spells the
// same table as a dense array whose slot 0 is the unused zero value, so
// that `publicKeyAlgoName[algo]` still indexes by the algorithm.
const publicKeyAlgoName: [&str; 5] = ["", "RSA", "DSA", "ECDSA", "Ed25519"];

impl PublicKeyAlgorithm {
    // go: sdk 1.25.5 crypto/x509/x509.go:280-285 PublicKeyAlgorithm.String
    pub fn String(&self) -> string {
        if 0 < self.0 && self.0 < int(publicKeyAlgoName.len()) {
            return string::from(publicKeyAlgoName[self.0 as usize]);
        }
        return crate::strconv::Itoa(self.0);
    }
}

// go: none — goish idiom: build an ObjectIdentifier from a literal.
fn oid(parts: &[int]) -> asn1::ObjectIdentifier {
    return asn1::ObjectIdentifier::New(slice::__from_vec(parts.to_vec()));
}

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:335-360 — the signature-algorithm OID `var` block. See the
// banner: goish has no const slice, so each `var` is a function.
fn oidSignatureMD5WithRSA() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 113549, 1, 1, 4]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureSHA1WithRSA() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 113549, 1, 1, 5]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureSHA256WithRSA() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 113549, 1, 1, 11]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureSHA384WithRSA() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 113549, 1, 1, 12]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureSHA512WithRSA() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 113549, 1, 1, 13]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureRSAPSS() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 113549, 1, 1, 10]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureDSAWithSHA1() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 10040, 4, 3]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureDSAWithSHA256() -> asn1::ObjectIdentifier {
    return oid(&[2, 16, 840, 1, 101, 3, 4, 3, 2]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureECDSAWithSHA1() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 10045, 4, 1]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureECDSAWithSHA256() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 10045, 4, 3, 2]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureECDSAWithSHA384() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 10045, 4, 3, 3]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureECDSAWithSHA512() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 10045, 4, 3, 4]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidSignatureEd25519() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 101, 112]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
/// Means the same as `oidSignatureSHA1WithRSA` but it's specified by ISO.
/// Microsoft's makecert.exe has been known to produce certificates with
/// this OID.
fn oidISOSignatureSHA1WithRSA() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 14, 3, 2, 29]);
}

// Go: x509.go:362-370 — the anonymous row type of
// `signatureAlgorithmDetails`. See the banner for why it is named here.
pub(super) struct signatureAlgorithmDetail {
    pub algo: SignatureAlgorithm,
    pub name: string,
    pub oid: asn1::ObjectIdentifier,
    pub params: asn1::RawValue,
    pub pubKeyAlgo: PublicKeyAlgorithm,
    pub hash: crypto::Hash,
    pub isRSAPSS: bool,
}

// go: none — goish idiom: one row of the table above. Go writes a
// composite literal inside the slice literal.
fn sad(
    algo: SignatureAlgorithm,
    name: &'static str,
    oid: asn1::ObjectIdentifier,
    params: asn1::RawValue,
    pubKeyAlgo: PublicKeyAlgorithm,
    hash: crypto::Hash,
    isRSAPSS: bool,
) -> signatureAlgorithmDetail {
    return signatureAlgorithmDetail {
        algo: algo,
        name: string::from(name),
        oid: oid,
        params: params,
        pubKeyAlgo: pubKeyAlgo,
        hash: hash,
        isRSAPSS: isRSAPSS,
    };
}

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:362-387 — `var signatureAlgorithmDetails = []struct{…}{…}`.
// A function for the same reason the OID vars are: no const slice.
//
// The three RSA-PSS rows carry `pssParametersSHA{256,384,512}` in Go;
// those blobs belong to the marshaling half and are not ported, so the
// rows carry `emptyRawValue`. `params` is read only by
// `signingParamsForKey`, which is not ported either.
pub(super) fn signatureAlgorithmDetails() -> slice<signatureAlgorithmDetail> {
    let mut v: Vec<signatureAlgorithmDetail> = Vec::with_capacity(16);
    v.push(sad(MD5WithRSA, "MD5-RSA", oidSignatureMD5WithRSA(), emptyRawValue(), RSA, crypto::MD5, false));
    v.push(sad(SHA1WithRSA, "SHA1-RSA", oidSignatureSHA1WithRSA(), asn1::NullRawValue(), RSA, crypto::SHA1, false));
    v.push(sad(SHA1WithRSA, "SHA1-RSA", oidISOSignatureSHA1WithRSA(), asn1::NullRawValue(), RSA, crypto::SHA1, false));
    v.push(sad(SHA256WithRSA, "SHA256-RSA", oidSignatureSHA256WithRSA(), asn1::NullRawValue(), RSA, crypto::SHA256, false));
    v.push(sad(SHA384WithRSA, "SHA384-RSA", oidSignatureSHA384WithRSA(), asn1::NullRawValue(), RSA, crypto::SHA384, false));
    v.push(sad(SHA512WithRSA, "SHA512-RSA", oidSignatureSHA512WithRSA(), asn1::NullRawValue(), RSA, crypto::SHA512, false));
    v.push(sad(SHA256WithRSAPSS, "SHA256-RSAPSS", oidSignatureRSAPSS(), emptyRawValue(), RSA, crypto::SHA256, true));
    v.push(sad(SHA384WithRSAPSS, "SHA384-RSAPSS", oidSignatureRSAPSS(), emptyRawValue(), RSA, crypto::SHA384, true));
    v.push(sad(SHA512WithRSAPSS, "SHA512-RSAPSS", oidSignatureRSAPSS(), emptyRawValue(), RSA, crypto::SHA512, true));
    v.push(sad(DSAWithSHA1, "DSA-SHA1", oidSignatureDSAWithSHA1(), emptyRawValue(), DSA, crypto::SHA1, false));
    v.push(sad(DSAWithSHA256, "DSA-SHA256", oidSignatureDSAWithSHA256(), emptyRawValue(), DSA, crypto::SHA256, false));
    v.push(sad(ECDSAWithSHA1, "ECDSA-SHA1", oidSignatureECDSAWithSHA1(), emptyRawValue(), ECDSA, crypto::SHA1, false));
    v.push(sad(ECDSAWithSHA256, "ECDSA-SHA256", oidSignatureECDSAWithSHA256(), emptyRawValue(), ECDSA, crypto::SHA256, false));
    v.push(sad(ECDSAWithSHA384, "ECDSA-SHA384", oidSignatureECDSAWithSHA384(), emptyRawValue(), ECDSA, crypto::SHA384, false));
    v.push(sad(ECDSAWithSHA512, "ECDSA-SHA512", oidSignatureECDSAWithSHA512(), emptyRawValue(), ECDSA, crypto::SHA512, false));
    // Ed25519 has no pre-hashing: crypto.Hash(0).
    v.push(sad(PureEd25519, "Ed25519", oidSignatureEd25519(), emptyRawValue(), Ed25519, crypto::Hash(0), false));
    return slice::__from_vec(v);
}

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:389 — `var emptyRawValue = asn1.RawValue{}`.
fn emptyRawValue() -> asn1::RawValue {
    return asn1::RawValue::default();
}

// go: sdk 1.25.5 crypto/x509/x509.go:416-470 getSignatureAlgorithmFromAI
/// Map an algorithm identifier to the `SignatureAlgorithm` it names.
///
/// **Partial**: the RSA-PSS branch needs `asn1.Unmarshal`; see the
/// banner. An `oidSignatureRSAPSS` identifier yields
/// `UnknownSignatureAlgorithm`, which is Go's own answer when that
/// Unmarshal fails.
pub(super) fn getSignatureAlgorithmFromAI(ai: &pkix::AlgorithmIdentifier) -> SignatureAlgorithm {
    if ai.Algorithm.Equal(&oidSignatureEd25519()) {
        // RFC 8410, Section 3
        // > For all of the OIDs, the parameters MUST be absent.
        if ai.Parameters.FullBytes.Len() != 0 {
            return UnknownSignatureAlgorithm;
        }
    }

    if !ai.Algorithm.Equal(&oidSignatureRSAPSS()) {
        for (_, details) in crate::range!(signatureAlgorithmDetails()) {
            if ai.Algorithm.Equal(&details.oid) {
                return details.algo;
            }
        }
        return UnknownSignatureAlgorithm;
    }

    // RSA PSS is special because it encodes important parameters
    // in the Parameters. Reading them is `asn1.Unmarshal` in Go and has
    // no goish counterpart yet.
    return UnknownSignatureAlgorithm;
}

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:472-495 — the public-key OID `var` block.
pub(super) fn oidPublicKeyRSA() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 113549, 1, 1, 1]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidPublicKeyDSA() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 10040, 4, 1]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidPublicKeyECDSA() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 10045, 2, 1]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidPublicKeyX25519() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 101, 110]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidPublicKeyEd25519() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 101, 112]);
}

// go: sdk 1.25.5 crypto/x509/x509.go:500-512 getPublicKeyAlgorithmFromOID
/// Return the exposed `PublicKeyAlgorithm` identifier for public key
/// types supported in certificates and CSRs. Marshal and Parse functions
/// may support a different set of public key types.
pub(super) fn getPublicKeyAlgorithmFromOID(oid: &asn1::ObjectIdentifier) -> PublicKeyAlgorithm {
    if oid.Equal(&oidPublicKeyRSA()) {
        return RSA;
    }
    if oid.Equal(&oidPublicKeyDSA()) {
        return DSA;
    }
    if oid.Equal(&oidPublicKeyECDSA()) {
        return ECDSA;
    }
    if oid.Equal(&oidPublicKeyEd25519()) {
        return Ed25519;
    }
    return UnknownPublicKeyAlgorithm;
}

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:530-535 — the named-curve OID `var` block.
fn oidNamedCurveP224() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 132, 0, 33]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidNamedCurveP256() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 10045, 3, 1, 7]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidNamedCurveP384() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 132, 0, 34]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidNamedCurveP521() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 132, 0, 35]);
}

// go: sdk 1.25.5 crypto/x509/x509.go:537-549 namedCurveFromOID
/// Map a named-curve OID to its curve. Go returns a nil
/// `elliptic.Curve` interface for an unknown OID; goish returns `None`,
/// the nil-able shape for a `&'static dyn` with no sentinel.
pub(super) fn namedCurveFromOID(
    oid: &asn1::ObjectIdentifier,
) -> Option<&'static (dyn elliptic::Curve + Send + Sync)> {
    if oid.Equal(&oidNamedCurveP224()) {
        return Some(elliptic::P224());
    }
    if oid.Equal(&oidNamedCurveP256()) {
        return Some(elliptic::P256());
    }
    if oid.Equal(&oidNamedCurveP384()) {
        return Some(elliptic::P384());
    }
    if oid.Equal(&oidNamedCurveP521()) {
        return Some(elliptic::P521());
    }
    return None;
}

// go: sdk 1.25.5 crypto/x509/x509.go:551-564 oidFromNamedCurve
/// The inverse of [`namedCurveFromOID`]. Go compares interface values
/// with `switch curve { case elliptic.P224(): … }`; goish compares the
/// curve's `Params().Name`, which is the same identity test — each
/// `elliptic.PXXX()` returns one `&'static` value with a unique name.
pub(super) fn oidFromNamedCurve(
    curve: &(dyn elliptic::Curve + Send + Sync),
) -> (asn1::ObjectIdentifier, bool) {
    let name = curve.Params().Name.clone();
    if name == elliptic::P224().Params().Name {
        return (oidNamedCurveP224(), true);
    }
    if name == elliptic::P256().Params().Name {
        return (oidNamedCurveP256(), true);
    }
    if name == elliptic::P384().Params().Name {
        return (oidNamedCurveP384(), true);
    }
    if name == elliptic::P521().Params().Name {
        return (oidNamedCurveP521(), true);
    }

    return (asn1::ObjectIdentifier::default(), false);
}

// go: sdk 1.25.5 crypto/x509/x509.go:566-579 oidFromECDHCurve
/// The ECDH mirror of [`oidFromNamedCurve`]. Same identity-by-name
/// deviation.
pub(super) fn oidFromECDHCurve(
    curve: &(dyn ecdh::Curve + Send + Sync),
) -> (asn1::ObjectIdentifier, bool) {
    let name = curve.String();
    if name == ecdh::X25519().String() {
        return (oidPublicKeyX25519(), true);
    }
    if name == ecdh::P256().String() {
        return (oidNamedCurveP256(), true);
    }
    if name == ecdh::P384().String() {
        return (oidNamedCurveP384(), true);
    }
    if name == ecdh::P521().String() {
        return (oidNamedCurveP521(), true);
    }

    return (asn1::ObjectIdentifier::default(), false);
}

// Go: x509.go:583 — `type KeyUsage int`
/// Represents the set of actions that are valid for a given key. It's a
/// bitmap of the `KeyUsage*` constants.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyUsage(pub int);

// Go: x509.go:585-595 — `1 << iota`.
pub const KeyUsageDigitalSignature: KeyUsage = KeyUsage(1 << 0);
pub const KeyUsageContentCommitment: KeyUsage = KeyUsage(1 << 1);
pub const KeyUsageKeyEncipherment: KeyUsage = KeyUsage(1 << 2);
pub const KeyUsageDataEncipherment: KeyUsage = KeyUsage(1 << 3);
pub const KeyUsageKeyAgreement: KeyUsage = KeyUsage(1 << 4);
pub const KeyUsageCertSign: KeyUsage = KeyUsage(1 << 5);
pub const KeyUsageCRLSign: KeyUsage = KeyUsage(1 << 6);
pub const KeyUsageEncipherOnly: KeyUsage = KeyUsage(1 << 7);
pub const KeyUsageDecipherOnly: KeyUsage = KeyUsage(1 << 8);

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:609-624 — the extended-key-usage OID `var` block.
fn oidExtKeyUsageAny() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 37, 0]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageServerAuth() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 3, 1]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageClientAuth() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 3, 2]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageCodeSigning() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 3, 3]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageEmailProtection() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 3, 4]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageIPSECEndSystem() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 3, 5]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageIPSECTunnel() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 3, 6]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageIPSECUser() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 3, 7]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageTimeStamping() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 3, 8]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageOCSPSigning() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 3, 9]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageMicrosoftServerGatedCrypto() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 4, 1, 311, 10, 3, 3]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageNetscapeServerGatedCrypto() -> asn1::ObjectIdentifier {
    return oid(&[2, 16, 840, 1, 113730, 4, 1]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageMicrosoftCommercialCodeSigning() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 4, 1, 311, 2, 1, 22]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
fn oidExtKeyUsageMicrosoftKernelCodeSigning() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 4, 1, 311, 61, 1, 1]);
}

// Go: x509.go:628 — `type ExtKeyUsage int`
/// Represents an extended set of actions that are valid for a given key.
/// Each of the `ExtKeyUsage*` constants define a unique action.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ExtKeyUsage(pub int);

// Go: x509.go:630-645 — the iota block.
pub const ExtKeyUsageAny: ExtKeyUsage = ExtKeyUsage(0);
pub const ExtKeyUsageServerAuth: ExtKeyUsage = ExtKeyUsage(1);
pub const ExtKeyUsageClientAuth: ExtKeyUsage = ExtKeyUsage(2);
pub const ExtKeyUsageCodeSigning: ExtKeyUsage = ExtKeyUsage(3);
pub const ExtKeyUsageEmailProtection: ExtKeyUsage = ExtKeyUsage(4);
pub const ExtKeyUsageIPSECEndSystem: ExtKeyUsage = ExtKeyUsage(5);
pub const ExtKeyUsageIPSECTunnel: ExtKeyUsage = ExtKeyUsage(6);
pub const ExtKeyUsageIPSECUser: ExtKeyUsage = ExtKeyUsage(7);
pub const ExtKeyUsageTimeStamping: ExtKeyUsage = ExtKeyUsage(8);
pub const ExtKeyUsageOCSPSigning: ExtKeyUsage = ExtKeyUsage(9);
pub const ExtKeyUsageMicrosoftServerGatedCrypto: ExtKeyUsage = ExtKeyUsage(10);
pub const ExtKeyUsageNetscapeServerGatedCrypto: ExtKeyUsage = ExtKeyUsage(11);
pub const ExtKeyUsageMicrosoftCommercialCodeSigning: ExtKeyUsage = ExtKeyUsage(12);
pub const ExtKeyUsageMicrosoftKernelCodeSigning: ExtKeyUsage = ExtKeyUsage(13);

// Go: x509.go:648-666 — the anonymous row type of `extKeyUsageOIDs`.
struct extKeyUsagePair {
    extKeyUsage: ExtKeyUsage,
    oid: asn1::ObjectIdentifier,
}

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:648-666 — `var extKeyUsageOIDs = []struct{…}{…}`. Contains
// the mapping between an `ExtKeyUsage` and its OID.
fn extKeyUsageOIDs() -> slice<extKeyUsagePair> {
    let mut v: Vec<extKeyUsagePair> = Vec::with_capacity(14);
    let mut push = |extKeyUsage: ExtKeyUsage, oid: asn1::ObjectIdentifier| {
        v.push(extKeyUsagePair {
            extKeyUsage: extKeyUsage,
            oid: oid,
        });
    };
    push(ExtKeyUsageAny, oidExtKeyUsageAny());
    push(ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth());
    push(ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth());
    push(ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning());
    push(ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection());
    push(ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem());
    push(ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel());
    push(ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser());
    push(ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping());
    push(ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning());
    push(
        ExtKeyUsageMicrosoftServerGatedCrypto,
        oidExtKeyUsageMicrosoftServerGatedCrypto(),
    );
    push(
        ExtKeyUsageNetscapeServerGatedCrypto,
        oidExtKeyUsageNetscapeServerGatedCrypto(),
    );
    push(
        ExtKeyUsageMicrosoftCommercialCodeSigning,
        oidExtKeyUsageMicrosoftCommercialCodeSigning(),
    );
    push(
        ExtKeyUsageMicrosoftKernelCodeSigning,
        oidExtKeyUsageMicrosoftKernelCodeSigning(),
    );
    drop(push);
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 crypto/x509/x509.go:668-675 extKeyUsageFromOID
pub(super) fn extKeyUsageFromOID(oid: &asn1::ObjectIdentifier) -> (ExtKeyUsage, bool) {
    for (_, pair) in crate::range!(extKeyUsageOIDs()) {
        if oid.Equal(&pair.oid) {
            return (pair.extKeyUsage, true);
        }
    }
    return (ExtKeyUsage::default(), false);
}

// go: sdk 1.25.5 crypto/x509/x509.go:677-684 oidFromExtKeyUsage
pub(super) fn oidFromExtKeyUsage(eku: ExtKeyUsage) -> (asn1::ObjectIdentifier, bool) {
    for (_, pair) in crate::range!(extKeyUsageOIDs()) {
        if eku == pair.extKeyUsage {
            return (pair.oid.clone(), true);
        }
    }
    return (asn1::ObjectIdentifier::default(), false);
}

// Go: x509.go:687-863
/// An X.509 certificate.
#[derive(Clone, Default)]
pub struct Certificate {
    /// Complete ASN.1 DER content (certificate, signature algorithm and signature).
    pub Raw: slice<byte>,
    /// Certificate part of raw ASN.1 DER content.
    pub RawTBSCertificate: slice<byte>,
    /// DER encoded SubjectPublicKeyInfo.
    pub RawSubjectPublicKeyInfo: slice<byte>,
    /// DER encoded Subject
    pub RawSubject: slice<byte>,
    /// DER encoded Issuer
    pub RawIssuer: slice<byte>,

    pub Signature: slice<byte>,
    pub SignatureAlgorithm: SignatureAlgorithm,

    pub PublicKeyAlgorithm: PublicKeyAlgorithm,
    pub PublicKey: Any,

    pub Version: int,
    pub SerialNumber: big::Int,
    pub Issuer: pkix::Name,
    pub Subject: pkix::Name,
    /// Validity bound.
    pub NotBefore: time::Time,
    /// Validity bound.
    pub NotAfter: time::Time,
    pub KeyUsage: KeyUsage,

    /// Raw X.509 extensions. When parsing certificates, this can be used
    /// to extract non-critical extensions that are not parsed by this
    /// package. When marshaling certificates, the Extensions field is
    /// ignored, see ExtraExtensions.
    pub Extensions: slice<pkix::Extension>,

    /// Extensions to be copied, raw, into any marshaled certificates.
    /// Values override any extensions that would otherwise be produced
    /// based on the other fields. The ExtraExtensions field is not
    /// populated when parsing certificates, see Extensions.
    pub ExtraExtensions: slice<pkix::Extension>,

    /// A list of extension IDs that were not (fully) processed when
    /// parsing. Verify will fail if this slice is non-empty, unless
    /// verification is delegated to an OS library which understands all
    /// the critical extensions.
    pub UnhandledCriticalExtensions: slice<asn1::ObjectIdentifier>,

    /// Sequence of extended key usages.
    pub ExtKeyUsage: slice<ExtKeyUsage>,
    /// Encountered extended key usages unknown to this package.
    pub UnknownExtKeyUsage: slice<asn1::ObjectIdentifier>,

    /// Indicates whether IsCA, MaxPathLen, and MaxPathLenZero are valid.
    pub BasicConstraintsValid: bool,
    pub IsCA: bool,

    /// Indicates the presence and value of the BasicConstraints'
    /// "pathLenConstraint". When parsing a certificate, a positive
    /// non-zero MaxPathLen means that the field was specified, -1 means
    /// it was unset, and MaxPathLenZero being true mean that the field
    /// was explicitly set to zero.
    pub MaxPathLen: int,
    /// Indicates that BasicConstraintsValid==true and MaxPathLen==0
    /// should be interpreted as an actual maximum path length of zero.
    pub MaxPathLenZero: bool,

    pub SubjectKeyId: slice<byte>,
    pub AuthorityKeyId: slice<byte>,

    /// RFC 5280, 4.2.2.1 (Authority Information Access)
    pub OCSPServer: slice<string>,
    /// RFC 5280, 4.2.2.1 (Authority Information Access)
    pub IssuingCertificateURL: slice<string>,

    /// Subject Alternate Name value.
    pub DNSNames: slice<string>,
    /// Subject Alternate Name value.
    pub EmailAddresses: slice<string>,
    /// Subject Alternate Name value.
    pub IPAddresses: slice<net::IP>,
    /// Subject Alternate Name value.
    pub URIs: slice<url::URL>,

    /// If true then the name constraints are marked critical.
    pub PermittedDNSDomainsCritical: bool,
    pub PermittedDNSDomains: slice<string>,
    pub ExcludedDNSDomains: slice<string>,
    pub PermittedIPRanges: slice<net::IPNet>,
    pub ExcludedIPRanges: slice<net::IPNet>,
    pub PermittedEmailAddresses: slice<string>,
    pub ExcludedEmailAddresses: slice<string>,
    pub PermittedURIDomains: slice<string>,
    pub ExcludedURIDomains: slice<string>,

    /// CRL Distribution Points
    pub CRLDistributionPoints: slice<string>,

    /// Contains `asn1::ObjectIdentifier`s, the components of which are
    /// limited to int32. If a certificate contains a policy which cannot
    /// be represented by `asn1::ObjectIdentifier`, it will not be
    /// included in PolicyIdentifiers, but will be present in Policies.
    pub PolicyIdentifiers: slice<asn1::ObjectIdentifier>,

    /// All policy identifiers included in the certificate.
    pub Policies: slice<OID>,

    /// The number of additional certificates in the path after this
    /// certificate that may use the anyPolicy policy OID.
    pub InhibitAnyPolicy: int,
    /// Indicates that InhibitAnyPolicy==0 should be interpreted as an
    /// actual maximum path length of zero.
    pub InhibitAnyPolicyZero: bool,

    /// The number of additional certificates in the path after this
    /// certificate that may use policy mapping.
    pub InhibitPolicyMapping: int,
    /// Indicates that InhibitPolicyMapping==0 should be interpreted as an
    /// actual maximum path length of zero.
    pub InhibitPolicyMappingZero: bool,

    /// The number of additional certificates in the path after this
    /// certificate before an explicit policy is required.
    pub RequireExplicitPolicy: int,
    /// Indicates that RequireExplicitPolicy==0 should be interpreted as
    /// an actual maximum path length of zero.
    pub RequireExplicitPolicyZero: bool,

    /// A list of policy mappings included in the certificate.
    pub PolicyMappings: slice<PolicyMapping>,
}

// Go: x509.go:866-873
/// Represents a policy mapping entry in the policyMappings extension.
#[derive(Clone, Default)]
pub struct PolicyMapping {
    /// Contains a policy OID the issuing certificate considers equivalent
    /// to SubjectDomainPolicy in the subject certificate.
    pub IssuerDomainPolicy: OID,
    /// Contains a OID the issuing certificate considers equivalent to
    /// IssuerDomainPolicy in the subject certificate.
    pub SubjectDomainPolicy: OID,
}

goish::var! {
    /// Results from attempting to perform an operation that involves
    /// algorithms that are not currently implemented.
    pub ErrUnsupportedAlgorithm: error = "x509: cannot verify signature: algorithm unimplemented";
}

// Go: x509.go:881 — `type InsecureAlgorithmError SignatureAlgorithm`
/// Results when the signature algorithm for a certificate is not one
/// that is currently supported.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct InsecureAlgorithmError(pub SignatureAlgorithm);

impl InsecureAlgorithmError {
    // go: sdk 1.25.5 crypto/x509/x509.go:883-888 InsecureAlgorithmError.Error
    pub fn Error(&self) -> string {
        return crate::fmt::Sprintf!("x509: cannot verify signature: insecure algorithm %v", self.0.String());
    }
}

// Go: x509.go:890 — `type ConstraintViolationError struct{}`
/// Results when a requested usage is not permitted by a certificate. For
/// example: checking a signature when the public key isn't a certificate
/// signing key.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct ConstraintViolationError {}

impl ConstraintViolationError {
    // go: sdk 1.25.5 crypto/x509/x509.go:892-894 ConstraintViolationError.Error
    pub fn Error(&self) -> string {
        return string::from("x509: invalid signature: parent certificate cannot sign this kind of certificate");
    }
}

impl Certificate {
    // go: sdk 1.25.5 crypto/x509/x509.go:896-901 Certificate.Equal
    pub fn Equal(&self, other: &Certificate) -> bool {
        // Go: if c == nil || other == nil { return c == other }
        if self.Raw.Len() == 0 || other.Raw.Len() == 0 {
            return self.Raw.Len() == other.Raw.Len();
        }
        return crate::bytes::Equal(self.Raw.clone(), other.Raw.clone());
    }

    // go: sdk 1.25.5 crypto/x509/x509.go:903-909 Certificate.hasSANExtension
    pub(super) fn hasSANExtension(&self) -> bool {
        return oidInExtensions(&oidExtensionSubjectAltName(), &self.Extensions);
    }

    // go: sdk 1.25.5 crypto/x509/x509.go:944-946 Certificate.hasNameConstraints
    pub(super) fn hasNameConstraints(&self) -> bool {
        return oidInExtensions(&oidExtensionNameConstraints(), &self.Extensions);
    }

    // go: sdk 1.25.5 crypto/x509/x509.go:948-955 Certificate.getSANExtension
    pub(super) fn getSANExtension(&self) -> slice<byte> {
        for (_, e) in crate::range!(self.Extensions.clone()) {
            if e.Id.Equal(&oidExtensionSubjectAltName()) {
                return e.Value.clone();
            }
        }
        // Go returns a nil []byte; `slice<byte>`'s zero value reads the
        // same under `len`.
        return slice::__from_vec(Vec::<byte>::new());
    }
}

// Go: x509.go:1035 — `type UnhandledCriticalExtension struct{}`
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct UnhandledCriticalExtension {}

impl UnhandledCriticalExtension {
    // go: sdk 1.25.5 crypto/x509/x509.go:1037-1039 UnhandledCriticalExtension.Error
    pub fn Error(&self) -> string {
        return string::from("x509: unhandled critical extension");
    }
}

// Go: x509.go:1052-1057 — the GeneralName tag numbers of RFC 5280 4.2.1.6.
pub(super) const nameTypeEmail: int = 1;
pub(super) const nameTypeDNS: int = 2;
pub(super) const nameTypeURI: int = 6;
pub(super) const nameTypeIP: int = 7;

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:1104-1117 — the extension OID `var` block. Only the four
// `parser.go` names are here; see the banner's GOISH021 waiver.
pub(super) fn oidExtensionSubjectAltName() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 17]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidExtensionAuthorityKeyId() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 35]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidExtensionNameConstraints() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 30]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidExtensionAuthorityInfoAccess() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 1, 1]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidExtensionCRLNumber() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 20]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidExtensionReasonCode() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 21]);
}

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:1119-1122
pub(super) fn oidAuthorityInfoAccessOcsp() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 48, 1]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidAuthorityInfoAccessIssuers() -> asn1::ObjectIdentifier {
    return oid(&[1, 3, 6, 1, 5, 5, 7, 48, 2]);
}

// go: sdk 1.25.5 crypto/x509/x509.go:1126-1135 oidInExtensions
/// Report whether an extension with the given oid exists in extensions.
fn oidInExtensions(oid: &asn1::ObjectIdentifier, extensions: &slice<pkix::Extension>) -> bool {
    for (_, e) in crate::range!(extensions.clone()) {
        if e.Id.Equal(oid) {
            return true;
        }
    }
    return false;
}

// go: sdk 1.25.5 crypto/x509/x509.go:1169-1178 isIA5String
pub(super) fn isIA5String(s: &string) -> error {
    for (_, r) in crate::range!(s) {
        // Per RFC5280 "IA5String is limited to the set of ASCII characters"
        if r > unicode::MaxASCII {
            return crate::fmt::Errorf!("x509: %q cannot be encoded as an IA5String", s.clone());
        }
    }

    return errors::nil;
}
