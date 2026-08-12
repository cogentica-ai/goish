// go: file crypto/x509/x509.go decls: ParsePKIXPublicKey, SignatureAlgorithm.isRSAPSS, SignatureAlgorithm.hashFunc, SignatureAlgorithm.String, PublicKeyAlgorithm.String, getSignatureAlgorithmFromAI, getPublicKeyAlgorithmFromOID, namedCurveFromOID, oidFromNamedCurve, oidFromECDHCurve, extKeyUsageFromOID, oidFromExtKeyUsage, InsecureAlgorithmError.Error, ConstraintViolationError.Error, Certificate.Equal, Certificate.hasSANExtension, Certificate.CheckSignatureFrom, Certificate.CheckSignature, Certificate.hasNameConstraints, Certificate.getSANExtension, signaturePublicKeyAlgoMismatchError, checkSignature, Certificate.CheckCRLSignature, UnhandledCriticalExtension.Error, oidInExtensions, isIA5String, marshalPublicKey, MarshalPKIXPublicKey, reverseBitsInAByte, asn1BitLength, marshalSANs, buildCertExtensions, marshalKeyUsage, marshalExtKeyUsage, marshalBasicConstraints, marshalCertificatePolicies, buildCSRExtensions, subjectBytes, signingParamsForKey, signTBS, CreateCertificate, Certificate.CreateCRL, CreateRevocationList, newRawAttributes, CreateCertificateRequest, ParseCRL, ParseDERCRL, parseRawAttributes, parseCSRExtensions, ParseCertificateRequest, parseCertificateRequest, CertificateRequest.CheckSignature, RevocationList.CheckSignatureFrom
//
// The X.509 type surface: the algorithm identifiers, the OID tables and
// the `Certificate` struct every other file in the package hangs on.
//
// **Partial port, and deliberately so.** x509.go is 2565 lines. Three
// of its four halves are here: the *parsing* type surface (everything
// `parser.go` reads or writes), the *signature-checking* half
// (CheckSignatureFrom, CheckSignature, checkSignature,
// signaturePublicKeyAlgoMismatchError, CheckCRLSignature) that
// `verify.go`'s chain builder calls, and — appended at the end of this
// file, in Go's own source order — the *marshaling / creation* half
// (CreateCertificate, CreateRevocationList, Certificate.CreateCRL,
// MarshalPKIXPublicKey and the extension builders behind them).
//
// What is still absent: the CSR and CRL *parsing* entry points —
// `ParseCRL`, `ParseDERCRL`, `ParseRevocationList`,
// `ParseCertificateRequest`, `parseCertificateRequest`,
// `parseRawAttributes` and `parseCSRExtensions`. They are the read side
// of the shapes declared here, and belong with `parser.go`'s half rather
// than this one. They are absent, not stubbed.
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
// goishlint:ignore GOISH018 ParseCRL, ParseDERCRL, parseRawAttributes, parseCSRExtensions, ParseCertificateRequest, parseCertificateRequest — the CSR/CRL parsing entry points; see the banner.
// goishlint:ignore GOISH019 pssParameters — the RSA-PSS parameter shape, read only by `getSignatureAlgorithmFromAI`'s unported RSA-PSS branch (which needs asn1.Unmarshal) and written by nothing. Every other ASN.1 shape in x509.go is declared, in this file.
// goishlint:ignore GOISH021 pssParameters, pssParametersSHA256, pssParametersSHA384, pssParametersSHA512, oidSHA256, oidSHA384, oidSHA512, oidMGF1, pemCRLPrefix, pemType — the RSA-PSS parameter blobs, which belong to the unported RSA-PSS branch of getSignatureAlgorithmFromAI, and the three vars read only by ParseCRL / ParseCRL. Every other type, const and var in x509.go is here.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use super::oid::OID;
use super::pkcs1::pkcs1PublicKey;
use crate::crypto;
use crate::crypto::cryptobyte;
use crate::crypto::cryptobyte::asn1 as cbasn1;
use crate::crypto::ecdh;
use crate::crypto::ecdsa;
use crate::crypto::ed25519;
use crate::crypto::elliptic;
use crate::crypto::rsa;
use crate::crypto::sha1;
use crate::crypto::sha256;
use crate::crypto::x509::pkix;
use crate::encoding::asn1;
use crate::error;
use crate::errors;
use crate::goany::Any;
use crate::io;
use crate::goany::AsExt;
use crate::goslice::slice;
use crate::gomap::map;
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
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct publicKeyInfo {
    pub Raw: asn1::RawContent,
    pub Algorithm: pkix::AlgorithmIdentifier,
    pub PublicKey: asn1::BitString,
}

// go: none — goish-only, and a prerequisite rather than a port:
// `asn1.Marshal`/`Unmarshal` reach their subject through `reflect`, so
// `publicKeyInfo` needs a descriptor. The **read** half is the
// `#[goish::reflect(reflect_only)]` attribute above; the **write** half
// — `FromReflectValue`, which `reflect_only` does not emit and which
// only an `Unmarshal` target needs — is written out here. The
// `Raw asn1.RawContent` first field is load-bearing in both directions:
// `parseField`'s struct arm fills it with the element's full DER (which
// is what `parsePublicKey` hands to `parseCertificate`), and
// `makeBody`'s strips it back out.
impl crate::reflect::FromReflectValue for publicKeyInfo {
    // go: none — goish-only: the write half of the descriptor above.
    fn from_reflect_value(v: crate::reflect::Value) -> (Self, error) {
        use crate::reflect::FromReflectValue;
        if v.Kind() != crate::reflect::Kind::Struct {
            return (
                publicKeyInfo::default(),
                errors::New("x509: expected publicKeyInfo"),
            );
        }
        let (raw, err) = <asn1::RawContent as FromReflectValue>::from_reflect_value(v.Field(0));
        if err != errors::nil {
            return (publicKeyInfo::default(), err);
        }
        let (algo, err) =
            <pkix::AlgorithmIdentifier as FromReflectValue>::from_reflect_value(v.Field(1));
        if err != errors::nil {
            return (publicKeyInfo::default(), err);
        }
        let (bs, err) = <asn1::BitString as FromReflectValue>::from_reflect_value(v.Field(2));
        if err != errors::nil {
            return (publicKeyInfo::default(), err);
        }
        return (
            publicKeyInfo {
                Raw: raw,
                Algorithm: algo,
                PublicKey: bs,
            },
            errors::nil,
        );
    }
}

// go: sdk 1.25.5 crypto/x509/x509.go:72-82 ParsePKIXPublicKey
/// Parse a public key in PKIX, ASN.1 DER form. The encoded public key is
/// a SubjectPublicKeyInfo structure (see RFC 5280, Section 4.1).
///
/// It returns an `rsa::PublicKey`, `dsa::PublicKey`, `ecdsa::PublicKey`,
/// `ed25519::PublicKey`, or `ecdh::PublicKey` (for X25519), wrapped in
/// `Any` — see the banner for why `Any::new_fn` rather than `Any::new`.
///
/// This kind of key is commonly encoded in PEM blocks of type
/// "PUBLIC KEY".
pub fn ParsePKIXPublicKey(derBytes: slice<byte>) -> (Any, error) {
    let mut pki = publicKeyInfo::default();
    let (rest, err) = asn1::Unmarshal(derBytes.clone(), &mut pki);
    if err != errors::nil {
        let mut p1 = super::pkcs1::pkcs1PublicKey::default();
        let (_, e) = asn1::Unmarshal(derBytes.clone(), &mut p1);
        if e == errors::nil {
            return (
                Any::default(),
                errors::New(
                    "x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)",
                ),
            );
        }
        return (Any::default(), err);
    } else if rest.Len() != 0 {
        return (
            Any::default(),
            errors::New("x509: trailing data after ASN.1 of public-key"),
        );
    }
    return super::parser::parsePublicKey(&pki);
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

// ─── the signature-checking half — x509.go:907-1030 ─────────────────────
//
// Go's three error shapes here are `error`-valued because every Go
// struct with an `Error() string` method satisfies the interface
// implicitly. goish needs the `impl ErrorTrait` block written out; the
// three types themselves are declared above, next to their `Error`
// methods, so only the trait wiring lives here.

// go: none — goish idiom: Go's `ErrUnsupportedAlgorithm`-adjacent error
// structs satisfy `error` implicitly through their `Error() string`
// method. goish requires an explicit `impl ErrorTrait`; the method body
// is the ported `Error` above, so this forwards to it.
impl errors::ErrorTrait for InsecureAlgorithmError {
    // go: none — goish idiom: forwards to the ported inherent `Error`.
    fn Error(&self) -> string {
        return InsecureAlgorithmError::Error(self);
    }
}

// go: none — goish idiom: see `impl ErrorTrait for InsecureAlgorithmError`.
impl errors::ErrorTrait for ConstraintViolationError {
    // go: none — goish idiom: forwards to the ported inherent `Error`.
    fn Error(&self) -> string {
        return ConstraintViolationError::Error(self);
    }
}

// go: none — goish idiom: see `impl ErrorTrait for InsecureAlgorithmError`.
impl errors::ErrorTrait for UnhandledCriticalExtension {
    // go: none — goish idiom: forwards to the ported inherent `Error`.
    fn Error(&self) -> string {
        return UnhandledCriticalExtension::Error(self);
    }
}

impl Certificate {
    // go: sdk 1.25.5 crypto/x509/x509.go:907-931 Certificate.CheckSignatureFrom
    /// Verify that the signature on c is a valid signature from parent.
    ///
    /// This is a low-level API that performs very limited checks, and not
    /// a full path verifier. Most users should use `Certificate::Verify`
    /// instead.
    pub fn CheckSignatureFrom(&self, parent: &Certificate) -> error {
        // RFC 5280, 4.2.1.9:
        // "If the basic constraints extension is not present in a version 3
        // certificate, or the extension is present but the cA boolean is not
        // asserted, then the certified public key MUST NOT be used to verify
        // certificate signatures."
        if parent.Version == 3 && !parent.BasicConstraintsValid
            || parent.BasicConstraintsValid && !parent.IsCA
        {
            return ConstraintViolationError {}.into();
        }

        if parent.KeyUsage != KeyUsage(0) && parent.KeyUsage.0 & KeyUsageCertSign.0 == 0 {
            return ConstraintViolationError {}.into();
        }

        if parent.PublicKeyAlgorithm == UnknownPublicKeyAlgorithm {
            return ErrUnsupportedAlgorithm.into();
        }

        return checkSignature(
            self.SignatureAlgorithm,
            self.RawTBSCertificate.clone(),
            self.Signature.clone(),
            &parent.PublicKey,
            false,
        );
    }

    // go: sdk 1.25.5 crypto/x509/x509.go:933-942 Certificate.CheckSignature
    /// Verify that `signature` is a valid signature over `signed` from c's
    /// public key.
    ///
    /// This is a low-level API that performs no validity checks on the
    /// certificate.
    ///
    /// `MD5WithRSA` signatures are rejected, while `SHA1WithRSA` and
    /// `ECDSAWithSHA1` signatures are currently accepted.
    pub fn CheckSignature(
        &self,
        algo: SignatureAlgorithm,
        signed: slice<byte>,
        signature: slice<byte>,
    ) -> error {
        return checkSignature(algo, signed, signature, &self.PublicKey, true);
    }

    // go: sdk 1.25.5 crypto/x509/x509.go:1030-1033 Certificate.CheckCRLSignature
    /// Check that the signature in `crl` is from c.
    ///
    /// Deprecated: use `RevocationList::CheckSignatureFrom` instead.
    pub fn CheckCRLSignature(&self, crl: &pkix::CertificateList) -> error {
        let algo = getSignatureAlgorithmFromAI(&crl.SignatureAlgorithm);
        return self.CheckSignature(
            algo,
            crl.TBSCertList.Raw.0.clone(),
            crl.SignatureValue.RightAlign(),
        );
    }
}

// go: sdk 1.25.5 crypto/x509/x509.go:957-959 signaturePublicKeyAlgoMismatchError
/// Go formats the offending key with `%T`, which prints the dynamic Go
/// type name. goish's `Any` carries no type name, so the message names
/// the algorithm the key *is* usable with instead of the Rust type. The
/// prefix and the first half of the sentence are verbatim.
// goishlint:ignore GOISH017 signaturePublicKeyAlgoMismatchError — the `%T` half of the message has no goish equivalent; see the doc comment.
pub(super) fn signaturePublicKeyAlgoMismatchError(
    expectedPubKeyAlgo: PublicKeyAlgorithm,
    pubKey: &Any,
) -> error {
    let have = if pubKey.As::<rsa::PublicKey>().is_some() {
        RSA.String()
    } else if pubKey.As::<ecdsa::PublicKey>().is_some() {
        ECDSA.String()
    } else if pubKey.As::<ed25519::PublicKey>().is_some() {
        Ed25519.String()
    } else {
        UnknownPublicKeyAlgorithm.String()
    };
    return crate::fmt::Errorf!(
        "x509: signature algorithm specifies an %s public key, but have public key of type %s",
        expectedPubKeyAlgo.String(),
        have
    );
}

// go: sdk 1.25.5 crypto/x509/x509.go:963-1025 checkSignature
/// Verify that `signature` is a valid signature over `signed` from a
/// `crypto.PublicKey`.
///
/// Go's `switch pub := publicKey.(type)` becomes an `As::<T>()` ladder
/// over the same three concrete key types, in the same order. Go's DSA
/// arm does not exist — Go dropped it from `checkSignature` too; a DSA
/// key falls through to `ErrUnsupportedAlgorithm`, exactly as in Go.
///
/// `hashType.New()` panics in goish when the hash is not registered.
/// Go's own `hashType.Available()` guard, one line above it, is what
/// makes that unreachable: an unregistered hash returns
/// `ErrUnsupportedAlgorithm` instead. In practice the registry is always
/// populated — `#[goish::main]` emits `goish::init()`, which calls
/// `crypto::RegisterStandardHashes()` — so this is belt-and-braces, not
/// a caller obligation.
pub(super) fn checkSignature(
    algo: SignatureAlgorithm,
    signed: slice<byte>,
    signature: slice<byte>,
    publicKey: &Any,
    allowSHA1: bool,
) -> error {
    let mut hashType = crypto::Hash(0);
    let mut pubKeyAlgo = UnknownPublicKeyAlgorithm;

    for (_, details) in crate::range!(signatureAlgorithmDetails()) {
        if details.algo == algo {
            hashType = details.hash;
            pubKeyAlgo = details.pubKeyAlgo;
            break;
        }
    }

    let mut signed = signed;
    if hashType == crypto::Hash(0) {
        if pubKeyAlgo != Ed25519 {
            return ErrUnsupportedAlgorithm.into();
        }
    } else if hashType == crypto::MD5 {
        return InsecureAlgorithmError(algo).into();
    } else {
        // Go's `case crypto.SHA1:` falls through into `default:` once the
        // allowSHA1 gate passes, so the two arms share one body here.
        if hashType == crypto::SHA1 {
            // SHA-1 signatures are only allowed for CRLs and CSRs.
            if !allowSHA1 {
                return InsecureAlgorithmError(algo).into();
            }
        }
        if !hashType.Available() {
            return ErrUnsupportedAlgorithm.into();
        }
        let mut h = hashType.New();
        let _ = crate::io::Writer::Write(&mut h, signed.clone());
        signed = crate::hash::Hash::Sum(&*h, slice::__from_vec(Vec::<byte>::new()));
    }

    if let Some(pub_) = publicKey.As::<rsa::PublicKey>() {
        if pubKeyAlgo != RSA {
            return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, publicKey);
        }
        if algo.isRSAPSS() {
            return rsa::VerifyPSS(
                pub_,
                hashType,
                signed,
                signature,
                Some(&rsa::PSSOptions {
                    SaltLength: rsa::PSSSaltLengthEqualsHash,
                    Hash: hashType,
                }),
            );
        } else {
            return rsa::VerifyPKCS1v15(pub_, hashType, signed, signature);
        }
    }
    if let Some(pub_) = publicKey.As::<ecdsa::PublicKey>() {
        if pubKeyAlgo != ECDSA {
            return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, publicKey);
        }
        if !ecdsa::VerifyASN1(pub_, &signed, &signature) {
            return errors::New("x509: ECDSA verification failure");
        }
        return errors::nil;
    }
    if let Some(pub_) = publicKey.As::<ed25519::PublicKey>() {
        if pubKeyAlgo != Ed25519 {
            return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, publicKey);
        }
        if !ed25519::Verify(pub_, signed, signature) {
            return errors::New("x509: Ed25519 verification failure");
        }
        return errors::nil;
    }
    return ErrUnsupportedAlgorithm.into();
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

// ─────────────────────────────────────────────────────────────────────
// The marshaling / signing / creation half of x509.go.
//
// Everything below this line is appended in Go's own source order, so
// the file reads top-to-bottom against `crypto/x509/x509.go`. The
// banner at the top of this file describes the *parsing* half and was
// written when this half did not exist; the GOISH018/019/021 waivers up
// there still name the symbols that are genuinely still absent.
//
// What is here: `marshalPublicKey` / `MarshalPKIXPublicKey`, the
// extension builders, `signingParamsForKey`, `signTBS`,
// `CreateCertificate`, `Certificate::CreateCRL` and
// `CreateRevocationList`, plus the ASN.1 shapes each of them marshals.
//
// What is still absent, and why:
//
//   * `newRawAttributes` and `CreateCertificateRequest` need
//     `asn1::Unmarshal`, which goish does not have yet. Both are
//     `asn1.Marshal`-then-`asn1.Unmarshal` round trips (x509.go:1962 and
//     x509.go:2148) whose whole job is to re-read DER that was just
//     written; there is no honest way to spell them without the decoder.
//     `CertificateRequest`, `tbsCertificateRequest`, `certificateRequest`
//     and `oidExtensionRequest` are here, because `buildCSRExtensions`
//     takes a `*CertificateRequest` and is portable on its own.
//   * `ParseCRL` / `ParseDERCRL` are the same story on the read side.
//
// Deviations from x509[go] @ Go 1.25.5, for this half:
//
//   * Go's `internal/godebug` has no goish counterpart, so
//     `x509usepolicies` and `x509sha256skid` are functions returning the
//     *unset* value `""` — which is what `godebug.New(name).Value()`
//     returns when the setting is absent from GODEBUG, and therefore the
//     branch Go takes by default in 1.25. Both call sites keep Go's
//     `!= "0"` test verbatim rather than being folded away, so the
//     non-default branch is still readable next to the default one. The
//     `IncNonDefault()` counter has nothing to count in goish and is
//     dropped.
//   * Go's `pub any` / `priv any` parameters are `&Any`; `pub` is a Rust
//     keyword, so it is spelled `pub_` (the spelling `parser.rs` already
//     uses).
//   * Go passes `key.Public()` — a `crypto.PublicKey`, which *is* `any`
//     — straight into `marshalPublicKey(pub any)` and into
//     `checkSignature(… publicKey crypto.PublicKey …)`. goish has two
//     distinct erasure carriers that do not convert without naming the
//     concrete type: `crypto::PublicKey` is
//     `Arc<dyn core::any::Any + Send + Sync>` (downcast only) and
//     `goany::Any` is the reflective carrier the x509 package passes
//     around. `anyFromPublicKey` bridges them by naming the four key
//     types this package supports — the same four `marshalPublicKey`
//     enumerates.
//   * `marshalCertificatePolicies`'s `policyIdentifiers` branch calls
//     `cryptobyte.Builder.AddASN1ObjectIdentifier`, which is part of
//     cryptobyte's Builder half and is not ported (see that file's
//     GOISH018 waiver). It is spelled here as
//     `asn1::Marshal(&oid)` + `AddBytes`, which emits the identical
//     `06 <len> <content>` element — `AddASN1ObjectIdentifier` is
//     `AddASN1(OBJECT_IDENTIFIER, …)` around the same base-128 content.
//     Pinned by `x509_create_smoke`'s POLICYIDS case against Go run with
//     `GODEBUG=x509usepolicies=0`.
//
// goishlint:ignore GOISH019 pssParameters, tbsCertificateRequest, certificateRequest — pssParameters is the RSA-PSS *parameter* shape, read by the unported `getSignatureAlgorithmFromAI` branch and written by nothing here; the two CSR shapes are declared but only reachable from `CreateCertificateRequest`, which is blocked on asn1::Unmarshal.

// Go: x509.go:58-61
//   type pkixPublicKey struct {
//       Algo      pkix.AlgorithmIdentifier
//       BitString asn1.BitString
//   }
/// A PKIX public key structure. See SubjectPublicKeyInfo in RFC 3280.
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct pkixPublicKey {
    pub Algo: pkix::AlgorithmIdentifier,
    pub BitString: asn1::BitString,
}

// go: sdk 1.25.5 crypto/x509/x509.go:85-140 marshalPublicKey
/// The DER of `pub`'s public-key bit string, plus the algorithm
/// identifier that names it.
pub(super) fn marshalPublicKey(
    pub_: &Any,
) -> (slice<byte>, pkix::AlgorithmIdentifier, error) {
    let mut publicKeyBytes: slice<byte>;
    let mut publicKeyAlgorithm = pkix::AlgorithmIdentifier::default();

    // Go: switch pub := pub.(type) { case *rsa.PublicKey: … }
    if let Some(pub_) = pub_.As::<rsa::PublicKey>() {
        let (b, err) = asn1::Marshal(&pkcs1PublicKey {
            N: pub_.N.clone(),
            E: pub_.E,
        });
        if err != errors::nil {
            return (slice::new(), pkix::AlgorithmIdentifier::default(), err);
        }
        publicKeyBytes = b;
        publicKeyAlgorithm.Algorithm = oidPublicKeyRSA();
        // This is a NULL parameters value which is required by
        // RFC 3279, Section 2.3.1.
        publicKeyAlgorithm.Parameters = asn1::NullRawValue();
    } else if let Some(pub_) = pub_.As::<ecdsa::PublicKey>() {
        let (oid, ok) = oidFromNamedCurve(pub_.Curve);
        if !ok {
            return (
                slice::new(),
                pkix::AlgorithmIdentifier::default(),
                errors::New("x509: unsupported elliptic curve"),
            );
        }
        if !pub_.Curve.IsOnCurve(&pub_.X, &pub_.Y) {
            return (
                slice::new(),
                pkix::AlgorithmIdentifier::default(),
                errors::New("x509: invalid elliptic curve public key"),
            );
        }
        publicKeyBytes = elliptic::Marshal(pub_.Curve, &pub_.X, &pub_.Y);
        publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA();
        let (paramBytes, err) = asn1::Marshal(&oid);
        if err != errors::nil {
            return (slice::new(), pkix::AlgorithmIdentifier::default(), err);
        }
        publicKeyAlgorithm.Parameters.FullBytes = paramBytes;
    } else if let Some(pub_) = pub_.As::<ed25519::PublicKey>() {
        publicKeyBytes = pub_.0.clone();
        publicKeyAlgorithm.Algorithm = oidPublicKeyEd25519();
    } else if let Some(pub_) = pub_.As::<ecdh::PublicKey>() {
        publicKeyBytes = pub_.Bytes();
        if pub_.Curve().String() == ecdh::X25519().String() {
            publicKeyAlgorithm.Algorithm = oidPublicKeyX25519();
        } else {
            let (oid, ok) = oidFromECDHCurve(pub_.Curve());
            if !ok {
                return (
                    slice::new(),
                    pkix::AlgorithmIdentifier::default(),
                    errors::New("x509: unsupported elliptic curve"),
                );
            }
            publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA();
            let (paramBytes, err) = asn1::Marshal(&oid);
            if err != errors::nil {
                return (slice::new(), pkix::AlgorithmIdentifier::default(), err);
            }
            publicKeyAlgorithm.Parameters.FullBytes = paramBytes;
        }
    } else {
        // Go: fmt.Errorf("x509: unsupported public key type: %T", pub).
        // goish has no `%T`; the carrier's recorded type name is the
        // nearest honest thing and is what the rest of this package
        // prints in the same position.
        return (
            slice::new(),
            pkix::AlgorithmIdentifier::default(),
            crate::fmt::Errorf!(
                "x509: unsupported public key type: %s",
                pub_.TypeName()
            ),
        );
    }

    return (publicKeyBytes, publicKeyAlgorithm, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/x509.go:151-170 MarshalPKIXPublicKey
/// Convert a public key to PKIX, ASN.1 DER form. The encoded public key
/// is a SubjectPublicKeyInfo structure (see RFC 5280, Section 4.1).
///
/// The following key types are currently supported: `rsa::PublicKey`,
/// `ecdsa::PublicKey`, `ed25519::PublicKey` and `ecdh::PublicKey`.
/// Unsupported key types result in an error.
///
/// This kind of key is commonly encoded in PEM blocks of type
/// "PUBLIC KEY".
pub fn MarshalPKIXPublicKey(pub_: &Any) -> (slice<byte>, error) {
    let publicKeyBytes: slice<byte>;
    let publicKeyAlgorithm: pkix::AlgorithmIdentifier;

    let (b, ai, err) = marshalPublicKey(pub_);
    if err != errors::nil {
        return (slice::new(), err);
    }
    publicKeyBytes = b;
    publicKeyAlgorithm = ai;

    let pkix_ = pkixPublicKey {
        Algo: publicKeyAlgorithm,
        BitString: asn1::BitString {
            Bytes: publicKeyBytes.clone(),
            BitLength: 8 * publicKeyBytes.Len(),
        },
    };

    let (ret, _) = asn1::Marshal(&pkix_);
    return (ret, errors::nil);
}

// These structures reflect the ASN.1 structure of X.509 certificates.:

// Go: x509.go:194-198
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct certificate {
    pub TBSCertificate: tbsCertificate,
    pub SignatureAlgorithm: pkix::AlgorithmIdentifier,
    pub SignatureValue: asn1::BitString,
}

// Go: x509.go:200-212
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct tbsCertificate {
    pub Raw: asn1::RawContent,
    #[tag(r#"asn1:"optional,explicit,default:0,tag:0""#)]
    pub Version: int,
    pub SerialNumber: big::Int,
    pub SignatureAlgorithm: pkix::AlgorithmIdentifier,
    pub Issuer: asn1::RawValue,
    pub Validity: validity,
    pub Subject: asn1::RawValue,
    pub PublicKey: publicKeyInfo,
    #[tag(r#"asn1:"optional,tag:1""#)]
    pub UniqueId: asn1::BitString,
    #[tag(r#"asn1:"optional,tag:2""#)]
    pub SubjectUniqueId: asn1::BitString,
    #[tag(r#"asn1:"omitempty,optional,explicit,tag:3""#)]
    pub Extensions: slice<pkix::Extension>,
}

// Go: x509.go:214-216
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct dsaAlgorithmParameters {
    pub P: big::Int,
    pub Q: big::Int,
    pub G: big::Int,
}

// Go: x509.go:218-220
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct validity {
    pub NotBefore: time::Time,
    pub NotAfter: time::Time,
}

// Go: x509.go:209-211
//   type authKeyId struct { Id []byte `asn1:"optional,tag:0"` }
/// RFC 5280, 4.2.1.1.
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct authKeyId {
    #[tag(r#"asn1:"optional,tag:0""#)]
    pub Id: slice<byte>,
}

// Go: x509.go:1041-1044
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct basicConstraints {
    #[tag(r#"asn1:"optional""#)]
    pub IsCA: bool,
    #[tag(r#"asn1:"optional,default:-1""#)]
    pub MaxPathLen: int,
}

// Go: x509.go:1047-1050
/// RFC 5280 4.2.1.4. `policyQualifiers` omitted.
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct policyInformation {
    pub Policy: asn1::ObjectIdentifier,
}

// Go: x509.go:1060-1063
/// RFC 5280, 4.2.2.1.
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct authorityInfoAccess {
    pub Method: asn1::ObjectIdentifier,
    pub Location: asn1::RawValue,
}

// Go: x509.go:1066-1070
/// RFC 5280, 4.2.1.14.
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct distributionPoint {
    #[tag(r#"asn1:"optional,tag:0""#)]
    pub DistributionPoint: distributionPointName,
    #[tag(r#"asn1:"optional,tag:1""#)]
    pub Reason: asn1::BitString,
    #[tag(r#"asn1:"optional,tag:2""#)]
    pub CRLIssuer: asn1::RawValue,
}

// Go: x509.go:1072-1075
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct distributionPointName {
    #[tag(r#"asn1:"optional,tag:0""#)]
    pub FullName: slice<asn1::RawValue>,
    #[tag(r#"asn1:"optional,tag:1""#)]
    pub RelativeName: pkix::RDNSequence,
}

// go: sdk 1.25.5 crypto/x509/x509.go:1077-1082 reverseBitsInAByte
pub(super) fn reverseBitsInAByte(in_: byte) -> byte {
    let b1 = in_ >> 4 | in_ << 4;
    let b2 = b1 >> 2 & 0x33 | b1 << 2 & 0xcc;
    let b3 = b2 >> 1 & 0x55 | b2 << 1 & 0xaa;
    return b3;
}

// go: sdk 1.25.5 crypto/x509/x509.go:1087-1102 asn1BitLength
/// The bit-length of `bitString`, considering the most-significant bit
/// in a byte to be the "first" bit. This convention matches ASN.1, but
/// differs from almost everything else.
pub(super) fn asn1BitLength(bitString: &slice<byte>) -> int {
    let mut bitLen = bitString.Len() * 8;

    for (i, _) in crate::range!(bitString.clone()) {
        let b = bitString[bitString.Len() - i - 1];

        let mut bit: crate::uint = 0;
        while bit < 8 {
            if (b >> bit) & 1 == 1 {
                return bitLen;
            }
            bitLen -= 1;
            bit += 1;
        }
    }

    return 0;
}

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:1104-1117 — the marshaling-side half of the extension OID
// `var` block. The parsing-side names are up in the first half of this
// file; between them the block is complete.
pub(super) fn oidExtensionSubjectKeyId() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 14]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidExtensionKeyUsage() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 15]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidExtensionExtendedKeyUsage() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 37]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidExtensionBasicConstraints() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 19]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidExtensionCertificatePolicies() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 32]);
}
// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
pub(super) fn oidExtensionCRLDistributionPoints() -> asn1::ObjectIdentifier {
    return oid(&[2, 5, 29, 31]);
}

// go: sdk 1.25.5 crypto/x509/x509.go:1137-1167 marshalSANs
/// Marshal a list of addresses into the contents of an X.509
/// SubjectAlternativeName extension.
pub(super) fn marshalSANs(
    dnsNames: &slice<string>,
    emailAddresses: &slice<string>,
    ipAddresses: &slice<net::IP>,
    uris: &slice<url::URL>,
) -> (slice<byte>, error) {
    let mut rawValues: slice<asn1::RawValue> = slice::new();
    for (_, name) in crate::range!(dnsNames.clone()) {
        let err = isIA5String(&name);
        if err != errors::nil {
            return (slice::new(), err);
        }
        rawValues = crate::append!(
            rawValues,
            asn1::RawValue {
                Tag: nameTypeDNS,
                Class: 2,
                Bytes: crate::convert::bytes(name.clone()),
                ..Default::default()
            }
        );
    }
    for (_, email) in crate::range!(emailAddresses.clone()) {
        let err = isIA5String(&email);
        if err != errors::nil {
            return (slice::new(), err);
        }
        rawValues = crate::append!(
            rawValues,
            asn1::RawValue {
                Tag: nameTypeEmail,
                Class: 2,
                Bytes: crate::convert::bytes(email.clone()),
                ..Default::default()
            }
        );
    }
    for (_, rawIP) in crate::range!(ipAddresses.clone()) {
        // If possible, we always want to encode IPv4 addresses in 4 bytes.
        // Go writes `if ip == nil`; `net::IP` spells its nil test
        // `IsNil()` (net/mod.rs:653), the runtime's documented
        // equivalent.
        let mut ip = rawIP.To4();
        if ip.IsNil() {
            ip = rawIP.clone();
        }
        rawValues = crate::append!(
            rawValues,
            asn1::RawValue {
                Tag: nameTypeIP,
                Class: 2,
                Bytes: ip.bytes.clone(),
                ..Default::default()
            }
        );
    }
    for (_, uri) in crate::range!(uris.clone()) {
        let uriStr = uri.String();
        let err = isIA5String(&uriStr);
        if err != errors::nil {
            return (slice::new(), err);
        }
        rawValues = crate::append!(
            rawValues,
            asn1::RawValue {
                Tag: nameTypeURI,
                Class: 2,
                Bytes: crate::convert::bytes(uriStr.clone()),
                ..Default::default()
            }
        );
    }
    return asn1::Marshal(&rawValues);
}

// go: none — goish idiom: Go's `var x509usepolicies = godebug.New("x509usepolicies")`
// reads a GODEBUG setting. goish has no `internal/godebug`, so this
// returns the value an *unset* setting has — `""` — which is what makes
// `x509usepolicies.Value() != "0"` true and selects the `Policies`
// field, Go 1.24+'s default. The call sites keep Go's test verbatim
// rather than folding it away, so the other branch stays readable.
// `IncNonDefault()` has no counter to bump here and is dropped.
fn x509usepolicies() -> string {
    return string::from_static("");
}

// go: sdk 1.25.5 crypto/x509/x509.go:1182-1403 buildCertExtensions
/// Build the extension list a certificate carries, from `template`'s
/// fields. `template.ExtraExtensions` is appended last and overrides
/// nothing — Go relies on the `oidInExtensions` guard on each branch to
/// skip an extension the caller already supplied raw.
pub(super) fn buildCertExtensions(
    template: &Certificate,
    subjectIsEmpty: bool,
    authorityKeyId: &slice<byte>,
    subjectKeyId: &slice<byte>,
) -> (slice<pkix::Extension>, error) {
    // Go: ret = make([]pkix.Extension, 10 /* maximum number of elements. */)
    let mut ret: slice<pkix::Extension> = crate::make!([]pkix::Extension, 10);
    let mut n: int = 0;

    if template.KeyUsage != KeyUsage(0)
        && !oidInExtensions(&oidExtensionKeyUsage(), &template.ExtraExtensions)
    {
        let (e, err) = marshalKeyUsage(template.KeyUsage);
        if err != errors::nil {
            return (slice::new(), err);
        }
        ret[n] = e;
        n += 1;
    }

    if (template.ExtKeyUsage.Len() > 0 || template.UnknownExtKeyUsage.Len() > 0)
        && !oidInExtensions(&oidExtensionExtendedKeyUsage(), &template.ExtraExtensions)
    {
        let (e, err) =
            marshalExtKeyUsage(&template.ExtKeyUsage, &template.UnknownExtKeyUsage);
        if err != errors::nil {
            return (slice::new(), err);
        }
        ret[n] = e;
        n += 1;
    }

    if template.BasicConstraintsValid
        && !oidInExtensions(&oidExtensionBasicConstraints(), &template.ExtraExtensions)
    {
        let (e, err) = marshalBasicConstraints(
            template.IsCA,
            template.MaxPathLen,
            template.MaxPathLenZero,
        );
        if err != errors::nil {
            return (slice::new(), err);
        }
        ret[n] = e;
        n += 1;
    }

    if subjectKeyId.Len() > 0
        && !oidInExtensions(&oidExtensionSubjectKeyId(), &template.ExtraExtensions)
    {
        ret[n].Id = oidExtensionSubjectKeyId();
        let (v, err) = asn1::Marshal(subjectKeyId);
        if err != errors::nil {
            return (slice::new(), err);
        }
        ret[n].Value = v;
        n += 1;
    }

    if authorityKeyId.Len() > 0
        && !oidInExtensions(&oidExtensionAuthorityKeyId(), &template.ExtraExtensions)
    {
        ret[n].Id = oidExtensionAuthorityKeyId();
        let (v, err) = asn1::Marshal(&authKeyId {
            Id: authorityKeyId.clone(),
        });
        if err != errors::nil {
            return (slice::new(), err);
        }
        ret[n].Value = v;
        n += 1;
    }

    if (template.OCSPServer.Len() > 0 || template.IssuingCertificateURL.Len() > 0)
        && !oidInExtensions(&oidExtensionAuthorityInfoAccess(), &template.ExtraExtensions)
    {
        ret[n].Id = oidExtensionAuthorityInfoAccess();
        let mut aiaValues: slice<authorityInfoAccess> = slice::new();
        for (_, name) in crate::range!(template.OCSPServer.clone()) {
            aiaValues = crate::append!(
                aiaValues,
                authorityInfoAccess {
                    Method: oidAuthorityInfoAccessOcsp(),
                    Location: asn1::RawValue {
                        Tag: 6,
                        Class: 2,
                        Bytes: crate::convert::bytes(name.clone()),
                        ..Default::default()
                    },
                }
            );
        }
        for (_, name) in crate::range!(template.IssuingCertificateURL.clone()) {
            aiaValues = crate::append!(
                aiaValues,
                authorityInfoAccess {
                    Method: oidAuthorityInfoAccessIssuers(),
                    Location: asn1::RawValue {
                        Tag: 6,
                        Class: 2,
                        Bytes: crate::convert::bytes(name.clone()),
                        ..Default::default()
                    },
                }
            );
        }
        let (v, err) = asn1::Marshal(&aiaValues);
        if err != errors::nil {
            return (slice::new(), err);
        }
        ret[n].Value = v;
        n += 1;
    }

    if (template.DNSNames.Len() > 0
        || template.EmailAddresses.Len() > 0
        || template.IPAddresses.Len() > 0
        || template.URIs.Len() > 0)
        && !oidInExtensions(&oidExtensionSubjectAltName(), &template.ExtraExtensions)
    {
        ret[n].Id = oidExtensionSubjectAltName();
        // From RFC 5280, Section 4.2.1.6:
        // "If the subject field contains an empty sequence ... then
        // subjectAltName extension ... is marked as critical"
        ret[n].Critical = subjectIsEmpty;
        let (v, err) = marshalSANs(
            &template.DNSNames,
            &template.EmailAddresses,
            &template.IPAddresses,
            &template.URIs,
        );
        if err != errors::nil {
            return (slice::new(), err);
        }
        ret[n].Value = v;
        n += 1;
    }

    let usePolicies = x509usepolicies() != "0";
    if ((!usePolicies && template.PolicyIdentifiers.Len() > 0)
        || (usePolicies && template.Policies.Len() > 0))
        && !oidInExtensions(&oidExtensionCertificatePolicies(), &template.ExtraExtensions)
    {
        let (e, err) =
            marshalCertificatePolicies(&template.Policies, &template.PolicyIdentifiers);
        if err != errors::nil {
            return (slice::new(), err);
        }
        ret[n] = e;
        n += 1;
    }

    if (template.PermittedDNSDomains.Len() > 0
        || template.ExcludedDNSDomains.Len() > 0
        || template.PermittedIPRanges.Len() > 0
        || template.ExcludedIPRanges.Len() > 0
        || template.PermittedEmailAddresses.Len() > 0
        || template.ExcludedEmailAddresses.Len() > 0
        || template.PermittedURIDomains.Len() > 0
        || template.ExcludedURIDomains.Len() > 0)
        && !oidInExtensions(&oidExtensionNameConstraints(), &template.ExtraExtensions)
    {
        ret[n].Id = oidExtensionNameConstraints();
        ret[n].Critical = template.PermittedDNSDomainsCritical;

        let (permitted, err) = serialiseConstraints(
            &template.PermittedDNSDomains,
            &template.PermittedIPRanges,
            &template.PermittedEmailAddresses,
            &template.PermittedURIDomains,
        );
        if err != errors::nil {
            return (slice::new(), err);
        }

        let (excluded, err) = serialiseConstraints(
            &template.ExcludedDNSDomains,
            &template.ExcludedIPRanges,
            &template.ExcludedEmailAddresses,
            &template.ExcludedURIDomains,
        );
        if err != errors::nil {
            return (slice::new(), err);
        }

        let mut b = cryptobyte::NewBuilder(slice::new());
        b.AddASN1(cbasn1::SEQUENCE, |b: &mut cryptobyte::Builder| {
            if permitted.Len() > 0 {
                b.AddASN1(
                    cbasn1::Tag(0).ContextSpecific().Constructed(),
                    |b: &mut cryptobyte::Builder| {
                        b.AddBytes(&permitted);
                    },
                );
            }

            if excluded.Len() > 0 {
                b.AddASN1(
                    cbasn1::Tag(1).ContextSpecific().Constructed(),
                    |b: &mut cryptobyte::Builder| {
                        b.AddBytes(&excluded);
                    },
                );
            }
        });

        let (v, err) = b.Bytes();
        if err != errors::nil {
            return (slice::new(), err);
        }
        ret[n].Value = v;
        n += 1;
    }

    if template.CRLDistributionPoints.Len() > 0
        && !oidInExtensions(
            &oidExtensionCRLDistributionPoints(),
            &template.ExtraExtensions,
        )
    {
        ret[n].Id = oidExtensionCRLDistributionPoints();

        let mut crlDp: slice<distributionPoint> = slice::new();
        for (_, name) in crate::range!(template.CRLDistributionPoints.clone()) {
            let dp = distributionPoint {
                DistributionPoint: distributionPointName {
                    FullName: slice::__from_vec(alloc::vec![asn1::RawValue {
                        Tag: 6,
                        Class: 2,
                        Bytes: crate::convert::bytes(name.clone()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
                ..Default::default()
            };
            crlDp = crate::append!(crlDp, dp);
        }

        let (v, err) = asn1::Marshal(&crlDp);
        if err != errors::nil {
            return (slice::new(), err);
        }
        ret[n].Value = v;
        n += 1;
    }

    // Adding another extension here? Remember to update the maximum number
    // of elements in the make() at the top of the function and the list of
    // template fields used in CreateCertificate documentation.

    return (
        crate::append!(ret.slice(0, n), template.ExtraExtensions.clone()...),
        errors::nil,
    );
}

// go: none — goish idiom: Go writes `ipAndMask` and `serialiseConstraints`
// as closures inside `buildCertExtensions` (x509.go:1283-1338). Rust
// closures cannot recurse into `Builder::AddASN1`'s `FnOnce` while also
// capturing the enclosing `ret[n]` borrow, so both are lifted to
// file-private functions with the same names, bodies and order.
fn ipAndMask(ipNet: &net::IPNet) -> slice<byte> {
    let maskedIP = ipNet.IP.Mask(ipNet.Mask.clone());
    let mut ipAndMask: Vec<byte> = Vec::with_capacity(
        (maskedIP.bytes.Len() + ipNet.Mask.bytes.Len()) as usize,
    );
    for (_, b) in crate::range!(maskedIP.bytes.clone()) {
        ipAndMask.push(*b);
    }
    for (_, b) in crate::range!(ipNet.Mask.bytes.clone()) {
        ipAndMask.push(*b);
    }
    return slice::__from_vec(ipAndMask);
}

// go: none — goish idiom: see `ipAndMask`.
fn serialiseConstraints(
    dns: &slice<string>,
    ips: &slice<net::IPNet>,
    emails: &slice<string>,
    uriDomains: &slice<string>,
) -> (slice<byte>, error) {
    let mut b = cryptobyte::NewBuilder(slice::new());

    for (_, name) in crate::range!(dns.clone()) {
        let err = isIA5String(&name);
        if err != errors::nil {
            return (slice::new(), err);
        }

        b.AddASN1(cbasn1::SEQUENCE, |b: &mut cryptobyte::Builder| {
            b.AddASN1(
                cbasn1::Tag(2).ContextSpecific(),
                |b: &mut cryptobyte::Builder| {
                    b.AddBytes(&crate::convert::bytes(name.clone()));
                },
            );
        });
    }

    for (_, ipNet) in crate::range!(ips.clone()) {
        b.AddASN1(cbasn1::SEQUENCE, |b: &mut cryptobyte::Builder| {
            b.AddASN1(
                cbasn1::Tag(7).ContextSpecific(),
                |b: &mut cryptobyte::Builder| {
                    b.AddBytes(&ipAndMask(&ipNet));
                },
            );
        });
    }

    for (_, email) in crate::range!(emails.clone()) {
        let err = isIA5String(&email);
        if err != errors::nil {
            return (slice::new(), err);
        }

        b.AddASN1(cbasn1::SEQUENCE, |b: &mut cryptobyte::Builder| {
            b.AddASN1(
                cbasn1::Tag(1).ContextSpecific(),
                |b: &mut cryptobyte::Builder| {
                    b.AddBytes(&crate::convert::bytes(email.clone()));
                },
            );
        });
    }

    for (_, uriDomain) in crate::range!(uriDomains.clone()) {
        let err = isIA5String(&uriDomain);
        if err != errors::nil {
            return (slice::new(), err);
        }

        b.AddASN1(cbasn1::SEQUENCE, |b: &mut cryptobyte::Builder| {
            b.AddASN1(
                cbasn1::Tag(6).ContextSpecific(),
                |b: &mut cryptobyte::Builder| {
                    b.AddBytes(&crate::convert::bytes(uriDomain.clone()));
                },
            );
        });
    }

    return b.Bytes();
}

// go: sdk 1.25.5 crypto/x509/x509.go:1405-1421 marshalKeyUsage
pub(super) fn marshalKeyUsage(ku: KeyUsage) -> (pkix::Extension, error) {
    let mut ext = pkix::Extension {
        Id: oidExtensionKeyUsage(),
        Critical: true,
        ..Default::default()
    };

    let mut a: [byte; 2] = [0; 2];
    a[0] = reverseBitsInAByte(crate::byte(ku.0));
    a[1] = reverseBitsInAByte(crate::byte(ku.0 >> 8));

    let mut l: int = 1;
    if a[1] != 0 {
        l = 2;
    }

    let bitString = slice::__from_vec(a[..(l as usize)].to_vec());
    let (v, err) = asn1::Marshal(&asn1::BitString {
        Bytes: bitString.clone(),
        BitLength: asn1BitLength(&bitString),
    });
    ext.Value = v;
    return (ext, err);
}

// go: sdk 1.25.5 crypto/x509/x509.go:1423-1440 marshalExtKeyUsage
pub(super) fn marshalExtKeyUsage(
    extUsages: &slice<ExtKeyUsage>,
    unknownUsages: &slice<asn1::ObjectIdentifier>,
) -> (pkix::Extension, error) {
    let mut ext = pkix::Extension {
        Id: oidExtensionExtendedKeyUsage(),
        ..Default::default()
    };

    let mut oids: slice<asn1::ObjectIdentifier> = crate::make!(
        []asn1::ObjectIdentifier,
        extUsages.Len() + unknownUsages.Len()
    );
    for (i, u) in crate::range!(extUsages.clone()) {
        let (oid, ok) = oidFromExtKeyUsage(*u);
        if ok {
            oids[i] = oid;
        } else {
            return (ext, errors::New("x509: unknown extended key usage"));
        }
    }

    // Go: copy(oids[len(extUsages):], unknownUsages).
    //
    // goish's `xs[lo:hi]` returns an independent copy, not a view
    // (goslice.rs:88), so `copy!` into a subslice expression would
    // write to a temporary and drop the result on the floor. The
    // destination indices are written directly instead — same
    // elements, same order, same overwrite semantics.
    for (i, u) in crate::range!(unknownUsages.clone()) {
        oids[extUsages.Len() + i] = u.clone();
    }

    let (v, err) = asn1::Marshal(&oids);
    ext.Value = v;
    return (ext, err);
}

// go: sdk 1.25.5 crypto/x509/x509.go:1442-1453 marshalBasicConstraints
pub(super) fn marshalBasicConstraints(
    isCA: bool,
    maxPathLen: int,
    maxPathLenZero: bool,
) -> (pkix::Extension, error) {
    let mut ext = pkix::Extension {
        Id: oidExtensionBasicConstraints(),
        Critical: true,
        ..Default::default()
    };
    // Leaving MaxPathLen as zero indicates that no maximum path
    // length is desired, unless MaxPathLenZero is set. A value of
    // -1 causes encoding/asn1 to omit the value as desired.
    let mut maxPathLen = maxPathLen;
    if maxPathLen == 0 && !maxPathLenZero {
        maxPathLen = -1;
    }
    let (v, err) = asn1::Marshal(&basicConstraints {
        IsCA: isCA,
        MaxPathLen: maxPathLen,
    });
    ext.Value = v;
    return (ext, err);
}

// go: sdk 1.25.5 crypto/x509/x509.go:1455-1485 marshalCertificatePolicies
pub(super) fn marshalCertificatePolicies(
    policies: &slice<OID>,
    policyIdentifiers: &slice<asn1::ObjectIdentifier>,
) -> (pkix::Extension, error) {
    let mut ext = pkix::Extension {
        Id: oidExtensionCertificatePolicies(),
        ..Default::default()
    };

    let mut b = cryptobyte::NewBuilder(crate::make!([]byte, 0, 128));
    b.AddASN1(cbasn1::SEQUENCE, |child: &mut cryptobyte::Builder| {
        if x509usepolicies() != "0" {
            // Go: x509usepolicies.IncNonDefault() — no goish counter.
            for (_, v) in crate::range!(policies.clone()) {
                child.AddASN1(cbasn1::SEQUENCE, |child: &mut cryptobyte::Builder| {
                    child.AddASN1(
                        cbasn1::OBJECT_IDENTIFIER,
                        |child: &mut cryptobyte::Builder| {
                            if v.der.Len() == 0 {
                                child.SetError(errors::New(
                                    "invalid policy object identifier",
                                ));
                                return;
                            }
                            child.AddBytes(&v.der);
                        },
                    );
                });
            }
        } else {
            for (_, v) in crate::range!(policyIdentifiers.clone()) {
                child.AddASN1(cbasn1::SEQUENCE, |child: &mut cryptobyte::Builder| {
                    // Go: child.AddASN1ObjectIdentifier(v). cryptobyte's
                    // Builder half is not ported (see that file's
                    // GOISH018 waiver); `asn1::Marshal` of an
                    // ObjectIdentifier emits the identical
                    // `06 <len> <base128 content>` element, which is all
                    // AddASN1ObjectIdentifier writes.
                    let (der, err) = asn1::Marshal(&v);
                    if err != errors::nil {
                        child.SetError(err);
                        return;
                    }
                    child.AddBytes(&der);
                });
            }
        }
    });

    let (v, err) = b.Bytes();
    ext.Value = v;
    return (ext, err);
}

// go: sdk 1.25.5 crypto/x509/x509.go:1487-1504 buildCSRExtensions
pub(super) fn buildCSRExtensions(
    template: &CertificateRequest,
) -> (slice<pkix::Extension>, error) {
    let mut ret: slice<pkix::Extension> = slice::new();

    if (template.DNSNames.Len() > 0
        || template.EmailAddresses.Len() > 0
        || template.IPAddresses.Len() > 0
        || template.URIs.Len() > 0)
        && !oidInExtensions(&oidExtensionSubjectAltName(), &template.ExtraExtensions)
    {
        let (sanBytes, err) = marshalSANs(
            &template.DNSNames,
            &template.EmailAddresses,
            &template.IPAddresses,
            &template.URIs,
        );
        if err != errors::nil {
            return (slice::new(), err);
        }

        ret = crate::append!(
            ret,
            pkix::Extension {
                Id: oidExtensionSubjectAltName(),
                Value: sanBytes,
                ..Default::default()
            }
        );
    }

    return (
        crate::append!(ret, template.ExtraExtensions.clone()...),
        errors::nil,
    );
}

// go: sdk 1.25.5 crypto/x509/x509.go:1506-1512 subjectBytes
pub(super) fn subjectBytes(cert: &Certificate) -> (slice<byte>, error) {
    if cert.RawSubject.Len() > 0 {
        return (cert.RawSubject.clone(), errors::nil);
    }

    return asn1::Marshal(&cert.Subject.ToRDNSequence());
}

// go: sdk 1.25.5 crypto/x509/x509.go:1517-1569 signingParamsForKey
/// The signature algorithm and its Algorithm Identifier to use for
/// signing, based on the key type. If `sigAlgo` is not zero then it
/// overrides the default.
pub(super) fn signingParamsForKey(
    key: &(dyn crypto::Signer + Send + Sync + 'static),
    sigAlgo: SignatureAlgorithm,
) -> (SignatureAlgorithm, pkix::AlgorithmIdentifier, error) {
    let ai = pkix::AlgorithmIdentifier::default();
    let pubType: PublicKeyAlgorithm;
    let defaultAlgo: SignatureAlgorithm;

    // Go: switch pub := key.Public().(type) { … }
    let pub_ = key.Public();
    if pub_.downcast_ref::<rsa::PublicKey>().is_some() {
        pubType = RSA;
        defaultAlgo = SHA256WithRSA;
    } else if let Some(p) = pub_.downcast_ref::<ecdsa::PublicKey>() {
        pubType = ECDSA;
        // Go: switch pub.Curve { case elliptic.P224(), elliptic.P256(): … }
        // goish compares `Params().Name`, the same identity test
        // `oidFromNamedCurve` above already uses.
        let name = p.Curve.Params().Name.clone();
        if name == elliptic::P224().Params().Name || name == elliptic::P256().Params().Name {
            defaultAlgo = ECDSAWithSHA256;
        } else if name == elliptic::P384().Params().Name {
            defaultAlgo = ECDSAWithSHA384;
        } else if name == elliptic::P521().Params().Name {
            defaultAlgo = ECDSAWithSHA512;
        } else {
            return (
                SignatureAlgorithm(0),
                ai,
                errors::New("x509: unsupported elliptic curve"),
            );
        }
    } else if pub_.downcast_ref::<ed25519::PublicKey>().is_some() {
        pubType = Ed25519;
        defaultAlgo = PureEd25519;
    } else {
        return (
            SignatureAlgorithm(0),
            ai,
            errors::New("x509: only RSA, ECDSA and Ed25519 keys supported"),
        );
    }

    let mut sigAlgo = sigAlgo;
    if sigAlgo == SignatureAlgorithm(0) {
        sigAlgo = defaultAlgo;
    }

    for (_, details) in crate::range!(signatureAlgorithmDetails()) {
        if details.algo == sigAlgo {
            if details.pubKeyAlgo != pubType {
                return (
                    SignatureAlgorithm(0),
                    ai,
                    errors::New(
                        "x509: requested SignatureAlgorithm does not match private key type",
                    ),
                );
            }
            if details.hash == crypto::MD5 {
                return (
                    SignatureAlgorithm(0),
                    ai,
                    errors::New("x509: signing with MD5 is not supported"),
                );
            }

            return (
                sigAlgo,
                pkix::AlgorithmIdentifier {
                    Algorithm: details.oid.clone(),
                    Parameters: details.params.clone(),
                },
                errors::nil,
            );
        }
    }

    return (
        SignatureAlgorithm(0),
        ai,
        errors::New("x509: unknown SignatureAlgorithm"),
    );
}

// go: none — goish idiom: Go's `crypto.PublicKey` *is* `any`, so
// `key.Public()` drops straight into `marshalPublicKey(pub any)` and
// into `checkSignature`'s `publicKey crypto.PublicKey`. goish has two
// distinct erasure carriers that do not convert without naming the
// concrete type: `crypto::PublicKey` is
// `Arc<dyn core::any::Any + Send + Sync>` (downcast only), and
// `goany::Any` is the reflective carrier this package passes around.
// The four key types x509 supports — the same four `marshalPublicKey`
// enumerates and `signingParamsForKey` accepts — are named here once.
//
// `Any::new_fn` rather than `Any::new`, for the reason the file banner
// already gives for `Certificate.PublicKey`: none of these key types is
// `PartialEq` in goish (Go spells their comparison as an `Equal`
// method), which `Any::new` requires. `As::<T>()` sees through either
// wrapper, so every downstream downcast is unaffected.
fn anyFromPublicKey(pub_: &crypto::PublicKey) -> (Any, error) {
    if let Some(k) = pub_.downcast_ref::<rsa::PublicKey>() {
        return (Any::new_fn(k.clone()), errors::nil);
    }
    if let Some(k) = pub_.downcast_ref::<ecdsa::PublicKey>() {
        return (Any::new_fn(k.clone()), errors::nil);
    }
    if let Some(k) = pub_.downcast_ref::<ed25519::PublicKey>() {
        return (Any::new_fn(k.clone()), errors::nil);
    }
    if let Some(k) = pub_.downcast_ref::<ecdh::PublicKey>() {
        return (Any::new_fn(k.clone()), errors::nil);
    }
    return (
        Any::from(crate::nil),
        errors::New("x509: only RSA, ECDSA and Ed25519 keys supported"),
    );
}

// go: sdk 1.25.5 crypto/x509/x509.go:1571-1593 signTBS
pub(super) fn signTBS(
    tbs: &slice<byte>,
    key: &(dyn crypto::Signer + Send + Sync + 'static),
    sigAlg: SignatureAlgorithm,
    rand: &mut dyn io::Reader,
) -> (slice<byte>, error) {
    let hashFunc = sigAlg.hashFunc();

    // Go: var signerOpts crypto.SignerOpts = hashFunc
    //     if sigAlg.isRSAPSS() { signerOpts = &rsa.PSSOptions{…} }
    let pssOpts = rsa::PSSOptions {
        SaltLength: rsa::PSSSaltLengthEqualsHash,
        Hash: hashFunc,
    };
    let signerOpts: &dyn crypto::SignerOpts = if sigAlg.isRSAPSS() {
        &pssOpts
    } else {
        &hashFunc
    };

    let (signature, err) = crypto::SignMessage(key, rand, tbs.clone(), signerOpts);
    if err != errors::nil {
        return (slice::new(), err);
    }

    // Check the signature to ensure the crypto.Signer behaved correctly.
    let (pubAny, err) = anyFromPublicKey(&key.Public());
    if err != errors::nil {
        return (slice::new(), err);
    }
    let err = checkSignature(sigAlg, tbs.clone(), signature.clone(), &pubAny, true);
    if err != errors::nil {
        return (
            slice::new(),
            crate::fmt::Errorf!("x509: signature returned by signer is invalid: %w", err),
        );
    }

    return (signature, errors::nil);
}

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:1595 — `var emptyASN1Subject = []byte{0x30, 0}`.
/// The ASN.1 DER encoding of an empty Subject, which is just an empty
/// SEQUENCE.
fn emptyASN1Subject() -> slice<byte> {
    return slice::__from_vec(alloc::vec![0x30, 0]);
}

// go: sdk 1.25.5 crypto/x509/x509.go:1662-1793 CreateCertificate
/// Create a new X.509 v3 certificate based on a template. The following
/// members of `template` are currently used:
///
///   - AuthorityKeyId
///   - BasicConstraintsValid
///   - CRLDistributionPoints
///   - DNSNames
///   - EmailAddresses
///   - ExcludedDNSDomains
///   - ExcludedEmailAddresses
///   - ExcludedIPRanges
///   - ExcludedURIDomains
///   - ExtKeyUsage
///   - ExtraExtensions
///   - IPAddresses
///   - IsCA
///   - IssuingCertificateURL
///   - KeyUsage
///   - MaxPathLen
///   - MaxPathLenZero
///   - NotAfter
///   - NotBefore
///   - OCSPServer
///   - PermittedDNSDomains
///   - PermittedDNSDomainsCritical
///   - PermittedEmailAddresses
///   - PermittedIPRanges
///   - PermittedURIDomains
///   - Policies
///   - PolicyIdentifiers
///   - SerialNumber
///   - SignatureAlgorithm
///   - Subject
///   - SubjectKeyId
///   - URIs
///   - UnknownExtKeyUsage
///
/// The certificate is signed by `parent`. If `parent` is equal to
/// `template` then the certificate is self-signed. `pub_` is the public
/// key of the certificate to be generated and `priv_` is the private key
/// of the signer.
///
/// The returned slice is the certificate in DER encoding.
///
/// The AuthorityKeyId will be taken from the SubjectKeyId of `parent`,
/// if any, unless the resulting certificate is self-signed. Otherwise
/// the value from `template` will be used.
///
/// If SubjectKeyId from `template` is empty and the template is a CA,
/// SubjectKeyId will be generated from the hash of the public key.
///
/// If `template.SerialNumber` is nil, a serial number will be generated
/// which conforms to RFC 5280, Section 4.1.2.2 using entropy from
/// `rand`.
pub fn CreateCertificate(
    rand: &mut dyn io::Reader,
    template: &Certificate,
    parent: &Certificate,
    pub_: &Any,
    priv_: &Any,
) -> (slice<byte>, error) {
    // Go: key, ok := priv.(crypto.Signer)
    //
    // Spelled `Any::As`, not `goish::cast!`. `cast!` resolves its
    // carrier through the *blanket* `HasDynAny for T` (goany.rs:635),
    // which hands back the carrier itself — for an `Any` that is `Any`'s
    // own TypeId, never the payload's, so the registry lookup can only
    // miss. `Any`'s inherent `As` goes through `as_any()`, which unwraps
    // to the stored key. Same comma-ok shape, and the same spelling
    // `crypto::SignMessage` already uses for its `MessageSigner`
    // upgrade.
    let key = match priv_.As::<dyn crypto::Signer + Send + Sync>() {
        Some(k) => k,
        None => {
            return (
                slice::new(),
                errors::New(
                    "x509: certificate private key does not implement crypto.Signer",
                ),
            )
        }
    };

    let mut serialNumber = template.SerialNumber.clone();
    if serialNumber == crate::nil {
        // Generate a serial number following RFC 5280, Section 4.1.2.2 if
        // one is not provided. The serial number must be positive and at
        // most 20 octets *when encoded*.
        let mut serialBytes: slice<byte> = crate::make!([]byte, 20);
        let (_, err) = io::ReadFull(rand, &mut serialBytes);
        if err != errors::nil {
            return (slice::new(), err);
        }
        // If the top bit is set, the serial will be padded with a leading
        // zero byte during encoding, so that it's not interpreted as a
        // negative integer. This padding would make the serial 21 octets
        // so we clear the top bit to ensure the correct length in all
        // cases.
        serialBytes[0] &= 0b0111_1111;
        serialNumber = big::Int::default();
        serialNumber.SetBytes(serialBytes);
    }

    // RFC 5280 Section 4.1.2.2: serial number must be positive
    //
    // We _should_ also restrict serials to <= 20 octets, but it turns out
    // a lot of people get this wrong, in part because the encoding can
    // itself alter the length of the serial. For now we accept these
    // non-conformant serials.
    if serialNumber.Sign() == -1 {
        return (
            slice::new(),
            errors::New("x509: serial number must be positive"),
        );
    }

    if template.BasicConstraintsValid && template.MaxPathLen < -1 {
        return (
            slice::new(),
            errors::New("x509: invalid MaxPathLen, must be greater or equal to -1"),
        );
    }

    if template.BasicConstraintsValid
        && !template.IsCA
        && template.MaxPathLen != -1
        && (template.MaxPathLen != 0 || template.MaxPathLenZero)
    {
        return (
            slice::new(),
            errors::New("x509: only CAs are allowed to specify MaxPathLen"),
        );
    }

    let (signatureAlgorithm, algorithmIdentifier, err) =
        signingParamsForKey(key, template.SignatureAlgorithm);
    if err != errors::nil {
        return (slice::new(), err);
    }

    let (publicKeyBytes, publicKeyAlgorithm, err) = marshalPublicKey(pub_);
    if err != errors::nil {
        return (slice::new(), err);
    }
    if getPublicKeyAlgorithmFromOID(&publicKeyAlgorithm.Algorithm) == UnknownPublicKeyAlgorithm
    {
        // Go: fmt.Errorf("x509: unsupported public key type: %T", pub).
        return (
            slice::new(),
            crate::fmt::Errorf!(
                "x509: unsupported public key type: %s",
                pub_.TypeName()
            ),
        );
    }

    let (asn1Issuer, err) = subjectBytes(parent);
    if err != errors::nil {
        return (slice::new(), err);
    }

    let (asn1Subject, err) = subjectBytes(template);
    if err != errors::nil {
        return (slice::new(), err);
    }

    let mut authorityKeyId = template.AuthorityKeyId.clone();
    if !crate::bytes::Equal(asn1Issuer.clone(), asn1Subject.clone())
        && parent.SubjectKeyId.Len() > 0
    {
        authorityKeyId = parent.SubjectKeyId.clone();
    }

    let mut subjectKeyId = template.SubjectKeyId.clone();
    if subjectKeyId.Len() == 0 && template.IsCA {
        if x509sha256skid() == "0" {
            // Go: x509sha256skid.IncNonDefault() — no goish counter.
            // SubjectKeyId generated using method 1 in RFC 5280,
            // Section 4.2.1.2:
            //   (1) The keyIdentifier is composed of the 160-bit SHA-1
            //   hash of the value of the BIT STRING subjectPublicKey
            //   (excluding the tag, length, and number of unused bits).
            let h = sha1::Sum(publicKeyBytes.clone());
            subjectKeyId = slice::__from_vec(h.to_vec());
        } else {
            // SubjectKeyId generated using method 1 in RFC 7093,
            // Section 2:
            //    1) The keyIdentifier is composed of the leftmost
            //    160-bits of the SHA-256 hash of the value of the BIT
            //    STRING subjectPublicKey (excluding the tag, length,
            //    and number of unused bits).
            let h = sha256::Sum256(publicKeyBytes.clone());
            subjectKeyId = slice::__from_vec(h[..20].to_vec());
        }
    }

    // Check that the signer's public key matches the private key, if
    // available.
    //
    // Go declares a local `privateKey interface{ Equal(crypto.PublicKey)
    // bool }` and asserts `key.Public().(privateKey)`. goish has no
    // runtime interface synthesis for a method set declared inline, and
    // the four supported key types all carry an inherent `Equal`; the
    // test is spelled over the concrete types instead.
    // `parent.PublicKey != nil` is `!parent.PublicKey.IsNil()`.
    let keyPub = key.Public();
    if !publicKeyEquals(&keyPub, &parent.PublicKey) {
        return (
            slice::new(),
            errors::New("x509: provided PrivateKey doesn't match parent's PublicKey"),
        );
    }

    let (extensions, err) = buildCertExtensions(
        template,
        crate::bytes::Equal(asn1Subject.clone(), emptyASN1Subject()),
        &authorityKeyId,
        &subjectKeyId,
    );
    if err != errors::nil {
        return (slice::new(), err);
    }

    let encodedPublicKey = asn1::BitString {
        BitLength: publicKeyBytes.Len() * 8,
        Bytes: publicKeyBytes.clone(),
    };
    let mut c = tbsCertificate {
        Version: 2,
        SerialNumber: serialNumber.clone(),
        SignatureAlgorithm: algorithmIdentifier.clone(),
        Issuer: asn1::RawValue {
            FullBytes: asn1Issuer.clone(),
            ..Default::default()
        },
        Validity: validity {
            NotBefore: template.NotBefore.clone().UTC(),
            NotAfter: template.NotAfter.clone().UTC(),
        },
        Subject: asn1::RawValue {
            FullBytes: asn1Subject.clone(),
            ..Default::default()
        },
        PublicKey: publicKeyInfo {
            Raw: asn1::RawContent::default(),
            Algorithm: publicKeyAlgorithm.clone(),
            PublicKey: encodedPublicKey,
        },
        Extensions: extensions,
        ..Default::default()
    };

    let (tbsCertContents, err) = asn1::Marshal(&c);
    if err != errors::nil {
        return (slice::new(), err);
    }
    c.Raw = asn1::RawContent(tbsCertContents.clone());

    let (signature, err) = signTBS(&tbsCertContents, key, signatureAlgorithm, rand);
    if err != errors::nil {
        return (slice::new(), err);
    }

    return asn1::Marshal(&certificate {
        TBSCertificate: c,
        SignatureAlgorithm: algorithmIdentifier,
        SignatureValue: asn1::BitString {
            Bytes: signature.clone(),
            BitLength: signature.Len() * 8,
        },
    });
}

// go: none — goish idiom: the concrete-type spelling of Go's inline
// `type privateKey interface { Equal(crypto.PublicKey) bool }`
// assertion at x509.go:1786-1792. Go's two failure modes collapse into
// one here: every key type goish's x509 accepts *has* an `Equal`, so the
// "does not implement Equal" branch is unreachable and only the mismatch
// branch survives. A nil `parent.PublicKey` skips the check, exactly as
// Go's `parent.PublicKey != nil` guard does.
fn publicKeyEquals(keyPub: &crypto::PublicKey, parentPub: &Any) -> bool {
    if *parentPub == crate::nil {
        return true;
    }
    if let Some(a) = keyPub.downcast_ref::<rsa::PublicKey>() {
        return match parentPub.As::<rsa::PublicKey>() {
            Some(b) => a.Equal(b),
            None => false,
        };
    }
    if let Some(a) = keyPub.downcast_ref::<ecdsa::PublicKey>() {
        return match parentPub.As::<ecdsa::PublicKey>() {
            Some(b) => a.Equal(b),
            None => false,
        };
    }
    if let Some(a) = keyPub.downcast_ref::<ed25519::PublicKey>() {
        return match parentPub.As::<ed25519::PublicKey>() {
            // `ed25519::PublicKey::Equal` takes the erased
            // `crypto::PublicKey` (Go's `Equal(x crypto.PublicKey)`),
            // where rsa's and ecdsa's take the concrete type; the
            // borrow is re-wrapped rather than the comparison
            // reimplemented.
            Some(b) => {
                let bPub: crypto::PublicKey = alloc::sync::Arc::new(b.clone());
                a.Equal(&bPub)
            }
            None => false,
        };
    }
    return false;
}

// go: none — goish idiom: Go's `var x509sha256skid = godebug.New("x509sha256skid")`.
// See `x509usepolicies` for why this is a function returning the unset
// value `""` — which makes `x509sha256skid.Value() == "0"` false and
// selects the RFC 7093 SHA-256 derivation, Go 1.22+'s default.
fn x509sha256skid() -> string {
    return string::from_static("");
}

impl Certificate {
    // go: sdk 1.25.5 crypto/x509/x509.go:1838-1891 Certificate.CreateCRL
    /// Return a DER encoded CRL, signed by this Certificate, that
    /// contains the given list of revoked certificates.
    ///
    /// Deprecated: this method does not generate an RFC 5280 conformant
    /// X.509 v2 CRL. To generate a standards compliant CRL, use
    /// [`CreateRevocationList`] instead.
    pub fn CreateCRL(
        &self,
        rand: &mut dyn io::Reader,
        priv_: &Any,
        revokedCerts: &slice<pkix::RevokedCertificate>,
        now: time::Time,
        expiry: time::Time,
    ) -> (slice<byte>, error) {
        // See `CreateCertificate` for why this is `Any::As` and not
        // `goish::cast!`.
        let key = match priv_.As::<dyn crypto::Signer + Send + Sync>() {
            Some(k) => k,
            None => {
                return (
                    slice::new(),
                    errors::New(
                        "x509: certificate private key does not implement crypto.Signer",
                    ),
                )
            }
        };

        let (signatureAlgorithm, algorithmIdentifier, err) =
            signingParamsForKey(key, SignatureAlgorithm(0));
        if err != errors::nil {
            return (slice::new(), err);
        }

        // Force revocation times to UTC per RFC 5280.
        let mut revokedCertsUTC: slice<pkix::RevokedCertificate> =
            crate::make!([]pkix::RevokedCertificate, revokedCerts.Len());
        for (i, rc) in crate::range!(revokedCerts.clone()) {
            let mut rc = rc.clone();
            rc.RevocationTime = rc.RevocationTime.clone().UTC();
            revokedCertsUTC[i] = rc;
        }

        let mut tbsCertList = pkix::TBSCertificateList {
            Version: 1,
            Signature: algorithmIdentifier.clone(),
            Issuer: self.Subject.ToRDNSequence(),
            ThisUpdate: now.UTC(),
            NextUpdate: expiry.UTC(),
            RevokedCertificates: revokedCertsUTC,
            ..Default::default()
        };

        // Authority Key Id
        if self.SubjectKeyId.Len() > 0 {
            let mut aki = pkix::Extension::default();
            aki.Id = oidExtensionAuthorityKeyId();
            let (v, err) = asn1::Marshal(&authKeyId {
                Id: self.SubjectKeyId.clone(),
            });
            if err != errors::nil {
                return (slice::new(), err);
            }
            aki.Value = v;
            tbsCertList.Extensions = crate::append!(tbsCertList.Extensions, aki);
        }

        let (tbsCertListContents, err) = asn1::Marshal(&tbsCertList);
        if err != errors::nil {
            return (slice::new(), err);
        }
        tbsCertList.Raw = asn1::RawContent(tbsCertListContents.clone());

        let (signature, err) = signTBS(&tbsCertListContents, key, signatureAlgorithm, rand);
        if err != errors::nil {
            return (slice::new(), err);
        }

        return asn1::Marshal(&pkix::CertificateList {
            TBSCertList: tbsCertList,
            SignatureAlgorithm: algorithmIdentifier,
            SignatureValue: asn1::BitString {
                Bytes: signature.clone(),
                BitLength: signature.Len() * 8,
            },
        });
    }
}

// Go: x509.go:1893-1934
/// A PKCS #10, certificate signature request.
#[derive(Clone, Default)]
pub struct CertificateRequest {
    /// Complete ASN.1 DER content (CSR, signature algorithm and signature).
    pub Raw: slice<byte>,
    /// Certificate request info part of raw ASN.1 DER content.
    pub RawTBSCertificateRequest: slice<byte>,
    /// DER encoded SubjectPublicKeyInfo.
    pub RawSubjectPublicKeyInfo: slice<byte>,
    /// DER encoded Subject.
    pub RawSubject: slice<byte>,

    pub Version: int,
    pub Signature: slice<byte>,
    pub SignatureAlgorithm: SignatureAlgorithm,

    pub PublicKeyAlgorithm: PublicKeyAlgorithm,
    pub PublicKey: Any,

    pub Subject: pkix::Name,

    /// The CSR attributes that can parse as
    /// `pkix::AttributeTypeAndValueSET`.
    ///
    /// Deprecated: Use Extensions and ExtraExtensions instead for
    /// parsing and generating the requestedExtensions attribute.
    pub Attributes: slice<pkix::AttributeTypeAndValueSET>,

    /// All requested extensions, in raw form. When parsing CSRs, this
    /// can be used to extract extensions that are not parsed by this
    /// package.
    pub Extensions: slice<pkix::Extension>,

    /// Extensions to be copied, raw, into any CSR marshaled by
    /// `CreateCertificateRequest`. Values override any extensions that
    /// would otherwise be produced based on the other fields but are
    /// overridden by any extensions specified in Attributes.
    ///
    /// The ExtraExtensions field is not populated by
    /// `ParseCertificateRequest`, see Extensions instead.
    pub ExtraExtensions: slice<pkix::Extension>,

    /// Subject Alternate Name value.
    pub DNSNames: slice<string>,
    /// Subject Alternate Name value.
    pub EmailAddresses: slice<string>,
    /// Subject Alternate Name value.
    pub IPAddresses: slice<net::IP>,
    /// Subject Alternate Name value.
    pub URIs: slice<url::URL>,
}

// These structures reflect the ASN.1 structure of X.509 certificate
// signature requests (see RFC 2986):

// Go: x509.go:1939-1945
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct tbsCertificateRequest {
    pub Raw: asn1::RawContent,
    pub Version: int,
    pub Subject: asn1::RawValue,
    pub PublicKey: publicKeyInfo,
    #[tag(r#"asn1:"tag:0""#)]
    pub RawAttributes: slice<asn1::RawValue>,
}

// Go: x509.go:1947-1952
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct certificateRequest {
    pub Raw: asn1::RawContent,
    pub TBSCSR: tbsCertificateRequest,
    pub SignatureAlgorithm: pkix::AlgorithmIdentifier,
    pub SignatureValue: asn1::BitString,
}

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go: x509.go:1956 — `var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}`.
/// A PKCS #9 OBJECT IDENTIFIER that indicates requested extensions in a
/// CSR.
pub(super) fn oidExtensionRequest() -> asn1::ObjectIdentifier {
    return oid(&[1, 2, 840, 113549, 1, 9, 14]);
}

// Go: x509.go:2262-2300
/// An entry in the revokedCertificates sequence of a CRL.
#[derive(Clone, Default)]
pub struct RevocationListEntry {
    /// The raw bytes of the revokedCertificates entry. It is set when
    /// parsing a CRL; it is ignored when generating a CRL.
    pub Raw: slice<byte>,

    /// The serial number of a revoked certificate. It is both used when
    /// creating a CRL and populated when parsing a CRL. It must not be
    /// nil.
    pub SerialNumber: big::Int,
    /// The time at which the certificate was revoked. It is both used
    /// when creating a CRL and populated when parsing a CRL. It must not
    /// be the zero time.
    pub RevocationTime: time::Time,
    /// The reason for revocation, using the integer enum values
    /// specified in RFC 5280 Section 5.3.1. When creating a CRL, the
    /// zero value will result in the reasonCode extension being omitted.
    /// When parsing a CRL, the zero value may represent either the
    /// reasonCode extension being absent (which implies the default
    /// revocation reason of 0/Unspecified), or it may represent the
    /// reasonCode extension being present and explicitly containing a
    /// value of 0/Unspecified.
    pub ReasonCode: int,

    /// Raw X.509 extensions. When parsing CRL entries, this can be used
    /// to extract non-critical extensions that are not parsed by this
    /// package. When marshaling CRL entries, the Extensions field is
    /// ignored, see ExtraExtensions.
    pub Extensions: slice<pkix::Extension>,
    /// Extensions to be copied, raw, into any marshaled CRL entries.
    /// Values override any extensions that would otherwise be produced
    /// based on the other fields. The ExtraExtensions field is not
    /// populated when parsing CRL entries, see Extensions.
    pub ExtraExtensions: slice<pkix::Extension>,
}

// Go: x509.go:2302-2361
/// A [`Certificate`] Revocation List (CRL) as specified by RFC 5280.
#[derive(Clone, Default)]
pub struct RevocationList {
    /// The complete ASN.1 DER content of the CRL (tbsCertList,
    /// signatureAlgorithm, and signatureValue).
    pub Raw: slice<byte>,
    /// Just the tbsCertList portion of the ASN.1 DER.
    pub RawTBSRevocationList: slice<byte>,
    /// The DER encoded Issuer.
    pub RawIssuer: slice<byte>,

    /// The DN of the issuing certificate.
    pub Issuer: pkix::Name,
    /// Used to identify the public key associated with the issuing
    /// certificate. It is populated from the authorityKeyIdentifier
    /// extension when parsing a CRL. It is ignored when creating a CRL;
    /// the extension is populated from the issuing certificate itself.
    pub AuthorityKeyId: slice<byte>,

    pub Signature: slice<byte>,
    /// Used to determine the signature algorithm to be used when signing
    /// the CRL. If 0 the default algorithm for the signing key will be
    /// used.
    pub SignatureAlgorithm: SignatureAlgorithm,

    /// The revokedCertificates sequence in the CRL. It is used when
    /// creating a CRL and also populated when parsing a CRL. When
    /// creating a CRL, it may be empty, in which case the
    /// revokedCertificates ASN.1 sequence will be omitted from the CRL
    /// entirely.
    pub RevokedCertificateEntries: slice<RevocationListEntry>,

    /// Used to populate the revokedCertificates sequence in the CRL if
    /// RevokedCertificateEntries is empty. It may be empty, in which
    /// case an empty CRL will be created.
    ///
    /// Deprecated: Use RevokedCertificateEntries instead.
    pub RevokedCertificates: slice<pkix::RevokedCertificate>,

    /// Used to populate the X.509 v2 cRLNumber extension in the CRL,
    /// which should be a monotonically increasing sequence number for a
    /// given CRL scope and CRL issuer. It is also populated from the
    /// cRLNumber extension when parsing a CRL.
    pub Number: big::Int,

    /// Used to populate the thisUpdate field in the CRL, which indicates
    /// the issuance date of the CRL.
    pub ThisUpdate: time::Time,
    /// Used to populate the nextUpdate field in the CRL, which indicates
    /// the date by which the next CRL will be issued. NextUpdate must be
    /// greater than ThisUpdate.
    pub NextUpdate: time::Time,

    /// Raw X.509 extensions. When creating a CRL, the Extensions field
    /// is ignored, see ExtraExtensions.
    pub Extensions: slice<pkix::Extension>,

    /// Any additional extensions to add directly to the CRL.
    pub ExtraExtensions: slice<pkix::Extension>,
}

// These structures reflect the ASN.1 structure of X.509 CRLs better than
// the existing crypto/x509/pkix variants do. These mirror the existing
// certificate structs in this file.
//
// Notably, we include issuer as an asn1.RawValue, mirroring the behavior
// of tbsCertificate and allowing raw (unparsed) subjects to be passed
// cleanly.

// Go: x509.go:2370-2374
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct certificateList {
    pub TBSCertList: tbsCertificateList,
    pub SignatureAlgorithm: pkix::AlgorithmIdentifier,
    pub SignatureValue: asn1::BitString,
}

// Go: x509.go:2376-2385
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct tbsCertificateList {
    pub Raw: asn1::RawContent,
    #[tag(r#"asn1:"optional,default:0""#)]
    pub Version: int,
    pub Signature: pkix::AlgorithmIdentifier,
    pub Issuer: asn1::RawValue,
    pub ThisUpdate: time::Time,
    #[tag(r#"asn1:"optional""#)]
    pub NextUpdate: time::Time,
    #[tag(r#"asn1:"optional""#)]
    pub RevokedCertificates: slice<pkix::RevokedCertificate>,
    #[tag(r#"asn1:"tag:0,optional,explicit""#)]
    pub Extensions: slice<pkix::Extension>,
}

// go: sdk 1.25.5 crypto/x509/x509.go:2400-2546 CreateRevocationList
/// Create a new X.509 v2 [`Certificate`] Revocation List, according to
/// RFC 5280, based on `template`.
///
/// The CRL is signed by `priv_`, which should be a `crypto::Signer`
/// associated with the public key in the issuer certificate.
///
/// The crlSign bit must be set in [`KeyUsage`] on `issuer` in order to
/// use it as a CRL issuer.
///
/// The issuer distinguished name CRL field and authority key identifier
/// extension are populated using the issuer certificate. `issuer` must
/// have SubjectKeyId set.
pub fn CreateRevocationList(
    rand: &mut dyn io::Reader,
    template: &RevocationList,
    issuer: &Certificate,
    priv_: &(dyn crypto::Signer + Send + Sync + 'static),
) -> (slice<byte>, error) {
    // Go: if template == nil { … } / if issuer == nil { … }
    //
    // goish takes both by reference rather than by nilable pointer, so
    // the two nil checks are unrepresentable — a caller cannot pass one.
    // The remaining validation is verbatim.
    if (issuer.KeyUsage & KeyUsageCRLSign) == KeyUsage(0) {
        return (
            slice::new(),
            errors::New("x509: issuer must have the crlSign key usage bit set"),
        );
    }
    if issuer.SubjectKeyId.Len() == 0 {
        return (
            slice::new(),
            errors::New(
                "x509: issuer certificate doesn't contain a subject key identifier",
            ),
        );
    }
    if template
        .NextUpdate
        .clone()
        .Before(template.ThisUpdate.clone())
    {
        return (
            slice::new(),
            errors::New("x509: template.ThisUpdate is after template.NextUpdate"),
        );
    }
    if template.Number == crate::nil {
        return (
            slice::new(),
            errors::New("x509: template contains nil Number field"),
        );
    }

    let (signatureAlgorithm, algorithmIdentifier, err) =
        signingParamsForKey(priv_, template.SignatureAlgorithm);
    if err != errors::nil {
        return (slice::new(), err);
    }

    let mut revokedCerts: slice<pkix::RevokedCertificate>;
    // Only process the deprecated RevokedCertificates field if it is
    // populated and the new RevokedCertificateEntries field is not
    // populated.
    if template.RevokedCertificates.Len() > 0 && template.RevokedCertificateEntries.Len() == 0
    {
        // Force revocation times to UTC per RFC 5280.
        revokedCerts = crate::make!(
            []pkix::RevokedCertificate,
            template.RevokedCertificates.Len()
        );
        for (i, rc) in crate::range!(template.RevokedCertificates.clone()) {
            let mut rc = rc.clone();
            rc.RevocationTime = rc.RevocationTime.clone().UTC();
            revokedCerts[i] = rc;
        }
    } else {
        // Convert the ReasonCode field to a proper extension, and force
        // revocation times to UTC per RFC 5280.
        revokedCerts = crate::make!(
            []pkix::RevokedCertificate,
            template.RevokedCertificateEntries.Len()
        );
        for (i, rce) in crate::range!(template.RevokedCertificateEntries.clone()) {
            if rce.SerialNumber == crate::nil {
                return (
                    slice::new(),
                    errors::New("x509: template contains entry with nil SerialNumber field"),
                );
            }
            if rce.RevocationTime.clone().IsZero() {
                return (
                    slice::new(),
                    errors::New(
                        "x509: template contains entry with zero RevocationTime field",
                    ),
                );
            }

            let mut rc = pkix::RevokedCertificate {
                SerialNumber: rce.SerialNumber.clone(),
                RevocationTime: rce.RevocationTime.clone().UTC(),
                ..Default::default()
            };

            // Copy over any extra extensions, except for a Reason Code
            // extension, because we'll synthesize that ourselves to
            // ensure it is correct.
            let mut exts: slice<pkix::Extension> =
                crate::make!([]pkix::Extension, 0, rce.ExtraExtensions.Len());
            for (_, ext) in crate::range!(rce.ExtraExtensions.clone()) {
                if ext.Id.Equal(&oidExtensionReasonCode()) {
                    return (
                        slice::new(),
                        errors::New(
                            "x509: template contains entry with ReasonCode ExtraExtension; use ReasonCode field instead",
                        ),
                    );
                }
                exts = crate::append!(exts, ext.clone());
            }

            // Only add a reasonCode extension if the reason is non-zero,
            // as per RFC 5280 Section 5.3.1.
            if rce.ReasonCode != 0 {
                let (reasonBytes, err) = asn1::Marshal(&asn1::Enumerated(rce.ReasonCode));
                if err != errors::nil {
                    return (slice::new(), err);
                }

                exts = crate::append!(
                    exts,
                    pkix::Extension {
                        Id: oidExtensionReasonCode(),
                        Value: reasonBytes,
                        ..Default::default()
                    }
                );
            }

            if exts.Len() > 0 {
                rc.Extensions = exts;
            }
            revokedCerts[i] = rc;
        }
    }

    let (aki, err) = asn1::Marshal(&authKeyId {
        Id: issuer.SubjectKeyId.clone(),
    });
    if err != errors::nil {
        return (slice::new(), err);
    }

    let numBytes = template.Number.Bytes();
    if numBytes.Len() > 20 || (numBytes.Len() == 20 && numBytes[0] & 0x80 != 0) {
        return (
            slice::new(),
            errors::New("x509: CRL number exceeds 20 octets"),
        );
    }
    let (crlNum, err) = asn1::Marshal(&template.Number);
    if err != errors::nil {
        return (slice::new(), err);
    }

    // Correctly use the issuer's subject sequence if one is specified.
    let (issuerSubject, err) = subjectBytes(issuer);
    if err != errors::nil {
        return (slice::new(), err);
    }

    let mut tbsCertList = tbsCertificateList {
        // v2
        Version: 1,
        Signature: algorithmIdentifier.clone(),
        Issuer: asn1::RawValue {
            FullBytes: issuerSubject,
            ..Default::default()
        },
        ThisUpdate: template.ThisUpdate.clone().UTC(),
        NextUpdate: template.NextUpdate.clone().UTC(),
        Extensions: slice::__from_vec(alloc::vec![
            pkix::Extension {
                Id: oidExtensionAuthorityKeyId(),
                Value: aki,
                ..Default::default()
            },
            pkix::Extension {
                Id: oidExtensionCRLNumber(),
                Value: crlNum,
                ..Default::default()
            },
        ]),
        ..Default::default()
    };
    if revokedCerts.Len() > 0 {
        tbsCertList.RevokedCertificates = revokedCerts;
    }

    if template.ExtraExtensions.Len() > 0 {
        tbsCertList.Extensions = crate::append!(
            tbsCertList.Extensions,
            template.ExtraExtensions.clone()...
        );
    }

    let (tbsCertListContents, err) = asn1::Marshal(&tbsCertList);
    if err != errors::nil {
        return (slice::new(), err);
    }

    // Optimization to only marshal this struct once, when signing and
    // then embedding in certificateList below.
    tbsCertList.Raw = asn1::RawContent(tbsCertListContents.clone());

    let (signature, err) = signTBS(&tbsCertListContents, priv_, signatureAlgorithm, rand);
    if err != errors::nil {
        return (slice::new(), err);
    }

    return asn1::Marshal(&certificateList {
        TBSCertList: tbsCertList,
        SignatureAlgorithm: algorithmIdentifier,
        SignatureValue: asn1::BitString {
            Bytes: signature.clone(),
            BitLength: signature.Len() * 8,
        },
    });
}

// go: none — goish idiom: `KeyUsage` is documented (x509.go:581-583) as
// "a bitmap of the KeyUsage* constants", and every Go caller writes
// `KeyUsageCertSign | KeyUsageCRLSign` and `ku & KeyUsageCRLSign != 0`.
// Go gets both for free because `type KeyUsage int` inherits int's
// operators; a Rust newtype inherits nothing, so the four the bitmap
// contract implies are spelled out. Without them the public API cannot
// express its own documented usage — `CreateRevocationList`'s own
// crlSign test had to reach through the tuple field.
impl core::ops::BitOr for KeyUsage {
    type Output = KeyUsage;
    // go: none — goish idiom (operator impl; see the note above)
    fn bitor(self, rhs: KeyUsage) -> KeyUsage {
        return KeyUsage(self.0 | rhs.0);
    }
}

// go: none — goish idiom: see `BitOr` above.
impl core::ops::BitAnd for KeyUsage {
    type Output = KeyUsage;
    // go: none — goish idiom (operator impl; see the note above)
    fn bitand(self, rhs: KeyUsage) -> KeyUsage {
        return KeyUsage(self.0 & rhs.0);
    }
}

// go: none — goish idiom: see `BitOr` above.
impl core::ops::BitOrAssign for KeyUsage {
    // go: none — goish idiom (operator impl; see the note above)
    fn bitor_assign(&mut self, rhs: KeyUsage) {
        self.0 |= rhs.0;
    }
}

// go: none — goish idiom: see `BitOr` above.
impl core::ops::BitAndAssign for KeyUsage {
    // go: none — goish idiom (operator impl; see the note above)
    fn bitand_assign(&mut self, rhs: KeyUsage) {
        self.0 &= rhs.0;
    }
}

// go: sdk 1.25.5 crypto/x509/x509.go:1960-1975 newRawAttributes
/// Convert AttributeTypeAndValueSETs from a template
/// [`CertificateRequest`]'s Attributes into `tbsCertificateRequest`
/// RawAttributes.
pub(super) fn newRawAttributes(
    attributes: &slice<pkix::AttributeTypeAndValueSET>,
) -> (slice<asn1::RawValue>, error) {
    let mut rawAttributes: slice<asn1::RawValue> = slice::new();
    let (b, err) = asn1::Marshal(attributes);
    if err != errors::nil {
        return (slice::new(), err);
    }
    let (rest, err) = asn1::Unmarshal(b, &mut rawAttributes);
    if err != errors::nil {
        return (slice::new(), err);
    }
    if rest.Len() != 0 {
        return (
            slice::new(),
            errors::New("x509: failed to unmarshal raw CSR Attributes"),
        );
    }
    return (rawAttributes, errors::nil);
}

// Go: x509.go:2141-2144 — the *anonymous* struct
// `struct { Type asn1.ObjectIdentifier; Value [][]pkix.Extension
// `asn1:"set"` }` that `CreateCertificateRequest` marshals as the
// extensionRequest attribute.
//
// go: none — goish idiom: Rust has no anonymous struct type, so the
// shape gets a name. Same deviation, and the same reason, as
// `signatureAlgorithmDetail` earlier in this file.
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
pub(super) struct extensionRequestAttribute {
    pub Type: asn1::ObjectIdentifier,
    #[tag(r#"asn1:"set""#)]
    pub Value: slice<slice<pkix::Extension>>,
}

// go: sdk 1.25.5 crypto/x509/x509.go:2035-2193 CreateCertificateRequest
/// Create a new certificate request based on a template. The following
/// members of `template` are used:
///
///   - SignatureAlgorithm
///   - Subject
///   - DNSNames
///   - EmailAddresses
///   - IPAddresses
///   - URIs
///   - ExtraExtensions
///   - Attributes (deprecated)
///
/// `priv_` is the private key to sign the CSR with, and the
/// corresponding public key will be included in the CSR. It must
/// implement `crypto::Signer` and its `Public()` method must return an
/// `rsa::PublicKey`, an `ecdsa::PublicKey` or an `ed25519::PublicKey`.
///
/// The returned slice is the certificate request in DER encoding.
pub fn CreateCertificateRequest(
    rand: &mut dyn io::Reader,
    template: &CertificateRequest,
    priv_: &Any,
) -> (slice<byte>, error) {
    // See `CreateCertificate` for why this is `Any::As` and not
    // `goish::cast!`.
    let key = match priv_.As::<dyn crypto::Signer + Send + Sync>() {
        Some(k) => k,
        None => {
            return (
                slice::new(),
                errors::New(
                    "x509: certificate private key does not implement crypto.Signer",
                ),
            )
        }
    };

    let (signatureAlgorithm, algorithmIdentifier, err) =
        signingParamsForKey(key, template.SignatureAlgorithm);
    if err != errors::nil {
        return (slice::new(), err);
    }

    let publicKeyBytes: slice<byte>;
    let publicKeyAlgorithm: pkix::AlgorithmIdentifier;
    // Go passes `key.Public()` — a `crypto.PublicKey`, which *is* `any` —
    // straight into `marshalPublicKey(pub any)`. goish's two erasure
    // carriers do not convert without naming the type; see
    // `anyFromPublicKey`.
    let (pubAny, err) = anyFromPublicKey(&key.Public());
    if err != errors::nil {
        return (slice::new(), err);
    }
    let (b, ai, err) = marshalPublicKey(&pubAny);
    if err != errors::nil {
        return (slice::new(), err);
    }
    publicKeyBytes = b;
    publicKeyAlgorithm = ai;

    let (extensions, err) = buildCSRExtensions(template);
    if err != errors::nil {
        return (slice::new(), err);
    }

    // Make a copy of template.Attributes because we may alter it below.
    let mut attributes: slice<pkix::AttributeTypeAndValueSET> =
        crate::make!([]pkix::AttributeTypeAndValueSET, 0, template.Attributes.Len());
    for (_, attr) in crate::range!(template.Attributes.clone()) {
        let mut values: slice<slice<pkix::AttributeTypeAndValue>> =
            crate::make!([]slice<pkix::AttributeTypeAndValue>, attr.Value.Len());
        // Go: copy(values, attr.Value)
        for (i, v) in crate::range!(attr.Value.clone()) {
            values[i] = v.clone();
        }
        attributes = crate::append!(
            attributes,
            pkix::AttributeTypeAndValueSET {
                Type: attr.Type.clone(),
                Value: values,
            }
        );
    }

    let mut extensionsAppended = false;
    if extensions.Len() > 0 {
        // Append the extensions to an existing attribute if possible.
        //
        // Go writes `for _, atvSet := range attributes` and then mutates
        // `atvSet.Value[0]`. That reaches the original because `atvSet`
        // is a copy of the struct but `Value` is a slice *header* over
        // shared backing. goish's `slice<T>` clones its backing
        // (goslice.rs:88 and the `Clone` derive), so the same spelling
        // would write to a discarded copy. The index the range already
        // yields is used to write back into `attributes`.
        for (idx, atvSet) in crate::range!(attributes.clone()) {
            if !atvSet.Type.Equal(&oidExtensionRequest()) || atvSet.Value.Len() == 0 {
                continue;
            }

            // specifiedExtensions contains all the extensions that we
            // found specified via template.Attributes.
            let mut specifiedExtensions = crate::make!(map[string]bool);

            for (_, atvs) in crate::range!(atvSet.Value.clone()) {
                for (_, atv) in crate::range!(atvs.clone()) {
                    specifiedExtensions.Set(atv.Type.String(), true);
                }
            }

            let mut newValue: slice<pkix::AttributeTypeAndValue> = crate::make!(
                []pkix::AttributeTypeAndValue,
                0,
                atvSet.Value[0].Len() + extensions.Len()
            );
            newValue = crate::append!(newValue, atvSet.Value[0].clone()...);

            for (_, e) in crate::range!(extensions.clone()) {
                let (seen, _) = specifiedExtensions.Get(e.Id.String());
                if seen {
                    // Attributes already contained a value for
                    // this extension and it takes priority.
                    continue;
                }

                newValue = crate::append!(
                    newValue,
                    pkix::AttributeTypeAndValue {
                        // There is no place for the critical
                        // flag in an AttributeTypeAndValue.
                        Type: e.Id.clone(),
                        Value: Any::new(e.Value.clone()),
                    }
                );
            }

            attributes[idx].Value[0] = newValue;
            extensionsAppended = true;
            break;
        }
    }

    let (mut rawAttributes, err) = newRawAttributes(&attributes);
    if err != errors::nil {
        return (slice::new(), err);
    }

    // If not included in attributes, add a new attribute for the
    // extensions.
    if extensions.Len() > 0 && !extensionsAppended {
        let attr = extensionRequestAttribute {
            Type: oidExtensionRequest(),
            Value: slice::__from_vec(alloc::vec![extensions.clone()]),
        };

        let (b, err) = asn1::Marshal(&attr);
        if err != errors::nil {
            return (
                slice::new(),
                errors::New(
                    string::from("x509: failed to serialise extensions attribute: ")
                        + err.Error(),
                ),
            );
        }

        let mut rawValue = asn1::RawValue::default();
        let (_, err) = asn1::Unmarshal(b, &mut rawValue);
        if err != errors::nil {
            return (slice::new(), err);
        }

        rawAttributes = crate::append!(rawAttributes, rawValue);
    }

    let mut asn1Subject = template.RawSubject.clone();
    if asn1Subject.Len() == 0 {
        let (b, err) = asn1::Marshal(&template.Subject.ToRDNSequence());
        if err != errors::nil {
            return (slice::new(), err);
        }
        asn1Subject = b;
    }

    let mut tbsCSR = tbsCertificateRequest {
        // PKCS #10, RFC 2986
        Version: 0,
        Subject: asn1::RawValue {
            FullBytes: asn1Subject,
            ..Default::default()
        },
        PublicKey: publicKeyInfo {
            Raw: asn1::RawContent::default(),
            Algorithm: publicKeyAlgorithm,
            PublicKey: asn1::BitString {
                Bytes: publicKeyBytes.clone(),
                BitLength: publicKeyBytes.Len() * 8,
            },
        },
        RawAttributes: rawAttributes,
        ..Default::default()
    };

    let (tbsCSRContents, err) = asn1::Marshal(&tbsCSR);
    if err != errors::nil {
        return (slice::new(), err);
    }
    tbsCSR.Raw = asn1::RawContent(tbsCSRContents.clone());

    let (signature, err) = signTBS(&tbsCSRContents, key, signatureAlgorithm, rand);
    if err != errors::nil {
        return (slice::new(), err);
    }

    return asn1::Marshal(&certificateRequest {
        TBSCSR: tbsCSR,
        SignatureAlgorithm: algorithmIdentifier,
        SignatureValue: asn1::BitString {
            Bytes: signature.clone(),
            BitLength: signature.Len() * 8,
        },
        ..Default::default()
    });
}

// Go x509.go:1804-1805
//   var pemCRLPrefix = []byte("-----BEGIN X509 CRL")
//   var pemType = "X509 CRL"
/// The PEM armour [`ParseCRL`] sniffs for before falling back to DER.
const pemCRLPrefix: &[byte] = b"-----BEGIN X509 CRL";
/// The PEM block type [`ParseCRL`] accepts.
const pemType: &str = "X509 CRL";

// go: sdk 1.25.5 crypto/x509/x509.go:1810-1818 ParseCRL
/// Parse a CRL from the given bytes, handling PEM transparently as long
/// as there is no leading garbage.
///
/// Deprecated: use [`ParseRevocationList`] instead.
pub fn ParseCRL(crlBytes: slice<byte>) -> (Option<pkix::CertificateList>, error) {
    // Go: if bytes.HasPrefix(crlBytes, pemCRLPrefix) {
    //         block, _ := pem.Decode(crlBytes)
    //         if block != nil && block.Type == pemType { crlBytes = block.Bytes }
    //     }
    let mut der = crlBytes.clone();
    if crate::bytes::HasPrefix(crlBytes.clone(), slice::__from_vec(pemCRLPrefix.to_vec())) {
        let (block, _) = crate::encoding::pem::Decode(crlBytes);
        if let Some(b) = block {
            if b.Type == pemType {
                der = b.Bytes;
            }
        }
    }
    // Go: return ParseDERCRL(crlBytes)
    return ParseDERCRL(der);
}

// go: sdk 1.25.5 crypto/x509/x509.go:1823-1831 ParseDERCRL
/// Parse a DER encoded CRL from the given bytes.
///
/// Deprecated: use [`ParseRevocationList`] instead.
pub fn ParseDERCRL(derBytes: slice<byte>) -> (Option<pkix::CertificateList>, error) {
    // Go: certList := new(pkix.CertificateList)
    let mut certList = pkix::CertificateList::default();
    // Go: if rest, err := asn1.Unmarshal(derBytes, certList); err != nil { … }
    let (rest, err) = asn1::Unmarshal(derBytes, &mut certList);
    if err != errors::nil {
        return (None, err);
    }
    // Go: } else if len(rest) != 0 { return nil, errors.New(…) }
    if rest.Len() != 0 {
        return (None, errors::New("x509: trailing data after CRL"));
    }
    // Go: return certList, nil
    return (Some(certList), errors::nil);
}

// go: none — goish-only: the write halves for the two CSR shapes.
// `reflect_only` emits only the read half; `asn1::Unmarshal` needs this
// direction. Same split as `pkix::AlgorithmIdentifier`.
impl crate::reflect::FromReflectValue for tbsCertificateRequest {
    // go: none — goish-only: see the banner above.
    fn from_reflect_value(v: crate::reflect::Value) -> (Self, error) {
        if v.Kind() != crate::reflect::Kind::Struct {
            return (
                tbsCertificateRequest::default(),
                errors::New("x509: expected tbsCertificateRequest"),
            );
        }
        let mut out = tbsCertificateRequest::default();
        let (raw, err) =
            <asn1::RawContent as crate::reflect::FromReflectValue>::from_reflect_value(v.Field(0));
        if err != errors::nil {
            return (tbsCertificateRequest::default(), err);
        }
        out.Raw = raw;
        let (ver, err) = <int as crate::reflect::FromReflectValue>::from_reflect_value(v.Field(1));
        if err != errors::nil {
            return (tbsCertificateRequest::default(), err);
        }
        out.Version = ver;
        let (subj, err) =
            <asn1::RawValue as crate::reflect::FromReflectValue>::from_reflect_value(v.Field(2));
        if err != errors::nil {
            return (tbsCertificateRequest::default(), err);
        }
        out.Subject = subj;
        let (pk, err) =
            <publicKeyInfo as crate::reflect::FromReflectValue>::from_reflect_value(v.Field(3));
        if err != errors::nil {
            return (tbsCertificateRequest::default(), err);
        }
        out.PublicKey = pk;
        let (attrs, err) =
            <slice<asn1::RawValue> as crate::reflect::FromReflectValue>::from_reflect_value(
                v.Field(4),
            );
        if err != errors::nil {
            return (tbsCertificateRequest::default(), err);
        }
        out.RawAttributes = attrs;
        return (out, errors::nil);
    }
}

// go: none — goish-only: see `tbsCertificateRequest`'s write half above.
impl crate::reflect::FromReflectValue for certificateRequest {
    // go: none — goish-only: see `tbsCertificateRequest`'s write half.
    fn from_reflect_value(v: crate::reflect::Value) -> (Self, error) {
        if v.Kind() != crate::reflect::Kind::Struct {
            return (
                certificateRequest::default(),
                errors::New("x509: expected certificateRequest"),
            );
        }
        let mut out = certificateRequest::default();
        let (raw, err) =
            <asn1::RawContent as crate::reflect::FromReflectValue>::from_reflect_value(v.Field(0));
        if err != errors::nil {
            return (certificateRequest::default(), err);
        }
        out.Raw = raw;
        let (tbs, err) =
            <tbsCertificateRequest as crate::reflect::FromReflectValue>::from_reflect_value(
                v.Field(1),
            );
        if err != errors::nil {
            return (certificateRequest::default(), err);
        }
        out.TBSCSR = tbs;
        let (sa, err) =
            <pkix::AlgorithmIdentifier as crate::reflect::FromReflectValue>::from_reflect_value(
                v.Field(2),
            );
        if err != errors::nil {
            return (certificateRequest::default(), err);
        }
        out.SignatureAlgorithm = sa;
        let (sv, err) =
            <asn1::BitString as crate::reflect::FromReflectValue>::from_reflect_value(v.Field(3));
        if err != errors::nil {
            return (certificateRequest::default(), err);
        }
        out.SignatureValue = sv;
        return (out, errors::nil);
    }
}

// go: sdk 1.25.5 crypto/x509/x509.go:1979-1991 parseRawAttributes
/// Parse `RawAttributes` into `AttributeTypeAndValueSET`s, silently
/// dropping any attribute that does not fit that shape (Go's comment:
/// "i.e.: challengePassword or unstructuredName").
fn parseRawAttributes(rawAttributes: slice<asn1::RawValue>) -> slice<pkix::AttributeTypeAndValueSET> {
    // Go: var attributes []pkix.AttributeTypeAndValueSET
    let mut attributes: Vec<pkix::AttributeTypeAndValueSET> = Vec::new();
    // Go: for _, rawAttr := range rawAttributes {
    for (_, rawAttr) in crate::range!(rawAttributes) {
        // Go: var attr pkix.AttributeTypeAndValueSET
        //     rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr)
        let mut attr = pkix::AttributeTypeAndValueSET::default();
        let (rest, err) = asn1::Unmarshal(rawAttr.FullBytes.clone(), &mut attr);
        // Go: if err == nil && len(rest) == 0 { attributes = append(…) }
        if err == errors::nil && rest.Len() == 0 {
            attributes.push(attr);
        }
    }
    // Go: return attributes
    return slice::__from_vec(attributes);
}

// Go x509.go:1996-1999 — the local type `parseCSRExtensions` declares:
//   type pkcs10Attribute struct {
//       Id     asn1.ObjectIdentifier
//       Values []asn1.RawValue `asn1:"set"`
//   }
//
// go: none — goish-only: Rust cannot declare a type with a derive
// attribute inside a function body and use it generically, so Go's
// function-local struct is hoisted to module scope under its own name.
#[goish::reflect(reflect_only)]
#[derive(Clone, Default)]
struct pkcs10Attribute {
    pub Id: asn1::ObjectIdentifier,
    #[tag(r#"asn1:"set""#)]
    pub Values: slice<asn1::RawValue>,
}

// go: none — goish-only: the write half of `pkcs10Attribute`.
impl crate::reflect::FromReflectValue for pkcs10Attribute {
    // go: none — goish-only: the write half of `pkcs10Attribute`.
    fn from_reflect_value(v: crate::reflect::Value) -> (Self, error) {
        if v.Kind() != crate::reflect::Kind::Struct {
            return (
                pkcs10Attribute::default(),
                errors::New("x509: expected pkcs10Attribute"),
            );
        }
        let (id, err) =
            <asn1::ObjectIdentifier as crate::reflect::FromReflectValue>::from_reflect_value(
                v.Field(0),
            );
        if err != errors::nil {
            return (pkcs10Attribute::default(), err);
        }
        let (values, err) =
            <slice<asn1::RawValue> as crate::reflect::FromReflectValue>::from_reflect_value(
                v.Field(1),
            );
        if err != errors::nil {
            return (pkcs10Attribute::default(), err);
        }
        return (
            pkcs10Attribute {
                Id: id,
                Values: values,
            },
            errors::nil,
        );
    }
}

// go: sdk 1.25.5 crypto/x509/x509.go:1995-2035 parseCSRExtensions
/// Parse the attributes from a CSR and extract any requested extensions.
fn parseCSRExtensions(
    rawAttributes: slice<asn1::RawValue>,
) -> (slice<pkix::Extension>, error) {
    // Go: var ret []pkix.Extension
    //     requestedExts := make(map[string]bool)
    let mut ret: Vec<pkix::Extension> = Vec::new();
    let mut requestedExts: crate::gomap::map<crate::gostring::string, bool> = crate::make!(map[crate::gostring::string]bool);
    // Go: for _, rawAttr := range rawAttributes {
    for (_, rawAttr) in crate::range!(rawAttributes) {
        // Go: var attr pkcs10Attribute
        //     if rest, err := asn1.Unmarshal(rawAttr.FullBytes, &attr);
        //        err != nil || len(rest) != 0 || len(attr.Values) == 0 { continue }
        let mut attr = pkcs10Attribute::default();
        let (rest, err) = asn1::Unmarshal(rawAttr.FullBytes.clone(), &mut attr);
        if err != errors::nil || rest.Len() != 0 || attr.Values.Len() == 0 {
            continue;
        }
        // Go: if !attr.Id.Equal(oidExtensionRequest) { continue }
        if !attr.Id.Equal(&oidExtensionRequest()) {
            continue;
        }
        // Go: var extensions []pkix.Extension
        //     if _, err := asn1.Unmarshal(attr.Values[0].FullBytes, &extensions); err != nil { … }
        let mut extensions: slice<pkix::Extension> = slice::__from_vec(Vec::new());
        let (_, err) = asn1::Unmarshal(attr.Values[0].FullBytes.clone(), &mut extensions);
        if err != errors::nil {
            return (slice::__from_vec(Vec::new()), err);
        }
        // Go: for _, ext := range extensions { … duplicate check … }
        for (_, ext) in crate::range!(extensions) {
            let oidStr = ext.Id.String();
            // Go: `requestedExts[oidStr]` — absent reads as false.
            let (seen, _) = requestedExts.Get(&oidStr);
            if seen {
                return (
                    slice::__from_vec(Vec::new()),
                    errors::New("x509: certificate request contains duplicate requested extensions"),
                );
            }
            requestedExts.Set(oidStr, true);
        }
        // Go: ret = append(ret, extensions...)
        for (_, ext) in crate::range!(extensions) {
            ret.push(ext.clone());
        }
    }
    // Go: return ret, nil
    return (slice::__from_vec(ret), errors::nil);
}

// go: sdk 1.25.5 crypto/x509/x509.go:2197-2207 ParseCertificateRequest
/// Parse a single certificate request from the given ASN.1 DER data.
pub fn ParseCertificateRequest(asn1Data: slice<byte>) -> (Option<CertificateRequest>, error) {
    // Go: var csr certificateRequest
    //     rest, err := asn1.Unmarshal(asn1Data, &csr)
    let mut csr = certificateRequest::default();
    let (rest, err) = asn1::Unmarshal(asn1Data, &mut csr);
    if err != errors::nil {
        return (None, err);
    }
    // Go: } else if len(rest) != 0 { return nil, asn1.SyntaxError{Msg: "trailing data"} }
    if rest.Len() != 0 {
        return (
            None,
            errors::Wrap(asn1::SyntaxError {
                Msg: string::from_static("trailing data"),
            }),
        );
    }
    // Go: return parseCertificateRequest(&csr)
    return parseCertificateRequest(&csr);
}

// go: sdk 1.25.5 crypto/x509/x509.go:2210-2258 parseCertificateRequest
/// Build the public [`CertificateRequest`] from the parsed ASN.1 shape.
fn parseCertificateRequest(in_: &certificateRequest) -> (Option<CertificateRequest>, error) {
    // Go: out := &CertificateRequest{ … }
    let mut out = CertificateRequest {
        Raw: in_.Raw.0.clone(),
        RawTBSCertificateRequest: in_.TBSCSR.Raw.0.clone(),
        RawSubjectPublicKeyInfo: in_.TBSCSR.PublicKey.Raw.0.clone(),
        RawSubject: in_.TBSCSR.Subject.FullBytes.clone(),

        Signature: in_.SignatureValue.RightAlign(),
        SignatureAlgorithm: getSignatureAlgorithmFromAI(&in_.SignatureAlgorithm),

        PublicKeyAlgorithm: getPublicKeyAlgorithmFromOID(
            &in_.TBSCSR.PublicKey.Algorithm.Algorithm,
        ),

        Version: in_.TBSCSR.Version,
        Attributes: parseRawAttributes(in_.TBSCSR.RawAttributes.clone()),
        ..Default::default()
    };

    // Go: if out.PublicKeyAlgorithm != UnknownPublicKeyAlgorithm {
    //         out.PublicKey, err = parsePublicKey(&in.TBSCSR.PublicKey)
    //     }
    if out.PublicKeyAlgorithm != UnknownPublicKeyAlgorithm {
        let (pk, err) = super::parser::parsePublicKey(&in_.TBSCSR.PublicKey);
        if err != errors::nil {
            return (None, err);
        }
        out.PublicKey = pk;
    }

    // Go: var subject pkix.RDNSequence
    //     if rest, err := asn1.Unmarshal(in.TBSCSR.Subject.FullBytes, &subject); err != nil { … }
    let mut subject = pkix::RDNSequence::default();
    let (rest, err) = asn1::Unmarshal(in_.TBSCSR.Subject.FullBytes.clone(), &mut subject);
    if err != errors::nil {
        return (None, err);
    }
    if rest.Len() != 0 {
        return (
            None,
            errors::New("x509: trailing data after X.509 Subject"),
        );
    }

    // Go: out.Subject.FillFromRDNSequence(&subject)
    out.Subject.FillFromRDNSequence(&subject);

    // Go: if out.Extensions, err = parseCSRExtensions(in.TBSCSR.RawAttributes); err != nil { … }
    let (exts, err) = parseCSRExtensions(in_.TBSCSR.RawAttributes.clone());
    if err != errors::nil {
        return (None, err);
    }
    out.Extensions = exts;

    // Go: for _, extension := range out.Extensions {
    //         switch { case extension.Id.Equal(oidExtensionSubjectAltName): … }
    //     }
    for (_, extension) in crate::range!(out.Extensions.clone()) {
        if extension.Id.Equal(&oidExtensionSubjectAltName()) {
            let (dns, emails, ips, uris, err) = super::parser::parseSANExtension(
                crate::crypto::cryptobyte::String::New(extension.Value.clone()),
            );
            if err != errors::nil {
                return (None, err);
            }
            out.DNSNames = dns;
            out.EmailAddresses = emails;
            out.IPAddresses = ips;
            out.URIs = uris;
        }
    }

    // Go: return out, nil
    return (Some(out), errors::nil);
}

impl CertificateRequest {
    // go: sdk 1.25.5 crypto/x509/x509.go:2260-2263 CertificateRequest.CheckSignature
    /// Report whether the signature on `self` is valid.
    pub fn CheckSignature(&self) -> error {
        // Go: return checkSignature(c.SignatureAlgorithm,
        //         c.RawTBSCertificateRequest, c.Signature, c.PublicKey, true)
        return checkSignature(
            self.SignatureAlgorithm,
            self.RawTBSCertificateRequest.clone(),
            self.Signature.clone(),
            &self.PublicKey,
            true,
        );
    }
}

impl RevocationList {
    // go: sdk 1.25.5 crypto/x509/x509.go:2550-2565 RevocationList.CheckSignatureFrom
    /// Verify that the signature on `self` is a valid signature from
    /// `parent`.
    pub fn CheckSignatureFrom(&self, parent: &Certificate) -> error {
        // Go: if parent.Version == 3 && !parent.BasicConstraintsValid ||
        //        parent.BasicConstraintsValid && !parent.IsCA {
        //         return ConstraintViolationError{}
        //     }
        if (parent.Version == 3 && !parent.BasicConstraintsValid)
            || (parent.BasicConstraintsValid && !parent.IsCA)
        {
            return errors::Wrap(ConstraintViolationError {});
        }

        // Go: if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCRLSign == 0 {
        //         return ConstraintViolationError{}
        //     }
        if parent.KeyUsage != KeyUsage(0) && (parent.KeyUsage & KeyUsageCRLSign) == KeyUsage(0) {
            return errors::Wrap(ConstraintViolationError {});
        }

        // Go: if parent.PublicKeyAlgorithm == UnknownPublicKeyAlgorithm {
        //         return ErrUnsupportedAlgorithm
        //     }
        if parent.PublicKeyAlgorithm == UnknownPublicKeyAlgorithm {
            return ErrUnsupportedAlgorithm.into();
        }

        // Go: return parent.CheckSignature(rl.SignatureAlgorithm,
        //         rl.RawTBSRevocationList, rl.Signature)
        return parent.CheckSignature(
            self.SignatureAlgorithm,
            self.RawTBSRevocationList.clone(),
            self.Signature.clone(),
        );
    }
}
