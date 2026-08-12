// go: file crypto/tls/common.go decls: VersionName, isTLS13OnlyKeyExchange, isPQKeyExchange, requiresClientCert, supportedVersionsFromMax, supportedSignatureAlgorithms, supportedSignatureAlgorithmsCert, isDisabledSignatureAlgorithm, isSupportedSignatureAlgorithm, CertificateVerificationError.Error, CertificateVerificationError.Unwrap, unexpectedMessageError, Certificate.leaf, Config.supportedVersions, Config.maxSupportedVersion, Config.mutualVersion, Config.curvePreferences, Config.supportsCurve, Config.cipherSuites, Config.supportedCipherSuites
//
// crypto/tls — the protocol-level type surface: versions, curve IDs,
// signature schemes and client-auth policy.
//
// **Partial port.** common.go is 1805 lines and most of it is `Config`
// and its methods, which hang on the handshake state machine. What is
// here is the part that stands alone: the enumerations every other file
// in the package refers to, plus the four free functions over them.
// `Config` and `Certificate` currently live in mod[rs] and are not yet
// ports — see ROADMAP.md.
//
// goishlint:ignore GOISH018 BuildNameToCertificate, CipherSuiteName, CipherSuites, Clone, Context, ExportKeyingMaterial, Get, InsecureCipherSuites, NewLRUClientSessionCache, Put, RenegotiateFreelyAsClient, RenegotiateNever, RenegotiateOnceAsClient, SetSessionTicketKeys, SupportsCertificate, aeadModes, aesgcmCiphers, certTypeECDSASign, certTypeRSASign, decodeCipherSuites, defaultCipherSuites, defaultCipherSuitesTLS13, defaultConfig, deprecatedSessionTicketKey, echField, emptyConfig, errNoCertificates, fips140tls, fipsAllowChain, fipsAllowedChains, getCertificate, handshakeMessage, handshakeMessageWithOriginalBytes, hasAESGCMHardwareSupport, initLegacySessionTicketKeyRLocked, lruSessionCache, lruSessionCacheEntry, needFIPS, rand, roleClient, roleServer, rsaKexCiphers, supportsSignatureAlgorithm, testingOnlyForceDowngradeCanary, testingOnlySupportedSignatureAlgorithms, ticketKeyFromBytes, ticketKeyLifetime, ticketKeyRotation, ticketKeys, time, tls10server, tlsrsakex, tlssha1, tlsunsafeekm, writeKeyLog, writerMutex — Config, ConnectionState, the session cache and the handshake-message machinery, none of which is ported yet; see the banner.
// goishlint:ignore GOISH019 recordType, keyShare, pskIdentity, ConnectionState, ClientSessionCache, ClientHelloInfo, CertificateRequestInfo, RenegotiationSupport, Config, EncryptedClientHelloKey, ticketKey, dsaSignature, ecdsaSignature — same.
// goishlint:ignore GOISH021 CertificateRequestInfo, ClientHelloInfo, ClientSessionCache, Config, ConnectionState, EncryptedClientHelloKey, Get, NewLRUClientSessionCache, Put, RenegotiateFreelyAsClient, RenegotiateNever, RenegotiateOnceAsClient, RenegotiationSupport, certTypeECDSASign, certTypeRSASign, defaultCipherSuitesFIPS, defaultConfig, defaultCurvePreferences, defaultCurvePreferencesFIPS, defaultSupportedSignatureAlgorithmsFIPS, defaultSupportedVersionsFIPS, deprecatedSessionTicketKey, directSigning, downgradeCanaryTLS11, downgradeCanaryTLS12, dsaSignature, ecdsaSignature, emptyConfig, errEarlyCloseWrite, errNoCertificates, errShutdown, extensionEncryptedClientHelloOuterExtensions, fipsAllowChain, fipsAllowedChains, handshakeMessage, handshakeMessageWithOriginalBytes, helloRetryRequestRandom, keyLogLabelClientHandshake, keyLogLabelClientTraffic, keyLogLabelEarlyTraffic, keyLogLabelServerHandshake, keyLogLabelServerTraffic, keyLogLabelTLS12, keyShare, lruSessionCache, lruSessionCacheEntry, maxSessionTicketLifetime, maxUselessBytes, pointFormatUncompressed, pskIdentity, pskModeDHE, pskModePlain, rand, signatureECDSA, signatureEd25519, signaturePKCS1v15, signatureRSAPSS, statusTypeOCSP, testingOnlyForceDowngradeCanary, testingOnlySupportedSignatureAlgorithms, ticketKey, ticketKeyLifetime, ticketKeyRotation, time, tls10server, tlssha1, typeCertificate, typeCertificateRequest, typeCertificateStatus, typeCertificateVerify, typeClientHello, typeClientKeyExchange, typeEncryptedExtensions, typeEndOfEarlyData, typeFinished, typeHelloRequest, typeKeyUpdate, typeMessageHash, typeNewSessionTicket, typeServerHello, typeServerHelloDone, typeServerKeyExchange, writerMutex — same.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use crate::fmt;
use crate::gostring::string;
use crate::types::{byte, int, uint16, uint8};

// Go: common.go:32-41
//   const ( VersionTLS10 = 0x0301; … VersionSSL30 = 0x0300 )
/// TLS 1.0.
pub const VersionTLS10: uint16 = 0x0301;
/// TLS 1.1.
pub const VersionTLS11: uint16 = 0x0302;
/// TLS 1.2.
pub const VersionTLS12: uint16 = 0x0303;
/// TLS 1.3.
pub const VersionTLS13: uint16 = 0x0304;
/// Deprecated: SSLv3 is cryptographically broken and is no longer
/// supported by this package. See golang.org/issue/32716.
pub const VersionSSL30: uint16 = 0x0300;

// go: sdk 1.25.5 crypto/tls/common.go:46-61 VersionName
/// Return the name for the provided TLS version number (e.g. "TLS 1.3"),
/// or a fallback representation of the value if the version is not
/// implemented by this package.
pub fn VersionName(version: uint16) -> string {
    // Go: switch version { case VersionSSL30: return "SSLv3"; … }
    return match version {
        VersionSSL30 => string::from_static("SSLv3"),
        VersionTLS10 => string::from_static("TLS 1.0"),
        VersionTLS11 => string::from_static("TLS 1.1"),
        VersionTLS12 => string::from_static("TLS 1.2"),
        VersionTLS13 => string::from_static("TLS 1.3"),
        // Go: default: return fmt.Sprintf("0x%04X", version)
        _ => fmt::Sprintf!("0x%04X", version),
    };
}

// Go: common.go:63-71 — record and handshake size limits.
/// Maximum plaintext payload length.
pub(crate) const maxPlaintext: int = 16384;
/// Maximum ciphertext payload length.
pub(crate) const maxCiphertext: int = 16384 + 2048;
/// Maximum ciphertext length in TLS 1.3.
pub(crate) const maxCiphertextTLS13: int = 16384 + 256;
/// Record header length.
pub(crate) const recordHeaderLen: int = 5;
/// Maximum handshake we support (the protocol max is 16 MB).
pub(crate) const maxHandshake: int = 65536;
/// Maximum certificate message size (256 KiB).
pub(crate) const maxHandshakeCertificateMsg: int = 262144;
/// Maximum number of consecutive non-advancing records.
pub(crate) const maxUselessRecords: int = 16;

// Go: common.go:74
//   type recordType uint8
/// A TLS record type.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct recordType(pub uint8);

// Go: common.go:76-81
pub(crate) const recordTypeChangeCipherSpec: recordType = recordType(20);
pub(crate) const recordTypeAlert: recordType = recordType(21);
pub(crate) const recordTypeHandshake: recordType = recordType(22);
pub(crate) const recordTypeApplicationData: recordType = recordType(23);

// Go: common.go:104-106 — TLS compression types.
pub(crate) const compressionNone: uint8 = 0;

// Go: common.go:108-131 — TLS extension numbers.
pub(crate) const extensionServerName: uint16 = 0;
pub(crate) const extensionStatusRequest: uint16 = 5;
/// `supported_groups` in TLS 1.3; see RFC 8446 §4.2.7.
pub(crate) const extensionSupportedCurves: uint16 = 10;
pub(crate) const extensionSupportedPoints: uint16 = 11;
pub(crate) const extensionSignatureAlgorithms: uint16 = 13;
pub(crate) const extensionALPN: uint16 = 16;
pub(crate) const extensionSCT: uint16 = 18;
pub(crate) const extensionExtendedMasterSecret: uint16 = 23;
pub(crate) const extensionSessionTicket: uint16 = 35;
pub(crate) const extensionPreSharedKey: uint16 = 41;
pub(crate) const extensionEarlyData: uint16 = 42;
pub(crate) const extensionSupportedVersions: uint16 = 43;
pub(crate) const extensionCookie: uint16 = 44;
pub(crate) const extensionPSKModes: uint16 = 45;
pub(crate) const extensionCertificateAuthorities: uint16 = 47;
pub(crate) const extensionSignatureAlgorithmsCert: uint16 = 50;
pub(crate) const extensionKeyShare: uint16 = 51;
pub(crate) const extensionQUICTransportParameters: uint16 = 57;
pub(crate) const extensionRenegotiationInfo: uint16 = 0xff01;
pub(crate) const extensionECHOuterExtensions: uint16 = 0xfd00;
pub(crate) const extensionEncryptedClientHello: uint16 = 0xfe0d;

// Go: common.go:133-136 — TLS signaling cipher suite values.
pub(crate) const scsvRenegotiation: uint16 = 0x00ff;

// Go: common.go:145
//   type CurveID uint16
/// `tls.CurveID` — the TLS elliptic-curve / key-exchange group ID, as
/// defined in RFC 8446 §4.2.7. Despite the name it is also used for
/// non-elliptic groups.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct CurveID(pub uint16);

// Go: common.go:147-153
pub const CurveP256: CurveID = CurveID(23);
pub const CurveP384: CurveID = CurveID(24);
pub const CurveP521: CurveID = CurveID(25);
pub const X25519: CurveID = CurveID(29);
pub const X25519MLKEM768: CurveID = CurveID(4588);

// go: sdk 1.25.5 crypto/tls/common.go:155-157 isTLS13OnlyKeyExchange
/// Report whether `curve` is only usable in TLS 1.3.
pub(crate) fn isTLS13OnlyKeyExchange(curve: CurveID) -> bool {
    // Go: return curve == X25519MLKEM768
    return curve == X25519MLKEM768;
}

// go: sdk 1.25.5 crypto/tls/common.go:159-161 isPQKeyExchange
/// Report whether `curve` is a post-quantum key exchange.
pub(crate) fn isPQKeyExchange(curve: CurveID) -> bool {
    // Go: return curve == X25519MLKEM768
    return curve == X25519MLKEM768;
}

// Go: common.go:334
//   type ClientAuthType int
/// `tls.ClientAuthType` — the server's policy for requesting and
/// verifying client certificates.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ClientAuthType(pub int);

// Go: common.go:336-360 — `iota`-numbered, so the values are 0..4.
/// No client certificate is requested, and any sent are not verified.
pub const NoClientCert: ClientAuthType = ClientAuthType(0);
/// A client certificate is requested but not required.
pub const RequestClientCert: ClientAuthType = ClientAuthType(1);
/// At least one certificate is required, but it need not be valid.
pub const RequireAnyClientCert: ClientAuthType = ClientAuthType(2);
/// A certificate is requested; if sent, it must be valid.
pub const VerifyClientCertIfGiven: ClientAuthType = ClientAuthType(3);
/// At least one valid certificate is required.
pub const RequireAndVerifyClientCert: ClientAuthType = ClientAuthType(4);

// go: sdk 1.25.5 crypto/tls/common.go:362-370 requiresClientCert
/// Report whether the [`ClientAuthType`] requires a client certificate
/// to be provided.
pub(crate) fn requiresClientCert(c: ClientAuthType) -> bool {
    // Go: switch c { case RequireAnyClientCert, RequireAndVerifyClientCert:
    //         return true; default: return false }
    return match c {
        RequireAnyClientCert | RequireAndVerifyClientCert => true,
        _ => false,
    };
}

// Go: common.go:200-211
//   const ( signaturePKCS1v15 uint8 = iota + 225; signatureRSAPSS;
//           signatureECDSA; signatureEd25519 )
//   var directSigning crypto.Hash = 0
//
// "signatureAlgorithm values, ONLY for internal use. Nothing on the wire."
/// RSASSA-PKCS1-v1_5.
pub(crate) const signaturePKCS1v15: uint8 = 225;
/// RSASSA-PSS.
pub(crate) const signatureRSAPSS: uint8 = 226;
/// ECDSA.
pub(crate) const signatureECDSA: uint8 = 227;
/// EdDSA (Ed25519).
pub(crate) const signatureEd25519: uint8 = 228;

/// `directSigning` is a standard `crypto.Hash` value that signals no
/// pre-hashing: the message is signed whole. Go declares it as
/// `var directSigning crypto.Hash = 0`.
pub(crate) const directSigning: crate::crypto::Hash = crate::crypto::Hash(0);

// Go: common.go:393
//   type SignatureScheme uint16
/// `tls.SignatureScheme` — a signature algorithm supported by TLS, as
/// defined in RFC 8446 §4.2.3.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct SignatureScheme(pub uint16);

// Go: common.go:395-419, in Go's declaration order and grouping.
/// RSASSA-PKCS1-v1_5 with SHA-256.
pub const PKCS1WithSHA256: SignatureScheme = SignatureScheme(0x0401);
/// RSASSA-PKCS1-v1_5 with SHA-384.
pub const PKCS1WithSHA384: SignatureScheme = SignatureScheme(0x0501);
/// RSASSA-PKCS1-v1_5 with SHA-512.
pub const PKCS1WithSHA512: SignatureScheme = SignatureScheme(0x0601);

/// RSASSA-PSS with SHA-256, public key OID rsaEncryption.
pub const PSSWithSHA256: SignatureScheme = SignatureScheme(0x0804);
/// RSASSA-PSS with SHA-384, public key OID rsaEncryption.
pub const PSSWithSHA384: SignatureScheme = SignatureScheme(0x0805);
/// RSASSA-PSS with SHA-512, public key OID rsaEncryption.
pub const PSSWithSHA512: SignatureScheme = SignatureScheme(0x0806);

/// ECDSA on P-256 with SHA-256. Only constrained to a specific curve in
/// TLS 1.3.
pub const ECDSAWithP256AndSHA256: SignatureScheme = SignatureScheme(0x0403);
/// ECDSA on P-384 with SHA-384.
pub const ECDSAWithP384AndSHA384: SignatureScheme = SignatureScheme(0x0503);
/// ECDSA on P-521 with SHA-512.
pub const ECDSAWithP521AndSHA512: SignatureScheme = SignatureScheme(0x0603);

/// EdDSA with Ed25519.
pub const Ed25519: SignatureScheme = SignatureScheme(0x0807);

/// Legacy: RSASSA-PKCS1-v1_5 with SHA-1 (TLS 1.2 only).
pub const PKCS1WithSHA1: SignatureScheme = SignatureScheme(0x0201);
/// Legacy: ECDSA with SHA-1 (TLS 1.2 only).
pub const ECDSAWithSHA1: SignatureScheme = SignatureScheme(0x0203);


// ─── Version, signature-algorithm and error helpers ───────────────────
//
// The free functions of common.go — the ones that do not reach into
// `Config`. Everything here is pure policy over the enumerations above.

extern crate alloc;
use alloc::vec::Vec;

use super::auth::typeAndHashFromSignatureScheme;
use super::defaults::defaultSupportedSignatureAlgorithms;
use super::internal::fips140tls;
use super::Config;
use crate::crypto;
use crate::error;
use crate::errors;
use crate::goslice::slice;

// Go: common.go:1156-1161
//   var supportedVersions = []uint16{ VersionTLS13, VersionTLS12, VersionTLS11, VersionTLS10 }
pub(crate) const supportedVersions: &[uint16] = &[
    VersionTLS13,
    VersionTLS12,
    VersionTLS11,
    VersionTLS10,
];

// go: sdk 1.25.5 crypto/tls/common.go:1208-1217 supportedVersionsFromMax
/// The supported versions derived from a legacy maximum version value.
/// Only versions this library supports are returned — any newer peer
/// will use `supportedVersions` anyway.
pub(crate) fn supportedVersionsFromMax(maxVersion: uint16) -> slice<uint16> {
    // Go: versions := make([]uint16, 0, len(supportedVersions))
    let mut versions: Vec<uint16> = Vec::with_capacity(supportedVersions.len());
    // Go: for _, v := range supportedVersions {
    //         if v > maxVersion { continue }
    //         versions = append(versions, v)
    //     }
    for v in supportedVersions {
        if *v > maxVersion {
            continue;
        }
        versions.push(*v);
    }
    // Go: return versions
    return slice::__from_vec(versions);
}

// go: none — goish idiom: `internal/godebug` is not ported. See
// defaults[rs]'s `godebugValue` for the same one-line hook; Go's
// `tlssha1` is unset by default, and every branch here compares against
// a specific string.
pub(crate) fn tlssha1Value() -> crate::gostring::string {
    return crate::gostring::string::from_static("");
}

// go: sdk 1.25.5 crypto/tls/common.go:1696-1704 supportedSignatureAlgorithms
/// The signature schemes we will accept from a peer negotiating at
/// `minVers` or above.
///
/// Deviation: Go consults `testingOnlySupportedSignatureAlgorithms`, a
/// test hook goish has no way to set from outside the package.
pub(crate) fn supportedSignatureAlgorithms(minVers: uint16) -> slice<SignatureScheme> {
    // Go: sigAlgs := defaultSupportedSignatureAlgorithms()
    //     if testingOnlySupportedSignatureAlgorithms != nil { sigAlgs = slices.Clone(…) }
    let sigAlgs = defaultSupportedSignatureAlgorithms();
    // Go: return slices.DeleteFunc(sigAlgs, func(s SignatureScheme) bool {
    //         return isDisabledSignatureAlgorithm(minVers, s, false) })
    let mut out: Vec<SignatureScheme> = Vec::new();
    for (_, s) in crate::range!(sigAlgs) {
        if !isDisabledSignatureAlgorithm(minVers, *s, false) {
            out.push(*s);
        }
    }
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 crypto/tls/common.go:1742-1747 supportedSignatureAlgorithmsCert
/// The signature schemes we will accept on a *certificate*. Wider than
/// [`supportedSignatureAlgorithms`] on purpose — see the comment in
/// `isDisabledSignatureAlgorithm`.
pub(crate) fn supportedSignatureAlgorithmsCert() -> slice<SignatureScheme> {
    // Go: sigAlgs := defaultSupportedSignatureAlgorithms()
    let sigAlgs = defaultSupportedSignatureAlgorithms();
    // Go: return slices.DeleteFunc(sigAlgs, func(s SignatureScheme) bool {
    //         return isDisabledSignatureAlgorithm(0, s, true) })
    let mut out: Vec<SignatureScheme> = Vec::new();
    for (_, s) in crate::range!(sigAlgs) {
        if !isDisabledSignatureAlgorithm(0, *s, true) {
            out.push(*s);
        }
    }
    return slice::__from_vec(out);
}

// go: sdk 1.25.5 crypto/tls/common.go:1708-1740 isDisabledSignatureAlgorithm
/// Whether `s` is off for a peer negotiating `version`. `isCert` widens
/// the answer for the `signature_algorithms_cert` extension.
pub(crate) fn isDisabledSignatureAlgorithm(
    version: uint16,
    s: SignatureScheme,
    isCert: bool,
) -> bool {
    // Go: if fips140tls.Required() && !slices.Contains(allowedSignatureAlgorithmsFIPS, s) { return true }
    if fips140tls::Required()
        && !super::defaults_fips140::allowedSignatureAlgorithmsFIPS.contains(&s)
    {
        return true;
    }

    // Go: For the _cert extension we include all algorithms, including
    // SHA-1 and PKCS#1 v1.5, because it's more likely that something on
    // our side will be willing to accept a *-with-SHA1 certificate (e.g.
    // with a custom VerifyConnection or by a direct match with the
    // CertPool), than that the peer would have a better certificate but
    // is just choosing not to send it. crypto/x509 will refuse to verify
    // important SHA-1 signatures anyway.
    if isCert {
        return false;
    }

    // Go: TLS 1.3 removed support for PKCS#1 v1.5 and SHA-1 signatures,
    // and Go 1.25 removed support for SHA-1 signatures in TLS 1.2.
    if version > VersionTLS12 {
        let (sigType, sigHash, _) = typeAndHashFromSignatureScheme(s);
        if sigType == signaturePKCS1v15 || sigHash == crypto::SHA1 {
            return true;
        }
    } else if tlssha1Value() != crate::gostring::string::from_static("1") {
        let (_, sigHash, _) = typeAndHashFromSignatureScheme(s);
        if sigHash == crypto::SHA1 {
            return true;
        }
    }

    // Go: return false
    return false;
}

// go: sdk 1.25.5 crypto/tls/common.go:1749-1751 isSupportedSignatureAlgorithm
pub(crate) fn isSupportedSignatureAlgorithm(
    sigAlg: SignatureScheme,
    supportedSignatureAlgorithms: slice<SignatureScheme>,
) -> bool {
    // Go: return slices.Contains(supportedSignatureAlgorithms, sigAlg)
    for (_, s) in crate::range!(supportedSignatureAlgorithms) {
        if *s == sigAlg {
            return true;
        }
    }
    return false;
}

// Go: common.go:1754-1758
//   type CertificateVerificationError struct {
//       UnverifiedCertificates []*x509.Certificate
//       Err                    error
//   }
/// Returned when certificate verification fails during the handshake.
#[derive(Clone, Default)]
pub struct CertificateVerificationError {
    /// Go: "UnverifiedCertificates and its contents should not be
    /// modified."
    pub UnverifiedCertificates: slice<crate::crypto::x509::Certificate>,
    pub Err: error,
}

impl CertificateVerificationError {
    // go: sdk 1.25.5 crypto/tls/common.go:1760-1762 CertificateVerificationError.Error
    pub fn Error(&self) -> crate::gostring::string {
        // Go: return fmt.Sprintf("tls: failed to verify certificate: %s", e.Err)
        return fmt::Sprintf!("tls: failed to verify certificate: %s", self.Err.Error());
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1764-1766 CertificateVerificationError.Unwrap
    pub fn Unwrap(&self) -> error {
        // Go: return e.Err
        return self.Err.clone();
    }
}

// go: none — goish idiom: Go satisfies `error` implicitly through the
// `Error() string` method, and `errors.Is` reaches `Err` through an
// `interface { Unwrap() error }` assertion. goish's `ErrorTrait` carries
// both, so the wiring forwards to the two ported methods.
impl errors::ErrorTrait for CertificateVerificationError {
    // go: none — goish idiom: forwards to the ported inherent `Error`.
    fn Error(&self) -> crate::gostring::string {
        return CertificateVerificationError::Error(self);
    }
    // go: none — goish idiom: forwards to the ported inherent `Unwrap`.
    fn Unwrap(&self) -> error {
        return CertificateVerificationError::Unwrap(self);
    }
}

// go: sdk 1.25.5 crypto/tls/common.go:1687-1689 unexpectedMessageError
/// Deviation: Go's message renders `%T` — the dynamic type of each
/// message — which goish's `Any` cannot produce (the downcast registry
/// answers "is it a T", not "what is it"). The caller passes the two
/// names instead, and the rest of the message is verbatim. The same
/// deviation is documented in auth[rs].
///
/// goishlint:ignore GOISH020 unexpectedMessageError — Go's two `any` arguments become their two type names
pub(crate) fn unexpectedMessageError(
    wanted: crate::gostring::string,
    got: crate::gostring::string,
) -> error {
    // Go: return fmt.Errorf("tls: received unexpected handshake message
    //         of type %T when waiting for %T", got, wanted)
    return fmt::Errorf!(
        "tls: received unexpected handshake message of type %s when waiting for %s",
        got,
        wanted
    );
}


// Go: common.go:1559-1579
//   type Certificate struct { Certificate [][]byte; PrivateKey crypto.PrivateKey
//                             SupportedSignatureAlgorithms []SignatureScheme
//                             OCSPStaple []byte; SignedCertificateTimestamps [][]byte
//                             Leaf *x509.Certificate }
/// `tls.Certificate` — a chain of one or more certificates, leaf first,
/// plus the leaf's private key.
#[derive(Clone)]
pub struct Certificate {
    /// A chain of one or more certificates, leaf first, in DER form.
    pub Certificate: slice<slice<byte>>,
    /// Go: "PrivateKey contains the private key corresponding to the
    /// public key in Leaf. This must implement crypto.Signer with an
    /// RSA, ECDSA or Ed25519 PublicKey. For a server up to TLS 1.2, it
    /// can also implement crypto.Decrypter with an RSA PublicKey."
    pub PrivateKey: crate::crypto::PrivateKey,
    /// Go: "an optional list restricting what signature algorithms the
    /// PrivateKey can be used for."
    pub SupportedSignatureAlgorithms: slice<SignatureScheme>,
    /// Go: "an optional OCSP response which will be served to clients
    /// that request it."
    pub OCSPStaple: slice<byte>,
    /// Go: "an optional list of Signed Certificate Timestamps which will
    /// be served to clients that request it."
    pub SignedCertificateTimestamps: slice<slice<byte>>,
    /// Go: "the parsed form of the leaf certificate, which may be
    /// initialized using x509.ParseCertificate to reduce per-handshake
    /// processing. If nil, the leaf certificate will be parsed as
    /// needed." Go's nil pointer is `None` here.
    pub Leaf: Option<crate::crypto::x509::Certificate>,
}

impl Default for Certificate {
    // go: none — goish idiom: Go's zero value. `PrivateKey` is an
    // interface with no nil sentinel, so the unit type stands in — it
    // downcasts to no key type, and a default-constructed Certificate
    // fails the handshake with a clean "does not implement
    // crypto.Signer" error.
    fn default() -> Self {
        return Certificate {
            Certificate: slice::new(),
            PrivateKey: alloc::sync::Arc::new(()),
            SupportedSignatureAlgorithms: slice::new(),
            OCSPStaple: slice::new(),
            SignedCertificateTimestamps: slice::new(),
            Leaf: None,
        };
    }
}

impl Certificate {
    // go: sdk 1.25.5 crypto/tls/common.go:1583-1588 Certificate.leaf
    /// The parsed leaf certificate, either from `c.Leaf` or by parsing
    /// `c.Certificate[0]`.
    pub(crate) fn leaf(&self) -> (crate::crypto::x509::Certificate, error) {
        // Go: if c.Leaf != nil { return c.Leaf, nil }
        if self.Leaf.is_some() {
            return (self.Leaf.clone().unwrap(), errors::nil);
        }
        // Go: return x509.ParseCertificate(c.Certificate[0])
        return crate::crypto::x509::ParseCertificate(self.Certificate[0].clone());
    }
}


// ─── Config: version, curve and cipher-suite negotiation ──────────────
//
// The `Config` record itself still lives in mod[rs] — it is the type the
// live handshake holds — but these methods are ported here, against
// common.go, because that is the file that defines them.
//
// One deviation runs through all of them: Go's receiver is a `*Config`
// and every method starts by testing `c == nil`. goish has no nil
// struct pointer; `impl From<Nil> for Config` yields the zero value, and
// every one of Go's nil tests is paired with a zero test on the same
// field (`c == nil || c.MinVersion == 0`), so testing the field alone is
// the same predicate.

// Go: common.go:1165-1166
//   const roleClient = true; const roleServer = false
/// Go: "roleClient and roleServer are meant to call supportedVersions
/// and parents with more readability at the callsite."
pub(crate) const roleClient: bool = true;
pub(crate) const roleServer: bool = false;

// go: none — goish idiom: `internal/godebug` is not ported; see
// `tlssha1Value` above and defaults[rs]'s `godebugValue`.
fn tls10serverValue() -> crate::gostring::string {
    return crate::gostring::string::from_static("");
}

impl Config {
    // go: sdk 1.25.5 crypto/tls/common.go:1172-1196 Config.supportedVersions
    /// The supported TLS versions, sorted from highest to lowest.
    pub(crate) fn supportedVersions(&self, isClient: bool) -> slice<uint16> {
        // Go: versions := make([]uint16, 0, len(supportedVersions))
        let mut versions: Vec<uint16> = Vec::with_capacity(supportedVersions.len());
        // Go: for _, v := range supportedVersions {
        for v in supportedVersions {
            // Go: if fips140tls.Required() && !slices.Contains(allowedSupportedVersionsFIPS, v) { continue }
            if fips140tls::Required()
                && !super::defaults_fips140::allowedSupportedVersionsFIPS.contains(v)
            {
                continue;
            }
            // Go: if (c == nil || c.MinVersion == 0) && v < VersionTLS12 {
            //         if isClient || tls10server.Value() != "1" { continue }
            //     }
            if self.MinVersion == 0 && *v < VersionTLS12 {
                if isClient || tls10serverValue() != crate::gostring::string::from_static("1") {
                    continue;
                }
            }
            // Go: if isClient && c.EncryptedClientHelloConfigList != nil && v < VersionTLS13 { continue }
            if isClient && self.EncryptedClientHelloConfigList.Len() != 0 && *v < VersionTLS13 {
                continue;
            }
            // Go: if c != nil && c.MinVersion != 0 && v < c.MinVersion { continue }
            if self.MinVersion != 0 && *v < self.MinVersion {
                continue;
            }
            // Go: if c != nil && c.MaxVersion != 0 && v > c.MaxVersion { continue }
            if self.MaxVersion != 0 && *v > self.MaxVersion {
                continue;
            }
            // Go: versions = append(versions, v)
            versions.push(*v);
        }
        // Go: return versions
        return slice::__from_vec(versions);
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1198-1204 Config.maxSupportedVersion
    /// The highest supported version, or zero if there is none.
    pub(crate) fn maxSupportedVersion(&self, isClient: bool) -> uint16 {
        // Go: supportedVersions := c.supportedVersions(isClient)
        //     if len(supportedVersions) == 0 { return 0 }
        //     return supportedVersions[0]
        //
        // Go shadows the package-level `supportedVersions` var here;
        // Rust reads a `let` of that name as the const's pattern, so the
        // local is spelled apart.
        let supported = self.supportedVersions(isClient);
        if supported.Len() == 0 {
            return 0;
        }
        return supported[0];
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1219-1235 Config.curvePreferences
    /// The key-exchange groups to offer, in preference order.
    pub(crate) fn curvePreferences(&self, version: uint16) -> slice<CurveID> {
        // Go: curvePreferences := defaultCurvePreferences()
        let mut curvePreferences = super::defaults::defaultCurvePreferences();
        // Go: if fips140tls.Required() {
        //         curvePreferences = slices.DeleteFunc(curvePreferences, func(x CurveID) bool {
        //             return !slices.Contains(allowedCurvePreferencesFIPS, x) })
        //     }
        if fips140tls::Required() {
            let mut kept: Vec<CurveID> = Vec::new();
            for (_, x) in crate::range!(curvePreferences.clone()) {
                if super::defaults_fips140::allowedCurvePreferencesFIPS.contains(x) {
                    kept.push(*x);
                }
            }
            curvePreferences = slice::__from_vec(kept);
        }
        // Go: if c != nil && len(c.CurvePreferences) != 0 {
        //         curvePreferences = slices.DeleteFunc(curvePreferences, func(x CurveID) bool {
        //             return !slices.Contains(c.CurvePreferences, x) })
        //     }
        if self.CurvePreferences.Len() != 0 {
            let mut kept: Vec<CurveID> = Vec::new();
            for (_, x) in crate::range!(curvePreferences.clone()) {
                if containsCurve(&self.CurvePreferences, *x) {
                    kept.push(*x);
                }
            }
            curvePreferences = slice::__from_vec(kept);
        }
        // Go: if version < VersionTLS13 {
        //         curvePreferences = slices.DeleteFunc(curvePreferences, isTLS13OnlyKeyExchange)
        //     }
        if version < VersionTLS13 {
            let mut kept: Vec<CurveID> = Vec::new();
            for (_, x) in crate::range!(curvePreferences.clone()) {
                if !isTLS13OnlyKeyExchange(*x) {
                    kept.push(*x);
                }
            }
            curvePreferences = slice::__from_vec(kept);
        }
        // Go: return curvePreferences
        return curvePreferences;
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1237-1239 Config.supportsCurve
    pub(crate) fn supportsCurve(&self, version: uint16, curve: CurveID) -> bool {
        // Go: return slices.Contains(c.curvePreferences(version), curve)
        return containsCurve(&self.curvePreferences(version), curve);
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1132-1148 Config.cipherSuites
    /// The TLS 1.0-1.2 cipher suites to offer, in preference order.
    pub(crate) fn cipherSuites(&self, aesGCMPreferred: bool) -> slice<uint16> {
        // Go: var cipherSuites []uint16
        //     if c.CipherSuites == nil { cipherSuites = defaultCipherSuites(aesGCMPreferred) }
        //     else {
        //         cipherSuites = supportedCipherSuites(aesGCMPreferred)
        //         cipherSuites = slices.DeleteFunc(cipherSuites, func(id uint16) bool {
        //             return !slices.Contains(c.CipherSuites, id) })
        //     }
        let mut cipherSuites: slice<uint16>;
        if self.CipherSuites.Len() == 0 {
            cipherSuites = super::defaults::defaultCipherSuites(aesGCMPreferred);
        } else {
            cipherSuites = super::defaults::supportedCipherSuites(aesGCMPreferred);
            let mut kept: Vec<uint16> = Vec::new();
            for (_, id) in crate::range!(cipherSuites.clone()) {
                if containsU16(&self.CipherSuites, *id) {
                    kept.push(*id);
                }
            }
            cipherSuites = slice::__from_vec(kept);
        }
        // Go: if fips140tls.Required() {
        //         cipherSuites = slices.DeleteFunc(cipherSuites, func(id uint16) bool {
        //             return !slices.Contains(allowedCipherSuitesFIPS, id) })
        //     }
        if fips140tls::Required() {
            let mut kept: Vec<uint16> = Vec::new();
            for (_, id) in crate::range!(cipherSuites.clone()) {
                if super::defaults_fips140::allowedCipherSuitesFIPS.contains(id) {
                    kept.push(*id);
                }
            }
            cipherSuites = slice::__from_vec(kept);
        }
        // Go: return cipherSuites
        return cipherSuites;
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1152-1154 Config.supportedCipherSuites
    /// Go: "the supported TLS 1.0–1.2 cipher suites in an undefined
    /// order. For preference ordering, use [Config.cipherSuites]."
    pub(crate) fn supportedCipherSuites(&self) -> slice<uint16> {
        // Go: return c.cipherSuites(false)
        return self.cipherSuites(false);
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1241-1249 Config.mutualVersion
    /// The highest version both sides support, and whether there is one.
    pub(crate) fn mutualVersion(
        &self,
        isClient: bool,
        peerVersions: slice<uint16>,
    ) -> (uint16, bool) {
        // Go: supportedVersions := c.supportedVersions(isClient)
        //     for _, v := range supportedVersions {
        //         if slices.Contains(peerVersions, v) { return v, true }
        //     }
        //
        // The local is spelled apart from the package var — see
        // `maxSupportedVersion`.
        let supported = self.supportedVersions(isClient);
        for (_, v) in crate::range!(supported) {
            if containsU16(&peerVersions, *v) {
                return (*v, true);
            }
        }
        // Go: return 0, false
        return (0, false);
    }
}

// go: none — goish idiom: `slices.Contains` over a `slice<uint16>`.
fn containsU16(set: &slice<uint16>, want: uint16) -> bool {
    for (_, v) in crate::range!(set.clone()) {
        if *v == want {
            return true;
        }
    }
    return false;
}

// go: none — goish idiom: `slices.Contains` over a `slice<CurveID>`.
fn containsCurve(set: &slice<CurveID>, want: CurveID) -> bool {
    for (_, v) in crate::range!(set.clone()) {
        if *v == want {
            return true;
        }
    }
    return false;
}
