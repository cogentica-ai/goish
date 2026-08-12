// go: file crypto/tls/common.go decls: VersionName, isTLS13OnlyKeyExchange, isPQKeyExchange, requiresClientCert, supportedVersionsFromMax, supportedSignatureAlgorithms, supportedSignatureAlgorithmsCert, isDisabledSignatureAlgorithm, isSupportedSignatureAlgorithm, CertificateVerificationError.Error, CertificateVerificationError.Unwrap, unexpectedMessageError, Certificate.leaf, Config.supportedVersions, Config.maxSupportedVersion, Config.mutualVersion, Config.curvePreferences, Config.supportsCurve, Config.cipherSuites, Config.supportedCipherSuites, Config.rand, Config.time, Config.ticketKeyFromBytes, Config.BuildNameToCertificate, defaultConfig, fipsAllowedChains, fipsAllowChain, emptyConfig, Config.initLegacySessionTicketKeyRLocked, Config.SetSessionTicketKeys, Config.ticketKeys, Config.Clone, ClientHelloInfo.Context, ClientHelloInfo.SupportsCertificate, CertificateRequestInfo.Context, CertificateRequestInfo.SupportsCertificate, NewLRUClientSessionCache, lruSessionCache.Put, lruSessionCache.Get, ConnectionState.ExportKeyingMaterial, Config.getCertificate, Config.writeKeyLog
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
// goishlint:ignore GOISH018 CipherSuiteName, CipherSuites, InsecureCipherSuites, aeadModes, aesgcmCiphers, decodeCipherSuites, defaultCipherSuites, defaultCipherSuitesTLS13, deprecatedSessionTicketKey, echField, emptyConfig, errNoCertificates, fips140tls, handshakeMessage, hasAESGCMHardwareSupport, lruSessionCache, lruSessionCacheEntry, needFIPS, roleClient, roleServer, rsaKexCiphers, supportsSignatureAlgorithm, testingOnlyForceDowngradeCanary, testingOnlySupportedSignatureAlgorithms, ticketKeyLifetime, ticketKeyRotation, tls10server, tlsrsakex, tlssha1, tlsunsafeekm, writerMutex — Config, ConnectionState, the session cache and the handshake-message machinery, none of which is ported yet; see the banner.
// goishlint:ignore GOISH019 recordType, keyShare, pskIdentity, Config, dsaSignature, ecdsaSignature — same.
// goishlint:ignore GOISH021 Config, defaultCipherSuitesFIPS, defaultCurvePreferences, defaultCurvePreferencesFIPS, defaultSupportedSignatureAlgorithmsFIPS, defaultSupportedVersionsFIPS, directSigning, downgradeCanaryTLS11, downgradeCanaryTLS12, dsaSignature, ecdsaSignature, errEarlyCloseWrite, errShutdown, extensionEncryptedClientHelloOuterExtensions, keyShare, maxUselessBytes, pskIdentity, signatureECDSA, signatureEd25519, signaturePKCS1v15, signatureRSAPSS, statusTypeOCSP, testingOnlyForceDowngradeCanary, testingOnlySupportedSignatureAlgorithms, tls10server, tlssha1, typeCertificate, typeCertificateRequest, typeCertificateStatus, typeCertificateVerify, typeClientHello, typeClientKeyExchange, typeEncryptedExtensions, typeEndOfEarlyData, typeFinished, typeHelloRequest, typeKeyUpdate, typeMessageHash, typeNewSessionTicket, typeServerHello, typeServerHelloDone, typeServerKeyExchange, writerMutex — same.

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

// Go: common.go:1532-1538
//   const ( keyLogLabelTLS12 = "CLIENT_RANDOM"; … )
/// Go: the NSS key-log labels, as written by `Config.writeKeyLog`.
pub(crate) const keyLogLabelTLS12: &str = "CLIENT_RANDOM";
pub(crate) const keyLogLabelClientHandshake: &str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
pub(crate) const keyLogLabelServerHandshake: &str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
pub(crate) const keyLogLabelClientTraffic: &str = "CLIENT_TRAFFIC_SECRET_0";
pub(crate) const keyLogLabelServerTraffic: &str = "SERVER_TRAFFIC_SECRET_0";

// Go: common.go:215-220
//   var helloRetryRequestRandom = []byte{ … } // See RFC 8446, Section 4.1.3.
/// Go: the fixed `ServerHello.random` that marks a HelloRetryRequest.
pub(crate) const helloRetryRequestRandom: [byte; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

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


    // go: sdk 1.25.5 crypto/tls/common.go:1127-1133 Config.time
    /// The current time, as the handshake sees it.
    ///
    /// Deviation: Go's `Config.Time` field holds a `func() time.Time`;
    /// goish's Config has no such field, so `c.Time` is always nil and
    /// this always takes Go's nil branch — `time.Now`. Verbatim
    /// behaviour for every Config goish can express.
    pub(crate) fn time(&self) -> crate::time::Time {
        // Go: t := c.Time; if t == nil { t = time.Now }; return t()
        return crate::time::Now();
    }

    // go: sdk 1.25.5 crypto/tls/common.go:927-937 Config.ticketKeyFromBytes
    /// Go: "ticketKeyFromBytes converts from the external representation
    /// of a session ticket key to a ticketKey. Externally, session ticket
    /// keys are 32 random bytes and this function expands that into
    /// sufficient name and key material."
    pub(crate) fn ticketKeyFromBytes(&self, b: [byte; 32]) -> ticketKey {
        // Go: hashed := sha512.Sum512(b[:])
        let hashed = crate::crypto::sha512::Sum512(slice::__from_vec(b.to_vec()));
        // Go: The first 16 bytes of the hash used to be exposed on the
        // wire as a ticket prefix. They MUST NOT be used as a secret. In
        // the future, it would make sense to use a proper KDF here, like
        // HKDF with a fixed salt.
        // Go: const legacyTicketKeyNameLen = 16
        //     copy(key.aesKey[:], hashed[legacyTicketKeyNameLen:])
        //     copy(key.hmacKey[:], hashed[legacyTicketKeyNameLen+len(key.aesKey):])
        //     key.created = c.time()
        const legacyTicketKeyNameLen: usize = 16;
        let mut key = ticketKey::default();
        key.aesKey
            .copy_from_slice(&hashed[legacyTicketKeyNameLen..legacyTicketKeyNameLen + 16]);
        key.hmacKey.copy_from_slice(
            &hashed[legacyTicketKeyNameLen + 16..legacyTicketKeyNameLen + 32],
        );
        key.created = self.time();
        // Go: return key
        return key;
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1513-1530 Config.BuildNameToCertificate
    /// Go: "BuildNameToCertificate parses c.Certificates and builds
    /// c.NameToCertificate from the CommonName and SubjectAlternateName
    /// fields of each of the leaf certificates."
    ///
    /// Deprecated in Go: "NameToCertificate only allows associating a
    /// single certificate with a given name. Leave that field nil to let
    /// the library select the first compatible chain from Certificates."
    pub fn BuildNameToCertificate(&mut self) {
        // Go: c.NameToCertificate = make(map[string]*Certificate)
        self.NameToCertificate = crate::gomap::map::new();
        // Go: for i := range c.Certificates { cert := &c.Certificates[i]
        //         x509Cert, err := cert.leaf(); if err != nil { continue }
        for (_, cert) in crate::range!(self.Certificates.clone()) {
            let (x509Cert, err) = cert.leaf();
            if err != errors::nil {
                continue;
            }
            // Go: If SANs are *not* present, some clients will consider
            // the certificate valid for the name in the Common Name.
            // Go: if x509Cert.Subject.CommonName != "" && len(x509Cert.DNSNames) == 0 {
            //         c.NameToCertificate[x509Cert.Subject.CommonName] = cert }
            if x509Cert.Subject.CommonName != crate::gostring::string::from_static("")
                && x509Cert.DNSNames.Len() == 0
            {
                self.NameToCertificate
                    .Set(x509Cert.Subject.CommonName.clone(), cert.clone());
            }
            // Go: for _, san := range x509Cert.DNSNames {
            //         c.NameToCertificate[san] = cert }
            for (_, san) in crate::range!(x509Cert.DNSNames.clone()) {
                self.NameToCertificate.Set(san.clone(), cert.clone());
            }
        }
    }


    // go: sdk 1.25.5 crypto/tls/common.go:1006-1032 Config.initLegacySessionTicketKeyRLocked
    /// Seed `sessionTicketKeys` from the deprecated `SessionTicketKey`
    /// field, or randomise that field so an application that reuses it
    /// does not get a fixed value.
    ///
    /// Deviation: Go's name ends in `RLocked` because it is called under
    /// a read lock and upgrades to a write lock inside. goish takes
    /// `&mut self` instead — Rust's borrow checker gives the same
    /// exclusion statically, so there is no lock to juggle. The name is
    /// kept because it is Go's.
    pub(crate) fn initLegacySessionTicketKeyRLocked(&mut self) {
        // Go: Don't write if SessionTicketKey is already defined as our
        // deprecated string, or if it is defined by the user but
        // sessionTicketKeys is already set.
        // Go: if c.SessionTicketKey != [32]byte{} &&
        //        (bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) ||
        //         len(c.sessionTicketKeys) > 0) { return }
        if self.SessionTicketKey != [0u8; 32]
            && (hasDeprecatedPrefix(&self.SessionTicketKey) || self.sessionTicketKeys.Len() > 0)
        {
            return;
        }

        // Go: if c.SessionTicketKey == [32]byte{} {
        //         if _, err := io.ReadFull(c.rand(), c.SessionTicketKey[:]); err != nil {
        //             panic(…) }
        //         // Write the deprecated prefix at the beginning so we know we
        //         // created it. This key with the DEPRECATED prefix isn't used
        //         // as an actual session ticket key, and is only randomized in
        //         // case the application reuses it for some reason.
        //         copy(c.SessionTicketKey[:], deprecatedSessionTicketKey)
        //     } else if !bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey) &&
        //               len(c.sessionTicketKeys) == 0 {
        //         c.sessionTicketKeys = []ticketKey{c.ticketKeyFromBytes(c.SessionTicketKey)}
        //     }
        if self.SessionTicketKey == [0u8; 32] {
            let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 32]);
            let mut r = self.rand();
            let (_, err) = crate::io::ReadFull(&mut *r, &mut buf);
            if err != errors::nil {
                panic!("tls: unable to generate random session ticket key");
            }
            let raw: &[byte] = &buf;
            self.SessionTicketKey.copy_from_slice(raw);
            let dep = deprecatedSessionTicketKey;
            self.SessionTicketKey[..dep.len()].copy_from_slice(dep);
        } else if !hasDeprecatedPrefix(&self.SessionTicketKey)
            && self.sessionTicketKeys.Len() == 0
        {
            let k = self.ticketKeyFromBytes(self.SessionTicketKey);
            self.sessionTicketKeys = slice::__from_vec(alloc::vec![k]);
        }
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1043-1056 Config.SetSessionTicketKeys
    /// Go: "SetSessionTicketKeys updates the session ticket keys for a
    /// server. The first key will be used when creating new tickets,
    /// while all keys can be used for decrypting tickets. It is safe to
    /// call this function while the server is running in order to rotate
    /// the session ticket keys. The function will panic if keys is
    /// empty."
    ///
    /// Deviation: `&mut self` rather than Go's mutex; see
    /// `initLegacySessionTicketKeyRLocked`.
    pub fn SetSessionTicketKeys(&mut self, keys: slice<[byte; 32]>) {
        // Go: if len(keys) == 0 { panic("tls: keys must have at least one key") }
        if keys.Len() == 0 {
            panic!("tls: keys must have at least one key");
        }

        // Go: newKeys := make([]ticketKey, len(keys))
        //     for i, bytes := range keys { newKeys[i] = c.ticketKeyFromBytes(bytes) }
        let mut newKeys: Vec<ticketKey> = Vec::with_capacity(keys.Len() as usize);
        for (_, b) in crate::range!(keys) {
            newKeys.push(self.ticketKeyFromBytes(*b));
        }

        // Go: c.mutex.Lock(); c.sessionTicketKeys = newKeys; c.mutex.Unlock()
        self.sessionTicketKeys = slice::__from_vec(newKeys);
    }

    // go: sdk 1.25.5 crypto/tls/common.go:940-987 Config.ticketKeys
    /// The ticket keys to use, newest first, rotating the auto-managed
    /// set when the newest is older than `ticketKeyRotation`.
    ///
    /// Deviation: `&mut self` rather than Go's read-lock/write-lock
    /// dance; see `initLegacySessionTicketKeyRLocked`.
    pub(crate) fn ticketKeys(&mut self, configForClient: Option<&mut Config>) -> slice<ticketKey> {
        // Go: If the ConfigForClient callback returned a Config with
        // explicitly set keys, use those, otherwise just use the
        // original Config.
        if configForClient.is_some() {
            let cfc = configForClient.unwrap();
            if cfc.SessionTicketsDisabled {
                return slice::new();
            }
            cfc.initLegacySessionTicketKeyRLocked();
            if cfc.sessionTicketKeys.Len() != 0 {
                return cfc.sessionTicketKeys.clone();
            }
        }

        // Go: if c.SessionTicketsDisabled { return nil }
        if self.SessionTicketsDisabled {
            return slice::new();
        }
        // Go: c.initLegacySessionTicketKeyRLocked()
        //     if len(c.sessionTicketKeys) != 0 { return c.sessionTicketKeys }
        self.initLegacySessionTicketKeyRLocked();
        if self.sessionTicketKeys.Len() != 0 {
            return self.sessionTicketKeys.clone();
        }
        // Go: Fast path for the common case where the key is fresh enough.
        // Go: if len(c.autoSessionTicketKeys) > 0 &&
        //        c.time().Sub(c.autoSessionTicketKeys[0].created) < ticketKeyRotation {
        //         return c.autoSessionTicketKeys }
        if self.autoSessionTicketKeys.Len() > 0
            && self.time().Sub(self.autoSessionTicketKeys[0].created) < ticketKeyRotation
        {
            return self.autoSessionTicketKeys.clone();
        }

        // Go: autoSessionTicketKeys are managed by auto-rotation.
        // Go: Re-check the condition in case it changed since obtaining
        // the new lock.
        if self.autoSessionTicketKeys.Len() == 0
            || self.time().Sub(self.autoSessionTicketKeys[0].created) >= ticketKeyRotation
        {
            // Go: var newKey [32]byte
            //     if _, err := io.ReadFull(c.rand(), newKey[:]); err != nil {
            //         panic(fmt.Sprintf("unable to generate random session ticket key: %v", err)) }
            let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 32]);
            let mut r = self.rand();
            let (_, err) = crate::io::ReadFull(&mut *r, &mut buf);
            if err != errors::nil {
                panic!("unable to generate random session ticket key");
            }
            let mut newKey = [0u8; 32];
            let raw: &[byte] = &buf;
            newKey.copy_from_slice(raw);
            // Go: valid := make([]ticketKey, 0, len(c.autoSessionTicketKeys)+1)
            //     valid = append(valid, c.ticketKeyFromBytes(newKey))
            //     for _, k := range c.autoSessionTicketKeys {
            //         // While rotating the current key, also remove any expired ones.
            //         if c.time().Sub(k.created) < ticketKeyLifetime { valid = append(valid, k) } }
            //     c.autoSessionTicketKeys = valid
            let mut valid: Vec<ticketKey> =
                Vec::with_capacity((self.autoSessionTicketKeys.Len() + 1) as usize);
            valid.push(self.ticketKeyFromBytes(newKey));
            for (_, k) in crate::range!(self.autoSessionTicketKeys.clone()) {
                if self.time().Sub(k.created) < ticketKeyLifetime {
                    valid.push(k.clone());
                }
            }
            self.autoSessionTicketKeys = slice::__from_vec(valid);
        }
        // Go: return c.autoSessionTicketKeys
        return self.autoSessionTicketKeys.clone();
    }

    // go: sdk 1.25.5 crypto/tls/common.go:826-878 Config.Clone
    /// Go: "Clone returns a shallow clone of c or nil if c is nil. It is
    /// safe to clone a [Config] that is being used concurrently by a TLS
    /// client or server."
    ///
    /// Deviation: Go returns nil for a nil receiver; goish has no nil
    /// struct pointer, so a zero Config clones to a zero Config. Go
    /// enumerates every field under a read lock; goish derives the same
    /// shallow copy, and Rust's `&self` gives the exclusion the lock
    /// bought.
    pub fn Clone(&self) -> Config {
        // Go: return &Config{Rand: c.Rand, Time: c.Time, …} — a
        // field-by-field shallow copy.
        return self.clone();
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1119-1125 Config.rand
    /// The entropy source for the handshake.
    ///
    /// Deviation: Go's `Config.Rand` field holds an `io.Reader`
    /// interface value; goish's Config has no such field, so `c.Rand` is
    /// always nil and this always takes Go's nil branch. That is
    /// verbatim behaviour for every Config goish can express.
    pub(crate) fn rand(&self) -> alloc::boxed::Box<dyn crate::io::Reader + Send + Sync> {
        // Go: r := c.Rand; if r == nil { return rand.Reader }; return r
        return alloc::boxed::Box::new(crate::crypto::rand::Reader);
    }

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

// Go: common.go:890-905
//   type EncryptedClientHelloKey struct { Config []byte
//                                         PrivateKey []byte
//                                         SendAsRetry bool }
/// Go: "EncryptedClientHelloKey holds a private key that is associated
/// with a specific ECH config known to a client."
///
#[derive(Clone, Default)]
pub struct EncryptedClientHelloKey {
    /// Go: "Config should be a marshalled ECHConfig associated with
    /// PrivateKey. This must match the config provided to clients
    /// byte-for-byte."
    pub Config: slice<byte>,
    /// Go: "PrivateKey should be a marshalled private key. Currently, we
    /// expect this to be the output of [ecdh.PrivateKey.Bytes]."
    pub PrivateKey: slice<byte>,
    /// Go: "SendAsRetry indicates if Config should be sent as part of
    /// the list of retry configs when ECH is requested by the client but
    /// rejected by the server."
    pub SendAsRetry: bool,
}



// Go: common.go:917-922
//   type ticketKey struct { aesKey [16]byte; hmacKey [16]byte; created time.Time }
#[derive(Clone, Default)]
pub(crate) struct ticketKey {
    pub aesKey: [byte; 16],
    pub hmacKey: [byte; 16],
    /// Go: "created is the time at which this ticket key was created.
    /// See Config.ticketKeys."
    pub created: crate::time::Time,
}

// go: none — goish idiom: Go's package-level `var emptyConfig Config`.
// goish builds the zero value on demand, because a `static` of a type
// holding a `map` cannot be const-initialised. Named a function so that
// `defaultConfig` reads as Go's does.
fn emptyConfig() -> Config {
    return Config::default();
}

// go: sdk 1.25.5 crypto/tls/common.go:1683-1685 defaultConfig
pub(crate) fn defaultConfig() -> Config {
    // Go: return &emptyConfig
    return emptyConfig();
}

// go: sdk 1.25.5 crypto/tls/common.go:1774-1790 fipsAllowedChains
/// Go: "fipsAllowedChains returns chains that are allowed to be used in
/// a TLS connection based on the current fips140tls enforcement setting.
/// If fips140tls is not required, the chains are returned as-is with no
/// processing. Otherwise, the returned chains are filtered to only those
/// allowed by FIPS 140-3. If this results in no chains it returns an
/// error."
pub(crate) fn fipsAllowedChains(
    chains: slice<slice<crate::crypto::x509::Certificate>>,
) -> (slice<slice<crate::crypto::x509::Certificate>>, error) {
    // Go: if !fips140tls.Required() { return chains, nil }
    if !fips140tls::Required() {
        return (chains, errors::nil);
    }

    // Go: permittedChains := make([][]*x509.Certificate, 0, len(chains))
    //     for _, chain := range chains {
    //         if fipsAllowChain(chain) { permittedChains = append(permittedChains, chain) } }
    let mut permittedChains: Vec<slice<crate::crypto::x509::Certificate>> =
        Vec::with_capacity(chains.Len() as usize);
    for (_, chain) in crate::range!(chains.clone()) {
        if fipsAllowChain(chain.clone()) {
            permittedChains.push(chain.clone());
        }
    }

    // Go: if len(permittedChains) == 0 {
    //         return nil, errors.New("tls: no FIPS compatible certificate chains found") }
    if permittedChains.len() == 0 {
        return (
            slice::new(),
            errors::New("tls: no FIPS compatible certificate chains found"),
        );
    }

    // Go: return permittedChains, nil
    return (slice::__from_vec(permittedChains), errors::nil);
}

// go: sdk 1.25.5 crypto/tls/common.go:1792-1804 fipsAllowChain
pub(crate) fn fipsAllowChain(chain: slice<crate::crypto::x509::Certificate>) -> bool {
    // Go: if len(chain) == 0 { return false }
    if chain.Len() == 0 {
        return false;
    }

    // Go: for _, cert := range chain {
    //         if !isCertificateAllowedFIPS(cert) { return false } }
    for (_, cert) in crate::range!(chain) {
        if !super::defaults_fips140::isCertificateAllowedFIPS(cert) {
            return false;
        }
    }

    // Go: return true
    return true;
}


// Go: common.go:907-913
//   const ( ticketKeyLifetime = 7 * 24 * time.Hour
//           ticketKeyRotation = 24 * time.Hour )
/// Go: "ticketKeyLifetime is how long a ticket key remains valid and can
/// be used to decrypt tickets."
pub(crate) const ticketKeyLifetime: crate::time::Duration =
    crate::time::Duration(7 * 24 * 60 * 60 * 1_000_000_000);
/// Go: "ticketKeyRotation is how often the server should rotate the
/// session ticket key that is used to create new tickets."
pub(crate) const ticketKeyRotation: crate::time::Duration =
    crate::time::Duration(24 * 60 * 60 * 1_000_000_000);

// Go: common.go:991
//   var deprecatedSessionTicketKey = []byte("DEPRECATED")
/// Go: "deprecatedSessionTicketKey is set as the prefix of
/// SessionTicketKey if it was randomized by the library."
pub(crate) const deprecatedSessionTicketKey: &[byte] = b"DEPRECATED";

// go: none — goish idiom: Go writes
// `bytes.HasPrefix(c.SessionTicketKey[:], deprecatedSessionTicketKey)`;
// naming it keeps the two call sites in `initLegacySessionTicketKeyRLocked`
// on one line, as Go's are.
fn hasDeprecatedPrefix(key: &[byte; 32]) -> bool {
    let dep = deprecatedSessionTicketKey;
    return key.len() >= dep.len() && &key[..dep.len()] == dep;
}


// Go: common.go — `const pointFormatUncompressed uint8 = 0`
/// The only ECPointFormat this library supports (RFC 8422 §5.1.2).
pub(crate) const pointFormatUncompressed: uint8 = 0;

// Go: common.go — `const ( certTypeRSASign = 1; certTypeECDSASign = 64 )`
/// Go: "certTypeRSASign — A certificate containing an RSA key."
pub(crate) const certTypeRSASign: byte = 1;
/// Go: "certTypeECDSASign — A certificate containing an ECDSA-capable
/// public key."
pub(crate) const certTypeECDSASign: byte = 64;

// Go: common.go — `const ( pskModePlain uint8 = 0; pskModeDHE uint8 = 1 )`
/// PSK-only key establishment (RFC 8446 §4.2.9).
pub(crate) const pskModePlain: uint8 = 0;
/// PSK with (EC)DHE key establishment — the only mode this library uses.
pub(crate) const pskModeDHE: uint8 = 1;

// Go: common.go — `const maxSessionTicketLifetime = 7 * 24 * time.Hour`
/// Go: "maxSessionTicketLifetime is the maximum allowed lifetime of a
/// TLS 1.3 session ticket, and the lifetime we set for all tickets we
/// send."
pub(crate) const maxSessionTicketLifetime: crate::time::Duration =
    crate::time::Duration(7 * 24 * 60 * 60 * 1_000_000_000);

// ─── ClientHelloInfo and CertificateRequestInfo ───────────────────────

// Go: common.go:452-514
//   type ClientHelloInfo struct { CipherSuites []uint16; ServerName string
//                                 SupportedCurves []CurveID; SupportedPoints []uint8
//                                 SignatureSchemes []SignatureScheme
//                                 SupportedProtos []string; SupportedVersions []uint16
//                                 Extensions []uint16; Conn net.Conn
//                                 config *Config; ctx context.Context }
/// Go: "ClientHelloInfo contains information from a ClientHello message
/// in order to guide application logic in the GetCertificate and
/// GetConfigForClient callbacks."
///
/// Two fields of Go's are absent: `Conn net.Conn`, which arrives with
/// the Conn record, and `ctx context.Context`, which `Context()` returns
/// — goish's `context::Context` is a trait with no nil sentinel, so the
/// field is an `Option` and `Context` hands back what is there.
#[derive(Clone, Default)]
pub struct ClientHelloInfo {
    /// Go: "the bitmap of the cipher suites listed by the client."
    pub CipherSuites: slice<uint16>,
    /// Go: "the name of the server requested by the client in order to
    /// support virtual hosting. ServerName is only set if the client is
    /// using SNI."
    pub ServerName: crate::gostring::string,
    /// Go: "the elliptic curves supported by the client."
    pub SupportedCurves: slice<CurveID>,
    /// Go: "the point formats supported by the client."
    pub SupportedPoints: slice<uint8>,
    /// Go: "the signature and hash schemes that the client is willing to
    /// verify."
    pub SignatureSchemes: slice<SignatureScheme>,
    /// Go: "the application protocols supported by the client."
    pub SupportedProtos: slice<crate::gostring::string>,
    /// Go: "the TLS versions supported by the client."
    pub SupportedVersions: slice<uint16>,
    /// Go: "lists the IDs of the extensions presented by the client in
    /// the ClientHello."
    pub Extensions: slice<uint16>,
    pub(crate) config: Option<alloc::boxed::Box<Config>>,
    pub(crate) ctx: Option<alloc::sync::Arc<dyn crate::context::Context>>,
}

impl ClientHelloInfo {

    // go: none — goish-only: `config` is unexported in Go, where
    // handshake_server.go is in the same package.
    #[doc(hidden)]
    pub fn __setConfig(&mut self, cfg: Config) {
        self.config = Some(alloc::boxed::Box::new(cfg));
    }

    // go: sdk 1.25.5 crypto/tls/common.go:516-518 ClientHelloInfo.Context
    /// Go: "Context returns the context of the connection that is
    /// currently being handshaked."
    pub fn Context(&self) -> Option<alloc::sync::Arc<dyn crate::context::Context>> {
        // Go: return c.ctx
        return self.ctx.clone();
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1266-1400 ClientHelloInfo.SupportsCertificate
    /// Go: "SupportsCertificate returns nil if the provided certificate
    /// is supported by the client that sent the ClientHello. Otherwise,
    /// it returns an error describing the reason for the incompatibility."
    pub fn SupportsCertificate(&self, c: &Certificate) -> error {
        // Go: Note we don't currently support certificate_authorities
        // nor signature_algorithms_cert, and don't check the algorithms
        // of the signatures on the chain (which anyway are a SHOULD, see
        // RFC 8446, Section 4.4.2.2).

        // Go: config := chi.config; if config == nil { config = &Config{} }
        let config = match &self.config {
            Some(cfg) => (**cfg).clone(),
            None => Config::default(),
        };
        // Go: vers, ok := config.mutualVersion(roleServer, chi.SupportedVersions)
        //     if !ok { return errors.New("no mutually supported protocol versions") }
        let (vers, ok) = config.mutualVersion(roleServer, self.SupportedVersions.clone());
        if !ok {
            return errors::New("no mutually supported protocol versions");
        }

        // Go: If the client specified the name they are trying to
        // connect to, the certificate needs to be valid for it.
        if self.ServerName != crate::gostring::string::from_static("") {
            let (x509Cert, err) = c.leaf();
            if err != errors::nil {
                return fmt::Errorf!("failed to parse certificate: %s", err.Error());
            }
            let err = x509Cert.VerifyHostname(self.ServerName.clone());
            if err != errors::nil {
                return fmt::Errorf!(
                    "certificate is not valid for requested server name: %s",
                    err.Error()
                );
            }
        }

        // Go: If the client sent the signature_algorithms extension,
        // ensure it supports schemes we can use with this certificate
        // and TLS version.
        if self.SignatureSchemes.Len() > 0 {
            let (_, err) =
                super::auth::selectSignatureScheme(vers, c, self.SignatureSchemes.clone());
            if err != errors::nil {
                return supportsRSAFallback(self, c, &config, vers, err);
            }
        }

        // Go: In TLS 1.3 we are done because supported_groups is only
        // relevant to the ECDHE computation, point format negotiation is
        // removed, cipher suites are only relevant to the AEAD choice,
        // and static RSA does not exist.
        if vers == VersionTLS13 {
            return errors::nil;
        }

        // Go: The only signed key exchange we support is ECDHE.
        // Go: ecdheSupported, err := supportsECDHE(config, vers,
        //         chi.SupportedCurves, chi.SupportedPoints)
        //     if err != nil { return err }
        let (ecdheSupported, err) = super::handshake_server::supportsECDHE(
            &config,
            vers,
            self.SupportedCurves.clone(),
            self.SupportedPoints.clone(),
        );
        if err != errors::nil {
            return err;
        }
        // Go: if !ecdheSupported { return supportsRSAFallback(errors.New(
        //         "client doesn't support ECDHE, can only use legacy RSA key exchange")) }
        if !ecdheSupported {
            return supportsRSAFallback(
                self,
                c,
                &config,
                vers,
                errors::New("client doesn't support ECDHE, can only use legacy RSA key exchange"),
            );
        }

        // Go: var ecdsaCipherSuite bool
        //     if priv, ok := c.PrivateKey.(crypto.Signer); ok {
        //         switch pub := priv.Public().(type) { … }
        //     } else { return supportsRSAFallback(unsupportedCertificateError(c)) }
        let mut ecdsaCipherSuite = false;
        let signer = super::auth::signerOf(&c.PrivateKey);
        if signer.is_none() {
            return supportsRSAFallback(
                self,
                c,
                &config,
                vers,
                super::auth::unsupportedCertificateError(c),
            );
        }
        let pub_ = signer.unwrap().Public();
        if let Some(p) = pub_.downcast_ref::<crate::crypto::ecdsa::PublicKey>() {
            // Go: case *ecdsa.PublicKey:
            //         switch pub.Curve { case elliptic.P256(): curve = CurveP256; … }
            let name = p.Curve.Params().Name.clone();
            let curve: CurveID;
            if name == crate::gostring::string::from_static("P-256") {
                curve = CurveP256;
            } else if name == crate::gostring::string::from_static("P-384") {
                curve = CurveP384;
            } else if name == crate::gostring::string::from_static("P-521") {
                curve = CurveP521;
            } else {
                return supportsRSAFallback(
                    self,
                    c,
                    &config,
                    vers,
                    super::auth::unsupportedCertificateError(c),
                );
            }
            // Go: var curveOk bool
            //     for _, c := range chi.SupportedCurves {
            //         if c == curve && config.supportsCurve(vers, c) { curveOk = true; break } }
            //     if !curveOk { return errors.New("client doesn't support certificate curve") }
            let mut curveOk = false;
            for (_, cc) in crate::range!(self.SupportedCurves.clone()) {
                if *cc == curve && config.supportsCurve(vers, *cc) {
                    curveOk = true;
                    break;
                }
            }
            if !curveOk {
                return errors::New("client doesn't support certificate curve");
            }
            ecdsaCipherSuite = true;
        } else if pub_
            .downcast_ref::<crate::crypto::ed25519::PublicKey>()
            .is_some()
        {
            // Go: case ed25519.PublicKey:
            //         if vers < VersionTLS12 || len(chi.SignatureSchemes) == 0 {
            //             return errors.New("connection doesn't support Ed25519") }
            //         ecdsaCipherSuite = true
            if vers < VersionTLS12 || self.SignatureSchemes.Len() == 0 {
                return errors::New("connection doesn't support Ed25519");
            }
            ecdsaCipherSuite = true;
        } else if pub_
            .downcast_ref::<crate::crypto::rsa::PublicKey>()
            .is_some()
        {
            // Go: case *rsa.PublicKey:
        } else {
            // Go: default: return supportsRSAFallback(unsupportedCertificateError(c))
            return supportsRSAFallback(
                self,
                c,
                &config,
                vers,
                super::auth::unsupportedCertificateError(c),
            );
        }

        // Go: Make sure that there is a mutually supported cipher suite
        // that works with this certificate. Cipher suite selection will
        // then apply the logic in reverse to pick it. See also
        // serverHandshakeState.cipherSuiteOk.
        let cipherSuite = super::cipher_suites::selectCipherSuite(
            self.CipherSuites.clone(),
            config.supportedCipherSuites(),
            &|c: &'static super::cipher_suites::cipherSuite| {
                if c.flags & super::cipher_suites::suiteECDHE == 0 {
                    return false;
                }
                if c.flags & super::cipher_suites::suiteECSign != 0 {
                    if !ecdsaCipherSuite {
                        return false;
                    }
                } else if ecdsaCipherSuite {
                    return false;
                }
                if vers < VersionTLS12 && c.flags & super::cipher_suites::suiteTLS12 != 0 {
                    return false;
                }
                return true;
            },
        );
        // Go: if cipherSuite == nil { return supportsRSAFallback(errors.New(
        //         "client doesn't support any cipher suites compatible with the certificate")) }
        if cipherSuite.is_none() {
            return supportsRSAFallback(
                self,
                c,
                &config,
                vers,
                errors::New(
                    "client doesn't support any cipher suites compatible with the certificate",
                ),
            );
        }

        // Go: return nil
        return errors::nil;
    }
}

// go: none — goish-only: Go declares `supportsRSAFallback` as a closure
// inside `SupportsCertificate`, capturing `c`, `config`, `vers` and
// `chi`. Rust cannot call a closure that borrows `self` from the same
// body that also borrows it mutably elsewhere, so the closure is a named
// function over the same four captures. Body is verbatim.
fn supportsRSAFallback(
    chi: &ClientHelloInfo,
    c: &Certificate,
    config: &Config,
    vers: uint16,
    unsupported: error,
) -> error {
    // Go: TLS 1.3 dropped support for the static RSA key exchange.
    if vers == VersionTLS13 {
        return unsupported;
    }
    // Go: The static RSA key exchange works by decrypting a challenge
    // with the RSA private key, not by signing, so check the PrivateKey
    // implements crypto.Decrypter, like *rsa.PrivateKey does.
    let priv_ = super::key_agreement::decrypterOf(&c.PrivateKey);
    if priv_.is_none() {
        return unsupported;
    }
    if priv_
        .unwrap()
        .Public()
        .downcast_ref::<crate::crypto::rsa::PublicKey>()
        .is_none()
    {
        return unsupported;
    }
    // Go: Finally, there needs to be a mutual cipher suite that uses the
    // static RSA key exchange instead of ECDHE.
    let rsaCipherSuite = super::cipher_suites::selectCipherSuite(
        chi.CipherSuites.clone(),
        config.supportedCipherSuites(),
        &|c: &'static super::cipher_suites::cipherSuite| {
            if c.flags & super::cipher_suites::suiteECDHE != 0 {
                return false;
            }
            if vers < VersionTLS12 && c.flags & super::cipher_suites::suiteTLS12 != 0 {
                return false;
            }
            return true;
        },
    );
    if rsaCipherSuite.is_none() {
        return unsupported;
    }
    return errors::nil;
}

// Go: common.go:527-548
//   type CertificateRequestInfo struct { AcceptableCAs [][]byte
//                                        SignatureSchemes []SignatureScheme
//                                        Version uint16; ctx context.Context }
/// Go: "CertificateRequestInfo contains information from a server's
/// CertificateRequest message, which is used to demand a certificate and
/// proof of control from a client."
#[derive(Clone, Default)]
pub struct CertificateRequestInfo {
    /// Go: "AcceptableCAs contains zero or more, DER-encoded, X.501
    /// Distinguished Names. These are the names of root and intermediate
    /// CAs that the server wishes the returned certificate to be signed
    /// by. An empty slice indicates that the server has no preference."
    pub AcceptableCAs: slice<slice<byte>>,
    /// Go: "SignatureSchemes lists the signature schemes that the server
    /// is willing to verify."
    pub SignatureSchemes: slice<SignatureScheme>,
    /// Go: "Version is the TLS version that was negotiated for this
    /// connection."
    pub Version: uint16,
    pub(crate) ctx: Option<alloc::sync::Arc<dyn crate::context::Context>>,
}

impl CertificateRequestInfo {
    // go: sdk 1.25.5 crypto/tls/common.go:550-552 CertificateRequestInfo.Context
    /// Go: "Context returns the context of the connection that is
    /// currently being handshaked."
    pub fn Context(&self) -> Option<alloc::sync::Arc<dyn crate::context::Context>> {
        // Go: return c.ctx
        return self.ctx.clone();
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1405-1435 CertificateRequestInfo.SupportsCertificate
    /// Go: "SupportsCertificate returns nil if the provided certificate
    /// is supported by the server that sent the CertificateRequest.
    /// Otherwise, it returns an error describing the reason for the
    /// incompatibility."
    pub fn SupportsCertificate(&self, c: &Certificate) -> error {
        // Go: if _, err := selectSignatureScheme(cri.Version, c,
        //         cri.SignatureSchemes); err != nil { return err }
        let (_, err) =
            super::auth::selectSignatureScheme(self.Version, c, self.SignatureSchemes.clone());
        if err != errors::nil {
            return err;
        }

        // Go: if len(cri.AcceptableCAs) == 0 { return nil }
        if self.AcceptableCAs.Len() == 0 {
            return errors::nil;
        }

        // Go: for j, cert := range c.Certificate {
        //         x509Cert := c.Leaf
        //         // Parse the certificate if this isn't the leaf node, or if
        //         // chain.Leaf was nil.
        //         if j != 0 || x509Cert == nil {
        //             if x509Cert, err = x509.ParseCertificate(cert); err != nil {
        //                 return fmt.Errorf("failed to parse certificate #%d in the chain: %w", j, err) } }
        //         for _, ca := range cri.AcceptableCAs {
        //             if bytes.Equal(x509Cert.RawIssuer, ca) { return nil } } }
        for (j, cert) in crate::range!(c.Certificate.clone()) {
            let x509Cert: crate::crypto::x509::Certificate;
            if j != 0 || c.Leaf.is_none() {
                let (parsed, err) = crate::crypto::x509::ParseCertificate(cert.clone());
                if err != errors::nil {
                    return fmt::Errorf!(
                        "failed to parse certificate #%d in the chain: %s",
                        j,
                        err.Error()
                    );
                }
                x509Cert = parsed;
            } else {
                x509Cert = c.Leaf.clone().unwrap();
            }
            for (_, ca) in crate::range!(self.AcceptableCAs.clone()) {
                if x509Cert.RawIssuer == *ca {
                    return errors::nil;
                }
            }
        }
        // Go: return errors.New("chain is not signed by an acceptable CA")
        return errors::New("chain is not signed by an acceptable CA");
    }
}


// ─── The client session cache ─────────────────────────────────────────

// Go: common.go:594-604
//   type ClientSessionCache interface {
//       Get(sessionKey string) (session *ClientSessionState, ok bool)
//       Put(sessionKey string, cs *ClientSessionState)
//   }
/// Go: "ClientSessionCache is a cache of ClientSessionState objects that
/// can be used by a client to resume a TLS session with a given server.
/// ClientSessionCache implementations should expect to be called
/// concurrently from different goroutines."
pub trait ClientSessionCache: Send + Sync {
    /// Go: "Get searches for a ClientSessionState associated with the
    /// given key. On return, ok is true if one was found."
    fn Get(&mut self, sessionKey: crate::gostring::string)
        -> (Option<super::ticket::ClientSessionState>, bool);

    /// Go: "Put adds the ClientSessionState to the cache with the given
    /// key. It might get called multiple times in a connection if a TLS
    /// 1.3 server provides more than one session ticket. If called with
    /// a nil *ClientSessionState, it should remove the cache entry."
    fn Put(
        &mut self,
        sessionKey: crate::gostring::string,
        cs: Option<super::ticket::ClientSessionState>,
    );
}

// Go: common.go:1614-1617
//   type lruSessionCacheEntry struct { sessionKey string; state *ClientSessionState }
#[derive(Clone, Default)]
pub(crate) struct lruSessionCacheEntry {
    pub sessionKey: crate::gostring::string,
    pub state: Option<super::ticket::ClientSessionState>,
}

// Go: common.go:1606-1612
//   type lruSessionCache struct { sync.Mutex
//                                 m map[string]*list.Element
//                                 q *list.List; capacity int }
/// Go: "lruSessionCache is a ClientSessionCache implementation that uses
/// an LRU caching strategy."
///
/// Deviation: Go pairs a `map[string]*list.Element` with a
/// `container/list` so both lookup and reordering are O(1). goish has no
/// `container/list`, so the queue is a `Vec` ordered most-recently-used
/// first and the lookup is a scan of it. The default capacity is 64, so
/// the scan is bounded; the observable behaviour — which key is evicted,
/// and when — is identical. The `sync.Mutex` is gone for the same reason
/// `Config`'s is: the methods take `&mut self`.
pub struct lruSessionCache {
    pub(crate) q: Vec<lruSessionCacheEntry>,
    pub(crate) capacity: int,
}

// go: sdk 1.25.5 crypto/tls/common.go:1622-1633 NewLRUClientSessionCache
/// Go: "NewLRUClientSessionCache returns a [ClientSessionCache] with the
/// given capacity that uses an LRU strategy. If capacity is < 1, a
/// default capacity is used instead."
pub fn NewLRUClientSessionCache(capacity: int) -> lruSessionCache {
    // Go: const defaultSessionCacheCapacity = 64
    //     if capacity < 1 { capacity = defaultSessionCacheCapacity }
    const defaultSessionCacheCapacity: int = 64;
    let mut capacity = capacity;
    if capacity < 1 {
        capacity = defaultSessionCacheCapacity;
    }
    // Go: return &lruSessionCache{m: …, q: list.New(), capacity: capacity}
    return lruSessionCache {
        q: Vec::new(),
        capacity,
    };
}

impl ClientSessionCache for lruSessionCache {
    // go: sdk 1.25.5 crypto/tls/common.go:1637-1666 lruSessionCache.Put
    /// Go: "Put adds the provided (sessionKey, cs) pair to the cache. If
    /// cs is nil, the entry corresponding to sessionKey is removed from
    /// the cache instead."
    fn Put(
        &mut self,
        sessionKey: crate::gostring::string,
        cs: Option<super::ticket::ClientSessionState>,
    ) {
        // Go: if elem, ok := c.m[sessionKey]; ok {
        //         if cs == nil { c.q.Remove(elem); delete(c.m, sessionKey) }
        //         else { entry := elem.Value.(*lruSessionCacheEntry)
        //                entry.state = cs; c.q.MoveToFront(elem) }
        //         return }
        let mut at: Option<usize> = None;
        let mut i: usize = 0;
        while i < self.q.len() {
            if self.q[i].sessionKey == sessionKey {
                at = Some(i);
                break;
            }
            i += 1;
        }
        if at.is_some() {
            let i = at.unwrap();
            if cs.is_none() {
                self.q.remove(i);
            } else {
                let mut entry = self.q.remove(i);
                entry.state = cs;
                self.q.insert(0, entry);
            }
            return;
        }

        // Go: if c.q.Len() < c.capacity {
        //         entry := &lruSessionCacheEntry{sessionKey, cs}
        //         c.m[sessionKey] = c.q.PushFront(entry); return }
        if crate::int(self.q.len()) < self.capacity {
            self.q.insert(
                0,
                lruSessionCacheEntry {
                    sessionKey,
                    state: cs,
                },
            );
            return;
        }

        // Go: elem := c.q.Back()
        //     entry := elem.Value.(*lruSessionCacheEntry)
        //     delete(c.m, entry.sessionKey)
        //     entry.sessionKey = sessionKey; entry.state = cs
        //     c.q.MoveToFront(elem); c.m[sessionKey] = elem
        //
        // The oldest entry is reused rather than dropped and re-made,
        // which is why Go rewrites both of its fields in place.
        let mut entry = self.q.pop().unwrap();
        entry.sessionKey = sessionKey;
        entry.state = cs;
        self.q.insert(0, entry);
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1670-1679 lruSessionCache.Get
    /// Go: "Get returns the [ClientSessionState] value associated with a
    /// given key. It returns (nil, false) if no value is found."
    fn Get(
        &mut self,
        sessionKey: crate::gostring::string,
    ) -> (Option<super::ticket::ClientSessionState>, bool) {
        // Go: if elem, ok := c.m[sessionKey]; ok {
        //         c.q.MoveToFront(elem)
        //         return elem.Value.(*lruSessionCacheEntry).state, true }
        //     return nil, false
        let mut i: usize = 0;
        while i < self.q.len() {
            if self.q[i].sessionKey == sessionKey {
                let entry = self.q.remove(i);
                let state = entry.state.clone();
                self.q.insert(0, entry);
                return (state, true);
            }
            i += 1;
        }
        return (None, false);
    }
}


// ─── ConnectionState and the remaining Config accessors ───────────────

// Go: common.go:236-320
//   type ConnectionState struct { Version uint16; HandshakeComplete bool
//                                 DidResume bool; CipherSuite uint16; CurveID CurveID
//                                 NegotiatedProtocol string
//                                 NegotiatedProtocolIsMutual bool; ServerName string
//                                 PeerCertificates []*x509.Certificate
//                                 VerifiedChains [][]*x509.Certificate
//                                 SignedCertificateTimestamps [][]byte
//                                 OCSPResponse []byte; TLSUnique []byte
//                                 ECHAccepted bool
//                                 ekm func(string, []byte, int) ([]byte, error)
//                                 testingOnlyDidHRR bool
//                                 testingOnlyPeerSignatureAlgorithm SignatureScheme }
/// Go: "ConnectionState records basic TLS details about the connection."
///
/// Go's two `testingOnly*` fields are absent: they exist for in-package
/// tests, which goish cannot be.
#[derive(Clone, Default)]
pub struct ConnectionState {
    /// Go: "the TLS version used by the connection (e.g. VersionTLS12)."
    pub Version: uint16,
    /// Go: "true if the handshake has concluded."
    pub HandshakeComplete: bool,
    /// Go: "true if this connection was successfully resumed from a
    /// previous session with a session ticket or similar mechanism."
    pub DidResume: bool,
    /// Go: "the cipher suite negotiated for the connection."
    pub CipherSuite: uint16,
    /// Go: "the key exchange mechanism used."
    pub CurveID: CurveID,
    /// Go: "the application protocol negotiated with ALPN."
    pub NegotiatedProtocol: crate::gostring::string,
    /// Go: "Deprecated: this value is always true."
    pub NegotiatedProtocolIsMutual: bool,
    /// Go: "the value of the Server Name Indication extension sent by
    /// the client."
    pub ServerName: crate::gostring::string,
    /// Go: "the parsed certificates sent by the peer, in the order in
    /// which they were sent."
    pub PeerCertificates: slice<crate::crypto::x509::Certificate>,
    /// Go: "the certificate chains for the certificate presented by the
    /// peer."
    pub VerifiedChains: slice<slice<crate::crypto::x509::Certificate>>,
    /// Go: "a list of SCTs provided by the peer through the TLS
    /// handshake for the leaf certificate, if any."
    pub SignedCertificateTimestamps: slice<slice<byte>>,
    /// Go: "a stapled Online Certificate Status Protocol (OCSP) response
    /// provided by the peer for the leaf certificate, if any."
    pub OCSPResponse: slice<byte>,
    /// Go: "contains the 'tls-unique' channel binding value (see RFC
    /// 5929, Section 3)."
    pub TLSUnique: slice<byte>,
    /// Go: "indicates if Encrypted Client Hello was offered and
    /// successfully accepted by the server."
    pub ECHAccepted: bool,
    pub(crate) ekm:
        Option<alloc::sync::Arc<dyn Fn(crate::gostring::string, slice<byte>, int) -> (slice<byte>, error) + Send + Sync>>,
}

impl ConnectionState {

    // go: none — goish-only: `ekm` is unexported in Go, where the tests
    // are in-package. Selects one of prf[rs]'s two refusal hooks.
    #[doc(hidden)]
    pub fn __setEKM(&mut self, renegotiation: bool) {
        if renegotiation {
            self.ekm = Some(alloc::sync::Arc::new(|l, c, n| {
                super::prf::noEKMBecauseRenegotiation(l, c, n)
            }));
        } else {
            self.ekm = Some(alloc::sync::Arc::new(|l, c, n| {
                super::prf::noEKMBecauseNoEMS(l, c, n)
            }));
        }
    }


    // go: none — goish-only: see `__setEKM`. Installs the connection's
    // own exporter, which is what Go's `state.ekm = c.ekm` does.
    #[doc(hidden)]
    pub fn __setEKMHook(
        &mut self,
        f: Option<alloc::sync::Arc<dyn Fn(crate::gostring::string, slice<byte>, int) -> (slice<byte>, error) + Send + Sync>>,
    ) {
        self.ekm = f;
    }

    // go: sdk 1.25.5 crypto/tls/common.go:326-328 ConnectionState.ExportKeyingMaterial
    /// Go: "ExportKeyingMaterial returns length bytes of exported key
    /// material in a new slice as defined in RFC 5705. If context is nil,
    /// it is not used as part of the seed. If the connection was set to
    /// allow renegotiation via Config.Renegotiation, or if the
    /// connections supports neither TLS 1.3 nor Extended Master Secret,
    /// this function will return an error."
    ///
    /// Deviation: Go calls `cs.ekm` unconditionally, so a zero
    /// ConnectionState panics on a nil func value. goish panics with a
    /// message instead of a nil dereference; both are a panic, and
    /// neither is reachable from a completed handshake, which always
    /// sets `ekm` to one of the three functions prf[rs] declares.
    pub fn ExportKeyingMaterial(
        &self,
        label: crate::gostring::string,
        context: slice<byte>,
        length: int,
    ) -> (slice<byte>, error) {
        // Go: return cs.ekm(label, context, length)
        if self.ekm.is_none() {
            panic!("tls: ExportKeyingMaterial on a ConnectionState with no handshake");
        }
        return (self.ekm.clone().unwrap())(label, context, length);
    }
}

crate::var! {
    /// Go: `var errNoCertificates = errors.New("tls: no certificates configured")`
    pub(crate) errNoCertificates: error = "tls: no certificates configured";
}

impl Config {
    // go: sdk 1.25.5 crypto/tls/common.go:1440-1481 Config.getCertificate
    /// Go: "getCertificate returns the best certificate for the given
    /// ClientHelloInfo, defaulting to the first element of
    /// c.Certificates. If there are no certificates configured, it
    /// returns errNoCertificates."
    ///
    /// Deviation: Go consults the `GetCertificate` callback first; goish's
    /// Config has no such field, so that branch is unreachable and the
    /// selection starts at `c.Certificates`.
    pub(crate) fn getCertificate(
        &self,
        clientHello: &ClientHelloInfo,
    ) -> (Certificate, error) {
        // Go: if c.GetCertificate != nil && (len(c.Certificates) == 0 ||
        //         len(clientHello.ServerName) > 0) {
        //         cert, err := c.GetCertificate(clientHello)
        //         if cert != nil || err != nil { return cert, err } }

        // Go: if len(c.Certificates) == 0 { return nil, errNoCertificates }
        if self.Certificates.Len() == 0 {
            return (Certificate::default(), errNoCertificates.into());
        }

        // Go: if len(c.Certificates) == 1 {
        //         // There's only one choice, so no point doing any work.
        //         return &c.Certificates[0], nil }
        if self.Certificates.Len() == 1 {
            return (self.Certificates[0].clone(), errors::nil);
        }

        // Go: if c.NameToCertificate != nil {
        //         name := strings.ToLower(clientHello.ServerName)
        //         if cert, ok := c.NameToCertificate[name]; ok { return cert, nil }
        //         if len(name) > 0 {
        //             labels := strings.Split(name, ".")
        //             labels[0] = "*"
        //             wildcardName := strings.Join(labels, ".")
        //             if cert, ok := c.NameToCertificate[wildcardName]; ok { return cert, nil } } }
        if self.NameToCertificate.Len() > 0 {
            let name = crate::strings::ToLower(clientHello.ServerName.clone());
            let (cert, ok) = self.NameToCertificate.Get(name.clone());
            if ok {
                return (cert, errors::nil);
            }
            if name.Len() > 0 {
                let mut labels = crate::strings::Split(name, ".");
                labels[0] = crate::gostring::string::from_static("*");
                let wildcardName = crate::strings::Join(labels, ".");
                let (cert, ok) = self.NameToCertificate.Get(wildcardName);
                if ok {
                    return (cert, errors::nil);
                }
            }
        }

        // Go: for _, cert := range c.Certificates {
        //         if err := clientHello.SupportsCertificate(&cert); err == nil {
        //             return &cert, nil } }
        for (_, cert) in crate::range!(self.Certificates.clone()) {
            if clientHello.SupportsCertificate(cert) == errors::nil {
                return (cert.clone(), errors::nil);
            }
        }

        // Go: If nothing matches, return the first certificate.
        return (self.Certificates[0].clone(), errors::nil);
    }

    // go: sdk 1.25.5 crypto/tls/common.go:1545-1557 Config.writeKeyLog
    /// Write a NSS key-log line, if `KeyLogWriter` is set.
    ///
    /// Deviation: goish's Config has no `KeyLogWriter` field — it holds
    /// an `io.Writer` interface value, which goish cannot store in a
    /// `Clone`-able record without a shareable wrapper — so this always
    /// takes Go's nil branch and returns nil. The line format is ported
    /// anyway, because it is the part a future field has to match.
    pub(crate) fn writeKeyLog(
        &self,
        _label: crate::gostring::string,
        _clientRandom: slice<byte>,
        _secret: slice<byte>,
    ) -> error {
        // Go: if c.KeyLogWriter == nil { return nil }
        //     logLine := fmt.Appendf(nil, "%s %x %x\n", label, clientRandom, secret)
        //     writerMutex.Lock()
        //     _, err := c.KeyLogWriter.Write(logLine)
        //     writerMutex.Unlock()
        //     return err
        return errors::nil;
    }
}

// go: none — goish-only: the NSS key-log line Go builds with
// `fmt.Appendf(nil, "%s %x %x\n", …)`. Named so that wiring a
// `KeyLogWriter` field up later is one call, and so the format is
// diffable against Go today.
pub(crate) fn keyLogLine(
    label: crate::gostring::string,
    clientRandom: slice<byte>,
    secret: slice<byte>,
) -> slice<byte> {
    let line = fmt::Sprintf!(
        "%s %s %s\n",
        label,
        crate::encoding::hex::EncodeToString(&clientRandom),
        crate::encoding::hex::EncodeToString(&secret)
    );
    return slice::__from_vec(line.as_bytes().to_vec());
}


// Go: common.go:529-542
//   type RenegotiationSupport int
//   const ( RenegotiateNever RenegotiationSupport = iota
//           RenegotiateOnceAsClient; RenegotiateFreelyAsClient )
/// Go: "RenegotiationSupport enumerates the different levels of support
/// for TLS renegotiation. TLS renegotiation is the act of performing
/// subsequent handshakes on a connection after the first."
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct RenegotiationSupport(pub int);
/// Go: "RenegotiateNever disables renegotiation."
pub const RenegotiateNever: RenegotiationSupport = RenegotiationSupport(0);
/// Go: "RenegotiateOnceAsClient allows a remote server to request
/// renegotiation once per connection."
pub const RenegotiateOnceAsClient: RenegotiationSupport = RenegotiationSupport(1);
/// Go: "RenegotiateFreelyAsClient allows a remote server to repeatedly
/// request renegotiation."
pub const RenegotiateFreelyAsClient: RenegotiationSupport = RenegotiationSupport(2);

// ── the handshake-message interfaces ────────────────────────────────

// Go: common.go:1590-1593
//   type handshakeMessage interface {
//       marshal() ([]byte, error)
//       unmarshal([]byte) bool
//   }
/// Go's `handshakeMessage` — the shape every wire message shares, so
/// that `Conn.unmarshalHandshakeMessage` can pick a concrete type from
/// the message byte and hand it back behind one pointer.
///
/// Deviations, both forced by Rust having no interface-to-interface
/// type assertion:
///
///  - `asAny` is added so a caller can recover the concrete message,
///    the way Go writes `msg.(*serverHelloMsg)` on the `any` that
///    `readHandshake` returns.
///  - `asWithOriginalBytes` is added so `transcriptMsg` can perform
///    Go's `msg.(handshakeMessageWithOriginalBytes)` assertion. It
///    defaults to `None`; the two types that keep their original wire
///    bytes override it.
pub(crate) trait handshakeMessage {
    /// Go: `marshal() ([]byte, error)`
    fn marshal(&self) -> (crate::goslice::slice<crate::types::byte>, crate::error);
    /// Go: `unmarshal([]byte) bool`
    fn unmarshal(&mut self, data: crate::goslice::slice<crate::types::byte>) -> bool;
    /// goish-only: stands in for Go's type assertion on the returned `any`.
    fn asAny(&self) -> &dyn core::any::Any;
    // go: none — goish-only: stands in for Go's
    // `msg.(handshakeMessageWithOriginalBytes)` assertion. Defaults to
    // `None`; the two types that keep their wire bytes override it.
    fn asWithOriginalBytes(&self) -> Option<&dyn handshakeMessageWithOriginalBytes> {
        return None;
    }
}

// Go: common.go:1595-1602
//   type handshakeMessageWithOriginalBytes interface {
//       handshakeMessage
//       originalBytes() []byte
//   }
/// Go's `handshakeMessageWithOriginalBytes`. Go: "originalBytes should
/// return the original bytes that were passed to unmarshal to create
/// the message. If the message was not produced by unmarshal, it should
/// return nil."
pub(crate) trait handshakeMessageWithOriginalBytes: handshakeMessage {
    /// Go: `originalBytes() []byte`
    fn originalBytes(&self) -> crate::goslice::slice<crate::types::byte>;
}
