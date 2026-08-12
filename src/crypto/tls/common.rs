// go: file crypto/tls/common.go decls: VersionName, isTLS13OnlyKeyExchange, isPQKeyExchange, requiresClientCert
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
// goishlint:ignore GOISH018 BuildNameToCertificate, CertificateVerificationError, CipherSuiteName, CipherSuites, Clone, Context, Error, ExportKeyingMaterial, Get, InsecureCipherSuites, NewLRUClientSessionCache, Put, RenegotiateFreelyAsClient, RenegotiateNever, RenegotiateOnceAsClient, SetSessionTicketKeys, SupportsCertificate, Unwrap, aeadModes, aesgcmCiphers, certTypeECDSASign, certTypeRSASign, curvePreferences, decodeCipherSuites, defaultCipherSuites, defaultCipherSuitesTLS13, defaultConfig, deprecatedSessionTicketKey, echField, emptyConfig, errNoCertificates, fips140tls, fipsAllowChain, fipsAllowedChains, getCertificate, handshakeMessage, handshakeMessageWithOriginalBytes, hasAESGCMHardwareSupport, initLegacySessionTicketKeyRLocked, isDisabledSignatureAlgorithm, isSupportedSignatureAlgorithm, leaf, lruSessionCache, lruSessionCacheEntry, maxSupportedVersion, mutualVersion, needFIPS, rand, roleClient, roleServer, rsaKexCiphers, supportedCipherSuites, supportedSignatureAlgorithms, supportedSignatureAlgorithmsCert, supportedVersions, supportedVersionsFromMax, supportsCurve, supportsSignatureAlgorithm, testingOnlyForceDowngradeCanary, testingOnlySupportedSignatureAlgorithms, ticketKeyFromBytes, ticketKeyLifetime, ticketKeyRotation, ticketKeys, time, tls10server, tlsrsakex, tlssha1, tlsunsafeekm, unexpectedMessageError, writeKeyLog, writerMutex — Config, ConnectionState, the session cache and the handshake-message machinery, none of which is ported yet; see the banner.
// goishlint:ignore GOISH019 recordType, keyShare, pskIdentity, ConnectionState, ClientSessionCache, ClientHelloInfo, CertificateRequestInfo, RenegotiationSupport, Config, EncryptedClientHelloKey, ticketKey, Certificate, dsaSignature, ecdsaSignature — same.
// goishlint:ignore GOISH021 Certificate, CertificateRequestInfo, CertificateVerificationError, ClientHelloInfo, ClientSessionCache, Config, ConnectionState, EncryptedClientHelloKey, Error, Get, NewLRUClientSessionCache, Put, RenegotiateFreelyAsClient, RenegotiateNever, RenegotiateOnceAsClient, RenegotiationSupport, Unwrap, certTypeECDSASign, certTypeRSASign, compressionNone, defaultCipherSuitesFIPS, defaultConfig, defaultCurvePreferences, defaultCurvePreferencesFIPS, defaultSupportedSignatureAlgorithmsFIPS, defaultSupportedVersionsFIPS, deprecatedSessionTicketKey, directSigning, downgradeCanaryTLS11, downgradeCanaryTLS12, dsaSignature, ecdsaSignature, emptyConfig, errEarlyCloseWrite, errNoCertificates, errShutdown, extensionALPN, extensionCertificateAuthorities, extensionCookie, extensionECHOuterExtensions, extensionEarlyData, extensionEncryptedClientHello, extensionEncryptedClientHelloOuterExtensions, extensionExtendedMasterSecret, extensionKeyShare, extensionPSKModes, extensionPreSharedKey, extensionQUICTransportParameters, extensionRenegotiationInfo, extensionSCT, extensionServerName, extensionSessionTicket, extensionSignatureAlgorithms, extensionSignatureAlgorithmsCert, extensionStatusRequest, extensionSupportedCurves, extensionSupportedPoints, extensionSupportedVersions, fipsAllowChain, fipsAllowedChains, handshakeMessage, handshakeMessageWithOriginalBytes, helloRetryRequestRandom, isDisabledSignatureAlgorithm, keyLogLabelClientHandshake, keyLogLabelClientTraffic, keyLogLabelEarlyTraffic, keyLogLabelServerHandshake, keyLogLabelServerTraffic, keyLogLabelTLS12, keyShare, leaf, lruSessionCache, lruSessionCacheEntry, maxCiphertext, maxCiphertextTLS13, maxHandshake, maxHandshakeCertificateMsg, maxPlaintext, maxSessionTicketLifetime, maxUselessBytes, maxUselessRecords, pointFormatUncompressed, pskIdentity, pskModeDHE, pskModePlain, rand, recordHeaderLen, recordType, recordTypeAlert, recordTypeApplicationData, recordTypeChangeCipherSpec, recordTypeHandshake, roleClient, roleServer, scsvRenegotiation, signatureECDSA, signatureEd25519, signaturePKCS1v15, signatureRSAPSS, statusTypeOCSP, supportedCipherSuites, supportedSignatureAlgorithms, supportedSignatureAlgorithmsCert, supportedVersions, testingOnlyForceDowngradeCanary, testingOnlySupportedSignatureAlgorithms, ticketKey, ticketKeyLifetime, ticketKeyRotation, time, tls10server, tlssha1, typeCertificate, typeCertificateRequest, typeCertificateStatus, typeCertificateVerify, typeClientHello, typeClientKeyExchange, typeEncryptedExtensions, typeEndOfEarlyData, typeFinished, typeHelloRequest, typeKeyUpdate, typeMessageHash, typeNewSessionTicket, typeServerHello, typeServerHelloDone, typeServerKeyExchange, writerMutex — same.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use crate::fmt;
use crate::gostring::string;
use crate::types::{int, uint16, uint8};

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
