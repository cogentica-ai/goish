// go: file crypto/tls/defaults_fips140.go decls: isCertificateAllowedFIPS
//
// crypto/tls — the FIPS 140-3 filters.
//
// Go: "These FIPS 140-3 policies allow anything approved by SP 800-140C
// and SP 800-140D, and tested as part of the Go Cryptographic Module.
//
// Notably, not SHA-1, 3DES, RC4, ChaCha20Poly1305, RSA PKCS #1 v1.5 key
// transport, or TLS 1.0—1.1 (because we don't test its KDF).
//
// These are not default lists, but filters to apply to the default or
// configured lists. Missing items are treated as if they were not
// implemented.
//
// They are applied when the fips140 GODEBUG is "on" or "only"."
//
// The five tables are `var` in Go and `const` here; nothing mutates
// them.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

use super::cipher_suites::{
    TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
};
use super::common::{
    CurveID, SignatureScheme, CurveP256, CurveP384, CurveP521, ECDSAWithP256AndSHA256,
    ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, Ed25519, PKCS1WithSHA256, PKCS1WithSHA384,
    PKCS1WithSHA512, PSSWithSHA256, PSSWithSHA384, PSSWithSHA512, VersionTLS12, VersionTLS13,
    X25519MLKEM768,
};
use crate::crypto::x509;
use crate::types::uint16;

// Go: defaults_fips140.go:28-31
pub(crate) const allowedSupportedVersionsFIPS: &[uint16] = &[VersionTLS12, VersionTLS13];

// Go: defaults_fips140.go:32-37
pub(crate) const allowedCurvePreferencesFIPS: &[CurveID] =
    &[X25519MLKEM768, CurveP256, CurveP384, CurveP521];

// Go: defaults_fips140.go:38-49
pub(crate) const allowedSignatureAlgorithmsFIPS: &[SignatureScheme] = &[
    PSSWithSHA256,
    ECDSAWithP256AndSHA256,
    Ed25519,
    PSSWithSHA384,
    PSSWithSHA512,
    PKCS1WithSHA256,
    PKCS1WithSHA384,
    PKCS1WithSHA512,
    ECDSAWithP384AndSHA384,
    ECDSAWithP521AndSHA512,
];

// Go: defaults_fips140.go:50-57
pub(crate) const allowedCipherSuitesFIPS: &[uint16] = &[
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
];

// Go: defaults_fips140.go:58-61
pub(crate) const allowedCipherSuitesTLS13FIPS: &[uint16] =
    &[TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384];

// go: sdk 1.25.5 crypto/tls/defaults_fips140.go:64-75 isCertificateAllowedFIPS
/// Whether a certificate's public key is one FIPS 140-3 permits: RSA of
/// at least 2048 bits, ECDSA on P-256/384/521, or Ed25519.
pub(crate) fn isCertificateAllowedFIPS(c: &x509::Certificate) -> bool {
    // Go: switch k := c.PublicKey.(type) {
    //     case *rsa.PublicKey: return k.N.BitLen() >= 2048
    if let Some(k) = c.PublicKey.As::<crate::crypto::rsa::PublicKey>() {
        return k.N.BitLen() >= 2048;
    }
    //     case *ecdsa.PublicKey:
    //         return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() ||
    //                k.Curve == elliptic.P521()
    if let Some(k) = c.PublicKey.As::<crate::crypto::ecdsa::PublicKey>() {
        let name = k.Curve.Params().Name.clone();
        return name == crate::gostring::string::from_static("P-256")
            || name == crate::gostring::string::from_static("P-384")
            || name == crate::gostring::string::from_static("P-521");
    }
    //     case ed25519.PublicKey: return true
    if c.PublicKey
        .As::<crate::crypto::ed25519::PublicKey>()
        .is_some()
    {
        return true;
    }
    //     default: return false
    return false;
}
