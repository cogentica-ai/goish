// go: file crypto/tls/auth.go decls: verifyHandshakeSignature, signedMessage, typeAndHashFromSignatureScheme, legacyTypeAndHashFromPublicKey, signatureSchemesForPublicKey, selectSignatureScheme, unsupportedCertificateError
//
// crypto/tls — handshake signature verification and signature-scheme
// selection.
//
// **Partial port.** `selectSignatureScheme` and
// `unsupportedCertificateError` take a `*Certificate`, which is not yet
// a port (mod[rs] declares a hand-written one) — they land with
// common.go's Certificate. Everything else in auth.go is here.
//
// goishlint:ignore GOISH018  — both take a *Certificate, which is not ported yet; see the banner.
// goishlint:ignore GOISH021 rsaSignatureSchemes — the table only selectSignatureScheme reads.
//
// One further deviation: Go's error strings for a wrong key type end
// with `%T` — the dynamic Go type of the value. goish's `Any` has no
// `%T` rendering (the dynamic type is only recoverable through the
// downcast registry, which answers "is it a T", not "what is it"), so
// those four messages stop at the fixed prefix. Everything before the
// type name is verbatim.

#![allow(non_snake_case, dead_code)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use super::common::{
    directSigning, signatureECDSA, signatureEd25519, signaturePKCS1v15, signatureRSAPSS,
    ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, ECDSAWithSHA1, Ed25519,
    PKCS1WithSHA1, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PSSWithSHA256, PSSWithSHA384,
    PSSWithSHA512, SignatureScheme,
};
use crate::crypto;
use crate::crypto::ecdsa;
use crate::crypto::ed25519;
use crate::crypto::elliptic;
use crate::crypto::rsa;
use crate::error;
use crate::goany::Any;
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::Hash as HashTrait;
use crate::io::Writer as _;
use crate::types::{byte, int, uint16, uint8};

// go: sdk 1.25.5 crypto/tls/auth.go:23-61 verifyHandshakeSignature
/// Verify a signature against pre-hashed (if required) handshake
/// contents.
pub(crate) fn verifyHandshakeSignature(
    sigType: uint8,
    pubkey: &Any,
    hashFunc: crypto::Hash,
    signed: slice<byte>,
    sig: slice<byte>,
) -> error {
    // Go: switch sigType { case signatureECDSA: … }
    if sigType == signatureECDSA {
        // Go: pubKey, ok := pubkey.(*ecdsa.PublicKey)
        let pubKey = match pubkey.As::<ecdsa::PublicKey>() {
            Some(k) => k,
            None => return crate::errors::New("expected an ECDSA public key"),
        };
        // Go: if !ecdsa.VerifyASN1(pubKey, signed, sig) { … }
        if !ecdsa::VerifyASN1(pubKey, &signed, &sig) {
            return crate::errors::New("ECDSA verification failure");
        }
    } else if sigType == signatureEd25519 {
        // Go: pubKey, ok := pubkey.(ed25519.PublicKey)
        let pubKey = match pubkey.As::<ed25519::PublicKey>() {
            Some(k) => k,
            None => return crate::errors::New("expected an Ed25519 public key"),
        };
        // Go: if !ed25519.Verify(pubKey, signed, sig) { … }
        if !ed25519::Verify(pubKey, signed, sig) {
            return crate::errors::New("Ed25519 verification failure");
        }
    } else if sigType == signaturePKCS1v15 {
        // Go: pubKey, ok := pubkey.(*rsa.PublicKey)
        let pubKey = match pubkey.As::<rsa::PublicKey>() {
            Some(k) => k,
            None => return crate::errors::New("expected an RSA public key"),
        };
        // Go: if err := rsa.VerifyPKCS1v15(pubKey, hashFunc, signed, sig); err != nil { return err }
        let err = rsa::VerifyPKCS1v15(pubKey, hashFunc, signed, sig);
        if err != crate::errors::nil {
            return err;
        }
    } else if sigType == signatureRSAPSS {
        // Go: pubKey, ok := pubkey.(*rsa.PublicKey)
        let pubKey = match pubkey.As::<rsa::PublicKey>() {
            Some(k) => k,
            None => return crate::errors::New("expected an RSA public key"),
        };
        // Go: signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
        let signOpts = rsa::PSSOptions {
            SaltLength: rsa::PSSSaltLengthEqualsHash,
            Hash: hashFunc,
        };
        // Go: if err := rsa.VerifyPSS(pubKey, hashFunc, signed, sig, signOpts); err != nil { return err }
        let err = rsa::VerifyPSS(pubKey, hashFunc, signed, sig, Some(&signOpts));
        if err != crate::errors::nil {
            return err;
        }
    } else {
        // Go: default: return errors.New("internal error: unknown signature type")
        return crate::errors::New("internal error: unknown signature type");
    }
    // Go: return nil
    return crate::errors::nil;
}

// Go: auth.go:63-66
//   const ( serverSignatureContext = "TLS 1.3, server CertificateVerify\x00"
//           clientSignatureContext = "TLS 1.3, client CertificateVerify\x00" )
pub(crate) const serverSignatureContext: &str = "TLS 1.3, server CertificateVerify\x00";
pub(crate) const clientSignatureContext: &str = "TLS 1.3, client CertificateVerify\x00";

// Go: auth.go:68-77
//   var signaturePadding = []byte{0x20 × 64}
/// 64 spaces, per RFC 8446 §4.4.3.
pub(crate) const signaturePadding: &[byte] = &[0x20u8; 64];

// go: sdk 1.25.5 crypto/tls/auth.go:82-96 signedMessage
/// The pre-hashed (if necessary) message to be signed by certificate
/// keys in TLS 1.3. See RFC 8446, Section 4.4.3.
pub(crate) fn signedMessage(
    sigHash: crypto::Hash,
    context: &str,
    transcript: &mut dyn HashTrait,
) -> slice<byte> {
    // Go: if sigHash == directSigning {
    //         b := &bytes.Buffer{}; b.Write(signaturePadding)
    //         io.WriteString(b, context); b.Write(transcript.Sum(nil))
    //         return b.Bytes()
    //     }
    if sigHash == directSigning {
        let mut b: Vec<byte> = Vec::new();
        b.extend_from_slice(signaturePadding);
        b.extend_from_slice(context.as_bytes());
        let t = transcript.Sum(slice::__from_vec(Vec::new()));
        let raw: &[byte] = &t;
        b.extend_from_slice(raw);
        return slice::__from_vec(b);
    }
    // Go: h := sigHash.New(); h.Write(signaturePadding)
    //     io.WriteString(h, context); h.Write(transcript.Sum(nil))
    //     return h.Sum(nil)
    let mut h = sigHash.New();
    let _ = h.Write(slice::__from_vec(signaturePadding.to_vec()));
    let _ = h.Write(slice::__from_vec(context.as_bytes().to_vec()));
    let t = transcript.Sum(slice::__from_vec(Vec::new()));
    let _ = h.Write(t);
    return h.Sum(slice::__from_vec(Vec::new()));
}

// go: sdk 1.25.5 crypto/tls/auth.go:99-128 typeAndHashFromSignatureScheme
/// The signature type and `crypto.Hash` for a given TLS
/// [`SignatureScheme`].
pub(crate) fn typeAndHashFromSignatureScheme(
    signatureAlgorithm: SignatureScheme,
) -> (uint8, crypto::Hash, error) {
    // Go: switch signatureAlgorithm { … sigType … }
    let sigType: uint8 = match signatureAlgorithm {
        PKCS1WithSHA1 | PKCS1WithSHA256 | PKCS1WithSHA384 | PKCS1WithSHA512 => signaturePKCS1v15,
        PSSWithSHA256 | PSSWithSHA384 | PSSWithSHA512 => signatureRSAPSS,
        ECDSAWithSHA1
        | ECDSAWithP256AndSHA256
        | ECDSAWithP384AndSHA384
        | ECDSAWithP521AndSHA512 => signatureECDSA,
        Ed25519 => signatureEd25519,
        // Go: default: return 0, 0, fmt.Errorf("unsupported signature algorithm: %v", …)
        _ => {
            return (
                0,
                crypto::Hash(0),
                crate::fmt::Errorf!(
                    "unsupported signature algorithm: %v",
                    signatureAlgorithm.String()
                ),
            )
        }
    };
    // Go: switch signatureAlgorithm { … hash … }
    let hash: crypto::Hash = match signatureAlgorithm {
        PKCS1WithSHA1 | ECDSAWithSHA1 => crypto::SHA1,
        PKCS1WithSHA256 | PSSWithSHA256 | ECDSAWithP256AndSHA256 => crypto::SHA256,
        PKCS1WithSHA384 | PSSWithSHA384 | ECDSAWithP384AndSHA384 => crypto::SHA384,
        PKCS1WithSHA512 | PSSWithSHA512 | ECDSAWithP521AndSHA512 => crypto::SHA512,
        Ed25519 => directSigning,
        _ => {
            return (
                0,
                crypto::Hash(0),
                crate::fmt::Errorf!(
                    "unsupported signature algorithm: %v",
                    signatureAlgorithm.String()
                ),
            )
        }
    };
    // Go: return sigType, hash, nil
    return (sigType, hash, crate::errors::nil);
}

// go: sdk 1.25.5 crypto/tls/auth.go:132-147 legacyTypeAndHashFromPublicKey
/// The fixed signature type and `crypto.Hash` for a given public key
/// used with TLS 1.0 and 1.1, before signature-algorithm negotiation.
pub(crate) fn legacyTypeAndHashFromPublicKey(pub_: &Any) -> (uint8, crypto::Hash, error) {
    // Go: switch pub.(type) { case *rsa.PublicKey: … }
    if pub_.As::<rsa::PublicKey>().is_some() {
        return (signaturePKCS1v15, crypto::MD5SHA1, crate::errors::nil);
    }
    if pub_.As::<ecdsa::PublicKey>().is_some() {
        return (signatureECDSA, crypto::SHA1, crate::errors::nil);
    }
    if pub_.As::<ed25519::PublicKey>().is_some() {
        // Go: RFC 8422 specifies support for Ed25519 in TLS 1.0 and 1.1,
        // but it requires holding on to a handshake transcript to do a
        // full signature, and not even OpenSSL bothers with the
        // complexity, so we can't even test it properly.
        return (
            0,
            crypto::Hash(0),
            crate::errors::New("tls: Ed25519 public keys are not supported before TLS 1.2"),
        );
    }
    // Go: default: return 0, 0, fmt.Errorf("tls: unsupported public key: %T", pub)
    return (
        0,
        crypto::Hash(0),
        crate::errors::New("tls: unsupported public key"),
    );
}

// go: none — goish idiom: Go declares this as a package-level `var` of
// an anonymous-struct slice (auth.go:151-164). goish has no const slice
// of tuples, so it is a function returning the same table. The minimum
// modulus sizes are computed from the hash sizes rather than written
// out, exactly as Go does, so a hash-size change tracks.
fn rsaSignatureSchemes() -> [(SignatureScheme, int); 7] {
    return [
        // RSA-PSS is used with PSSSaltLengthEqualsHash, and requires
        //    emLen >= hLen + sLen + 2
        (PSSWithSHA256, crypto::SHA256.Size() * 2 + 2),
        (PSSWithSHA384, crypto::SHA384.Size() * 2 + 2),
        (PSSWithSHA512, crypto::SHA512.Size() * 2 + 2),
        // PKCS #1 v1.5 uses prefixes from hashPrefixes in crypto/rsa,
        // and requires emLen >= len(prefix) + hLen + 11
        (PKCS1WithSHA256, 19 + crypto::SHA256.Size() + 11),
        (PKCS1WithSHA384, 19 + crypto::SHA384.Size() + 11),
        (PKCS1WithSHA512, 19 + crypto::SHA512.Size() + 11),
        (PKCS1WithSHA1, 15 + crypto::SHA1.Size() + 11),
    ];
}

// go: sdk 1.25.5 crypto/tls/auth.go:166-202 signatureSchemesForPublicKey
/// The signature schemes supported by a given public key, in Go's
/// preference order. Each branch returns directly, as Go's does.
pub(crate) fn signatureSchemesForPublicKey(version: uint16, pub_: &Any) -> slice<SignatureScheme> {
    // Go: switch pub := pub.(type) { case *ecdsa.PublicKey: … }
    if let Some(p) = pub_.As::<ecdsa::PublicKey>() {
        // Go: if version < VersionTLS13 {
        //         // In TLS 1.2 and earlier, ECDSA algorithms are not
        //         // constrained to a single curve.
        //         return []SignatureScheme{…four…}
        //     }
        if version < super::common::VersionTLS13 {
            return slice::__from_vec(alloc::vec![
                ECDSAWithP256AndSHA256,
                ECDSAWithP384AndSHA384,
                ECDSAWithP521AndSHA512,
                ECDSAWithSHA1,
            ]);
        }
        // Go: switch pub.Curve { case elliptic.P256(): … default: return nil }
        //
        // Go compares interface identity; goish's `Curve` is a trait
        // object, so the comparison goes through the curve's name — the
        // same way crypto/ecdsa's own `curveName` does it.
        let c = p.Curve.Params().Name;
        if c == elliptic::P256().Params().Name {
            return slice::__from_vec(alloc::vec![ECDSAWithP256AndSHA256]);
        }
        if c == elliptic::P384().Params().Name {
            return slice::__from_vec(alloc::vec![ECDSAWithP384AndSHA384]);
        }
        if c == elliptic::P521().Params().Name {
            return slice::__from_vec(alloc::vec![ECDSAWithP521AndSHA512]);
        }
        return slice::__from_vec(Vec::new());
    }
    // Go: case *rsa.PublicKey:
    //         size := pub.Size()
    //         sigAlgs := make([]SignatureScheme, 0, len(rsaSignatureSchemes))
    //         for _, candidate := range rsaSignatureSchemes {
    //             if size >= candidate.minModulusBytes { sigAlgs = append(…) }
    //         }
    //         return sigAlgs
    if let Some(p) = pub_.As::<rsa::PublicKey>() {
        let size = p.Size();
        let mut sigAlgs: Vec<SignatureScheme> = Vec::new();
        for (scheme, minModulusBytes) in rsaSignatureSchemes() {
            if size >= minModulusBytes {
                sigAlgs.push(scheme);
            }
        }
        return slice::__from_vec(sigAlgs);
    }
    // Go: case ed25519.PublicKey: return []SignatureScheme{Ed25519}
    if pub_.As::<ed25519::PublicKey>().is_some() {
        return slice::__from_vec(alloc::vec![Ed25519]);
    }
    // Go: default: return nil
    return slice::__from_vec(Vec::new());
}

// Silence the unused-import warning for `Box` in builds where no arm
// needs it; the signature of `sigHash.New()` returns one.
const _: Option<Box<u8>> = None;

// ─── Certificate-driven scheme selection ──────────────────────────────

// go: none — goish-only: Go's `crypto.PublicKey` is one `any`; goish has
// two carriers for it — `goany::Any`, which is what x509 parses into and
// what `signatureSchemesForPublicKey` takes, and `crypto::PublicKey`, an
// `Arc<dyn core::any::Any>`, which is what `Signer.Public` returns. This
// re-wraps the latter as the former so the scheme table has one body
// rather than two.
pub(crate) fn anyOfPublicKey(pub_: &crypto::PublicKey) -> Any {
    if let Some(k) = pub_.downcast_ref::<ecdsa::PublicKey>() {
        return Any::new_fn(k.clone());
    }
    if let Some(k) = pub_.downcast_ref::<rsa::PublicKey>() {
        return Any::new_fn(k.clone());
    }
    if let Some(k) = pub_.downcast_ref::<ed25519::PublicKey>() {
        return Any::new_fn(k.clone());
    }
    return Any::new_fn(());
}

// go: none — goish-only: `crypto::PrivateKey` is `Arc<dyn core::any::Any>`,
// and `.As::<dyn Signer>()` on it resolves through the *blanket*
// `HasDynAny for T: Sized` (goany.rs:635), which hands back the Arc's
// own TypeId — so the registry lookup can only miss, silently. The
// payload has to be dereferenced first, which is exactly what
// `goany::Any::As` does internally. x509's CreateCertificate is safe
// because it takes a `goany::Any`, not a `crypto::PrivateKey`.
pub(crate) fn signerOf(key: &crypto::PrivateKey) -> Option<&(dyn crypto::Signer + Send + Sync)> {
    return <dyn crypto::Signer + Send + Sync as crate::goany::DowncastableFromAny>::from_any(
        &**key,
    );
}

// go: sdk 1.25.5 crypto/tls/auth.go:208-245 selectSignatureScheme
/// Pick the signature scheme to sign the handshake with, in the *peer's*
/// preference order — ours is not configurable.
pub(crate) fn selectSignatureScheme(
    vers: uint16,
    c: &super::Certificate,
    peerAlgs: slice<SignatureScheme>,
) -> (SignatureScheme, error) {
    // Go: priv, ok := c.PrivateKey.(crypto.Signer)
    //     if !ok { return 0, unsupportedCertificateError(c) }
    let priv_ = signerOf(&c.PrivateKey);
    if priv_.is_none() {
        return (SignatureScheme(0), unsupportedCertificateError(c));
    }
    // Go: supportedAlgs := signatureSchemesForPublicKey(vers, priv.Public())
    let pubAny = anyOfPublicKey(&priv_.unwrap().Public());
    let mut supportedAlgs = signatureSchemesForPublicKey(vers, &pubAny);
    // Go: if c.SupportedSignatureAlgorithms != nil {
    //         supportedAlgs = slices.DeleteFunc(supportedAlgs, func(sigAlg SignatureScheme) bool {
    //             return !isSupportedSignatureAlgorithm(sigAlg, c.SupportedSignatureAlgorithms) })
    //     }
    if c.SupportedSignatureAlgorithms.Len() != 0 {
        let mut kept: Vec<SignatureScheme> = Vec::new();
        for (_, sigAlg) in crate::range!(supportedAlgs.clone()) {
            if super::common::isSupportedSignatureAlgorithm(
                *sigAlg,
                c.SupportedSignatureAlgorithms.clone(),
            ) {
                kept.push(*sigAlg);
            }
        }
        supportedAlgs = slice::__from_vec(kept);
    }
    // Go: Filter out any unsupported signature algorithms, for example
    // due to FIPS 140-3 policy, tlssha1=0, or protocol version.
    let mut kept: Vec<SignatureScheme> = Vec::new();
    for (_, sigAlg) in crate::range!(supportedAlgs.clone()) {
        if !super::common::isDisabledSignatureAlgorithm(vers, *sigAlg, false) {
            kept.push(*sigAlg);
        }
    }
    supportedAlgs = slice::__from_vec(kept);
    // Go: if len(supportedAlgs) == 0 { return 0, unsupportedCertificateError(c) }
    if supportedAlgs.Len() == 0 {
        return (SignatureScheme(0), unsupportedCertificateError(c));
    }
    // Go: if len(peerAlgs) == 0 && vers == VersionTLS12 {
    //         // For TLS 1.2, if the client didn't send signature_algorithms then
    //         // we can assume that it supports SHA1. See RFC 5246, Section
    //         // 7.4.1.4.1. RFC 9155 made signature_algorithms mandatory in TLS
    //         // 1.2, and we gated it behind the tlssha1 GODEBUG setting.
    //         if tlssha1.Value() != "1" {
    //             return 0, errors.New("tls: missing signature_algorithms from TLS 1.2 peer")
    //         }
    //         peerAlgs = []SignatureScheme{PKCS1WithSHA1, ECDSAWithSHA1}
    //     }
    let mut peerAlgs = peerAlgs;
    if peerAlgs.Len() == 0 && vers == super::common::VersionTLS12 {
        if super::common::tlssha1Value() != string::from_static("1") {
            return (
                SignatureScheme(0),
                crate::errors::New("tls: missing signature_algorithms from TLS 1.2 peer"),
            );
        }
        peerAlgs = slice::__from_vec(alloc::vec![PKCS1WithSHA1, ECDSAWithSHA1]);
    }
    // Go: Pick signature scheme in the peer's preference order, as our
    // preference order is not configurable.
    for (_, preferredAlg) in crate::range!(peerAlgs) {
        if super::common::isSupportedSignatureAlgorithm(*preferredAlg, supportedAlgs.clone()) {
            return (*preferredAlg, crate::errors::nil);
        }
    }
    // Go: return 0, errors.New("tls: peer doesn't support any of the
    //     certificate's signature algorithms")
    return (
        SignatureScheme(0),
        crate::errors::New(
            "tls: peer doesn't support any of the certificate's signature algorithms",
        ),
    );
}

// go: sdk 1.25.5 crypto/tls/auth.go:249-285 unsupportedCertificateError
/// A helpful error for a certificate with an unsupported private key.
///
/// Two deviations, both structural:
///
///   * Go's first two arms catch a key stored by *value* where a pointer
///     was meant (`rsa.PrivateKey` for `*rsa.PrivateKey`) or the reverse
///     for Ed25519. goish has no value/pointer split on a key type, so
///     those three messages are unreachable and are not ported.
///   * The three `%T` renderings stop at the fixed prefix — goish's
///     `Any` cannot produce a dynamic type name. Same deviation as the
///     banner at the top of this file.
pub(crate) fn unsupportedCertificateError(cert: &super::Certificate) -> error {
    // Go: signer, ok := cert.PrivateKey.(crypto.Signer)
    //     if !ok { return fmt.Errorf("tls: certificate private key (%T)
    //         does not implement crypto.Signer", cert.PrivateKey) }
    let signer = signerOf(&cert.PrivateKey);
    if signer.is_none() {
        return crate::errors::New("tls: certificate private key does not implement crypto.Signer");
    }

    // Go: switch pub := signer.Public().(type) {
    let pub_ = signer.unwrap().Public();
    // Go: case *ecdsa.PublicKey:
    //         switch pub.Curve {
    //         case elliptic.P256(): case elliptic.P384(): case elliptic.P521():
    //         default: return fmt.Errorf("tls: unsupported certificate curve (%s)",
    //                      pub.Curve.Params().Name)
    //         }
    if let Some(p) = pub_.downcast_ref::<ecdsa::PublicKey>() {
        let name = p.Curve.Params().Name.clone();
        if name != string::from_static("P-256")
            && name != string::from_static("P-384")
            && name != string::from_static("P-521")
        {
            return crate::fmt::Errorf!("tls: unsupported certificate curve (%s)", name);
        }
    // Go: case *rsa.PublicKey:
    //         return fmt.Errorf("tls: certificate RSA key size too small
    //             for supported signature algorithms")
    } else if pub_.downcast_ref::<rsa::PublicKey>().is_some() {
        return crate::errors::New(
            "tls: certificate RSA key size too small for supported signature algorithms",
        );
    // Go: case ed25519.PublicKey:
    } else if pub_.downcast_ref::<ed25519::PublicKey>().is_some() {
        // Go: default:
        //         return fmt.Errorf("tls: unsupported certificate key (%T)", pub)
    } else {
        return crate::errors::New("tls: unsupported certificate key");
    }

    // Go: if cert.SupportedSignatureAlgorithms != nil {
    //         return fmt.Errorf("tls: peer doesn't support the certificate
    //             custom signature algorithms")
    //     }
    if cert.SupportedSignatureAlgorithms.Len() != 0 {
        return crate::errors::New(
            "tls: peer doesn't support the certificate custom signature algorithms",
        );
    }

    // Go: return fmt.Errorf("tls: internal error: unsupported key (%T)", cert.PrivateKey)
    return crate::errors::New("tls: internal error: unsupported key");
}
