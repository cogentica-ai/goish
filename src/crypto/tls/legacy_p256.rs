// go: namespace crypto/tls
//
// legacy_p256 — array-shaped P-256 entry points for the TLS handshake.
//
// NOTHING HERE IS A PORT, and nothing here is crypto any more. Every
// function is a thin adapter: it converts between the fixed-size arrays
// crypto/tls's handshake code was written against and the `slice<byte>`
// APIs of the real, ported packages, and delegates the actual arithmetic.
//
//   p256_keypair_generate            -> ecdh::P256().GenerateKey
//   p256_ecdh_compute                -> PrivateKey::ECDH
//   p256_ecdh_generate_and_compute*  -> the two above, composed
//   VerifyP256                       -> ecdsa::VerifyASN1
//   decode_x509_ec_p256_pubkey       -> x509::ParseCertificate
//
// History
// -------
// This file used to be 915 lines of hand-rolled secp256r1 — 32-byte
// bignums, Jacobian point arithmetic, its own ECDSA verify and ECDH —
// squatting on `src/crypto/ecdsa/` under the name of a package that had
// never been ported. It was a *second* P-256, unverified against Go, and
// it was the one the live handshake called while crypto/ecdh (17/17) and
// fips140/nistec sat unused. 09b32c4 moved it out of the way; this
// rewrite deletes it. There is now one P-256 implementation in the tree.
//
// The ASN.1 walk from the certificate down to the SubjectPublicKeyInfo
// used to be the one thing left here, "until crypto/x509 is ported and
// can supply it". It is ported, and it does; the walk and its
// `find_spki_in_tbs` are gone, along with the copies record.rs and
// handshake_client_tls13.rs kept. What remains is the shape
// conversion.
//
// The array shapes are kept deliberately: rewriting them to `slice<byte>`
// would churn the handshake for no behavioural gain, and they are the
// natural spelling for TLS's fixed-width key-share fields. Errors are
// reported the way the existing call sites already check for them — an
// all-zero result, or an `error` return.
//
// goishlint:ignore GOISH016 — not a package root; see the namespace
// anchor above. This is a goish-only module inside crypto/tls.

#![allow(non_snake_case, non_upper_case_globals, dead_code)]

extern crate alloc;

use crate::crypto::ecdh;
use crate::crypto::ecdsa;
use crate::crypto::elliptic;
use crate::crypto::rand::RandReader;
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::math::big::Int;
use crate::types::byte;

// go: none — goish-only: the fixed-size public key crypto/tls stores in
// its server-key enum. Mirrors the x25519 shims in crypto/ecdh.
#[derive(Clone, Copy, Default)]
pub struct P256PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

// go: none — goish idiom: `slice<byte>` from a borrowed byte run.
fn s(b: &[byte]) -> slice<byte> {
    return slice::__from_vec(b.to_vec());
}

// go: none — goish idiom: the empty slice Go spells as a nil `[]byte`.
fn empty() -> slice<byte> {
    return slice::__from_vec(alloc::vec::Vec::new());
}

// ─── ECDH ─────────────────────────────────────────────────────────────

// go: none — goish-only: array-shaped `ecdh::P256().GenerateKey`.
/// Generate a P-256 keypair. Returns (private scalar, uncompressed public
/// point). Both are all-zero if generation failed, which is what the
/// handshake already checks for.
pub fn p256_keypair_generate() -> ([u8; 32], [u8; 65]) {
    let mut r = RandReader;
    let (k, err) = ecdh::P256().GenerateKey(&mut r);
    if err != nil {
        return ([0u8; 32], [0u8; 65]);
    }
    return (to32(&k.Bytes()), to65(&k.PublicKey().Bytes()));
}

// go: none — goish-only: array-shaped `PrivateKey::ECDH`.
/// Compute the P-256 ECDH shared secret between `scalar` and the peer's
/// uncompressed point. All-zero on any failure, including an invalid or
/// off-curve peer point — `NewPublicKey` rejects those, where the
/// hand-rolled predecessor did not.
pub fn p256_ecdh_compute(scalar: &[u8; 32], server_pub_65: &[u8]) -> [u8; 32] {
    let (priv_, err) = ecdh::P256().NewPrivateKey(&s(scalar));
    if err != nil {
        return [0u8; 32];
    }
    let (pub_, err) = ecdh::P256().NewPublicKey(&s(server_pub_65));
    if err != nil {
        return [0u8; 32];
    }
    let (shared, err) = priv_.ECDH(&pub_);
    if err != nil {
        return [0u8; 32];
    }
    return to32(&shared);
}

// go: none — goish-only: generate, then agree, in one call. Returns
/// (private scalar, our uncompressed point, shared secret).
pub fn p256_ecdh_generate_and_compute_full(server_pub_65: &[u8]) -> ([u8; 32], [u8; 65], [u8; 32]) {
    let (scalar, pub65) = p256_keypair_generate();
    if scalar == [0u8; 32] {
        return ([0u8; 32], [0u8; 65], [0u8; 32]);
    }
    let shared = p256_ecdh_compute(&scalar, server_pub_65);
    if shared == [0u8; 32] {
        return ([0u8; 32], [0u8; 65], [0u8; 32]);
    }
    return (scalar, pub65, shared);
}

// go: none — goish-only: the shared-secret-only variant, kept because
// examples/p256_ecdh_smoke.rs exercises it.
pub fn p256_ecdh_generate_and_compute(server_pub_65: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let (scalar, pub65, shared) = p256_ecdh_generate_and_compute_full(server_pub_65);
    let mut x = [0u8; 32];
    x.copy_from_slice(&pub65[1..33]);
    return (scalar, x, shared);
}

// ─── ECDSA verification ───────────────────────────────────────────────

// go: none — goish-only: array-shaped `ecdsa::VerifyASN1`.
/// Verify a DER-encoded ECDSA-P256 signature over `digest`. Returns nil on
/// success, an error otherwise.
pub fn VerifyP256(pubkey: &P256PublicKey, digest: &[u8], sig: &[u8]) -> error {
    let mut X = Int::default();
    let mut Y = Int::default();
    X.SetBytes(s(&pubkey.x));
    Y.SetBytes(s(&pubkey.y));
    let pk = ecdsa::PublicKey {
        Curve: elliptic::P256(),
        X,
        Y,
    };
    if !ecdsa::VerifyASN1(&pk, &s(digest), &s(sig)) {
        return errors::New("tls: ECDSA-P256 signature verification failed");
    }
    return nil;
}

// ─── X.509 SubjectPublicKeyInfo ───────────────────────────────────────

// go: none — goish-only: the array-shaped P-256 key the handshake code
// stores. crypto/x509 supplies the parse; this converts the shape.
/// Parse a P-256 public key from a DER-encoded X.509 certificate.
///
/// This used to walk the DER by hand down to the SubjectPublicKeyInfo,
/// with a `find_spki_in_tbs` that record.rs had a second copy of and
/// handshake_client_tls13.rs a third. crypto/x509 is ported, which was
/// the stated condition for removing them, and it checks the algorithm
/// OID and the curve — which the hand walk did not, leaving the
/// dispatch to whatever the caller had already decided.
pub fn decode_x509_ec_p256_pubkey(cert_der: &[byte]) -> (P256PublicKey, error) {
    let nil_key = P256PublicKey::default();
    let (cert, err) = crate::crypto::x509::ParseCertificate(s(cert_der));
    if !err.IsNil() {
        return (nil_key, err);
    }
    // As in record.rs: redundant against ParseCertificate today, kept
    // as the explicit statement of intent. The P-256 check below is
    // NOT redundant — see its own note.
    if cert.PublicKeyAlgorithm != crate::crypto::x509::ECDSA {
        return (
            nil_key,
            errors::New("tls/x509: certificate public key is not ECDSA"),
        );
    }
    let pk = match cert.PublicKey.as_any().downcast_ref::<ecdsa::PublicKey>() {
        Some(k) => k.clone(),
        None => {
            return (
                nil_key,
                errors::New("tls/x509: certificate public key is not ECDSA"),
            );
        }
    };
    // LOAD-BEARING, and measured. The equality (not `<=`) is deliberate
    // twice over: this type is P-256 and nothing else, and the two
    // FillBytes calls below need every coordinate to fit in 32 bytes.
    // `FillBytes` into a buffer too small to hold the value PANICS. Delete this check, hand the function a P-384
    // certificate, and the process dies with "math/big: buffer too
    // small to fit value" — reachable from a server's Certificate
    // message on the invented ECDSA suite. The predecessor happened to
    // fail closed by a different route: it passed the raw BIT STRING to
    // ParseUncompressedPublicKey(P256, ...), which rejected the 97-byte
    // point on length. Delegating to the real parser gets a valid
    // P-384 key back instead, so the curve has to be checked here.
    if pk.Curve.Params().BitSize != elliptic::P256().Params().BitSize {
        return (
            nil_key,
            errors::New("tls/x509: certificate public key is not P-256"),
        );
    }
    let mut out = P256PublicKey::default();
    let xb = pk.X.FillBytes(slice::__from_vec(alloc::vec![0u8; 32]));
    let yb = pk.Y.FillBytes(slice::__from_vec(alloc::vec![0u8; 32]));
    let (xr, yr): (&[byte], &[byte]) = (&xb, &yb);
    out.x.copy_from_slice(xr);
    out.y.copy_from_slice(yr);
    return (out, nil);
}

// ─── array/slice conversions ──────────────────────────────────────────

// go: none — goish idiom: a 32-byte array from a slice the real API
// returned. Short input yields zeros, which every caller treats as
// failure.
fn to32(v: &slice<byte>) -> [u8; 32] {
    let raw: &[byte] = v;
    let mut out = [0u8; 32];
    if raw.len() != 32 {
        return out;
    }
    out.copy_from_slice(raw);
    return out;
}

// go: none — goish idiom: see to32.
fn to65(v: &slice<byte>) -> [u8; 65] {
    let raw: &[byte] = v;
    let mut out = [0u8; 65];
    if raw.len() != 65 {
        return out;
    }
    out.copy_from_slice(raw);
    return out;
}
