// crypto/x509 — Go's `crypto/x509` package, minimal stub for ports that
// reference `*x509.CertPool` as a value carrier.
//
// Goish v1 ships only the type surface — `CertPool` as a struct that
// stores DER-encoded certificate bytes parsed from PEM. No actual X.509
// certificate parsing or chain verification yet; that requires a full
// ASN.1 / X.509 parser which is out of scope for the no_std runtime today.
// Ports that pass `*tls.Config{RootCAs: pool}` around for configuration
// purposes can compile against this surface.
//
// Reference: Go 1.25 `src/crypto/x509/cert_pool.go`.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::sync::Mutex;
use crate::types::byte;

// ─── CertPoolInner ────────────────────────────────────────────────────────────

/// Internal state for the cert pool, protected by a Mutex.
#[derive(Default)]
struct CertPoolInner {
    /// DER-encoded certificates that were added.
    /// We do NOT parse them yet — real X.509 verification is deferred
    /// to a future Goish revision.
    der_certs: Vec<Vec<u8>>,
}

// ─── CertPool (x509/cert_pool.go) ────────────────────────────────────────────

/// `x509.CertPool` (Go 1.25 src/crypto/x509/cert_pool.go) — a set of
/// certificates. Goish v1 carries only the DER bytes; no chain building
/// or cert parsing is wired yet. Callers may use `AppendCertsFromPEM` to
/// load PEM-encoded CA bundles, and the stored bytes will eventually be
/// passed to a real TLS verifier once the handshake layer is wired.
#[derive(Clone, Default)]
pub struct CertPool {
    inner: Arc<Mutex<CertPoolInner>>,
}

impl CertPool {
    /// Create a new empty CertPool.
    pub fn new() -> CertPool {
        CertPool {
            inner: Arc::new(Mutex::new(CertPoolInner::default())),
        }
    }

    /// `CertPool.AppendCertsFromPEM(pemCerts)` (cert_pool.go) — parses
    /// PEM-encoded certificates and adds them to the pool.
    ///
    /// Reports whether any certificates were successfully parsed.
    ///
    /// Stub policy: we accept any "CERTIFICATE" PEM block and store its
    /// DER bytes, but do NOT parse or verify the X.509 structure.
    pub fn AppendCertsFromPEM(&self, pemCerts: slice<byte>) -> bool {
        let pem_bytes: Vec<u8> = pemCerts.__into_vec();
        let mut added = false;
        let mut rest: Vec<u8> = pem_bytes;

        loop {
            let data_slice = slice::<byte>::__from_vec(rest.clone());
            let (block_opt, new_rest) = crate::encoding::pem::Decode(data_slice);
            match block_opt {
                None => break,
                Some(blk) => {
                    let type_str: &str = blk.Type.as_ref();
                    if type_str == "CERTIFICATE" {
                        let der: Vec<u8> = blk.Bytes.__into_vec();
                        let mut guard = self.inner.Lock();
                        guard.der_certs.push(der);
                        added = true;
                    }
                    let nr: Vec<u8> = new_rest.__into_vec();
                    if nr.is_empty() {
                        break;
                    }
                    rest = nr;
                }
            }
        }
        added
    }

    /// `CertPool.Subjects()` (cert_pool.go) — returns placeholder DER bytes
    /// for each certificate in the pool.
    ///
    /// Stub deviation: Go's `Subjects()` returns the DER-encoded Subject
    /// field of each certificate. Since we don't parse X.509 structures
    /// yet, we return the entire DER cert bytes as a placeholder. Callers
    /// should not depend on this being a real Subject until full X.509
    /// parsing is wired.
    pub fn Subjects(&self) -> slice<slice<byte>> {
        let guard = self.inner.Lock();
        let mut out = slice::<slice<byte>>::__from_vec(alloc::vec![]);
        for der in guard.der_certs.iter() {
            let s = slice::<byte>::__from_vec(der.clone());
            out = crate::append!(out, s);
        }
        out
    }

    /// `CertPool.Len()` — returns the number of certificates in the pool.
    /// (Not in Go's public API, but useful for testing.)
    pub fn Len(&self) -> crate::types::int {
        let guard = self.inner.Lock();
        guard.der_certs.len() as crate::types::int
    }
}

// ─── Constructors ─────────────────────────────────────────────────────────────

/// `x509.NewCertPool()` (cert_pool.go) — returns a new, empty CertPool.
pub fn NewCertPool() -> CertPool {
    CertPool::new()
}

// ─── ParsePKCS8PrivateKey (pkcs8.go) ─────────────────────────────────────────
//
// Reference: Go 1.25 src/crypto/x509/pkcs8.go
//
// PKCS#8 (RFC 5208) PrivateKeyInfo structure:
//
//   PrivateKeyInfo ::= SEQUENCE {
//       version              Version,               -- INTEGER (0)
//       privateKeyAlgorithm  AlgorithmIdentifier,   -- SEQUENCE { OID, params }
//       privateKey           OCTET STRING           -- DER encoding of the key
//   }
//
// Only rsaEncryption OID (1.2.840.113549.1.1.1) is supported.
// On success returns an rsa::PrivateKey with all CRT fields populated.

use crate::encoding::asn1;
use crate::errors;
use crate::math::big;

// ─── Certificate (x509.go) ───────────────────────────────────────────────────

/// `x509.Certificate` — a parsed X.509 certificate.
///
/// Goish v1 exposes only the fields needed for TLS 1.2 RSA key exchange:
/// the raw DER bytes, TBS bytes, and the extracted RSA public key.
/// Full chain verification and field exposure are deferred to a later revision.
#[derive(Clone, Default)]
pub struct Certificate {
    /// Full DER-encoded certificate.
    pub Raw: slice<byte>,
    /// RSA public key extracted from SubjectPublicKeyInfo.
    pub PublicKey: crate::crypto::rsa::PublicKey,
}

/// `x509.ParseCertificate(asn1Data)` — decode a DER-encoded X.509 certificate.
///
/// Goish v1 extracts only the RSA public key from SubjectPublicKeyInfo.
/// Returns an error for non-RSA keys or malformed DER.
pub fn ParseCertificate(der: slice<byte>) -> (Certificate, crate::error) {
    let nil_cert = Certificate::default();
    // Reuse the TLS-layer decoder which already walks the full ASN.1 tree.
    let der_raw: &[byte] = &der;
    let (pk, err) = crate::crypto::tls::record::decode_x509_rsa_pubkey(der_raw);
    if !err.IsNil() {
        return (nil_cert, err);
    }
    let cert = Certificate {
        Raw: der,
        PublicKey: pk,
    };
    (cert, errors::nil)
}

// OID rsaEncryption value bytes (the content octets after the 06 09 header):
// 1.2.840.113549.1.1.1  →  2a 86 48 86 f7 0d 01 01 01
const OID_RSA_ENCRYPTION: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];

/// `x509.ParsePKCS8PrivateKey` — decode a DER-encoded PKCS#8
/// PrivateKeyInfo and return the RSA private key.
///
/// Only rsaEncryption (1.2.840.113549.1.1.1) is supported. Returns
/// an error for any other algorithm OID.
pub fn ParsePKCS8PrivateKey(
    der: slice<byte>,
) -> (crate::crypto::rsa::PrivateKey, crate::error) {
    let nil_key = crate::crypto::rsa::PrivateKey::default();

    // ── outer SEQUENCE ────────────────────────────────────────────────
    let (outer, _, err) = asn1::ParseRaw(der.clone());
    if !err.IsNil() {
        return (nil_key, err);
    }
    if outer.Tag != asn1::TagSequence {
        return (
            nil_key,
            errors::New("x509: PKCS#8: outer element is not a SEQUENCE"),
        );
    }
    let body = outer.Bytes;

    // ── version INTEGER (must be 0) ───────────────────────────────────
    let (ver_rv, rest1, err) = asn1::ParseRaw(body.clone());
    if !err.IsNil() {
        return (nil_key, err);
    }
    if ver_rv.Tag != asn1::TagInteger {
        return (
            nil_key,
            errors::New("x509: PKCS#8: version field is not an INTEGER"),
        );
    }
    let (ver_val, err) = asn1::ParseInt64(ver_rv.Bytes.clone());
    if !err.IsNil() {
        return (nil_key, err);
    }
    if ver_val != 0 {
        return (
            nil_key,
            errors::New("x509: PKCS#8: unsupported version (only version 0 supported)"),
        );
    }

    // ── AlgorithmIdentifier SEQUENCE ──────────────────────────────────
    let (alg_rv, rest2, err) = asn1::ParseRaw(rest1.clone());
    if !err.IsNil() {
        return (nil_key, err);
    }
    if alg_rv.Tag != asn1::TagSequence {
        return (
            nil_key,
            errors::New("x509: PKCS#8: algorithmIdentifier is not a SEQUENCE"),
        );
    }
    // First element of AlgorithmIdentifier must be the OID.
    let (oid_rv, _, err) = asn1::ParseRaw(alg_rv.Bytes.clone());
    if !err.IsNil() {
        return (nil_key, err);
    }
    if oid_rv.Tag != asn1::TagOID {
        return (
            nil_key,
            errors::New("x509: PKCS#8: algorithmIdentifier first element is not an OID"),
        );
    }
    if !pkcs8_oid_bytes_equal(&oid_rv.Bytes, OID_RSA_ENCRYPTION) {
        return (
            nil_key,
            errors::New(
                "x509: PKCS#8: unsupported algorithm OID (only rsaEncryption supported)",
            ),
        );
    }

    // ── privateKey OCTET STRING ───────────────────────────────────────
    let (pk_rv, _, err) = asn1::ParseRaw(rest2.clone());
    if !err.IsNil() {
        return (nil_key, err);
    }
    if pk_rv.Tag != asn1::TagOctetString {
        return (
            nil_key,
            errors::New("x509: PKCS#8: privateKey is not an OCTET STRING"),
        );
    }

    // ── parse inner RSAPrivateKey (PKCS#1) ────────────────────────────
    pkcs8_parse_rsa_private_key(pk_rv.Bytes)
}

fn pkcs8_parse_rsa_private_key(
    der: slice<byte>,
) -> (crate::crypto::rsa::PrivateKey, crate::error) {
    let nil_key = crate::crypto::rsa::PrivateKey::default();

    // outer SEQUENCE
    let (outer, _, err) = asn1::ParseRaw(der.clone());
    if !err.IsNil() {
        return (nil_key, err);
    }
    if outer.Tag != asn1::TagSequence {
        return (
            nil_key,
            errors::New("x509: PKCS#1 RSAPrivateKey: outer element is not a SEQUENCE"),
        );
    }

    let mut rest = outer.Bytes;

    // version INTEGER (must be 0)
    let (ver, r, err) = pkcs8_read_integer(&rest);
    if !err.IsNil() {
        return (nil_key, err);
    }
    rest = r;
    if ver.Int64() != 0 {
        return (
            nil_key,
            errors::New("x509: PKCS#1 RSAPrivateKey: unsupported version (must be 0)"),
        );
    }

    // n — modulus
    let (n_int, r, err) = pkcs8_read_big_integer(&rest);
    if !err.IsNil() {
        return (nil_key, err);
    }
    rest = r;

    // e — publicExponent
    let (e_int, r, err) = pkcs8_read_integer(&rest);
    if !err.IsNil() {
        return (nil_key, err);
    }
    rest = r;
    let e_val = e_int.Int64();

    // d — privateExponent
    let (d_int, r, err) = pkcs8_read_big_integer(&rest);
    if !err.IsNil() {
        return (nil_key, err);
    }
    rest = r;

    // p — prime1
    let (p_int, r, err) = pkcs8_read_big_integer(&rest);
    if !err.IsNil() {
        return (nil_key, err);
    }
    rest = r;

    // q — prime2
    let (q_int, r, err) = pkcs8_read_big_integer(&rest);
    if !err.IsNil() {
        return (nil_key, err);
    }
    rest = r;

    // dp — exponent1 = d mod (p-1)
    let (dp_int, r, err) = pkcs8_read_big_integer(&rest);
    if !err.IsNil() {
        return (nil_key, err);
    }
    rest = r;

    // dq — exponent2 = d mod (q-1)
    let (dq_int, r, err) = pkcs8_read_big_integer(&rest);
    if !err.IsNil() {
        return (nil_key, err);
    }
    rest = r;

    // qinv — coefficient = q^-1 mod p
    let (qinv_int, _r, err) = pkcs8_read_big_integer(&rest);
    if !err.IsNil() {
        return (nil_key, err);
    }

    // Build Primes slice: [p, q]
    let mut primes_vec: alloc::vec::Vec<big::Int> = alloc::vec::Vec::with_capacity(2);
    primes_vec.push(p_int);
    primes_vec.push(q_int);

    let key = crate::crypto::rsa::PrivateKey {
        PublicKey: crate::crypto::rsa::PublicKey {
            N: n_int,
            E: e_val,
        },
        D: d_int,
        Primes: slice::<big::Int>::__from_vec(primes_vec),
        Precomputed: crate::crypto::rsa::PrecomputedValues {
            Dp: dp_int,
            Dq: dq_int,
            Qinv: qinv_int,
            CRTValues: slice::<crate::crypto::rsa::CRTValue>::__from_vec(alloc::vec::Vec::new()),
        },
    };
    (key, crate::errors::nil)
}

fn pkcs8_read_big_integer(
    data: &slice<byte>,
) -> (big::Int, slice<byte>, crate::error) {
    let (rv, rest, err) = asn1::ParseRaw(data.clone());
    if !err.IsNil() {
        return (big::Int::new(), rest, err);
    }
    if rv.Tag != asn1::TagInteger {
        return (
            big::Int::new(),
            rest,
            errors::New("x509: expected INTEGER tag"),
        );
    }
    let (z, err) = asn1::ParseBigInt(rv.Bytes);
    (z, rest, err)
}

fn pkcs8_read_integer(
    data: &slice<byte>,
) -> (big::Int, slice<byte>, crate::error) {
    let (rv, rest, err) = asn1::ParseRaw(data.clone());
    if !err.IsNil() {
        return (big::Int::new(), rest, err);
    }
    if rv.Tag != asn1::TagInteger {
        return (
            big::Int::new(),
            rest,
            errors::New("x509: expected INTEGER tag"),
        );
    }
    let (v, err) = asn1::ParseInt64(rv.Bytes);
    if !err.IsNil() {
        return (big::Int::new(), rest, err);
    }
    let mut z = big::Int::new();
    z.SetInt64(v);
    (z, rest, crate::errors::nil)
}

fn pkcs8_oid_bytes_equal(a: &slice<byte>, b: &[u8]) -> bool {
    if a.Len() != b.len() as crate::types::int { // goishlint:ignore GOISH005
        return false;
    }
    let mut i: crate::types::int = 0;
    while i < a.Len() {
        if a[i] != b[i as usize] { // goishlint:ignore GOISH005
            return false;
        }
        i += 1;
    }
    true
}
