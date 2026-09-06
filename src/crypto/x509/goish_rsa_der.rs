// go: package crypto/x509
//
// **Goish-only. No Go counterpart, and deliberately not named after
// one.**
//
// Go parses private keys with `asn1.Unmarshal` into tagged structs —
// `pkcs1.ParsePKCS1PrivateKey`, `pkcs8.ParsePKCS8PrivateKey`,
// `sec1.ParseECPrivateKey`. This banner said goish "has `asn1.Marshal`
// but not `asn1.Unmarshal` (it needs reflect setter dispatch), so none
// of those three can be ported today". All four of those statements
// are now false: `asn1::Unmarshal` is in `encoding/asn1`, and all
// three parsers exist here as real ports — `pkcs1.rs`, `pkcs8.rs`,
// `sec1.rs`.
//
// What lives here is the hand-written DER walk `crypto/tls` has been
// using since before this package had a parser. It is RSA-only and it is
// not a port of anything. It carries goish-flavoured names on purpose:
// calling it `ParsePKCS1PrivateKey` would make `port_coverage` count
// `crypto/x509` as having ported a function it has not, which is exactly
// the squatting this file exists to avoid.
//
// The exit condition written here was "when `asn1.Unmarshal` lands,
// pkcs1.go and pkcs8.go get real ports and this file is deleted". That
// happened, and the deletion did not. Two callers remain, both in
// `crypto/tls`'s `parsePrivateKey`, where these are the first two
// fast paths tried before it falls through to the real
// `ParsePKCS8PrivateKey` / `ParseECPrivateKey` — so the RSA shapes
// never reach a ported parser. Retiring this file means pointing those
// two arms at `x509::ParsePKCS1PrivateKey` and
// `x509::ParsePKCS8PrivateKey` and deleting both functions and the
// re-export. It moves TLS key loading, so it wants the e2e run this
// machine does not do; see ROADMAP.md.
//
// goishlint:ignore GOISH015 — goish-only file; there is no
// `crypto/x509/goish_rsa_der.go` to anchor against, and the two
// functions here are not ports. See the banner.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::encoding::asn1;
use crate::errors;
use crate::goslice::slice;
use crate::math::big;
use crate::types::byte;

// go: none — the rsaEncryption OID content octets (the bytes after the
// `06 09` header): 1.2.840.113549.1.1.1.
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

// go: none — see the file banner. Roughly what Go's
// `pkcs8.ParsePKCS8PrivateKey` does for the rsaEncryption OID, written
// by hand because `asn1.Unmarshal` does not exist here. Go's function
// returns `any` and handles EC and Ed25519 as well; this returns
// `rsa::PrivateKey` and rejects every other algorithm OID.
pub fn goishParsePKCS8RSAPrivateKey(
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
            errors::New("x509: PKCS#8: unsupported algorithm OID (only rsaEncryption supported)"),
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
    return pkcs8_parse_rsa_private_key(pk_rv.Bytes);
}

// go: none — see the file banner. Roughly what Go's
// `pkcs1.ParsePKCS1PrivateKey` does, hand-written for the same reason.
// Go additionally validates and recomputes the CRT values; this does
// not.
pub fn goishParsePKCS1RSAPrivateKey(
    der: slice<byte>,
) -> (crate::crypto::rsa::PrivateKey, crate::error) {
    return pkcs8_parse_rsa_private_key(der);
}

// go: none — the shared RSAPrivateKey DER walk.
fn pkcs8_parse_rsa_private_key(der: slice<byte>) -> (crate::crypto::rsa::PrivateKey, crate::error) {
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
        PublicKey: crate::crypto::rsa::PublicKey { N: n_int, E: e_val },
        D: d_int,
        Primes: slice::<big::Int>::__from_vec(primes_vec),
        Precomputed: crate::crypto::rsa::PrecomputedValues {
            Dp: dp_int,
            Dq: dq_int,
            Qinv: qinv_int,
            CRTValues: slice::<crate::crypto::rsa::CRTValue>::__from_vec(alloc::vec::Vec::new()),
        },
    };
    return (key, crate::errors::nil);
}

// go: none — read one INTEGER element as a big.Int.
fn pkcs8_read_big_integer(data: &slice<byte>) -> (big::Int, slice<byte>, crate::error) {
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
    return (z, rest, err);
}

// go: none — read one INTEGER element as an int64-valued big.Int.
fn pkcs8_read_integer(data: &slice<byte>) -> (big::Int, slice<byte>, crate::error) {
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
    return (z, rest, crate::errors::nil);
}

// go: none — byte-compare an OID's content octets against a literal.
fn pkcs8_oid_bytes_equal(a: &slice<byte>, b: &[u8]) -> bool {
    if a.Len() != crate::int(b.len()) {
        return false;
    }
    let av: &[byte] = a;
    return av == b;
}
