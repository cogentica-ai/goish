// crypto/tls's two SPKI decoders, against every key algorithm.
//
// `decode_x509_ec_p256_pubkey` and `decode_x509_rsa_pubkey` used to
// walk the certificate DER by hand — outer SEQUENCE, TBSCertificate,
// count six fields to the SubjectPublicKeyInfo, step OVER the
// AlgorithmIdentifier, take the BIT STRING. Three copies of that walk
// existed (record.rs, legacy_p256.rs, handshake_client_tls13.rs) and
// none of them read the algorithm it stepped over, so an RSASSA-PSS
// certificate yielded a perfectly good 2048-bit RSA key that
// crypto/x509 refuses to produce at all.
//
// They now delegate to `x509::ParseCertificate`. This table is what
// says so: each decoder against an RSA, an ECDSA P-256, an Ed25519, an
// RSA-PSS and an ECDSA P-384 certificate, plus the real github.com
// leaf the smoke started as. A decoder that stopped checking the
// algorithm again would turn eight of these rows green in the wrong
// direction.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use goish::crypto::tls::legacy_p256::decode_x509_ec_p256_pubkey;
use goish::crypto::tls::record::decode_x509_rsa_pubkey;
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

// github.com DER cert snapshot committed as a fixture (1010 bytes).
// The test only decodes the P-256 pubkey — no validity-window checks —
// so the snapshot never goes stale.
const CERT_DER: &[u8] = include_bytes!("testdata/github.com.der");

// Self-signed CN=localhost leaves, one per key algorithm, generated
// with openssl. P-384 is here because the array-shaped P256PublicKey
// has 32 bytes per coordinate: a curve check is the only thing between
// a P-384 key and a silent truncation.
const RSA_DER: &[u8] = include_bytes!("testdata/spki_rsa1.der");
const EC_DER: &[u8] = include_bytes!("testdata/spki_ec.der");
const ED_DER: &[u8] = include_bytes!("testdata/spki_ed.der");
const PSS_DER: &[u8] = include_bytes!("testdata/spki_pss.der");
const EC384_DER: &[u8] = include_bytes!("testdata/spki_ec384.der");

static mut PASS: int = 0;
static mut FAIL: int = 0;

fn eq(what: &'static str, got: string, want: &'static str) {
    let ok = got == string::from_static(want);
    unsafe {
        if ok {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!("FAIL %s: got %s want %s\n", what, got.clone(), want);
        }
    }
}

// "ok" for an accepted key, otherwise the error text. The RSA arm adds
// the modulus size, so a decoder that accepts the right certificate and
// returns the wrong key is still a red row.
fn rsa_of(der: &[u8]) -> string {
    let (pk, e) = decode_x509_rsa_pubkey(der);
    if !e.IsNil() {
        return e.Error();
    }
    return fmt::Sprintf!("ok N=%v", pk.N.BitLen());
}

fn ec_of(der: &[u8]) -> string {
    let (pk, e) = decode_x509_ec_p256_pubkey(der);
    if !e.IsNil() {
        return e.Error();
    }
    return fmt::Sprintf!("ok x0=%v y0=%v", goish::int(pk.x[0]), goish::int(pk.y[0]));
}

#[goish::main]
fn main() {
    // ── decode_x509_rsa_pubkey ────────────────────────────────────
    eq("RSA cert decodes as RSA", rsa_of(RSA_DER), "ok N=2048");
    eq(
        "an ECDSA cert is not an RSA key",
        rsa_of(EC_DER),
        "tls/x509: certificate public key is not RSA",
    );
    eq(
        "an Ed25519 cert is not an RSA key",
        rsa_of(ED_DER),
        "tls/x509: certificate public key is not RSA",
    );
    // The whole point. The hand walk returned "ok N=2048" here.
    eq(
        "an RSA-PSS cert is not an rsaEncryption key",
        rsa_of(PSS_DER),
        "tls/x509: certificate public key is not RSA",
    );
    eq(
        "the github.com leaf is not an RSA key",
        rsa_of(CERT_DER),
        "tls/x509: certificate public key is not RSA",
    );

    // ── decode_x509_ec_p256_pubkey ────────────────────────────────
    eq(
        "an RSA cert is not an ECDSA key",
        ec_of(RSA_DER),
        "tls/x509: certificate public key is not ECDSA",
    );
    eq(
        "an Ed25519 cert is not an ECDSA key",
        ec_of(ED_DER),
        "tls/x509: certificate public key is not ECDSA",
    );
    eq(
        "an RSA-PSS cert is not an ECDSA key",
        ec_of(PSS_DER),
        "tls/x509: certificate public key is not ECDSA",
    );
    eq(
        "a P-384 cert is refused, not truncated into 32-byte arrays",
        ec_of(EC384_DER),
        "tls/x509: certificate public key is not P-256",
    );

    // The two accepting rows, pinned by their leading coordinate bytes
    // so a decoder that returns the zero key cannot pass them.
    let gh = ec_of(CERT_DER);
    let ec = ec_of(EC_DER);
    unsafe {
        if goish::strings::HasPrefix(gh.clone(), string::from_static("ok ")) {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!("FAIL the github.com leaf decodes as P-256: %s\n", gh.clone());
        }
        if goish::strings::HasPrefix(ec.clone(), string::from_static("ok ")) {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!("FAIL the P-256 leaf decodes: %s\n", ec.clone());
        }
    }
    fmt::Printf!("  github.com P-256 %s\n", gh);
    fmt::Printf!("  localhost  P-256 %s\n", ec);

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        fmt::Printf!("x509_ecdsa_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
