// x509_certpool_smoke — exercise crypto::x509::CertPool + tls::Config.RootCAs.
//
// Tests:
//   1. test_certpool_append_pem     — feed the goref-generated PEM; assert
//      AppendCertsFromPEM returns true and pool.Len() == 1.
//   2. test_certpool_subjects_is_rawsubject — Subjects() must return the
//      certificate's DER-encoded *Subject*, not its whole DER. The
//      expected 110-byte length and hex prefix are `scripts/goref.sh
//      crypto/x509` output.
//   3. test_certpool_rejects_garbage — a PEM CERTIFICATE block whose
//      payload is not a certificate must be skipped, and the pool left
//      empty. Before x509 had a parser this was accepted, which is
//      exactly the hole the port closes.
//   4. test_certpool_dedupes        — the same certificate twice is one
//      entry (haveSum).
//   5. test_tls_config_has_rootcas_field — construct a tls::Config with
//      RootCAs = Some(pool); verify the field round-trips.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::crypto::tls;
use goish::crypto::x509::NewCertPool;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::types::byte;
use goish::{convert, syscall};

/// A real, self-signed RSA-2048 certificate. Same bytes as
/// `examples/x509_parse_smoke.rs` — see that file's banner for how it was
/// generated.
const TEST_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIE4DCCA8igAwIBAgIFAQIDBAUwDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMC\n\
VEgxEDAOBgNVBAcTB0Jhbmdrb2sxFzAVBgNVBAoTDkdvaXNoIFRlc3QgT3JnMQ4w\n\
DAYDVQQLEwVQb3J0czETMBEGA1UEAxMKZ29pc2ggbGVhZjENMAsGA1UEBRMEU04t\n\
NzAeFw0yNDAzMDExMjAwMDBaFw0zMzA0MDIxMzE0MTVaMGwxCzAJBgNVBAYTAlRI\n\
MRAwDgYDVQQHEwdCYW5na29rMRcwFQYDVQQKEw5Hb2lzaCBUZXN0IE9yZzEOMAwG\n\
A1UECxMFUG9ydHMxEzARBgNVBAMTCmdvaXNoIGxlYWYxDTALBgNVBAUTBFNOLTcw\n\
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEE3zZMggLiQDVMKhbusFF\n\
qr5rE7BxpUMyaL9fCRhQHqKRaqwBHzo7fry6P9/SQmGQehkiS4ciMyhFI8YtYjHq\n\
dCT/K0o5Y0kk2gFBzmEWNKRN3J+dxZWYrA5gExmMpQCTdsYUSHG1683Z7a+S1rcL\n\
c+rHxhYDswT6HIioJfiF+Mko+27mtCirEJzHe/wA0NzHv6Wk+rQmjA8spQ4azr88\n\
duWqrxmh5l6Xcy6l1pnHaOvsIk78JtP7KTTeTvtLKCqdzrRrBKj+ISBj2gXopXJW\n\
ROUBenJhcyNYROah0woJNrNw0Eq1ILBLBree7hx6rGog90dUn8lGkW7FWVnRgH8t\n\
AgMBAAGjggGHMIIBgzAOBgNVHQ8BAf8EBAMCAqQwHQYDVR0lBBYwFAYIKwYBBQUH\n\
AwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQIwDgYDVR0OBAcEBQECAwQF\n\
MGEGCCsGAQUFBwEBBFUwUzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AuZ29pc2gu\n\
ZXhhbXBsZTAqBggrBgEFBQcwAoYeaHR0cDovL2NhLmdvaXNoLmV4YW1wbGUvY2Eu\n\
Y3J0MF8GA1UdEQRYMFaCDWdvaXNoLmV4YW1wbGWCEXd3dy5nb2lzaC5leGFtcGxl\n\
gRJwb3J0QGdvaXNoLmV4YW1wbGWHBMAAAgqGGGh0dHBzOi8vZ29pc2guZXhhbXBs\n\
ZS9jYTA5BgNVHR4EMjAwoB0wD4INZ29pc2guZXhhbXBsZTAKhwgKAAAA/wAAAKEP\n\
MA2CC2JhZC5leGFtcGxlMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwuZ29p\n\
c2guZXhhbXBsZS94LmNybDANBgkqhkiG9w0BAQsFAAOCAQEAdIYb7TNaVRqsSMoV\n\
fCf+IcCmKjZaKJfIkxrOpupQZK205mzX+/w3szqUl/EUFhFrmqWCBAgntuZ7VZDN\n\
XF9KBrNjNwbCkV8EkP/uyNDzr0PYuutfhEY7V7GbJX4aUU+i+unHbTEcPbQjoVTW\n\
g6DVUUihnejtkee3b88GaRQFWhWy1GgwUPLe3xx2UEsok7bcBfFOzsOwyU8jcdl6\n\
YXQca37j974lL9Ej/C6lnO+ilk45+T08TVx3YQCmQGJWXYmmUQOL7WYZOPXEhreo\n\
gZrVDGi8Uw80/fjU2zWB58JCMly/pK9s3yGcYqYSmDZfZZ3PR4appnTEXHCBV6AY\n\
Rr1Nlw==\n\
-----END CERTIFICATE-----\n";

/// A PEM CERTIFICATE block whose payload is ten bytes of 0x00..0x09 —
/// well-formed PEM, not a certificate.
const GARBAGE_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
AAECAwQFBgcICQ==\n\
-----END CERTIFICATE-----\n";

fn test_certpool_append_pem() -> bool {
    let mut pool = NewCertPool();
    let pem_slice: slice<byte> = convert::bytes(TEST_CERT_PEM);
    let added = pool.AppendCertsFromPEM(pem_slice);
    if !added {
        fmt::Println!("[1] AppendCertsFromPEM returned false — FAIL");
        return false;
    }
    if pool.Len() != 1 {
        fmt::Println!("[1] pool.Len() =", pool.Len(), " want 1 — FAIL");
        return false;
    }
    fmt::Println!("[1] test_certpool_append_pem                  PASS");
    return true;
}

fn test_certpool_subjects_is_rawsubject() -> bool {
    let mut pool = NewCertPool();
    let pem_slice: slice<byte> = convert::bytes(TEST_CERT_PEM);
    let _ = pool.AppendCertsFromPEM(pem_slice);

    let subjects = pool.Subjects();
    if subjects.Len() != 1 {
        fmt::Println!("[2] Subjects().Len() =", subjects.Len(), " want 1 — FAIL");
        return false;
    }
    // goref: len(RawSubject)=110, RawSubjectHex=306c310b3009...
    let entry: &slice<byte> = &subjects[0];
    if entry.Len() != 110 {
        fmt::Println!("[2] Subjects()[0].Len() =", entry.Len(), " want 110 — FAIL");
        return false;
    }
    let h = hex::EncodeToString(entry.as_ref());
    if !h
        .as_bytes()
        .starts_with(b"306c310b30090603550406130254483110300e0603550407130742616e676b6f6b")
    {
        fmt::Println!("[2] Subjects()[0] is not the DER Subject — FAIL");
        return false;
    }
    fmt::Println!("[2] test_certpool_subjects_is_rawsubject      PASS");
    return true;
}

fn test_certpool_rejects_garbage() -> bool {
    let mut pool = NewCertPool();
    let pem_slice: slice<byte> = convert::bytes(GARBAGE_CERT_PEM);
    let added = pool.AppendCertsFromPEM(pem_slice);
    if added || pool.Len() != 0 {
        fmt::Println!("[3] a non-certificate PEM block was accepted — FAIL");
        return false;
    }
    fmt::Println!("[3] test_certpool_rejects_garbage             PASS");
    return true;
}

fn test_certpool_dedupes() -> bool {
    let mut pool = NewCertPool();
    let mut both: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    both.extend_from_slice(TEST_CERT_PEM.as_bytes());
    both.extend_from_slice(TEST_CERT_PEM.as_bytes());
    let pem_slice: slice<byte> = slice::__from_vec(both);
    let added = pool.AppendCertsFromPEM(pem_slice);
    if !added || pool.Len() != 1 {
        fmt::Println!("[4] pool.Len() =", pool.Len(), " want 1 (deduped) — FAIL");
        return false;
    }
    fmt::Println!("[4] test_certpool_dedupes                     PASS");
    return true;
}

fn test_tls_config_has_rootcas_field() -> bool {
    // Construct a Config with RootCAs populated.
    let mut pool = NewCertPool();
    let pem_slice: slice<byte> = convert::bytes(TEST_CERT_PEM);
    let _ = pool.AppendCertsFromPEM(pem_slice);

    let cfg = tls::Config {
        RootCAs: Some(pool),
        InsecureSkipVerify: false,
        ..Default::default()
    };

    // Verify the field round-trips: RootCAs should be Some and the pool
    // should still have Len() == 1.
    match &cfg.RootCAs {
        None => {
            fmt::Println!("[5] RootCAs is None — FAIL");
            return false;
        }
        Some(p) => {
            if p.Len() != 1 {
                fmt::Println!("[5] RootCAs pool.Len() =", p.Len(), " want 1 — FAIL");
                return false;
            }
        }
    }
    fmt::Println!("[5] test_tls_config_has_rootcas_field         PASS");
    return true;
}

#[goish::main]
fn main() {
    let mut passed = 0;
    let mut total = 0;

    total += 1;
    if test_certpool_append_pem() {
        passed += 1;
    }

    total += 1;
    if test_certpool_subjects_is_rawsubject() {
        passed += 1;
    }

    total += 1;
    if test_certpool_rejects_garbage() {
        passed += 1;
    }

    total += 1;
    if test_certpool_dedupes() {
        passed += 1;
    }

    total += 1;
    if test_tls_config_has_rootcas_field() {
        passed += 1;
    }

    if passed == total {
        fmt::Println!("ok", passed, "/", total);
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", passed, "of", total, "passed");
        syscall::Exit(1);
    }
}
