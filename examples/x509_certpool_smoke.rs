// x509_certpool_smoke — exercise crypto::x509::CertPool + tls::Config.RootCAs.
//
// Tests:
//   1. test_certpool_append_pem    — feed a canned PEM with one CERTIFICATE
//      block; assert AppendCertsFromPEM returns true and pool.Len() == 1.
//   2. test_certpool_subjects_returns_der — verify Subjects() returns the same
//      DER bytes that were loaded.
//   3. test_tls_config_has_rootcas_field  — construct a tls::Config with
//      RootCAs = Some(NewCertPool()); verify the field round-trips.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::crypto::tls;
use goish::crypto::x509::NewCertPool;
use goish::goslice::slice;
use goish::types::byte;
use goish::{convert, syscall};

/// A minimal but structurally-valid PEM CERTIFICATE block.
///
/// The base64 payload is 10 raw bytes (0x00..0x09) which are NOT a valid
/// DER certificate — that is intentional, since we stub the X.509 parser.
/// What matters is that pem::Decode sees a "CERTIFICATE" block type and
/// AppendCertsFromPEM stores the decoded bytes.
const TEST_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
AAECAwQFBgcICQ==\n\
-----END CERTIFICATE-----\n";

/// The decoded bytes corresponding to the base64 above.
const TEST_CERT_DER: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];

fn test_certpool_append_pem() -> bool {
    let pool = NewCertPool();
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
    true
}

fn test_certpool_subjects_returns_der() -> bool {
    let pool = NewCertPool();
    let pem_slice: slice<byte> = convert::bytes(TEST_CERT_PEM);
    let _ = pool.AppendCertsFromPEM(pem_slice);

    let subjects = pool.Subjects();
    if subjects.Len() != 1 {
        fmt::Println!("[2] Subjects().Len() =", subjects.Len(), " want 1 — FAIL");
        return false;
    }
    // The first element must contain the DER bytes we loaded.
    let entry: &slice<byte> = &subjects[0];
    let raw: &[byte] = entry.as_ref();
    if raw != TEST_CERT_DER {
        fmt::Println!("[2] Subjects()[0] bytes mismatch — FAIL");
        return false;
    }
    fmt::Println!("[2] test_certpool_subjects_returns_der        PASS");
    true
}

fn test_tls_config_has_rootcas_field() -> bool {
    // Construct a Config with RootCAs populated.
    let pool = NewCertPool();
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
            fmt::Println!("[3] RootCAs is None — FAIL");
            return false;
        }
        Some(p) => {
            if p.Len() != 1 {
                fmt::Println!("[3] RootCAs pool.Len() =", p.Len(), " want 1 — FAIL");
                return false;
            }
        }
    }
    fmt::Println!("[3] test_tls_config_has_rootcas_field         PASS");
    true
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
    if test_certpool_subjects_returns_der() {
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
