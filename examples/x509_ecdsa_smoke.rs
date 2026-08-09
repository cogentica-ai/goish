// Test decode_x509_ec_p256_pubkey on real github.com cert.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
use goish::crypto::ecdsa::decode_x509_ec_p256_pubkey;
use goish::syscall;
use goish::fmt;

// github.com DER cert snapshot committed as a fixture (1010 bytes).
// The test only decodes the P-256 pubkey — no validity-window checks —
// so the snapshot never goes stale.
const CERT_DER: &[u8] = include_bytes!("testdata/github.com.der");

#[goish::main]
fn main() {
    let (pk, err) = decode_x509_ec_p256_pubkey(CERT_DER);
    if err.IsNil() {
        let mut xs = alloc::vec::Vec::new();
        for b in &pk.x { xs.push(b'0' + ((b >> 4) % 10)); }
        fmt::Println!(goish::string("PASS: decoded github.com ECDSA pubkey OK"));
        fmt::Println!(fmt::Sprintf!("  pubkey.x[0..4] = %02x %02x %02x %02x",
            pk.x[0] as i64, pk.x[1] as i64, pk.x[2] as i64, pk.x[3] as i64));
        fmt::Println!(fmt::Sprintf!("  pubkey.y[0..4] = %02x %02x %02x %02x",
            pk.y[0] as i64, pk.y[1] as i64, pk.y[2] as i64, pk.y[3] as i64));
        syscall::Exit(0);
    } else {
        fmt::Println!(fmt::Sprintf!("FAIL: decode_x509_ec_p256_pubkey err=%v", err));
        syscall::Exit(1);
    }
}
