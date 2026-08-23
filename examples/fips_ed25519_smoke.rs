// fips_ed25519_smoke — exercise crypto/internal/fips140/ed25519:
// RFC 8032 EdDSA key generation, signing, and verification.
//
// Coverage:
//   1. GenerateKey -> Sign -> Verify round-trips.
//   2. Verify rejects a tampered message.
//   3. Verify rejects a tampered signature.
//   4. NewPrivateKeyFromSeed is deterministic (same seed => same key
//      and same signature).
//   5. RFC 8032 TEST 1 cross-check: the standard seed produces the
//      standard public key, and Sign of the empty message produces the
//      exact RFC signature, byte-for-byte; Verify accepts it.
//   6. NewPrivateKey / Bytes / PublicKey round-trip; NewPublicKey
//      rejects a bad length.
//   7. Ed25519ctx (SignCtx / VerifyCtx) round-trips; pure-Ed25519
//      Verify rejects an Ed25519ctx signature (domain separation).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::internal::fips140::ed25519::{
    GenerateKey, NewPrivateKey, NewPrivateKeyFromSeed, NewPublicKey, Sign, SignCtx, Verify,
    VerifyCtx,
};
use goish::fmt;
use goish::types::byte;
use goish::{slice, syscall};

static FAILED: AtomicUsize = AtomicUsize::new(0);
const TOTAL: u8 = 7;

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

fn from_bytes(b: &[u8]) -> goish::slice<byte> {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(b.len());
    for &x in b {
        v.push(x);
    }
    slice::__from_vec(v)
}

fn slice_eq(a: &goish::slice<byte>, b: &goish::slice<byte>) -> bool {
    if a.Len() != b.Len() {
        return false;
    }
    let mut i: goish::int = 0;
    while i < a.Len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn write_result(idx: u8, label: &[u8], pass: bool) {
    syscall::Write(syscall::STDOUT, b"[".as_ptr(), 1);
    let d2 = b'0' + (idx % 10);
    if idx >= 10 {
        let d1 = b'0' + (idx / 10);
        let buf = [d1, d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    } else {
        let buf = [b' ', d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    }
    syscall::Write(syscall::STDOUT, b"] ".as_ptr(), 2);
    syscall::Write(syscall::STDOUT, label.as_ptr(), label.len());
    if pass {
        syscall::Write(syscall::STDOUT, b" PASS\n".as_ptr(), 6);
    } else {
        syscall::Write(syscall::STDOUT, b" FAIL\n".as_ptr(), 6);
    }
}

// RFC 8032 §7.1 TEST 1 (also Go's crypto/ed25519 testdata/sign.input,
// line 1): seed -> public key, and signature of the empty message.
const RFC_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const RFC_PUB: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];
const RFC_SIG: [u8; 64] = [
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
];

#[goish::main]
fn main() {
    goish::go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            fmt::Println!("ok 7/7");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", f as i64, "of 7");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run_tests() {
    test_1_generate_sign_verify();
    test_2_tampered_message();
    test_3_tampered_signature();
    test_4_seed_deterministic();
    test_5_rfc8032_vector();
    test_6_key_roundtrip();
    test_7_ctx_variant();
}

fn test_1_generate_sign_verify() {
    let mut ok = true;
    let (priv_, err) = GenerateKey();
    if !err.IsNil() {
        ok = false;
    }
    let (pub_, perr) = NewPublicKey(priv_.PublicKey());
    if !perr.IsNil() {
        ok = false;
    }
    let msg = from_bytes(b"hello edwards25519");
    let sig = Sign(&priv_, msg.clone());
    if sig.Len() != 64 {
        ok = false;
    }
    let verr = Verify(&pub_, msg, sig);
    if !verr.IsNil() {
        ok = false;
    }
    write_result(1, b"GenerateKey -> Sign -> Verify  ", ok);
    if !ok {
        fail();
    }
}

fn test_2_tampered_message() {
    let mut ok = true;
    let (priv_, _) = GenerateKey();
    let (pub_, _) = NewPublicKey(priv_.PublicKey());
    let msg = from_bytes(b"the original message");
    let sig = Sign(&priv_, msg);
    // A different message must fail verification.
    let tampered = from_bytes(b"the tampered message");
    let verr = Verify(&pub_, tampered, sig);
    if verr.IsNil() {
        ok = false;
    }
    write_result(2, b"Verify rejects bad message     ", ok);
    if !ok {
        fail();
    }
}

fn test_3_tampered_signature() {
    let mut ok = true;
    let (priv_, _) = GenerateKey();
    let (pub_, _) = NewPublicKey(priv_.PublicKey());
    let msg = from_bytes(b"sign me");
    let sig = Sign(&priv_, msg.clone());
    // Flip a bit in the S half of the signature.
    let mut bad: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(64);
    let mut i: goish::int = 0;
    while i < sig.Len() {
        bad.push(sig[i]);
        i += 1;
    }
    bad[40] ^= 0x01;
    let bad_sig = slice::__from_vec(bad);
    let verr = Verify(&pub_, msg, bad_sig);
    if verr.IsNil() {
        ok = false;
    }
    write_result(3, b"Verify rejects bad signature   ", ok);
    if !ok {
        fail();
    }
}

fn test_4_seed_deterministic() {
    let mut ok = true;
    let seed: [u8; 32] = [
        0x42, 0x11, 0x99, 0x07, 0xaa, 0x3c, 0x5e, 0xf1, 0x00, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
        0x80, 0x90,
    ];
    let (k1, e1) = NewPrivateKeyFromSeed(from_bytes(&seed));
    let (k2, e2) = NewPrivateKeyFromSeed(from_bytes(&seed));
    if !e1.IsNil() || !e2.IsNil() {
        ok = false;
    }
    // Same seed => same public key and same private key encoding.
    if !slice_eq(&k1.PublicKey(), &k2.PublicKey()) {
        ok = false;
    }
    if !slice_eq(&k1.Bytes(), &k2.Bytes()) {
        ok = false;
    }
    // Same seed => same signature over the same message.
    let msg = from_bytes(b"deterministic");
    let s1 = Sign(&k1, msg.clone());
    let s2 = Sign(&k2, msg);
    if !slice_eq(&s1, &s2) {
        ok = false;
    }
    // A bad seed length is rejected.
    let (_, errbad) = NewPrivateKeyFromSeed(from_bytes(b"short"));
    if errbad.IsNil() {
        ok = false;
    }
    write_result(4, b"NewPrivateKeyFromSeed determ.  ", ok);
    if !ok {
        fail();
    }
}

fn test_5_rfc8032_vector() {
    let mut ok = true;
    // RFC 8032 TEST 1: known seed -> known public key.
    let (priv_, err) = NewPrivateKeyFromSeed(from_bytes(&RFC_SEED));
    if !err.IsNil() {
        ok = false;
    }
    if !slice_eq(&priv_.PublicKey(), &from_bytes(&RFC_PUB)) {
        ok = false;
    }
    // Sign of the empty message must equal the RFC signature exactly.
    let empty = from_bytes(b"");
    let sig = Sign(&priv_, empty.clone());
    if !slice_eq(&sig, &from_bytes(&RFC_SIG)) {
        ok = false;
    }
    // Verify accepts the RFC signature.
    let (pub_, perr) = NewPublicKey(from_bytes(&RFC_PUB));
    if !perr.IsNil() {
        ok = false;
    }
    let verr = Verify(&pub_, empty, from_bytes(&RFC_SIG));
    if !verr.IsNil() {
        ok = false;
    }
    write_result(5, b"RFC 8032 TEST 1 byte-exact     ", ok);
    if !ok {
        fail();
    }
}

fn test_6_key_roundtrip() {
    let mut ok = true;
    let (priv_, _) = GenerateKey();
    // NewPrivateKey parses the 64-byte seed||pub encoding.
    let (priv2, err) = NewPrivateKey(priv_.Bytes());
    if !err.IsNil() {
        ok = false;
    }
    if !slice_eq(&priv2.PublicKey(), &priv_.PublicKey()) {
        ok = false;
    }
    if !slice_eq(&priv2.Seed(), &priv_.Seed()) {
        ok = false;
    }
    // The re-parsed key signs identically.
    let msg = from_bytes(b"roundtrip");
    if !slice_eq(&Sign(&priv_, msg.clone()), &Sign(&priv2, msg)) {
        ok = false;
    }
    // NewPublicKey rejects a wrong-length key.
    let (_, badlen) = NewPublicKey(from_bytes(b"too short"));
    if badlen.IsNil() {
        ok = false;
    }
    write_result(6, b"NewPrivateKey/Bytes roundtrip  ", ok);
    if !ok {
        fail();
    }
}

fn test_7_ctx_variant() {
    let mut ok = true;
    let (priv_, _) = GenerateKey();
    let (pub_, _) = NewPublicKey(priv_.PublicKey());
    let msg = from_bytes(b"context-bound message");
    let ctx = from_bytes(b"goish-test-ctx");
    // Ed25519ctx round-trip.
    let (sig, serr) = SignCtx(&priv_, msg.clone(), ctx.clone());
    if !serr.IsNil() {
        ok = false;
    }
    let verr = VerifyCtx(&pub_, msg.clone(), sig.clone(), ctx.clone());
    if !verr.IsNil() {
        ok = false;
    }
    // A different context must not verify (domain separation).
    let other_ctx = from_bytes(b"different-ctx");
    if VerifyCtx(&pub_, msg.clone(), sig.clone(), other_ctx).IsNil() {
        ok = false;
    }
    // Pure-Ed25519 Verify must reject an Ed25519ctx signature.
    if Verify(&pub_, msg, sig).IsNil() {
        ok = false;
    }
    let _ = TOTAL;
    write_result(7, b"Ed25519ctx Sign/Verify variant ", ok);
    if !ok {
        fail();
    }
}
