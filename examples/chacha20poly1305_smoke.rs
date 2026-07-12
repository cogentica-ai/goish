// chacha20poly1305_smoke — NIST/RFC 8439 test vectors for ChaCha20, Poly1305, and ChaCha20-Poly1305 AEAD.
//
// 3 test vectors:
//   1. RFC 8439 §2.4.2 — ChaCha20 encryption test vector
//   2. RFC 8439 §2.5.2 — Poly1305 MAC test vector
//   3. RFC 8439 §2.8.2 — ChaCha20-Poly1305 AEAD test vector

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::{syscall};
use goish::crypto::chacha20;
use goish::crypto::poly1305;
use goish::crypto::chacha20poly1305;
use goish::crypto::cipher::AEAD as AEADTrait;
use goish::goslice::slice;
use goish::types::byte;

// ─── hex printing helper ──────────────────────────────────────────────

fn hex(b: &[byte]) -> alloc::string::String {
    let mut s = alloc::string::String::new();
    for &x in b {
        // simple hex without format!
        let hi = (x >> 4) as u8;
        let lo = (x & 0xf) as u8;
        s.push(if hi < 10 { (b'0' + hi) as char } else { (b'a' + hi - 10) as char });
        s.push(if lo < 10 { (b'0' + lo) as char } else { (b'a' + lo - 10) as char });
    }
    s
}

fn assert_eq_bytes(label: &str, got: &[byte], want: &[byte]) -> bool {
    if got == want {
        fmt::Println!(fmt::Sprintf!("[PASS] %s", label));
        true
    } else {
        fmt::Println!(fmt::Sprintf!("[FAIL] %s", label));
        fmt::Println!(fmt::Sprintf!("  got:  %s", hex(got).as_str()));
        fmt::Println!(fmt::Sprintf!("  want: %s", hex(want).as_str()));
        false
    }
}

/// RFC 8439 §2.4.2 ChaCha20 encryption test vector.
fn test_chacha20_encrypt() -> bool {
    // Key: 32 bytes
    let key: [byte; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    // Nonce: 12 bytes (counter starts at 1 in the RFC, but our cipher starts at 0 then SetCounter(1))
    let nonce: [byte; 12] = [
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00,
    ];
    // Plaintext: "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    // Expected ciphertext from RFC 8439 §2.4.2
    let expected_ct: &[byte] = &[
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    ];

    let key_s = slice::<byte>::__from_vec(key.to_vec());
    let nonce_s = slice::<byte>::__from_vec(nonce.to_vec());
    let (mut cipher_opt, err) = chacha20::NewUnauthenticatedCipher(key_s, nonce_s);
    if !err.IsNil() {
        fmt::Println!(fmt::Sprintf!("[FAIL] chacha20 init: %v", err));
        return false;
    }
    let c = cipher_opt.as_mut().unwrap();
    // RFC 8439 §2.4.2 uses counter=1
    c.SetCounter(1);
    let mut ct = alloc::vec![0u8; plaintext.len()];
    c.XORKeyStream(&mut ct, plaintext);

    assert_eq_bytes("RFC8439 §2.4.2 ChaCha20 encrypt", &ct, expected_ct)
}

/// RFC 8439 §2.5.2 Poly1305 MAC test vector.
fn test_poly1305_mac() -> bool {
    // Key: 32 bytes
    let key: [byte; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
    ];
    let msg = b"Cryptographic Forum Research Group";
    // Expected tag from RFC 8439 §2.5.2
    let expected_tag: [byte; 16] = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
    ];

    let mut tag = [0u8; 16];
    poly1305::Sum(&mut tag, msg, &key);

    assert_eq_bytes("RFC8439 §2.5.2 Poly1305 MAC", &tag, &expected_tag)
}

/// RFC 8439 §2.8.2 ChaCha20-Poly1305 AEAD test vector.
fn test_chacha20poly1305_aead() -> bool {
    let key: [byte; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    ];
    let nonce: [byte; 12] = [
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47,
    ];
    let aad: &[byte] = &[
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let plaintext: &[byte] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    // Expected ciphertext + tag from RFC 8439 §2.8.2
    let expected_seal: &[byte] = &[
        // ciphertext (114 bytes)
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16,
        // Poly1305 tag (16 bytes)
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ];

    let key_s = slice::<byte>::__from_vec(key.to_vec());
    let (cp_opt, err) = chacha20poly1305::New(key_s);
    if !err.IsNil() {
        fmt::Println!(fmt::Sprintf!("[FAIL] chacha20poly1305 init: %v", err));
        return false;
    }
    let cp = cp_opt.unwrap();

    let nonce_s = slice::<byte>::__from_vec(nonce.to_vec());
    let pt_s = slice::<byte>::__from_vec(plaintext.to_vec());
    let aad_s = slice::<byte>::__from_vec(aad.to_vec());
    let empty = slice::<byte>::__from_vec(alloc::vec![]);

    let sealed = AEADTrait::Seal(&cp, empty.clone(), nonce_s.clone(), pt_s, aad_s.clone());
    let sealed_v = sealed.__into_vec();

    if !assert_eq_bytes("RFC8439 §2.8.2 ChaCha20-Poly1305 Seal", &sealed_v, expected_seal) {
        return false;
    }

    // Also verify Open
    let ct_s = slice::<byte>::__from_vec(sealed_v.clone());
    let (plain_s, oerr) = AEADTrait::Open(&cp, empty, nonce_s, ct_s, aad_s);
    if !oerr.IsNil() {
        fmt::Println!(fmt::Sprintf!("[FAIL] RFC8439 §2.8.2 Open error: %v", oerr));
        return false;
    }
    let plain_v = plain_s.__into_vec();

    assert_eq_bytes("RFC8439 §2.8.2 ChaCha20-Poly1305 Open (roundtrip)", &plain_v, plaintext)
}

#[goish::main]
fn main() {
    fmt::Println!("=== chacha20poly1305_smoke ===");

    let r1 = test_chacha20_encrypt();
    let r2 = test_poly1305_mac();
    let r3 = test_chacha20poly1305_aead();

    let total = (r1 as i32) + (r2 as i32) + (r3 as i32);
    fmt::Println!(fmt::Sprintf!("=== chacha20poly1305_smoke: %d/3 PASSED ===", total));

    if total == 3 {
        syscall::Exit(0);
    } else {
        syscall::Exit(1);
    }
}
