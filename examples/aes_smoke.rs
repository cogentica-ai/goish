// aes_smoke — exercise crypto/aes::NewCipher + Block trait.
//
// Test vectors lifted verbatim from /share/go/src/crypto/aes/aes_test.go
// (encryptTests slice). All four FIPS-197 Appendix B/C vectors are
// encrypted then decrypted; ciphertext / plaintext compared against
// the published expected values.
//
// Coverage:
//   1. AES-128 — FIPS-197 Appendix B (encrypt + decrypt).
//   2. AES-128 — FIPS-197 Appendix C.1 (encrypt + decrypt).
//   3. AES-192 — FIPS-197 Appendix C.2 (encrypt + decrypt).
//   4. AES-256 — FIPS-197 Appendix C.3 (encrypt + decrypt).
//   5. KeySizeError on length-0 key.
//   6. KeySizeError on length-15 key.
//   7. KeySizeError on length-31 key.
//   8. NewCipher succeeds on length-16, 24, 32 keys (no error).
//   9. BlockSize() returns 16.
//  10. Encrypt+Decrypt round-trip preserves an arbitrary 16-byte
//      plaintext (covers fresh-key path).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::crypto::aes;
use goish::crypto::cipher::Block;
use goish::types::byte;
use goish::{slice, syscall};

static FAILED: AtomicUsize = AtomicUsize::new(0);

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

fn check_bytes(got: &goish::slice<byte>, want: &[u8]) -> bool {
    if got.Len() as usize != want.len() {
        return false;
    }
    for i in 0..want.len() {
        if got[i as goish::int] != want[i] {
            return false;
        }
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

#[goish::main]
fn main() {
    goish::go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            fmt::Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run_tests() {
    test_1_appendix_b();
    test_2_appendix_c1();
    test_3_appendix_c2();
    test_4_appendix_c3();
    test_5_keysize_zero();
    test_6_keysize_15();
    test_7_keysize_31();
    test_8_keysize_valid();
    test_9_block_size();
    test_10_round_trip();
}

fn run_vector(idx: u8, key: &[u8], plain: &[u8], cipher: &[u8], label: &[u8]) {
    let key_s = from_bytes(key);
    let (c_opt, err) = aes::NewCipher(key_s);
    if !err.IsNil() || c_opt.is_none() {
        write_result(idx, label, false);
        fail();
        return;
    }
    let c = c_opt.unwrap();

    // Encrypt: plain → ct
    let mut ct = from_bytes(&[0u8; 16]);
    c.Encrypt(&mut ct, from_bytes(plain));
    if !check_bytes(&ct, cipher) {
        write_result(idx, label, false);
        fail();
        return;
    }

    // Decrypt: ct → pt
    let mut pt = from_bytes(&[0u8; 16]);
    c.Decrypt(&mut pt, from_bytes(cipher));
    if !check_bytes(&pt, plain) {
        write_result(idx, label, false);
        fail();
        return;
    }

    write_result(idx, label, true);
}

// FIPS-197 Appendix B — AES-128 with the FIPS reference vector.
fn test_1_appendix_b() {
    run_vector(
        1,
        &[
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ],
        &[
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ],
        &[
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ],
        b"AES-128 Appendix B           ",
    );
}

// FIPS-197 Appendix C.1 — AES-128 with the canonical NIST vector.
fn test_2_appendix_c1() {
    run_vector(
        2,
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ],
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ],
        &[
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ],
        b"AES-128 Appendix C.1         ",
    );
}

// FIPS-197 Appendix C.2 — AES-192.
fn test_3_appendix_c2() {
    run_vector(
        3,
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        ],
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ],
        &[
            0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d,
            0x71, 0x91,
        ],
        b"AES-192 Appendix C.2         ",
    );
}

// FIPS-197 Appendix C.3 — AES-256.
fn test_4_appendix_c3() {
    run_vector(
        4,
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ],
        &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ],
        &[
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ],
        b"AES-256 Appendix C.3         ",
    );
}

fn test_5_keysize_zero() {
    let (c_opt, err) = aes::NewCipher(from_bytes(&[]));
    if c_opt.is_none() && !err.IsNil() {
        write_result(5, b"KeySizeError on len=0        ", true);
    } else {
        write_result(5, b"KeySizeError on len=0        ", false);
        fail();
    }
}

fn test_6_keysize_15() {
    let (c_opt, err) = aes::NewCipher(from_bytes(&[0u8; 15]));
    if c_opt.is_none() && !err.IsNil() {
        write_result(6, b"KeySizeError on len=15       ", true);
    } else {
        write_result(6, b"KeySizeError on len=15       ", false);
        fail();
    }
}

fn test_7_keysize_31() {
    let (c_opt, err) = aes::NewCipher(from_bytes(&[0u8; 31]));
    if c_opt.is_none() && !err.IsNil() {
        write_result(7, b"KeySizeError on len=31       ", true);
    } else {
        write_result(7, b"KeySizeError on len=31       ", false);
        fail();
    }
}

fn test_8_keysize_valid() {
    let (c16, e16) = aes::NewCipher(from_bytes(&[0u8; 16]));
    let (c24, e24) = aes::NewCipher(from_bytes(&[0u8; 24]));
    let (c32, e32) = aes::NewCipher(from_bytes(&[0u8; 32]));
    if c16.is_some() && e16.IsNil() && c24.is_some() && e24.IsNil() && c32.is_some() && e32.IsNil()
    {
        write_result(8, b"NewCipher 16/24/32 ok        ", true);
    } else {
        write_result(8, b"NewCipher 16/24/32 ok        ", false);
        fail();
    }
}

fn test_9_block_size() {
    let (c_opt, _) = aes::NewCipher(from_bytes(&[0u8; 16]));
    let c = c_opt.unwrap();
    if c.BlockSize() == aes::BlockSize && c.BlockSize() == 16 {
        write_result(9, b"BlockSize() == 16            ", true);
    } else {
        write_result(9, b"BlockSize() == 16            ", false);
        fail();
    }
}

fn test_10_round_trip() {
    // Arbitrary key + plaintext (not a FIPS vector — just exercises
    // encrypt-then-decrypt end-to-end).
    let key: [u8; 16] = [
        0xa5, 0x5a, 0xc3, 0x3c, 0xf0, 0x0f, 0x96, 0x69, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xf0,
    ];
    let plain: [u8; 16] = [
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let (c_opt, _) = aes::NewCipher(from_bytes(&key));
    let c = c_opt.unwrap();
    let mut ct = from_bytes(&[0u8; 16]);
    c.Encrypt(&mut ct, from_bytes(&plain));

    // Sanity: ct should differ from plain (encryption did something).
    let mut differs = false;
    for i in 0..16 {
        if ct[i as goish::int] != plain[i] {
            differs = true;
            break;
        }
    }
    if !differs {
        write_result(10, b"round-trip 16B               ", false);
        fail();
        return;
    }

    let mut pt = from_bytes(&[0u8; 16]);
    c.Decrypt(&mut pt, ct);
    if check_bytes(&pt, &plain) {
        write_result(10, b"round-trip 16B               ", true);
    } else {
        write_result(10, b"round-trip 16B               ", false);
        fail();
    }
}
