// sha3_smoke — exercise crypto/sha3 SHA-3 + SHAKE.
//
// Test vectors lifted from FIPS 202 Appendix A + NIST CAVP examples
// (matching /share/go/src/crypto/sha3/sha3_test.go).
//
// Coverage:
//   1. SHA3-224("") = 6b4e0342…
//   2. SHA3-256("") = a7ffc6f8…
//   3. SHA3-384("") = 0c63a75b…
//   4. SHA3-512("") = a69f73cc…
//   5. SHA3-224("abc") = e642824c…
//   6. SHA3-256("abc") = 3a985da7…
//   7. SHA3-512("abc") = b751850b…
//   8. SHA3-256 streaming Write — split into 3 chunks, equal one-shot.
//   9. SHAKE128("", 32) = 7f9c2ba4… (extendable output).
//  10. SHAKE256("", 64) = 46b9dd2b… (extendable output).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::crypto::sha3;
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

fn check_arr(got: &[u8], want: &[u8]) -> bool {
    if got.len() != want.len() {
        return false;
    }
    for i in 0..want.len() {
        if got[i] != want[i] {
            return false;
        }
    }
    true
}

fn check_slice(got: &goish::slice<byte>, want: &[u8]) -> bool {
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
    test_1_sha3_224_empty();
    test_2_sha3_256_empty();
    test_3_sha3_384_empty();
    test_4_sha3_512_empty();
    test_5_sha3_224_abc();
    test_6_sha3_256_abc();
    test_7_sha3_512_abc();
    test_8_sha3_256_streaming();
    test_9_shake128_empty_32();
    test_10_shake256_empty_64();
}

fn test_1_sha3_224_empty() {
    let got = sha3::Sum224(from_bytes(&[]));
    let want = [
        0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7, 0x3b, 0x6e, 0x15, 0x45, 0x4f, 0x0e, 0xb1,
        0xab, 0xd4, 0x59, 0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f, 0x5b, 0x5a, 0x6b, 0xc7,
    ];
    if check_arr(&got, &want) {
        write_result(1, b"SHA3-224 empty               ", true);
    } else {
        write_result(1, b"SHA3-224 empty               ", false);
        fail();
    }
}

fn test_2_sha3_256_empty() {
    let got = sha3::Sum256(from_bytes(&[]));
    let want = [
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6,
        0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8,
        0x43, 0x4a,
    ];
    if check_arr(&got, &want) {
        write_result(2, b"SHA3-256 empty               ", true);
    } else {
        write_result(2, b"SHA3-256 empty               ", false);
        fail();
    }
}

fn test_3_sha3_384_empty() {
    let got = sha3::Sum384(from_bytes(&[]));
    let want = [
        0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d, 0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c, 0x24,
        0x85, 0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61, 0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98,
        0x3a, 0x2a, 0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47, 0xfb, 0x6b, 0xd1, 0xe0, 0x58,
        0xd5, 0xf0, 0x04,
    ];
    if check_arr(&got, &want) {
        write_result(3, b"SHA3-384 empty               ", true);
    } else {
        write_result(3, b"SHA3-384 empty               ", false);
        fail();
    }
}

fn test_4_sha3_512_empty() {
    let got = sha3::Sum512(from_bytes(&[]));
    let want = [
        0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75,
        0x6e, 0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c,
        0x80, 0xa6, 0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c,
        0x3a, 0xc5, 0x58, 0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86,
        0x28, 0x1d, 0xcd, 0x26,
    ];
    if check_arr(&got, &want) {
        write_result(4, b"SHA3-512 empty               ", true);
    } else {
        write_result(4, b"SHA3-512 empty               ", false);
        fail();
    }
}

fn test_5_sha3_224_abc() {
    let got = sha3::Sum224(from_bytes(b"abc"));
    let want = [
        0xe6, 0x42, 0x82, 0x4c, 0x3f, 0x8c, 0xf2, 0x4a, 0xd0, 0x92, 0x34, 0xee, 0x7d, 0x3c, 0x76,
        0x6f, 0xc9, 0xa3, 0xa5, 0x16, 0x8d, 0x0c, 0x94, 0xad, 0x73, 0xb4, 0x6f, 0xdf,
    ];
    if check_arr(&got, &want) {
        write_result(5, b"SHA3-224 abc                 ", true);
    } else {
        write_result(5, b"SHA3-224 abc                 ", false);
        fail();
    }
}

fn test_6_sha3_256_abc() {
    let got = sha3::Sum256(from_bytes(b"abc"));
    let want = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
        0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
        0x15, 0x32,
    ];
    if check_arr(&got, &want) {
        write_result(6, b"SHA3-256 abc                 ", true);
    } else {
        write_result(6, b"SHA3-256 abc                 ", false);
        fail();
    }
}

fn test_7_sha3_512_abc() {
    let got = sha3::Sum512(from_bytes(b"abc"));
    let want = [
        0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09,
        0x6e, 0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2,
        0x71, 0x2e, 0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9, 0x1a, 0x7e, 0xc5, 0x76, 0x47,
        0xe3, 0x93, 0x40, 0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5, 0x65, 0x92, 0xf8, 0x27,
        0x4e, 0xec, 0x53, 0xf0,
    ];
    if check_arr(&got, &want) {
        write_result(7, b"SHA3-512 abc                 ", true);
    } else {
        write_result(7, b"SHA3-512 abc                 ", false);
        fail();
    }
}

fn test_8_sha3_256_streaming() {
    // Same hash via streaming Write: "a" + "b" + "c" → same as Sum256("abc").
    let mut h = sha3::New256();
    let _ = h.Write(from_bytes(b"a"));
    let _ = h.Write(from_bytes(b"b"));
    let _ = h.Write(from_bytes(b"c"));
    let empty: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    let got = h.Sum(slice::__from_vec(empty));
    let want = [
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90,
        0xbd, 0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43,
        0x15, 0x32,
    ];
    if check_slice(&got, &want) {
        write_result(8, b"SHA3-256 streaming abc       ", true);
    } else {
        write_result(8, b"SHA3-256 streaming abc       ", false);
        fail();
    }
}

fn test_9_shake128_empty_32() {
    // SHAKE128("", 32) — first 32 bytes of squeezed output for empty input.
    let got = sha3::SumSHAKE128(from_bytes(&[]), 32);
    let want = [
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85,
        0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66,
        0xef, 0x26,
    ];
    if check_slice(&got, &want) {
        write_result(9, b"SHAKE128 empty 32B           ", true);
    } else {
        write_result(9, b"SHAKE128 empty 32B           ", false);
        fail();
    }
}

fn test_10_shake256_empty_64() {
    // SHAKE256("", 64).
    let got = sha3::SumSHAKE256(from_bytes(&[]), 64);
    let want = [
        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb,
        0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5,
        0x76, 0x2f, 0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00, 0xcb, 0x05, 0x01, 0x9d, 0x67,
        0xb5, 0x92, 0xf6, 0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86, 0x40, 0x29, 0x2e, 0xac,
        0xb3, 0xb7, 0xc4, 0xbe,
    ];
    if check_slice(&got, &want) {
        write_result(10, b"SHAKE256 empty 64B           ", true);
    } else {
        write_result(10, b"SHAKE256 empty 64B           ", false);
        fail();
    }
}
