// sha256_smoke — exercise crypto/sha256 (SHA-224 + SHA-256).
// (crypto/sha256/sha256.go + crypto/internal/fips140/sha256/*.go)
//
// Test vectors from FIPS 180-4 Appendix A and Go's sha256_test.go
// `golden` table.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::crypto::sha256;
use goish::goslice::slice;
use goish::hash::Hash;
use goish::types::byte;
use goish::{syscall, Println};

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
// SHA-256("abc") =
//   ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
// SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") =
//   248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1.
// SHA-224("") = d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f.
// SHA-224("abc") = 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7.

const SHA256_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

const SHA256_ABC: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
];

const SHA256_FIPS_LONG: [u8; 32] = [
    0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
    0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
];

const SHA224_EMPTY: [u8; 28] = [
    0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4,
    0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f,
];

const SHA224_ABC: [u8; 28] = [
    0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22, 0x86, 0x42, 0xa4, 0x77, 0xbd, 0xa2, 0x55, 0xb3,
    0x2a, 0xad, 0xbc, 0xe4, 0xbd, 0xa0, 0xb3, 0xf7, 0xe3, 0x6c, 0x9d, 0xa7,
];

fn array32_eq(a: &[u8; 32], b: &[u8]) -> bool {
    if b.len() != 32 {
        return false;
    }
    let mut i = 0;
    while i < 32 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

fn array28_eq(a: &[u8; 28], b: &[u8]) -> bool {
    if b.len() != 28 {
        return false;
    }
    let mut i = 0;
    while i < 28 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Sum256("") matches FIPS empty digest.
    {
        let s = sha256::Sum256(to_bytes(""));
        if array32_eq(&SHA256_EMPTY, &s) {
            Println!("[ 1] Sum256 empty              PASS");
        } else {
            Println!("[ 1] Sum256 empty              FAIL");
            failed += 1;
        }
    }

    // 2. Sum256("abc") matches FIPS 180-4 Appendix A.
    {
        let s = sha256::Sum256(to_bytes("abc"));
        if array32_eq(&SHA256_ABC, &s) {
            Println!("[ 2] Sum256 \"abc\"              PASS");
        } else {
            Println!("[ 2] Sum256 \"abc\"              FAIL");
            failed += 1;
        }
    }

    // 3. Sum256 of FIPS multi-block input (56 bytes — crosses no
    //    block boundary, exercises padding into 2nd block).
    {
        let s = sha256::Sum256(to_bytes(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        ));
        if array32_eq(&SHA256_FIPS_LONG, &s) {
            Println!("[ 3] Sum256 FIPS multi-block   PASS");
        } else {
            Println!("[ 3] Sum256 FIPS multi-block   FAIL");
            failed += 1;
        }
    }

    // 4. Sum224("") matches FIPS empty digest.
    {
        let s = sha256::Sum224(to_bytes(""));
        if array28_eq(&SHA224_EMPTY, &s) {
            Println!("[ 4] Sum224 empty              PASS");
        } else {
            Println!("[ 4] Sum224 empty              FAIL");
            failed += 1;
        }
    }

    // 5. Sum224("abc") matches FIPS 180-4 Appendix A.
    {
        let s = sha256::Sum224(to_bytes("abc"));
        if array28_eq(&SHA224_ABC, &s) {
            Println!("[ 5] Sum224 \"abc\"              PASS");
        } else {
            Println!("[ 5] Sum224 \"abc\"              FAIL");
            failed += 1;
        }
    }

    // 6. New + Write streaming equals one-shot.
    {
        let mut h = sha256::New();
        let _ = h.Write(to_bytes("a"));
        let _ = h.Write(to_bytes("bc"));
        let out = h.Sum(empty_buf());
        let raw: &[byte] = &out;
        if array32_eq(&SHA256_ABC, raw) {
            Println!("[ 6] streaming                 PASS");
        } else {
            Println!("[ 6] streaming                 FAIL");
            failed += 1;
        }
    }

    // 7. Reset clears state to initial.
    {
        let mut h = sha256::New();
        let _ = h.Write(to_bytes("hello"));
        h.Reset();
        let out = h.Sum(empty_buf());
        let raw: &[byte] = &out;
        if array32_eq(&SHA256_EMPTY, raw) {
            Println!("[ 7] Reset                     PASS");
        } else {
            Println!("[ 7] Reset                     FAIL");
            failed += 1;
        }
    }

    // 8. Sum preserves dst prefix; output 32 bytes for SHA-256.
    {
        let mut h = sha256::New();
        let _ = h.Write(to_bytes("abc"));
        let dst = to_bytes("PRE:");
        let out = h.Sum(dst);
        let raw: &[byte] = &out;
        if raw.len() == 4 + 32
            && &raw[0..4] == b"PRE:"
            && array32_eq(&SHA256_ABC, &raw[4..])
        {
            Println!("[ 8] Sum prefix                PASS");
        } else {
            Println!("[ 8] Sum prefix                FAIL");
            failed += 1;
        }
    }

    // 9. Long input crossing block boundary (>64 bytes).
    {
        // 200-byte input — multi-block path.
        let mut v: Vec<byte> = Vec::with_capacity(200);
        let mut i = 0;
        while i < 200 {
            v.push(b'A' + ((i % 26) as byte));
            i += 1;
        }
        let buf = slice::<byte>::__from_vec(v);
        let s_one = sha256::Sum256(buf.clone());

        let mut h = sha256::New();
        let _ = h.Write(buf);
        let s_stream = h.Sum(empty_buf());
        let raw: &[byte] = &s_stream;
        if array32_eq(&s_one, raw) {
            Println!("[ 9] >block boundary           PASS");
        } else {
            Println!("[ 9] >block boundary           FAIL");
            failed += 1;
        }
    }

    // 10. Size + BlockSize.
    {
        let h = sha256::New();
        let h224 = sha256::New224();
        if h.Size() == sha256::Size
            && h224.Size() == sha256::Size224
            && h.BlockSize() == sha256::BlockSize
        {
            Println!("[10] Size/BlockSize            PASS");
        } else {
            Println!("[10] Size/BlockSize            FAIL");
            failed += 1;
        }
    }

    // 11. Sum doesn't mutate digest — calling twice gives same result.
    {
        let mut h = sha256::New();
        let _ = h.Write(to_bytes("abc"));
        let s1 = h.Sum(empty_buf());
        let s2 = h.Sum(empty_buf());
        let r1: &[byte] = &s1;
        let r2: &[byte] = &s2;
        if r1 == r2 && array32_eq(&SHA256_ABC, r1) {
            Println!("[11] Sum non-mutating          PASS");
        } else {
            Println!("[11] Sum non-mutating          FAIL");
            failed += 1;
        }
    }

    // 12. Streaming after Sum continues correctly.
    {
        let mut h = sha256::New();
        let _ = h.Write(to_bytes("a"));
        let _ = h.Sum(empty_buf()); // intermediate sum, must not affect state
        let _ = h.Write(to_bytes("bc"));
        let out = h.Sum(empty_buf());
        let raw: &[byte] = &out;
        if array32_eq(&SHA256_ABC, raw) {
            Println!("[12] write-after-Sum           PASS");
        } else {
            Println!("[12] write-after-Sum           FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
