// sha1_smoke — exercise crypto/sha1.
// (crypto/sha1/sha1.go + sha1block.go)
//
// Reference vectors from RFC 3174 §7.3 and Go's sha1_test.go.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::crypto::sha1;
use goish::fmt;
use goish::goslice::slice;
use goish::hash::Hash;
use goish::syscall;
use goish::types::byte;

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

// SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
const SHA1_EMPTY: [u8; 20] = [
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
    0xaf, 0xd8, 0x07, 0x09,
];

// SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d (RFC 3174 §A.1)
const SHA1_ABC: [u8; 20] = [
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
    0x9c, 0xd0, 0xd8, 0x9d,
];

// SHA-1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
//    = 84983e441c3bd26ebaae4aa1f95129e5e54670f1 (RFC 3174 §A.2)
const SHA1_FIPS_LONG: [u8; 20] = [
    0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5,
    0xe5, 0x46, 0x70, 0xf1,
];

fn array20_eq(a: &[u8; 20], b: &[u8]) -> bool {
    if b.len() != 20 {
        return false;
    }
    let mut i = 0;
    while i < 20 {
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

    // 1. Sum("") matches RFC 3174 empty digest.
    {
        let s = sha1::Sum(to_bytes(""));
        if array20_eq(&SHA1_EMPTY, &s) {
            fmt::Println!("[ 1] Sum empty                 PASS");
        } else {
            fmt::Println!("[ 1] Sum empty                 FAIL");
            failed += 1;
        }
    }

    // 2. Sum("abc") matches RFC 3174 §A.1.
    {
        let s = sha1::Sum(to_bytes("abc"));
        if array20_eq(&SHA1_ABC, &s) {
            fmt::Println!("[ 2] Sum \"abc\"                 PASS");
        } else {
            fmt::Println!("[ 2] Sum \"abc\"                 FAIL");
            failed += 1;
        }
    }

    // 3. RFC 3174 §A.2 multi-block input.
    {
        let s = sha1::Sum(to_bytes(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        ));
        if array20_eq(&SHA1_FIPS_LONG, &s) {
            fmt::Println!("[ 3] Sum RFC §A.2              PASS");
        } else {
            fmt::Println!("[ 3] Sum RFC §A.2              FAIL");
            failed += 1;
        }
    }

    // 4. New + streaming Write equals one-shot Sum.
    {
        let mut h = sha1::New();
        let _ = h.Write(to_bytes("a"));
        let _ = h.Write(to_bytes("bc"));
        let out = h.Sum(empty_buf());
        let raw: &[byte] = &out;
        if array20_eq(&SHA1_ABC, raw) {
            fmt::Println!("[ 4] streaming                 PASS");
        } else {
            fmt::Println!("[ 4] streaming                 FAIL");
            failed += 1;
        }
    }

    // 5. Reset returns digest to initial state.
    {
        let mut h = sha1::New();
        let _ = h.Write(to_bytes("hello"));
        h.Reset();
        let out = h.Sum(empty_buf());
        let raw: &[byte] = &out;
        if array20_eq(&SHA1_EMPTY, raw) {
            fmt::Println!("[ 5] Reset                     PASS");
        } else {
            fmt::Println!("[ 5] Reset                     FAIL");
            failed += 1;
        }
    }

    // 6. Sum preserves dst prefix; output 20 bytes.
    {
        let mut h = sha1::New();
        let _ = h.Write(to_bytes("abc"));
        let dst = to_bytes("PRE:");
        let out = h.Sum(dst);
        let raw: &[byte] = &out;
        if raw.len() == 4 + 20 && &raw[0..4] == b"PRE:" && array20_eq(&SHA1_ABC, &raw[4..]) {
            fmt::Println!("[ 6] Sum prefix                PASS");
        } else {
            fmt::Println!("[ 6] Sum prefix                FAIL");
            failed += 1;
        }
    }

    // 7. Long input crossing block boundary (>64 bytes).
    {
        let mut v: Vec<byte> = Vec::with_capacity(200);
        let mut i = 0;
        while i < 200 {
            v.push(b'A' + ((i % 26) as byte));
            i += 1;
        }
        let buf = slice::<byte>::__from_vec(v);
        let s_one = sha1::Sum(buf.clone());

        let mut h = sha1::New();
        let _ = h.Write(buf);
        let s_stream = h.Sum(empty_buf());
        let raw: &[byte] = &s_stream;
        if array20_eq(&s_one, raw) {
            fmt::Println!("[ 7] >block boundary           PASS");
        } else {
            fmt::Println!("[ 7] >block boundary           FAIL");
            failed += 1;
        }
    }

    // 8. Size + BlockSize.
    {
        let h = sha1::New();
        if h.Size() == sha1::Size && h.BlockSize() == sha1::BlockSize {
            fmt::Println!("[ 8] Size/BlockSize            PASS");
        } else {
            fmt::Println!("[ 8] Size/BlockSize            FAIL");
            failed += 1;
        }
    }

    // 9. Sum doesn't mutate digest.
    {
        let mut h = sha1::New();
        let _ = h.Write(to_bytes("abc"));
        let s1 = h.Sum(empty_buf());
        let s2 = h.Sum(empty_buf());
        let r1: &[byte] = &s1;
        let r2: &[byte] = &s2;
        if r1 == r2 && array20_eq(&SHA1_ABC, r1) {
            fmt::Println!("[ 9] Sum non-mutating          PASS");
        } else {
            fmt::Println!("[ 9] Sum non-mutating          FAIL");
            failed += 1;
        }
    }

    // 10. WebSocket Sec-WebSocket-Accept handshake test vector.
    //     RFC 6455 §1.3: SHA-1("dGhlIHNhbXBsZSBub25jZQ==" + GUID) base64'd
    //     = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    //     Just verify the SHA-1 raw output here.
    {
        let key = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let s = sha1::Sum(to_bytes(key));
        // base64("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") decoded =
        //   b3 7a 4f 2c c0 62 4f 16 90 f6 46 06 cf 38 59 45 b2 be c4 ea
        let want: [u8; 20] = [
            0xb3, 0x7a, 0x4f, 0x2c, 0xc0, 0x62, 0x4f, 0x16, 0x90, 0xf6, 0x46, 0x06, 0xcf, 0x38,
            0x59, 0x45, 0xb2, 0xbe, 0xc4, 0xea,
        ];
        if array20_eq(&want, &s) {
            fmt::Println!("[10] WebSocket handshake       PASS");
        } else {
            fmt::Println!("[10] WebSocket handshake       FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
