// md5_smoke — exercise crypto/md5.
// (crypto/md5/md5.go + md5block.go)
//
// Reference vectors from RFC 1321 Appendix A.5 and Go's md5_test.go.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::fmt;
use goish::convert::bytes as to_bytes;
use goish::crypto::md5;
use goish::goslice::slice;
use goish::hash::Hash;
use goish::io::Writer as _;
use goish::types::byte;
use goish::{syscall};

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

// MD5("") = d41d8cd98f00b204e9800998ecf8427e (RFC 1321 §A.5)
const MD5_EMPTY: [u8; 16] = [
    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
];

// MD5("abc") = 900150983cd24fb0d6963f7d28e17f72 (RFC 1321 §A.5)
const MD5_ABC: [u8; 16] = [
    0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
];

// MD5("message digest") = f96b697d7cb7938d525a2f31aaf161d0
const MD5_MSG_DIGEST: [u8; 16] = [
    0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0,
];

// MD5("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
const MD5_ALPHA: [u8; 16] = [
    0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b,
];

// MD5("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
//  = d174ab98d277d9f5a5611c2c9f419d9f
const MD5_ALNUM: [u8; 16] = [
    0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f,
];

fn array16_eq(a: &[u8; 16], b: &[u8]) -> bool {
    if b.len() != 16 {
        return false;
    }
    let mut i = 0;
    while i < 16 {
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

    // 1. Sum("") matches RFC 1321 empty digest.
    {
        let s = md5::Sum(to_bytes(""));
        if array16_eq(&MD5_EMPTY, &s) {
            fmt::Println!("[ 1] Sum empty                 PASS");
        } else {
            fmt::Println!("[ 1] Sum empty                 FAIL");
            failed += 1;
        }
    }

    // 2. Sum("abc") matches RFC 1321 §A.5.
    {
        let s = md5::Sum(to_bytes("abc"));
        if array16_eq(&MD5_ABC, &s) {
            fmt::Println!("[ 2] Sum \"abc\"                 PASS");
        } else {
            fmt::Println!("[ 2] Sum \"abc\"                 FAIL");
            failed += 1;
        }
    }

    // 3. Sum("message digest").
    {
        let s = md5::Sum(to_bytes("message digest"));
        if array16_eq(&MD5_MSG_DIGEST, &s) {
            fmt::Println!("[ 3] Sum \"message digest\"      PASS");
        } else {
            fmt::Println!("[ 3] Sum \"message digest\"      FAIL");
            failed += 1;
        }
    }

    // 4. Sum("abcdefghijklmnopqrstuvwxyz") — 26-byte input, single block.
    {
        let s = md5::Sum(to_bytes("abcdefghijklmnopqrstuvwxyz"));
        if array16_eq(&MD5_ALPHA, &s) {
            fmt::Println!("[ 4] Sum alpha                 PASS");
        } else {
            fmt::Println!("[ 4] Sum alpha                 FAIL");
            failed += 1;
        }
    }

    // 5. Sum("ABC..XYZabc..xyz0..9") — 62 bytes, padding into 2nd block.
    {
        let s = md5::Sum(to_bytes(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        ));
        if array16_eq(&MD5_ALNUM, &s) {
            fmt::Println!("[ 5] Sum alnum (62 B)          PASS");
        } else {
            fmt::Println!("[ 5] Sum alnum (62 B)          FAIL");
            failed += 1;
        }
    }

    // 6. New + streaming Write equals one-shot Sum.
    {
        let mut h = md5::New();
        let _ = h.Write(to_bytes("a"));
        let _ = h.Write(to_bytes("bc"));
        let out = h.Sum(empty_buf());
        let raw: &[byte] = &out;
        if array16_eq(&MD5_ABC, raw) {
            fmt::Println!("[ 6] streaming                 PASS");
        } else {
            fmt::Println!("[ 6] streaming                 FAIL");
            failed += 1;
        }
    }

    // 7. Reset returns digest to initial state.
    {
        let mut h = md5::New();
        let _ = h.Write(to_bytes("hello"));
        h.Reset();
        let out = h.Sum(empty_buf());
        let raw: &[byte] = &out;
        if array16_eq(&MD5_EMPTY, raw) {
            fmt::Println!("[ 7] Reset                     PASS");
        } else {
            fmt::Println!("[ 7] Reset                     FAIL");
            failed += 1;
        }
    }

    // 8. Sum preserves dst prefix; output 16 bytes.
    {
        let mut h = md5::New();
        let _ = h.Write(to_bytes("abc"));
        let dst = to_bytes("PRE:");
        let out = h.Sum(dst);
        let raw: &[byte] = &out;
        if raw.len() == 4 + 16
            && &raw[0..4] == b"PRE:"
            && array16_eq(&MD5_ABC, &raw[4..])
        {
            fmt::Println!("[ 8] Sum prefix                PASS");
        } else {
            fmt::Println!("[ 8] Sum prefix                FAIL");
            failed += 1;
        }
    }

    // 9. Long input crossing block boundary (>64 bytes).
    {
        let mut v: Vec<byte> = Vec::with_capacity(200);
        let mut i = 0;
        while i < 200 {
            v.push(b'A' + ((i % 26) as byte));
            i += 1;
        }
        let buf = slice::<byte>::__from_vec(v);
        let s_one = md5::Sum(buf.clone());

        let mut h = md5::New();
        let _ = h.Write(buf);
        let s_stream = h.Sum(empty_buf());
        let raw: &[byte] = &s_stream;
        if array16_eq(&s_one, raw) {
            fmt::Println!("[ 9] >block boundary           PASS");
        } else {
            fmt::Println!("[ 9] >block boundary           FAIL");
            failed += 1;
        }
    }

    // 10. Size + BlockSize.
    {
        let h = md5::New();
        if h.Size() == md5::Size && h.BlockSize() == md5::BlockSize {
            fmt::Println!("[10] Size/BlockSize            PASS");
        } else {
            fmt::Println!("[10] Size/BlockSize            FAIL");
            failed += 1;
        }
    }

    // 11. Sum doesn't mutate digest.
    {
        let mut h = md5::New();
        let _ = h.Write(to_bytes("abc"));
        let s1 = h.Sum(empty_buf());
        let s2 = h.Sum(empty_buf());
        let r1: &[byte] = &s1;
        let r2: &[byte] = &s2;
        if r1 == r2 && array16_eq(&MD5_ABC, r1) {
            fmt::Println!("[11] Sum non-mutating          PASS");
        } else {
            fmt::Println!("[11] Sum non-mutating          FAIL");
            failed += 1;
        }
    }

    // 12. Boundary at exactly 64 bytes (1 block, requires padding into 2nd).
    {
        let s = md5::Sum(to_bytes(
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        ));
        // MD5("0123456789ABCDEF" * 4) — verify known length 64 hits the
        // exact-block-padding path. We just check Sum + streaming agree.
        let mut h = md5::New();
        let _ = h.Write(to_bytes(
            "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        ));
        let out = h.Sum(empty_buf());
        let raw: &[byte] = &out;
        if array16_eq(&s, raw) {
            fmt::Println!("[12] 64-byte boundary          PASS");
        } else {
            fmt::Println!("[12] 64-byte boundary          FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
