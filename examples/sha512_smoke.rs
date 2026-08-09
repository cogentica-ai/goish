// sha512_smoke — exercise crypto/sha512 (SHA-384, SHA-512, SHA-512/224,
// SHA-512/256). Reference vectors from FIPS 180-4 Appendix C and Go's
// sha512_test.go.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::fmt;
use goish::convert::bytes as to_bytes;
use goish::crypto::sha512;
use goish::goslice::slice;
use goish::hash::Hash;
use goish::io::Writer as _;
use goish::types::byte;
use goish::{syscall};

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

fn from_hex(s: &str) -> Vec<byte> {
    let b = s.as_bytes();
    let mut out: Vec<byte> = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        let hi = match b[i] {
            x @ b'0'..=b'9' => x - b'0',
            x @ b'a'..=b'f' => x - b'a' + 10,
            x @ b'A'..=b'F' => x - b'A' + 10,
            _ => 0,
        };
        let lo = match b[i + 1] {
            x @ b'0'..=b'9' => x - b'0',
            x @ b'a'..=b'f' => x - b'a' + 10,
            x @ b'A'..=b'F' => x - b'A' + 10,
            _ => 0,
        };
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn slice_eq(a: &[byte], b: &[byte]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
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

    // ── SHA-512 vectors ────────────────────────────────────────────────
    // SHA-512("") = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce
    //               47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
    {
        let s = sha512::Sum512(to_bytes(""));
        let want = from_hex(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );
        if slice_eq(&s, &want) {
            fmt::Println!("[ 1] Sum512 empty              PASS");
        } else {
            fmt::Println!("[ 1] Sum512 empty              FAIL");
            failed += 1;
        }
    }

    // FIPS 180-4 §C.1: SHA-512("abc") =
    //   ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a
    //   2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f
    {
        let s = sha512::Sum512(to_bytes("abc"));
        let want = from_hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        if slice_eq(&s, &want) {
            fmt::Println!("[ 2] Sum512 \"abc\"              PASS");
        } else {
            fmt::Println!("[ 2] Sum512 \"abc\"              FAIL");
            failed += 1;
        }
    }

    // FIPS 180-4 §C.2 (multi-block, 112-byte input):
    // SHA-512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
    //         "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") =
    //   8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018
    //   501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909
    {
        let s = sha512::Sum512(to_bytes(
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
             hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        ));
        let want = from_hex(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        );
        if slice_eq(&s, &want) {
            fmt::Println!("[ 3] Sum512 FIPS multi-block   PASS");
        } else {
            fmt::Println!("[ 3] Sum512 FIPS multi-block   FAIL");
            failed += 1;
        }
    }

    // ── SHA-384 vectors ────────────────────────────────────────────────
    // SHA-384("") = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da
    //               274edebfe76f65fbd51ad2f14898b95b
    {
        let s = sha512::Sum384(to_bytes(""));
        let want = from_hex(
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b",
        );
        if slice_eq(&s, &want) {
            fmt::Println!("[ 4] Sum384 empty              PASS");
        } else {
            fmt::Println!("[ 4] Sum384 empty              FAIL");
            failed += 1;
        }
    }

    // FIPS 180-4 §D.1: SHA-384("abc") =
    //   cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163
    //   1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7
    {
        let s = sha512::Sum384(to_bytes("abc"));
        let want = from_hex(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7",
        );
        if slice_eq(&s, &want) {
            fmt::Println!("[ 5] Sum384 \"abc\"              PASS");
        } else {
            fmt::Println!("[ 5] Sum384 \"abc\"              FAIL");
            failed += 1;
        }
    }

    // ── SHA-512/224 ────────────────────────────────────────────────────
    // SHA-512/224("") = 6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4
    // (Go golden224[0] in crypto/sha512/sha512_test.go)
    {
        let s = sha512::Sum512_224(to_bytes(""));
        let want = from_hex(
            "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
        );
        if slice_eq(&s, &want) {
            fmt::Println!("[ 6] Sum512_224 empty          PASS");
        } else {
            fmt::Println!("[ 6] Sum512_224 empty          FAIL");
            failed += 1;
        }
    }

    // SHA-512/224("abc") = 4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa
    {
        let s = sha512::Sum512_224(to_bytes("abc"));
        let want = from_hex(
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
        );
        if slice_eq(&s, &want) {
            fmt::Println!("[ 7] Sum512_224 \"abc\"          PASS");
        } else {
            fmt::Println!("[ 7] Sum512_224 \"abc\"          FAIL");
            failed += 1;
        }
    }

    // ── SHA-512/256 ────────────────────────────────────────────────────
    // SHA-512/256("") = c672b8d1ef56ed28 ab87c3622c5114069bdd3ad7b8f9737498d0c01ec
    //                   ef0967a (32 bytes)
    {
        let s = sha512::Sum512_256(to_bytes(""));
        let want = from_hex(
            "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        );
        if slice_eq(&s, &want) {
            fmt::Println!("[ 8] Sum512_256 empty          PASS");
        } else {
            fmt::Println!("[ 8] Sum512_256 empty          FAIL");
            failed += 1;
        }
    }

    // SHA-512/256("abc") = 53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23
    {
        let s = sha512::Sum512_256(to_bytes("abc"));
        let want = from_hex(
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
        );
        if slice_eq(&s, &want) {
            fmt::Println!("[ 9] Sum512_256 \"abc\"          PASS");
        } else {
            fmt::Println!("[ 9] Sum512_256 \"abc\"          FAIL");
            failed += 1;
        }
    }

    // ── streaming Write equals one-shot Sum ────────────────────────────
    {
        let mut h = sha512::New();
        let _ = h.Write(to_bytes("a"));
        let _ = h.Write(to_bytes("bc"));
        let out = h.Sum(empty_buf());
        let raw: &[byte] = &out;
        let want = sha512::Sum512(to_bytes("abc"));
        if slice_eq(raw, &want) {
            fmt::Println!("[10] streaming                 PASS");
        } else {
            fmt::Println!("[10] streaming                 FAIL");
            failed += 1;
        }
    }

    // ── Reset returns digest to fresh state ────────────────────────────
    {
        let mut h = sha512::New();
        let _ = h.Write(to_bytes("hello"));
        h.Reset();
        let out = h.Sum(empty_buf());
        let raw: &[byte] = &out;
        let want = sha512::Sum512(to_bytes(""));
        if slice_eq(raw, &want) {
            fmt::Println!("[11] Reset                     PASS");
        } else {
            fmt::Println!("[11] Reset                     FAIL");
            failed += 1;
        }
    }

    // ── Sum preserves dst prefix; output 64 bytes for SHA-512 ─────────
    {
        let mut h = sha512::New();
        let _ = h.Write(to_bytes("abc"));
        let dst = to_bytes("PRE:");
        let out = h.Sum(dst);
        let raw: &[byte] = &out;
        let want = sha512::Sum512(to_bytes("abc"));
        if raw.len() == 4 + 64 && &raw[0..4] == b"PRE:" && slice_eq(&raw[4..], &want) {
            fmt::Println!("[12] Sum prefix                PASS");
        } else {
            fmt::Println!("[12] Sum prefix                FAIL");
            failed += 1;
        }
    }

    // ── >block boundary (>128 bytes) ───────────────────────────────────
    {
        let mut v: Vec<byte> = Vec::with_capacity(300);
        let mut i = 0;
        while i < 300 {
            v.push(b'A' + ((i % 26) as byte));
            i += 1;
        }
        let buf = slice::<byte>::__from_vec(v);
        let s_one = sha512::Sum512(buf.clone());

        let mut h = sha512::New();
        let _ = h.Write(buf);
        let s_stream = h.Sum(empty_buf());
        let raw: &[byte] = &s_stream;
        if slice_eq(&s_one, raw) {
            fmt::Println!("[13] >block boundary           PASS");
        } else {
            fmt::Println!("[13] >block boundary           FAIL");
            failed += 1;
        }
    }

    // ── Size + BlockSize for all variants ─────────────────────────────
    {
        let h512 = sha512::New();
        let h384 = sha512::New384();
        let h224 = sha512::New512_224();
        let h256 = sha512::New512_256();
        if h512.Size() == sha512::Size
            && h384.Size() == sha512::Size384
            && h224.Size() == sha512::Size224
            && h256.Size() == sha512::Size256
            && h512.BlockSize() == sha512::BlockSize
            && h384.BlockSize() == sha512::BlockSize
        {
            fmt::Println!("[14] Size/BlockSize            PASS");
        } else {
            fmt::Println!("[14] Size/BlockSize            FAIL");
            failed += 1;
        }
    }

    // ── Sum doesn't mutate digest ──────────────────────────────────────
    {
        let mut h = sha512::New();
        let _ = h.Write(to_bytes("abc"));
        let s1 = h.Sum(empty_buf());
        let s2 = h.Sum(empty_buf());
        let r1: &[byte] = &s1;
        let r2: &[byte] = &s2;
        let want = sha512::Sum512(to_bytes("abc"));
        if slice_eq(r1, r2) && slice_eq(r1, &want) {
            fmt::Println!("[15] Sum non-mutating          PASS");
        } else {
            fmt::Println!("[15] Sum non-mutating          FAIL");
            failed += 1;
        }
    }

    // ── HMAC-SHA-512 cross-check (RFC 4231 Test Case 1) ──────────────
    // Key: 20 bytes 0x0b, Data: "Hi There"
    // HMAC: 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854
    {
        use goish::crypto::hmac;
        let key = slice::<byte>::__from_vec(alloc::vec![0x0b; 20]);
        let mut h = hmac::New(sha512::NewHash, key);
        let _ = h.Write(to_bytes("Hi There"));
        let mac = h.Sum(empty_buf());
        let raw: &[byte] = &mac;
        let want = from_hex(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        );
        if slice_eq(raw, &want) {
            fmt::Println!("[16] HMAC-SHA-512 RFC4231 #1   PASS");
        } else {
            fmt::Println!("[16] HMAC-SHA-512 RFC4231 #1   FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 16/16");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 16");
        syscall::Exit(1);
    }
}
