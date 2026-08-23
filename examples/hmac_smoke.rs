// hmac_smoke — exercise crypto/hmac.
// (crypto/hmac/hmac.go + crypto/internal/fips140/hmac/hmac.go)
//
// Test vectors from RFC 2202 (HMAC-SHA-1, HMAC-MD5) and RFC 4231
// (HMAC-SHA-256).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::crypto::{hmac, md5, sha1, sha256};
use goish::fmt;
use goish::goslice::slice;
use goish::hash::Hash;
use goish::io::Writer as _;
use goish::syscall;
use goish::types::byte;

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

    // ── RFC 4231 §4.2: HMAC-SHA-256 Test Case 1 ────────────────────────
    // Key: 20 bytes of 0x0b
    // Data: "Hi There"
    // HMAC: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    {
        let key = slice::<byte>::__from_vec(alloc::vec![0x0b; 20]);
        let data = to_bytes("Hi There");
        let mut h = hmac::New(sha256::NewHash, key);
        let _ = h.Write(data);
        let mac = h.Sum(empty_buf());
        let raw: &[byte] = &mac;
        let want = from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        if slice_eq(raw, &want) {
            fmt::Println!("[ 1] HMAC-SHA-256 RFC4231 #1   PASS");
        } else {
            fmt::Println!("[ 1] HMAC-SHA-256 RFC4231 #1   FAIL");
            failed += 1;
        }
    }

    // ── RFC 4231 §4.3: HMAC-SHA-256 Test Case 2 ────────────────────────
    // Key: "Jefe"
    // Data: "what do ya want for nothing?"
    // HMAC: 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    {
        let mac = {
            let mut h = hmac::New(sha256::NewHash, to_bytes("Jefe"));
            let _ = h.Write(to_bytes("what do ya want for nothing?"));
            h.Sum(empty_buf())
        };
        let raw: &[byte] = &mac;
        let want = from_hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        if slice_eq(raw, &want) {
            fmt::Println!("[ 2] HMAC-SHA-256 RFC4231 #2   PASS");
        } else {
            fmt::Println!("[ 2] HMAC-SHA-256 RFC4231 #2   FAIL");
            failed += 1;
        }
    }

    // ── RFC 4231 §4.6: HMAC-SHA-256 Test Case 6 (key > blocksize) ─────
    // Key: 131 bytes of 0xaa
    // Data: "Test Using Larger Than Block-Size Key - Hash Key First"
    // HMAC: 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54
    {
        let key = slice::<byte>::__from_vec(alloc::vec![0xaa; 131]);
        let mut h = hmac::New(sha256::NewHash, key);
        let _ = h.Write(to_bytes(
            "Test Using Larger Than Block-Size Key - Hash Key First",
        ));
        let mac = h.Sum(empty_buf());
        let raw: &[byte] = &mac;
        let want = from_hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        if slice_eq(raw, &want) {
            fmt::Println!("[ 3] HMAC-SHA-256 long key     PASS");
        } else {
            fmt::Println!("[ 3] HMAC-SHA-256 long key     FAIL");
            failed += 1;
        }
    }

    // ── RFC 2202 §3: HMAC-SHA-1 Test Case 1 ────────────────────────────
    // Key: 20 bytes of 0x0b, Data: "Hi There"
    // HMAC: b617318655057264e28bc0b6fb378c8ef146be00
    {
        let key = slice::<byte>::__from_vec(alloc::vec![0x0b; 20]);
        let mut h = hmac::New(sha1::NewHash, key);
        let _ = h.Write(to_bytes("Hi There"));
        let mac = h.Sum(empty_buf());
        let raw: &[byte] = &mac;
        let want = from_hex("b617318655057264e28bc0b6fb378c8ef146be00");
        if slice_eq(raw, &want) {
            fmt::Println!("[ 4] HMAC-SHA-1 RFC2202 #1     PASS");
        } else {
            fmt::Println!("[ 4] HMAC-SHA-1 RFC2202 #1     FAIL");
            failed += 1;
        }
    }

    // ── RFC 2202 §3: HMAC-SHA-1 Test Case 2 ────────────────────────────
    // Key: "Jefe", Data: "what do ya want for nothing?"
    // HMAC: effcdf6ae5eb2fa2d27416d5f184df9c259a7c79
    {
        let mut h = hmac::New(sha1::NewHash, to_bytes("Jefe"));
        let _ = h.Write(to_bytes("what do ya want for nothing?"));
        let mac = h.Sum(empty_buf());
        let raw: &[byte] = &mac;
        let want = from_hex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        if slice_eq(raw, &want) {
            fmt::Println!("[ 5] HMAC-SHA-1 RFC2202 #2     PASS");
        } else {
            fmt::Println!("[ 5] HMAC-SHA-1 RFC2202 #2     FAIL");
            failed += 1;
        }
    }

    // ── RFC 2202 §3: HMAC-SHA-1 Test Case 5 (long key) ─────────────────
    // Key: 80 bytes of 0xaa
    // Data: "Test Using Larger Than Block-Size Key - Hash Key First"
    // HMAC: aa4ae5e15272d00e95705637ce8a3b55ed402112
    {
        let key = slice::<byte>::__from_vec(alloc::vec![0xaa; 80]);
        let mut h = hmac::New(sha1::NewHash, key);
        let _ = h.Write(to_bytes(
            "Test Using Larger Than Block-Size Key - Hash Key First",
        ));
        let mac = h.Sum(empty_buf());
        let raw: &[byte] = &mac;
        let want = from_hex("aa4ae5e15272d00e95705637ce8a3b55ed402112");
        if slice_eq(raw, &want) {
            fmt::Println!("[ 6] HMAC-SHA-1 long key       PASS");
        } else {
            fmt::Println!("[ 6] HMAC-SHA-1 long key       FAIL");
            failed += 1;
        }
    }

    // ── RFC 2202 §2: HMAC-MD5 Test Case 1 ──────────────────────────────
    // Key: 16 bytes of 0x0b, Data: "Hi There"
    // HMAC: 9294727a3638bb1c13f48ef8158bfc9d
    {
        let key = slice::<byte>::__from_vec(alloc::vec![0x0b; 16]);
        let mut h = hmac::New(md5::NewHash, key);
        let _ = h.Write(to_bytes("Hi There"));
        let mac = h.Sum(empty_buf());
        let raw: &[byte] = &mac;
        let want = from_hex("9294727a3638bb1c13f48ef8158bfc9d");
        if slice_eq(raw, &want) {
            fmt::Println!("[ 7] HMAC-MD5 RFC2202 #1       PASS");
        } else {
            fmt::Println!("[ 7] HMAC-MD5 RFC2202 #1       FAIL");
            failed += 1;
        }
    }

    // ── RFC 2202 §2: HMAC-MD5 Test Case 2 ──────────────────────────────
    // Key: "Jefe", Data: "what do ya want for nothing?"
    // HMAC: 750c783e6ab0b503eaa86e310a5db738
    {
        let mut h = hmac::New(md5::NewHash, to_bytes("Jefe"));
        let _ = h.Write(to_bytes("what do ya want for nothing?"));
        let mac = h.Sum(empty_buf());
        let raw: &[byte] = &mac;
        let want = from_hex("750c783e6ab0b503eaa86e310a5db738");
        if slice_eq(raw, &want) {
            fmt::Println!("[ 8] HMAC-MD5 RFC2202 #2       PASS");
        } else {
            fmt::Println!("[ 8] HMAC-MD5 RFC2202 #2       FAIL");
            failed += 1;
        }
    }

    // ── Streaming Sum produces same digest as one-shot ─────────────────
    {
        let key = to_bytes("secret-key");
        let want = {
            let mut h = hmac::New(sha256::NewHash, key.clone());
            let _ = h.Write(to_bytes("hello world"));
            h.Sum(empty_buf())
        };
        let got = {
            let mut h = hmac::New(sha256::NewHash, key);
            let _ = h.Write(to_bytes("hello"));
            let _ = h.Write(to_bytes(" "));
            let _ = h.Write(to_bytes("world"));
            h.Sum(empty_buf())
        };
        let r1: &[byte] = &want;
        let r2: &[byte] = &got;
        if slice_eq(r1, r2) {
            fmt::Println!("[ 9] streaming write           PASS");
        } else {
            fmt::Println!("[ 9] streaming write           FAIL");
            failed += 1;
        }
    }

    // ── Reset returns digest to fresh-keyed state ──────────────────────
    {
        let key = to_bytes("k");
        let mut h = hmac::New(sha256::NewHash, key.clone());
        let _ = h.Write(to_bytes("garbage"));
        h.Reset();
        let _ = h.Write(to_bytes("Hi There"));
        let mac1 = h.Sum(empty_buf());

        let mut h2 = hmac::New(sha256::NewHash, key);
        let _ = h2.Write(to_bytes("Hi There"));
        let mac2 = h2.Sum(empty_buf());

        let r1: &[byte] = &mac1;
        let r2: &[byte] = &mac2;
        if slice_eq(r1, r2) {
            fmt::Println!("[10] Reset                     PASS");
        } else {
            fmt::Println!("[10] Reset                     FAIL");
            failed += 1;
        }
    }

    // ── Sum with dst prefix ────────────────────────────────────────────
    {
        let mut h = hmac::New(sha256::NewHash, to_bytes("k"));
        let _ = h.Write(to_bytes("data"));
        let dst = to_bytes("PRE:");
        let out = h.Sum(dst);
        let raw: &[byte] = &out;
        let mut h2 = hmac::New(sha256::NewHash, to_bytes("k"));
        let _ = h2.Write(to_bytes("data"));
        let bare = h2.Sum(empty_buf());
        let bare_raw: &[byte] = &bare;
        if raw.len() == 4 + 32 && &raw[0..4] == b"PRE:" && slice_eq(&raw[4..], bare_raw) {
            fmt::Println!("[11] Sum prefix                PASS");
        } else {
            fmt::Println!("[11] Sum prefix                FAIL");
            failed += 1;
        }
    }

    // ── Size + BlockSize delegate to underlying hash ───────────────────
    {
        let h_sha256 = hmac::New(sha256::NewHash, to_bytes("k"));
        let h_sha1 = hmac::New(sha1::NewHash, to_bytes("k"));
        let h_md5 = hmac::New(md5::NewHash, to_bytes("k"));
        if h_sha256.Size() == 32
            && h_sha256.BlockSize() == 64
            && h_sha1.Size() == 20
            && h_sha1.BlockSize() == 64
            && h_md5.Size() == 16
            && h_md5.BlockSize() == 64
        {
            fmt::Println!("[12] Size/BlockSize            PASS");
        } else {
            fmt::Println!("[12] Size/BlockSize            FAIL");
            failed += 1;
        }
    }

    // ── hmac.Equal — constant-time compare ────────────────────────────
    {
        let a = slice::<byte>::__from_vec(alloc::vec![1, 2, 3, 4]);
        let b = slice::<byte>::__from_vec(alloc::vec![1, 2, 3, 4]);
        let c = slice::<byte>::__from_vec(alloc::vec![1, 2, 3, 5]);
        let d = slice::<byte>::__from_vec(alloc::vec![1, 2, 3]);
        let pass = hmac::Equal(a.clone(), b) && !hmac::Equal(a.clone(), c) && !hmac::Equal(a, d);
        if pass {
            fmt::Println!("[13] Equal                     PASS");
        } else {
            fmt::Println!("[13] Equal                     FAIL");
            failed += 1;
        }
    }

    // ── Sum is non-mutating: calling twice yields identical digest ─────
    {
        let mut h = hmac::New(sha256::NewHash, to_bytes("k"));
        let _ = h.Write(to_bytes("x"));
        let s1 = h.Sum(empty_buf());
        let s2 = h.Sum(empty_buf());
        let r1: &[byte] = &s1;
        let r2: &[byte] = &s2;
        if slice_eq(r1, r2) {
            fmt::Println!("[14] Sum non-mutating          PASS");
        } else {
            fmt::Println!("[14] Sum non-mutating          FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 14/14");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 14");
        syscall::Exit(1);
    }
}
