// gcm_odd_nonce_smoke — GCM with non-96-bit nonces.
//
// A nonce whose length is not gcmStandardNonceSize (12) takes
// `deriveCounter`'s *other* branch: J0 is GHASH(H, nonce, lenBlock)
// rather than nonce||0x00000001. Every published AES-GCM vector uses a
// 96-bit IV, so that branch had no coverage at all — and it is the one
// place crypto/cipher calls into crypto/internal/fips140/aes/gcm.GHASH.
//
// Expected values are ground truth from Go 1.25.5 (AGENTS.md §10), not
// transcribed from a document:
//
//   b, _ := aes.NewCipher(key)
//   g, _ := cipher.NewGCMWithNonceSize(b, nlen)
//   ct := g.Seal(nil, nonce, pt, aad)
//
// with key/pt/aad below and nonce[i] = byte(i*7), for nlen in
// {1, 8, 13, 16, 20, 60}.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::aes;
use goish::crypto::cipher::{NewGCMWithNonceSize, AEAD};
use goish::types::byte;
use goish::{fmt, slice, syscall};

static FAILED: AtomicUsize = AtomicUsize::new(0);

// K = feffe9928665731c6d6a8f9467308308
const KEY: [u8; 16] = [
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
];
// P = d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
const PT: [u8; 32] = [
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
];
// A = feedfacedeadbeeffeedfacedeadbeefabaddad2
const AAD: [u8; 20] = [
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2,
];

// Go 1.25.5 output: ciphertext||tag, hex, one row per nonce length.
const CASES: [(usize, &str); 6] = [
    (
        1,
        "0bec58be9e8474a1a775c81b5c0ac53bdef2b49b506457524bcb969e8e68466dc212e04062c7fddb4e57852ec57a55cd",
    ),
    (
        8,
        "a73c7ba189d7f24e5edec1ccf4653304541729a73327fa6fd142f00d1f52c11d65d1d6b282d1e0937ac320f112042702",
    ),
    (
        13,
        "5df35bb1a2928073e28052c20cc793359484e10efd1ccf60a60aa538671cc3ad7d8ffaba32659310a1b11b70d7bd2a2b",
    ),
    (
        16,
        "a9281cb3a8f7757f7404a4828a98c52b1f562f50b8a731b56c80e3afc2028462e3fe7e542e1e5b07f129b6932e6b6119",
    ),
    (
        20,
        "54f7e5584b1df4f1eb5b07bfa5adc8cbb3011afcb47873307f07d30b9eda7fd4c945dcc12b907a619a5ecf6ce1de24fd",
    ),
    (
        60,
        "712a588d21f61ea0835995ee335c0b60da98be7f0a31b497ee85311304d17c60a23115fd356cead80222d4ad8645a7b3",
    ),
];

fn from_bytes(b: &[u8]) -> goish::slice<byte> {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(b.len());
    for &x in b {
        v.push(x);
    }
    slice::__from_vec(v)
}

fn unhex(s: &str) -> alloc::vec::Vec<u8> {
    let b = s.as_bytes();
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(b.len() / 2);
    let mut i = 0usize;
    while i + 1 < b.len() {
        out.push(nib(b[i]) * 16 + nib(b[i + 1]));
        i += 2;
    }
    out
}

fn nib(c: u8) -> u8 {
    if c >= b'a' {
        c - b'a' + 10
    } else {
        c - b'0'
    }
}

fn check(got: &goish::slice<byte>, want: &[u8]) -> bool {
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

fn report(nlen: usize, pass: bool) {
    if pass {
        fmt::Println!("nonce len", nlen as i64, "PASS");
    } else {
        fmt::Println!("nonce len", nlen as i64, "FAIL");
        FAILED.fetch_add(1, Ordering::AcqRel);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(256 * goish::KB), || {
        run();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            fmt::Println!("ok 6/6");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", f as i64, "of 6");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run() {
    for (nlen, want_hex) in CASES.iter() {
        let n = *nlen;
        let mut nonce: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(n);
        for i in 0..n {
            nonce.push(((i * 7) & 0xff) as u8);
        }

        let (cipher_opt, err) = aes::NewCipher(from_bytes(&KEY));
        if !err.IsNil() || cipher_opt.is_none() {
            report(n, false);
            continue;
        }
        let (gcm_opt, err) = NewGCMWithNonceSize(cipher_opt.unwrap(), n as goish::int);
        if !err.IsNil() || gcm_opt.is_none() {
            report(n, false);
            continue;
        }
        let g = gcm_opt.unwrap();

        let dst: goish::slice<byte> = slice::__from_vec(alloc::vec::Vec::new());
        let out = g.Seal(dst, from_bytes(&nonce), from_bytes(&PT), from_bytes(&AAD));
        let want = unhex(want_hex);
        if !check(&out, &want) {
            report(n, false);
            continue;
        }

        // Round-trip: Open must recover the plaintext.
        let dst2: goish::slice<byte> = slice::__from_vec(alloc::vec::Vec::new());
        let (back, err) = g.Open(dst2, from_bytes(&nonce), out, from_bytes(&AAD));
        if !err.IsNil() || !check(&back, &PT) {
            report(n, false);
            continue;
        }
        report(n, true);
    }
}
