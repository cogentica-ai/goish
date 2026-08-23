// gcm_random_nonce_smoke — crypto/cipher::NewGCMWithRandomNonce vs Go 1.25.5.
//
// Seal generates its own nonce, so its output is not reproducible. The
// nonce is prepended to the ciphertext, though, which makes Open fully
// deterministic — so the load-bearing assertion is that goish decrypts a
// ciphertext produced by Go. That value and the two error strings came
// from `scripts/goref.sh crypto/aes` (run from the aes side; crypto/cipher
// cannot import crypto/aes in an in-package test — import cycle).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::aes;
use goish::crypto::cipher::{NewGCMWithRandomNonce, AEAD};
use goish::fmt;
use goish::goslice::slice;
use goish::types::byte;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static RAN: AtomicUsize = AtomicUsize::new(0);

fn check(ok: bool, what: &'static str) {
    RAN.fetch_add(1, Ordering::AcqRel);
    if ok {
        fmt::Printf!("PASS: %s\n", goish::string(what));
    } else {
        FAILED.fetch_add(1, Ordering::AcqRel);
        fmt::Printf!("FAIL: %s\n", goish::string(what));
    }
}

fn nib(c: u8) -> u8 {
    if c >= b'0' && c <= b'9' {
        return c - b'0';
    }
    if c >= b'a' && c <= b'f' {
        return c - b'a' + 10;
    }
    return c - b'A' + 10;
}

fn unhex(s: &str) -> slice<byte> {
    let b = s.as_bytes();
    let mut out: Vec<byte> = Vec::with_capacity(b.len() / 2);
    let mut i = 0usize;
    while i + 1 < b.len() {
        out.push(nib(b[i]) * 16 + nib(b[i + 1]));
        i += 2;
    }
    return slice::__from_vec(out);
}

fn bs(b: &[u8]) -> slice<byte> {
    return slice::__from_vec(b.to_vec());
}

fn empty() -> slice<byte> {
    return slice::__from_vec(Vec::new());
}

#[goish::main]
fn main() {
    let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let (blk, err) = aes::NewCipher(key);
    if err != goish::nil {
        fmt::Printf!("FAIL: aes::NewCipher\n");
        goish::syscall::Exit(1);
    }
    let blk = blk.unwrap();

    let (a, err) = NewGCMWithRandomNonce(&blk);
    check(
        err == goish::nil && a.is_some(),
        "NewGCMWithRandomNonce accepts an aes.Block",
    );
    let a = a.unwrap();

    check(a.NonceSize() == 0, "NonceSize() == 0 (Go: 0)");
    check(a.Overhead() == 28, "Overhead() == 28 (Go: 28)");

    let pt = bs(b"goish random-nonce GCM");
    let aad = bs(b"header");

    // The load-bearing check: decrypt what Go sealed.
    let goCT = unhex(
        "4d8bed549b232b1dc46d94c259879013200ab4fd83a695c580b2bab8285c2f20017ebb7304d60ed0bfae07746c55263b285c",
    );
    check(goCT.Len() == 50, "Go ciphertext is 50 bytes (22 + 28)");
    let (got, err) = a.Open(empty(), empty(), goCT.clone(), aad.clone());
    let (g, p): (&[byte], &[byte]) = (&got, &pt);
    check(err == goish::nil && g == p, "Open decrypts Go's ciphertext");

    // Round-trip our own Seal.
    let ct = a.Seal(empty(), empty(), pt.clone(), aad.clone());
    check(ct.Len() == pt.Len() + 28, "Seal output is plaintext + 28");
    let (got, err) = a.Open(empty(), empty(), ct.clone(), aad.clone());
    let (g, p): (&[byte], &[byte]) = (&got, &pt);
    check(err == goish::nil && g == p, "Seal -> Open round-trips");

    // Two Seals of the same plaintext must differ — the nonce is random.
    let ct2 = a.Seal(empty(), empty(), pt.clone(), aad.clone());
    let (c1, c2): (&[byte], &[byte]) = (&ct, &ct2);
    check(c1 != c2, "two Seals differ (nonce is random)");

    // Rejection paths, with Go's message.
    let (_, err) = a.Open(empty(), empty(), goCT.clone(), bs(b"wrong"));
    check(
        err != goish::nil && err.Error().as_bytes() == b"cipher: message authentication failed",
        "wrong AAD rejected with Go's message",
    );

    let raw: &[byte] = &goCT;
    let short = slice::__from_vec(raw[..27].to_vec());
    let (_, err) = a.Open(empty(), empty(), short, aad.clone());
    check(
        err != goish::nil && err.Error().as_bytes() == b"cipher: message authentication failed",
        "too-short ciphertext rejected with Go's message",
    );

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("gcm_random_nonce_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!(
            "gcm_random_nonce_smoke FAILED %d of %d\n",
            failed as i64,
            ran as i64
        );
        goish::syscall::Exit(1);
    }
}
