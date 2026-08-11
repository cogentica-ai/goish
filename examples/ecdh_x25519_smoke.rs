// ecdh_x25519_smoke — crypto/ecdh's X25519 curve.
//
// This file's implementation replaced a goish-only X25519 that predated
// the port: a hand-written 10-limb radix-2^25.5 field with its own
// Montgomery ladder. The arithmetic now comes from the ported
// crypto/internal/fips140/edwards25519/field, so this checks the swap did
// not change any answer — starting with the RFC 7748 §6.1 vector the old
// implementation carried in its header.
//
// Every expected value is what Go prints for the same input, via
// scripts/goref.sh (AGENTS.md §10).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::ecdh;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::types::byte;

static mut FAILED: bool = false;

fn check(name: &str, got: goish::string, want: &str) {
    if got == goish::string::from(want) {
        fmt::Printf!("PASS: %s\n", goish::string::from(name));
    } else {
        fmt::Printf!(
            "FAIL: %s\n  got  %s\n  want %s\n",
            goish::string::from(name),
            got,
            goish::string::from(want)
        );
        unsafe { FAILED = true };
    }
}

fn hx(s: &slice<byte>) -> goish::string {
    let r: &[byte] = s;
    return hex::EncodeToString(r);
}

fn unhex(s: &str) -> slice<byte> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        panic!("unhex: odd length");
    }
    let mut out: Vec<byte> = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = nib(b[i]);
        let lo = nib(b[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    return slice::__from_vec(out);
}

fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("unhex: not a hex digit"),
    }
}

fn keyOf(mul: usize, add: usize) -> slice<byte> {
    let mut v: Vec<byte> = Vec::with_capacity(32);
    let mut i: usize = 0;
    while i < 32 {
        v.push(((i * mul + add) & 0xff) as byte);
        i += 1;
    }
    return slice::__from_vec(v);
}

#[goish::main]
fn main() {
    // RFC 7748 §6.1, through the goish-only shim crypto/tls calls.
    {
        let scalar = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let mut sa = [0u8; 32];
        let mut ua = [0u8; 32];
        {
            let r: &[byte] = &scalar;
            sa.copy_from_slice(r);
            let r: &[byte] = &u;
            ua.copy_from_slice(r);
        }
        let got = ecdh::x25519_scalarmult(&sa, &ua);
        check("RFC 7748 §6.1 vector", hx(&slice::__from_vec(got.to_vec())), RFC7748);
    }

    // The public Curve API.
    let a = keyOf(7, 3);
    let b = keyOf(11, 5);
    let (ka, err) = ecdh::X25519().NewPrivateKey(&a);
    check("NewPrivateKey a err", fmt::Sprintf!("%v", err != goish::nil), "false");
    let (kb, err) = ecdh::X25519().NewPrivateKey(&b);
    check("NewPrivateKey b err", fmt::Sprintf!("%v", err != goish::nil), "false");

    check("public key A", hx(&ka.PublicKey().Bytes()), PUB_A);
    check("public key B", hx(&kb.PublicKey().Bytes()), PUB_B);

    let (ab, err) = ka.ECDH(&kb.PublicKey());
    check("ECDH ab err", fmt::Sprintf!("%v", err != goish::nil), "false");
    check("shared secret ab", hx(&ab), SHARED);
    let (ba, err) = kb.ECDH(&ka.PublicKey());
    check("ECDH ba err", fmt::Sprintf!("%v", err != goish::nil), "false");
    check("shared secret ba", hx(&ba), SHARED);

    check("curve name", ecdh::X25519().String(), "X25519");
    check("Equal(self)", fmt::Sprintf!("%v", ka.Equal(&ka)), "true");
    check("Equal(other)", fmt::Sprintf!("%v", ka.Equal(&kb)), "false");

    // A low-order point (all zeroes) must be rejected.
    let (lp, err) = ecdh::X25519().NewPublicKey(&slice::__from_vec(alloc::vec![0u8; 32]));
    check("NewPublicKey(zero) err", fmt::Sprintf!("%v", err != goish::nil), "false");
    let (_, err) = ka.ECDH(&lp);
    check(
        "low order point rejected",
        fmt::Sprintf!("%v", err.Error()),
        "crypto/ecdh: bad X25519 remote ECDH input: low order point",
    );

    // Length checks.
    let short = {
        let r: &[byte] = &a;
        slice::__from_vec(r[..31].to_vec())
    };
    let (_, err) = ecdh::X25519().NewPrivateKey(&short);
    check(
        "short private key rejected",
        fmt::Sprintf!("%v", err.Error()),
        "crypto/ecdh: invalid private key size",
    );
    let (_, err) = ecdh::X25519().NewPublicKey(&short);
    check(
        "short public key rejected",
        fmt::Sprintf!("%v", err.Error()),
        "crypto/ecdh: invalid public key",
    );

    // The TLS shim must agree with the public API.
    let (sk, pk) = ecdh::x25519_generate();
    let (kg, err) = ecdh::X25519().NewPrivateKey(&slice::__from_vec(sk.0.to_vec()));
    check("shim key parses", fmt::Sprintf!("%v", err != goish::nil), "false");
    check(
        "shim public key matches the Curve API",
        hx(&kg.PublicKey().Bytes()),
        &hexOf(&pk.0),
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("ecdh_x25519_smoke OK\n");
}

/// `check` wants a &str; this renders a fixed 32-byte key to one.
fn hexOf(b: &[u8; 32]) -> alloc::string::String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = alloc::string::String::with_capacity(64);
    for x in b.iter() {
        s.push(D[(*x >> 4) as usize] as char);
        s.push(D[(*x & 0xf) as usize] as char);
    }
    return s;
}

const RFC7748: &str = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
const PUB_A: &str = "bb50ff9e82a574cfbf820e97f60fb9c143ec7415cf514f8cfd98eff59e059614";
const PUB_B: &str = "14ee0e07f34e3a17030c6eecf66d3705e80d1e153f7a0ca5b345e83ce9d62643";
const SHARED: &str = "32dfa776c16b37746565aff7031b504c4208d9a0e4b23076a0887249aaf7b50e";
