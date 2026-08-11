// ecdh_x25519_smoke — crypto/ecdh: the X25519 curve and the three NIST
// curves.
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

    // ---- the NIST curves, through the same Curve interface. These reach
    // crypto/internal/fips140/ecdh, so agreement with Go here is agreement
    // all the way down to nistec.
    nist("p256", ecdh::P256(), 32, &[P256_NAME, P256_PUBA, P256_AB]);
    nist("p384", ecdh::P384(), 48, &[P384_NAME, P384_PUBA, P384_AB]);
    nist("p521", ecdh::P521(), 66, &[P521_NAME, P521_PUBA, P521_AB]);

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("ecdh_x25519_smoke OK\n");
}

/// The same deterministic keys the Go reference used for each curve.
fn nistKey(n: usize, seed: byte) -> slice<byte> {
    let mut v: Vec<byte> = Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n {
        v.push((((i * 13 + 3) & 0xff) as byte) ^ seed);
        i += 1;
    }
    if n == 66 {
        v[0] &= 0x01;
    } else {
        v[0] &= 0x0f;
    }
    return slice::__from_vec(v);
}

fn nist(name: &str, c: &'static (dyn ecdh::Curve + Send + Sync), n: usize, want: &[&str; 3]) {
    let mut nm = alloc::string::String::from(name);
    nm.push(' ');

    check(&(nm.clone() + "name"), c.String(), want[0]);

    let (ka, err) = c.NewPrivateKey(&nistKey(n, 0x00));
    check(&(nm.clone() + "NewPrivateKey a err"), fmt::Sprintf!("%v", err != goish::nil), "false");
    let (kb, err) = c.NewPrivateKey(&nistKey(n, 0x5a));
    check(&(nm.clone() + "NewPrivateKey b err"), fmt::Sprintf!("%v", err != goish::nil), "false");

    check(&(nm.clone() + "public key A"), hx(&ka.PublicKey().Bytes()), want[1]);

    let (ab, err) = ka.ECDH(&kb.PublicKey());
    check(&(nm.clone() + "ECDH err"), fmt::Sprintf!("%v", err != goish::nil), "false");
    check(&(nm.clone() + "shared secret"), hx(&ab), want[2]);
    let (ba, _) = kb.ECDH(&ka.PublicKey());
    check(
        &(nm.clone() + "both sides agree"),
        fmt::Sprintf!("%v", hx(&ab) == hx(&ba)),
        "true",
    );

    // A compressed / malformed point is rejected before any arithmetic.
    let (_, err) = c.NewPublicKey(&slice::__from_vec(alloc::vec![2u8, 3u8]));
    check(
        &(nm + "malformed public key rejected"),
        fmt::Sprintf!("%v", err.Error()),
        "crypto/ecdh: invalid public key",
    );
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
const P256_NAME: &str = "P-256";
const P256_PUBA: &str = "049aa0c8cf2c7d1a3aadf3cc1a9ae6ddb166d942d6725546f18a94a312ba297d\
                      7e0603f5365ac752648d1e8702cbd60ac61171c171b9d9f9686941227ff77083\
                      a9";
const P256_AB: &str = "a09b8f3233878edefe75563b706283c411b5519ef4b7fb73738d6b755d784a00";
const P384_NAME: &str = "P-384";
const P384_PUBA: &str = "0452c6243481b08a8ac29360ba811ddc312225e67ecd2056971aa615eccafd05\
                      3e426c11371027d3f05915e1ef9e5e85a5eeeb49c7163a683843758a6c0c42f6\
                      cd07f2ecb785ddaf555248cde8b14067c8604acb118475ea5cf6be0720b0d3e1\
                      b3";
const P384_AB: &str = "73f789e82ea991989292355f96a74272182c26dd6e5ca4fd53dc662aa38b6d39\
                      e2bc990b8101369fb69142be0672e618";
const P521_NAME: &str = "P-521";
const P521_PUBA: &str = "040195f92e7e40ef0e9339c472a34e8acb2da4130311c0f8b2baf85e62267e0f\
                      5ca382ad17fc6e29df971623d210ba93a3b7d87a3406febc9ac6abe4954c9b90\
                      411f5800ae76a8ca4d1cd28254dc78d47faa6e053e1be860ce968e004a00c8ae\
                      52a3391a2ccf94aeba8565c591fa15ee82d98815a9a47ab58a9c1fb8d391637c\
                      e40473197f";
const P521_AB: &str = "01f4145cf251e891ec12108ab0cdbf36dc1f082d4381438f1d9b948c1a6b498e\
                      449dc91cfe5b1da269bccb8e74532a4086c8861e09b7c95e8183c1d2aa88a3c2\
                      252a";
