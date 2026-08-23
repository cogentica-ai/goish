// fips140hash_smoke — crypto/internal/fips140hash.
//
// Unwrap swaps a crypto/sha3.SHA3 wrapper for the
// crypto/internal/fips140/sha3.Digest inside it, so FIPS code gets the
// module-internal implementation. Nothing about the *digest* changes —
// that is the point — so what is checkable is:
//
//   * the unwrapped hash produces the same bytes as the wrapper;
//   * a non-SHA3 hash passes through untouched;
//   * UnwrapNew's returned factory behaves like the one it wrapped.
//
// UnwrapNew is why hash::HashFunc exists: it returns a closure capturing
// newHash, which a bare `fn` pointer cannot represent. The last check
// feeds that closure to hmac::New, the shape crypto/ecdsa needs.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::boxed::Box;
use goish::crypto::internal::fips140::hmac;
use goish::crypto::internal::fips140hash;
use goish::crypto::sha3;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::hash::{Hash, HashFunc};
use goish::io;
use goish::types::byte;

static mut FAILED: bool = false;

fn check(name: &str, got: goish::string, want: goish::string) {
    if got == want {
        fmt::Printf!("PASS: %s\n", goish::string::from(name));
    } else {
        fmt::Printf!(
            "FAIL: %s\n  got  %s\n  want %s\n",
            goish::string::from(name),
            got,
            want
        );
        unsafe { FAILED = true };
    }
}

fn msg() -> slice<byte> {
    return slice::__from_vec(alloc::vec![
        0x67, 0x6f, 0x69, 0x73, 0x68, 0x20, 0x66, 0x69, 0x70, 0x73, 0x31, 0x34, 0x30, 0x68, 0x61,
        0x73, 0x68
    ]);
}

/// Feed the message through a hash and hex-encode the digest.
fn digest(mut h: Box<dyn Hash + Send + Sync>) -> goish::string {
    let _ = io::Writer::Write(&mut h, msg());
    let d = h.Sum(slice::__from_vec(alloc::vec::Vec::<byte>::new()));
    let r: &[byte] = &d;
    return hex::EncodeToString(r);
}

#[goish::main]
fn main() {
    // SHA3-256: the wrapper and the unwrapped inner Digest must agree.
    let wrapped: Box<dyn Hash + Send + Sync> = sha3::NewHash256();
    let unwrapped = fips140hash::Unwrap(sha3::NewHash256());
    check(
        "sha3-256 unwrap preserves the digest",
        digest(unwrapped),
        digest(wrapped),
    );

    // A non-SHA3 hash is returned as-is.
    let passthrough = fips140hash::Unwrap(goish::crypto::sha256::NewHash());
    check(
        "sha-256 passes through unchanged",
        digest(passthrough),
        digest(goish::crypto::sha256::NewHash()),
    );

    // UnwrapNew returns a factory; it must behave like the one it wrapped.
    let f: HashFunc = fips140hash::UnwrapNew(sha3::NewHash256);
    check(
        "UnwrapNew factory matches",
        digest(f.Call()),
        digest(sha3::NewHash256()),
    );

    // And that factory is a closure, so it can only reach hmac::New at all
    // because the parameter takes hash::HashFunc rather than a fn pointer.
    // This is the crypto/ecdsa call shape.
    let key = slice::__from_vec(alloc::vec![0x0bu8; 20]);
    let mut viaClosure = hmac::New(f, key.clone());
    let mut viaPlain = hmac::New(sha3::NewHash256, key);
    let _ = io::Writer::Write(&mut viaClosure, msg());
    let _ = io::Writer::Write(&mut viaPlain, msg());
    let a = viaClosure.Sum(slice::__from_vec(alloc::vec::Vec::<byte>::new()));
    let b = viaPlain.Sum(slice::__from_vec(alloc::vec::Vec::<byte>::new()));
    let ar: &[byte] = &a;
    let br: &[byte] = &b;
    check(
        "HMAC over the unwrapped closure factory",
        hex::EncodeToString(ar),
        hex::EncodeToString(br),
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140hash_smoke OK\n");
}
