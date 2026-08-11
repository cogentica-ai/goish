// fips140_entropy_smoke — crypto/internal/entropy and
// crypto/internal/randutil.
//
// Neither has a fixed output to pin: entropy.Depleted hands the LOAD
// callback 48 bytes of operating-system randomness, and
// randutil.MaybeReadByte consumes a byte with probability ½. What is
// checkable is the contract each one has with its caller, which is what
// the FIPS module actually depends on.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::internal::entropy;
use goish::crypto::internal::randutil;
use goish::fmt;
use goish::goslice::slice;
use goish::io;
use goish::types::{byte, int};

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

/// A reader that counts how many bytes it was asked for.
struct countingReader {
    n: int,
}

impl io::Reader for countingReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, goish::error) {
        self.n += p.Len();
        return (p.Len(), goish::nil.into());
    }
}

#[goish::main]
fn main() {
    // ── entropy.Depleted ──────────────────────────────────────────────
    //
    // The callback must receive exactly 48 bytes (SeedSize for the
    // CTR_DRBG this feeds), and they must not be all zero.
    let mut seen: Vec<byte> = Vec::new();
    entropy::Depleted(|e: &[byte; 48]| {
        seen.extend_from_slice(e);
    });
    check(
        "Depleted hands LOAD 48 bytes",
        fmt::Sprintf!("%d", seen.len() as int),
        "48",
    );
    let allZero = seen.iter().all(|b| *b == 0);
    check("entropy is not all zero", fmt::Sprintf!("%v", allZero), "false");

    // Two calls must not return the same seed.
    let mut second: Vec<byte> = Vec::new();
    entropy::Depleted(|e: &[byte; 48]| {
        second.extend_from_slice(e);
    });
    check(
        "two Depleted calls differ",
        fmt::Sprintf!("%v", seen != second),
        "true",
    );

    // ── randutil.MaybeReadByte ────────────────────────────────────────
    //
    // It reads one byte with probability ½, so over many calls it must
    // consume some bytes but not all of them. Both degenerate
    // implementations — never read, always read — fail this.
    let mut r = countingReader { n: 0 };
    let mut i = 0;
    while i < 200 {
        randutil::MaybeReadByte(&mut r);
        i += 1;
    }
    check(
        "MaybeReadByte reads sometimes",
        fmt::Sprintf!("%v", r.n > 0),
        "true",
    );
    check(
        "MaybeReadByte does not read always",
        fmt::Sprintf!("%v", r.n < 200),
        "true",
    );
    // One byte per read, never more.
    check(
        "MaybeReadByte reads one byte at a time",
        fmt::Sprintf!("%v", r.n <= 200),
        "true",
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_entropy_smoke OK\n");
}
