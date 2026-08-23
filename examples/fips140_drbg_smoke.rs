// fips140_drbg_smoke — crypto/internal/fips140/drbg's CTR_DRBG, against
// the known-answer test Go ships in cast[go].
//
// Per FIPS 140-3 IG 10.3.A Resolution 7, a DRBG KAT is: instantiate with
// known data, reseed with other known data, generate, and compare to a
// precomputed value. That single sequence exercises NewCounter, update,
// increment, Reseed and Generate together — which is the point, because
// the DRBG's output is a function of all of them and any one being wrong
// still yields random-looking bytes.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
extern crate goish;

use goish::io;

use alloc::vec::Vec;
use goish::crypto::internal::fips140::drbg;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
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

// Go's cast.go builds these as ascending byte runs.
fn run(start: byte) -> [byte; drbg::SeedSize] {
    let mut a = [0u8; drbg::SeedSize];
    let mut i: usize = 0;
    while i < drbg::SeedSize {
        a[i] = start + (i as byte);
        i += 1;
    }
    return a;
}

#[goish::main]
fn main() {
    check(
        "SeedSize is 48",
        fmt::Sprintf!("%d", drbg::SeedSize as i64),
        "48",
    );

    // cast[go]: entropy 0x01.., reseed 0x31.., additional input 0x61..
    let entropy = run(0x01);
    let reseedEntropy = run(0x31);
    let additionalInput = run(0x61);

    let mut c = drbg::NewCounter(&entropy);
    c.Reseed(&reseedEntropy, &additionalInput);
    let mut got: Vec<byte> = alloc::vec![0u8; 32];
    let reseedRequired = c.Generate(&mut got, Some(&additionalInput));

    check(
        "CTR_DRBG KAT (instantiate, reseed, generate)",
        hex::EncodeToString(&got),
        "6e6e479d24f86a3b7787a8f8186d985a53bebeeddeab9228f0f4ac6e10bf0193",
    );
    check(
        "no reseed required after one generate",
        fmt::Sprintf!("%v", reseedRequired),
        "false",
    );

    // A second Generate must advance: the DRBG is not a fixed function.
    let mut second: Vec<byte> = alloc::vec![0u8; 32];
    c.Generate(&mut second, Some(&additionalInput));
    let a = hex::EncodeToString(&got);
    let b = hex::EncodeToString(&second);
    check(
        "successive Generate calls differ",
        fmt::Sprintf!("%v", a != b),
        "true",
    );

    // Generate with no additional input is a distinct code path: the
    // first CTR_DRBG_Update is skipped and an all-zero string is used for
    // the second.
    let mut c2 = drbg::NewCounter(&entropy);
    let mut noAI: Vec<byte> = alloc::vec![0u8; 32];
    c2.Generate(&mut noAI, None);
    let mut c3 = drbg::NewCounter(&entropy);
    let zero = [0u8; drbg::SeedSize];
    let mut withZero: Vec<byte> = alloc::vec![0u8; 32];
    c3.Generate(&mut withZero, Some(&zero));
    // Passing nil is NOT the same as passing an all-zero array: nil skips
    // the first update, the zero array does not.
    check(
        "nil additional input differs from all-zero",
        fmt::Sprintf!(
            "%v",
            hex::EncodeToString(&noAI) != hex::EncodeToString(&withZero)
        ),
        "true",
    );

    // Requests are served at any length, including across the 16-byte
    // block boundary that RoundToBlock realigns.
    let mut c4 = drbg::NewCounter(&entropy);
    let mut n: usize = 1;
    let mut lenOK = true;
    while n <= 64 {
        let mut buf: Vec<byte> = alloc::vec![0u8; n];
        c4.Generate(&mut buf, None);
        if buf.len() != n {
            lenOK = false;
        }
        n += 1;
    }
    check(
        "Generate serves every length 1..64",
        fmt::Sprintf!("%v", lenOK),
        "true",
    );

    // ── drbg.Read and the reader wrappers (rand.go) ───────────────────
    //
    // fips140.Enabled() is false in goish, so Read takes Go's non-FIPS
    // branch and forwards to the OS. What is checkable is that it fills
    // the whole buffer and does not repeat.
    let mut b1 = slice::__from_vec(alloc::vec![0u8; 64]);
    drbg::Read(&mut b1);
    let mut b2 = slice::__from_vec(alloc::vec![0u8; 64]);
    drbg::Read(&mut b2);
    check(
        "drbg.Read fills the buffer",
        fmt::Sprintf!("%d", b1.Len()),
        "64",
    );
    let r1: &[byte] = &b1;
    check(
        "drbg.Read is not all zero",
        fmt::Sprintf!("%v", r1.iter().all(|x| *x == 0)),
        "false",
    );
    let r2: &[byte] = &b2;
    check(
        "two drbg.Read calls differ",
        fmt::Sprintf!("%v", r1 != r2),
        "true",
    );

    // ReadWithReader on a NON-default reader must drain that reader, not
    // the OS: it is what lets callers inject a deterministic stream.
    let mut fixed = fixedReader { pos: 0 };
    let mut out = slice::__from_vec(alloc::vec![0u8; 8]);
    let err = drbg::ReadWithReaderDeterministic(&mut fixed, &mut out);
    let orr: &[byte] = &out;
    check(
        "ReadWithReaderDeterministic uses the given reader",
        fmt::Sprintf!("%v %d", err == goish::nil, orr[0]),
        "true 0",
    );
    check(
        "…and reads it in order",
        fmt::Sprintf!("%d %d", orr[1], orr[7]),
        "1 7",
    );

    // The non-deterministic form may consume one extra byte first
    // (randutil.MaybeReadByte), so the stream can start at 0 or 1.
    let mut fixed = fixedReader { pos: 0 };
    let mut out = slice::__from_vec(alloc::vec![0u8; 8]);
    let err = drbg::ReadWithReader(&mut fixed, &mut out);
    let orr: &[byte] = &out;
    check(
        "ReadWithReader uses the given reader",
        fmt::Sprintf!("%v %v", err == goish::nil, orr[0] == 0 || orr[0] == 1),
        "true true",
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_drbg_smoke OK\n");
}

/// A reader that yields 0, 1, 2, … so the caller can tell how far into
/// the stream it started.
struct fixedReader {
    pos: byte,
}

impl io::Reader for fixedReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, goish::error) {
        let n = p.Len();
        let mut i = 0;
        while i < n {
            p[i as usize] = self.pos;
            self.pos = self.pos.wrapping_add(1);
            i += 1;
        }
        return (n, goish::nil.into());
    }
}
