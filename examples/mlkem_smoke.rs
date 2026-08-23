// mlkem_smoke — crypto/mlkem, the public wrapper over
// crypto/internal/fips140/mlkem.
//
// The arithmetic underneath is already checked byte-for-byte against Go by
// fips140_mlkem768_smoke / fips140_mlkem1024_smoke. What this adds is the
// wrapper's own contract: that a seed expands to the same key material
// through the public entry points, that an encapsulation key survives a
// parse round trip, that the two length checks reject, and that
// encapsulate/decapsulate agree.
//
// The fixed values are what Go prints for the same seed, via
// scripts/goref.sh (AGENTS.md §10). Encapsulate draws from crypto/rand and
// so is checked by round trip rather than by value — which is the property
// that actually matters for a KEM.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::mlkem;
use goish::crypto::sha256;
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

fn checkSame(name: &str, got: goish::string, want: goish::string) {
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

fn hx(s: &slice<byte>) -> goish::string {
    let r: &[byte] = s;
    return hex::EncodeToString(r);
}

/// SHA-256 of a slice, so a 1184- or 1568-byte key can be pinned in one
/// line instead of twenty.
fn sha(s: &slice<byte>) -> goish::string {
    let d = sha256::Sum256(s.clone());
    return hex::EncodeToString(&d);
}

/// The same deterministic seed the Go reference used.
fn seedOf() -> slice<byte> {
    let mut s: Vec<byte> = Vec::with_capacity(mlkem::SeedSize);
    let mut i: usize = 0;
    while i < mlkem::SeedSize {
        s.push(((i * 11 + 5) & 0xff) as byte);
        i += 1;
    }
    return slice::__from_vec(s);
}

#[goish::main]
fn main() {
    let s = seedOf();

    // ---- ML-KEM-768
    let (dk, err) = mlkem::NewDecapsulationKey768(&s);
    check(
        "768 NewDecapsulationKey768 err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    check("768 seed round trip", hx(&dk.Bytes()), DK768_SEED);

    let ek = dk.EncapsulationKey();
    check(
        "768 encapsulation key length",
        fmt::Sprintf!("%d", ek.Bytes().Len()),
        "1184",
    );
    check("768 encapsulation key", sha(&ek.Bytes()), EK768_SHA);

    let (ek2, err) = mlkem::NewEncapsulationKey768(&ek.Bytes());
    check(
        "768 NewEncapsulationKey768 err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    check(
        "768 encapsulation key parse round trip",
        sha(&ek2.Bytes()),
        EK768_SHA,
    );

    // Encapsulate is randomised, so it is checked by the property that
    // matters: the sender's shared key is the one the receiver derives.
    let (sk, ct) = ek2.Encapsulate();
    check("768 shared key length", fmt::Sprintf!("%d", sk.Len()), "32");
    check(
        "768 ciphertext length",
        fmt::Sprintf!("%d", ct.Len()),
        "1088",
    );
    let (sk2, err) = dk.Decapsulate(&ct);
    check(
        "768 Decapsulate err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    checkSame("768 encapsulate/decapsulate agree", hx(&sk), hx(&sk2));

    // Length checks.
    let short = {
        let r: &[byte] = &s;
        slice::__from_vec(r[..mlkem::SeedSize - 1].to_vec())
    };
    let (_, err) = mlkem::NewDecapsulationKey768(&short);
    check(
        "768 short seed rejected",
        fmt::Sprintf!("%v", err.Error()),
        "mlkem: invalid seed length",
    );
    let shortEK = {
        let r: &[byte] = &ek.Bytes();
        slice::__from_vec(r[..10].to_vec())
    };
    let (_, err) = mlkem::NewEncapsulationKey768(&shortEK);
    check(
        "768 short encapsulation key rejected",
        fmt::Sprintf!("%v", err.Error()),
        "mlkem: invalid encapsulation key length",
    );

    // ---- ML-KEM-1024
    let (dk1, err) = mlkem::NewDecapsulationKey1024(&s);
    check(
        "1024 NewDecapsulationKey1024 err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    check("1024 seed round trip", hx(&dk1.Bytes()), DK1024_SEED);

    let ek1 = dk1.EncapsulationKey();
    check(
        "1024 encapsulation key length",
        fmt::Sprintf!("%d", ek1.Bytes().Len()),
        "1568",
    );
    check("1024 encapsulation key", sha(&ek1.Bytes()), EK1024_SHA);

    let (ek1b, err) = mlkem::NewEncapsulationKey1024(&ek1.Bytes());
    check(
        "1024 NewEncapsulationKey1024 err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    let (sk1, ct1) = ek1b.Encapsulate();
    check(
        "1024 ciphertext length",
        fmt::Sprintf!("%d", ct1.Len()),
        "1568",
    );
    let (sk1b, err) = dk1.Decapsulate(&ct1);
    check(
        "1024 Decapsulate err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    checkSame("1024 encapsulate/decapsulate agree", hx(&sk1), hx(&sk1b));

    // GenerateKey draws from crypto/rand, so only its shape and its own
    // round trip are checkable.
    let (g, err) = mlkem::GenerateKey768();
    check(
        "768 GenerateKey768 err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    check(
        "768 generated seed length",
        fmt::Sprintf!("%d", g.Bytes().Len()),
        "64",
    );
    let (g2, err) = mlkem::NewDecapsulationKey768(&g.Bytes());
    check(
        "768 regenerate err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    checkSame(
        "768 generated key re-expands identically",
        sha(&g2.EncapsulationKey().Bytes()),
        sha(&g.EncapsulationKey().Bytes()),
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("mlkem_smoke OK\n");
}

const DK768_SEED: &str = "05101b26313c47525d68737e89949faab5c0cbd6e1ecf7020d18232e39444f5a\
                      65707b86919ca7b2bdc8d3dee9f4ff0a15202b36414c57626d78838e99a4afba";
const EK768_SHA: &str = "f64c62d7d96aa5bc79d1996234dc980da8954a234ab4d7cc73e3d240b055612c";
const DK1024_SEED: &str = "05101b26313c47525d68737e89949faab5c0cbd6e1ecf7020d18232e39444f5a\
                      65707b86919ca7b2bdc8d3dee9f4ff0a15202b36414c57626d78838e99a4afba";
const EK1024_SHA: &str = "50ef60a83f7e2525ec4db8c85725be73f986d0dd57167b87778d384b6215f53c";
