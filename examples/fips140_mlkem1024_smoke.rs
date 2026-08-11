// fips140_mlkem1024_smoke — ML-KEM-1024 key generation, encapsulation and
// decapsulation (FIPS 203), i.e. mlkem1024.go's 23 functions.
//
// Ground truth comes from `scripts/goref.sh crypto/internal/fips140/mlkem`
// (AGENTS.md §10): the values below are what the Go implementation being
// ported prints for the same derandomized inputs. Large outputs (the
// 1568-byte encapsulation key, the 3168-byte expanded key, the 1568-byte
// ciphertext) are pinned by their SHA-256 rather than inline hex — an
// equally exact check, and a readable one.
//
// A round-trip test alone would pass on a consistently wrong
// implementation, so the pinned values matter: they are what tie this to
// Go, and through Go to FIPS 203.
//
// The implicit-rejection path is exercised explicitly. A tampered
// ciphertext must still yield 32 bytes — derived from z, not from the
// plaintext — and must NOT surface as an error, which is the whole point
// of the construction.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::internal::fips140::mlkem;
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

fn hx(s: &slice<byte>) -> goish::string {
    let r: &[byte] = s;
    return hex::EncodeToString(r);
}

/// SHA-256 of a slice, hex encoded — the pin for the large values.
fn digest(s: &slice<byte>) -> goish::string {
    let r: &[byte] = s;
    return hex::EncodeToString(&sha256::Sum256(slice::__from_vec(r.to_vec())));
}

const EK_SHA: &str = "c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530";
const EXPANDED_SHA: &str = "880b0a73b29b379880ef96915fe548904a6cc5a14ac91d87a01269f56ee533b2";
const CT_SHA: &str = "7b4d6eabbbec6f192274f1a378c412982d6b909f8815c70e5daeb097445abe1d";
const SHARED_KEY: &str = "eeaeab917518e0187011bc7bd691534c3dbc309c8a0748417cd30caaa579c7cd";
const REJECTED_KEY: &str = "77a8d4cd6c67175099bbb885d032b470f3ed37cc0c20f70900c220fdd4f3bd54";
const DK_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                       808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";

#[goish::main]
fn main() {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    let mut m = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        d[i] = i as byte;
        z[i] = (0x80 + i) as byte;
        m[i] = (0xa0 + i) as byte;
        i += 1;
    }

    // ── KeyGen ────────────────────────────────────────────────────────
    let dk = mlkem::GenerateKeyInternal1024(&d, &z);
    let ek = dk.EncapsulationKey();

    check("dk.Bytes is d || z", hx(&dk.Bytes()), DK_SEED);
    check(
        "ek.Bytes is 1568 bytes",
        fmt::Sprintf!("%d", ek.Bytes().Len()),
        "1568",
    );
    check("ek.Bytes", digest(&ek.Bytes()), EK_SHA);
    check(
        "TestingOnlyExpandedBytes1024",
        digest(&mlkem::TestingOnlyExpandedBytes1024(&dk)),
        EXPANDED_SHA,
    );

    // ── Encaps / Decaps ───────────────────────────────────────────────
    let (K, c) = ek.EncapsulateInternal(&m);
    check("EncapsulateInternal K", hx(&K), SHARED_KEY);
    check(
        "ciphertext is 1568 bytes",
        fmt::Sprintf!("%d", c.Len()),
        "1568",
    );
    check("EncapsulateInternal c", digest(&c), CT_SHA);

    let (K1, err) = dk.Decapsulate(c.clone());
    check(
        "Decapsulate succeeds",
        fmt::Sprintf!("%v", err == goish::nil),
        "true",
    );
    check("Decapsulate K matches", hx(&K1), SHARED_KEY);

    // Implicit rejection: a flipped bit must yield a different but
    // well-formed key, derived from z — and no error.
    let mut badv = slice::__into_vec(c.clone());
    badv[0] ^= 1;
    let (K2, err) = dk.Decapsulate(slice::__from_vec(badv));
    check(
        "tampered ciphertext is not an error",
        fmt::Sprintf!("%v", err == goish::nil),
        "true",
    );
    check("implicit rejection key", hx(&K2), REJECTED_KEY);

    // ── Parsing round-trips ───────────────────────────────────────────
    let (dk2, err) = mlkem::NewDecapsulationKey1024(dk.Bytes());
    check(
        "NewDecapsulationKey1024 succeeds",
        fmt::Sprintf!("%v", err == goish::nil),
        "true",
    );
    check(
        "reseeded key rebuilds the same ek",
        digest(&dk2.EncapsulationKey().Bytes()),
        EK_SHA,
    );

    let (ek2, err) = mlkem::NewEncapsulationKey1024(ek.Bytes());
    check(
        "NewEncapsulationKey1024 succeeds",
        fmt::Sprintf!("%v", err == goish::nil),
        "true",
    );
    let (K3, c3) = ek2.EncapsulateInternal(&m);
    check("parsed ek gives same K", hx(&K3), SHARED_KEY);
    check("parsed ek gives same c", digest(&c3), CT_SHA);

    let (dk3, err) =
        mlkem::TestingOnlyNewDecapsulationKey1024(mlkem::TestingOnlyExpandedBytes1024(&dk));
    check(
        "TestingOnlyNewDecapsulationKey1024 succeeds",
        fmt::Sprintf!("%v", err == goish::nil),
        "true",
    );
    check(
        "expanded parse rebuilds the same ek",
        digest(&dk3.EncapsulationKey().Bytes()),
        EK_SHA,
    );
    let (K4, _) = dk3.Decapsulate(c);
    check("expanded parse decapsulates", hx(&K4), SHARED_KEY);

    // ── Error paths ───────────────────────────────────────────────────
    let (_, err) =
        mlkem::NewDecapsulationKey1024(slice::__from_vec(alloc::vec![0u8; 63]));
    check(
        "short seed rejected",
        fmt::Sprintf!("%v", err.Error()),
        "mlkem: invalid seed length",
    );
    let (_, err) =
        mlkem::NewEncapsulationKey1024(slice::__from_vec(alloc::vec![0u8; 10]));
    check(
        "short encapsulation key rejected",
        fmt::Sprintf!("%v", err.Error()),
        "mlkem: invalid encapsulation key length",
    );
    let (_, err) = dk.Decapsulate(slice::__from_vec(alloc::vec![0u8; 10]));
    check(
        "short ciphertext rejected",
        fmt::Sprintf!("%v", err.Error()),
        "mlkem: invalid ciphertext length",
    );
    let mut badEK: Vec<byte> = slice::__into_vec(ek.Bytes());
    badEK[0] = 0xff;
    badEK[1] = 0xff;
    let (_, err) = mlkem::NewEncapsulationKey1024(slice::__from_vec(badEK));
    check(
        "unreduced encapsulation key rejected",
        fmt::Sprintf!("%v", err != goish::nil),
        "true",
    );

    // ── GenerateKey1024 draws real randomness ──────────────────────────
    //
    // Nothing to pin here, but the pairwise-consistency path must run and
    // two calls must not collide.
    let (r1, err1) = mlkem::GenerateKey1024();
    let (r2, err2) = mlkem::GenerateKey1024();
    check(
        "GenerateKey1024 succeeds",
        fmt::Sprintf!("%v", err1 == goish::nil && err2 == goish::nil),
        "true",
    );
    check(
        "GenerateKey1024 is random",
        fmt::Sprintf!("%v", hx(&r1.Bytes()) != hx(&r2.Bytes())),
        "true",
    );
    // A freshly generated key must encapsulate/decapsulate to itself.
    let (Ka, ca) = r1.EncapsulationKey().Encapsulate();
    let (Kb, err) = r1.Decapsulate(ca);
    check(
        "fresh key round-trips",
        fmt::Sprintf!("%v", err == goish::nil && hx(&Ka) == hx(&Kb)),
        "true",
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_mlkem1024_smoke OK\n");
}
