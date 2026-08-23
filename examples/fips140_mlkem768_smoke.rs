// fips140_mlkem768_smoke — ML-KEM-768 key generation, encapsulation and
// decapsulation (FIPS 203), i.e. mlkem768.go's 23 functions.
//
// Ground truth comes from `scripts/goref.sh crypto/internal/fips140/mlkem`
// (AGENTS.md §10): the values below are what the Go implementation being
// ported prints for the same derandomized inputs. Large outputs (the
// 1184-byte encapsulation key, the 2400-byte expanded key, the 1088-byte
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

const EK_SHA: &str = "0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9";
const EXPANDED_SHA: &str = "9a6474f4517bdfc00dd65b10834f0ee23d60981d83a8c318b5b7de925e3e7a8f";
const CT_SHA: &str = "a86a10e3529994dd5ebd846b42716c8bc35f71edbbb72b43a0f6c7e1870777bc";
const SHARED_KEY: &str = "d4ab9572cd7c68df84854e27a7ddbfc54f89c74cd96d93fa1db660275420153b";
const REJECTED_KEY: &str = "594872620c3a47752c2586098daa3ef38635c9f46143a621025670ddb0c62db4";
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
    let dk = mlkem::GenerateKeyInternal768(&d, &z);
    let ek = dk.EncapsulationKey();

    check("dk.Bytes is d || z", hx(&dk.Bytes()), DK_SEED);
    check(
        "ek.Bytes is 1184 bytes",
        fmt::Sprintf!("%d", ek.Bytes().Len()),
        "1184",
    );
    check("ek.Bytes", digest(&ek.Bytes()), EK_SHA);
    check(
        "TestingOnlyExpandedBytes768",
        digest(&mlkem::TestingOnlyExpandedBytes768(&dk)),
        EXPANDED_SHA,
    );

    // ── Encaps / Decaps ───────────────────────────────────────────────
    let (K, c) = ek.EncapsulateInternal(&m);
    check("EncapsulateInternal K", hx(&K), SHARED_KEY);
    check(
        "ciphertext is 1088 bytes",
        fmt::Sprintf!("%d", c.Len()),
        "1088",
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
    let (dk2, err) = mlkem::NewDecapsulationKey768(dk.Bytes());
    check(
        "NewDecapsulationKey768 succeeds",
        fmt::Sprintf!("%v", err == goish::nil),
        "true",
    );
    check(
        "reseeded key rebuilds the same ek",
        digest(&dk2.EncapsulationKey().Bytes()),
        EK_SHA,
    );

    let (ek2, err) = mlkem::NewEncapsulationKey768(ek.Bytes());
    check(
        "NewEncapsulationKey768 succeeds",
        fmt::Sprintf!("%v", err == goish::nil),
        "true",
    );
    let (K3, c3) = ek2.EncapsulateInternal(&m);
    check("parsed ek gives same K", hx(&K3), SHARED_KEY);
    check("parsed ek gives same c", digest(&c3), CT_SHA);

    let (dk3, err) =
        mlkem::TestingOnlyNewDecapsulationKey768(mlkem::TestingOnlyExpandedBytes768(&dk));
    check(
        "TestingOnlyNewDecapsulationKey768 succeeds",
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
    let (_, err) = mlkem::NewDecapsulationKey768(slice::__from_vec(alloc::vec![0u8; 63]));
    check(
        "short seed rejected",
        fmt::Sprintf!("%v", err.Error()),
        "mlkem: invalid seed length",
    );
    let (_, err) = mlkem::NewEncapsulationKey768(slice::__from_vec(alloc::vec![0u8; 10]));
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
    let (_, err) = mlkem::NewEncapsulationKey768(slice::__from_vec(badEK));
    check(
        "unreduced encapsulation key rejected",
        fmt::Sprintf!("%v", err != goish::nil),
        "true",
    );

    // ── GenerateKey768 draws real randomness ──────────────────────────
    //
    // Nothing to pin here, but the pairwise-consistency path must run and
    // two calls must not collide.
    let (r1, err1) = mlkem::GenerateKey768();
    let (r2, err2) = mlkem::GenerateKey768();
    check(
        "GenerateKey768 succeeds",
        fmt::Sprintf!("%v", err1 == goish::nil && err2 == goish::nil),
        "true",
    );
    check(
        "GenerateKey768 is random",
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
    fmt::Printf!("fips140_mlkem768_smoke OK\n");
}
