// crypto_rsa_smoke — exercise the PUBLIC crypto/rsa package, the thin
// wrapper over the constant-time FIPS-internal RSA implementation.
//
// The bulk of testing uses a HARDCODED, externally-verified 512-bit key
// (debug-build RSA keygen is slow), with exactly one GenerateKey(512).
//
// Coverage:
//   1. Hardcoded key: PublicKey.Size() == 64 bytes (512-bit modulus).
//   2. Precompute fills Dp/Dq/Qinv (non-zero).
//   3. Validate passes on the good hardcoded key.
//   4. Validate fails on a key with <2 primes.
//   5. Public() returns a PublicKey equal to the embedded one.
//   6. PublicKey.Equal: equal vs differing E.
//   7. PrivateKey.Equal: a key equals its clone, differs after mutation.
//   8. EncryptPKCS1v15 -> DecryptPKCS1v15 round-trip.
//   9. SignPKCS1v15 -> VerifyPKCS1v15 round-trip (SHA-256).
//  10. VerifyPKCS1v15 rejects a tampered signature.
//  11. EncryptOAEP -> DecryptOAEP round-trip (SHA-1; fits the 512-bit key).
//  12. SignPSS -> VerifyPSS round-trip (SHA-256, auto salt).
//  13. VerifyPSS rejects a tampered signature.
//  14. GenerateKey(512): produces a valid key whose PKCS1v15 round-trips.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::rand::RandReader;
use goish::crypto::rsa::{self, PrivateKey, PublicKey};
use goish::crypto::{sha1, sha256};
use goish::math::big;
use goish::types::byte;
use goish::{slice, syscall, Println};


static FAILED: AtomicUsize = AtomicUsize::new(0);

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

// Verified 512-bit RSA test key (generated offline, round-trip checked).
const HEX_N: &str =
    "cf7d66032ac6618609a5950b45507b699d25682b60fec5215e4f6623177eb2b950b7319e68f5fa686ad475c77af452204e7fe4a877bec6fc8605ee54d8da13fb";
const HEX_D: &str =
    "0fe171255ce8c21e182eec3168a4b84d6511afdf62151dd167fe7bbac3d996a42511beadde7dd0395930885379d38eb50553979a60dd398ac7496fa2a751e1c1";
const HEX_P: &str = "dcf86e9a9e153e0843e1204627c32fa57e443eadcf3b1ad2ab973be5cddfb91d";
const HEX_Q: &str = "f061e34a29d282d957d988bede0fa09ce779751665fb968615d4024024780df7";

fn hex_int(s: &str) -> big::Int {
    let mut z = big::Int::new();
    z.SetString(s, 16);
    z
}

fn from_bytes(b: &[u8]) -> slice<byte> {
    slice::<byte>::__from_vec(b.to_vec())
}

fn test_key() -> PrivateKey {
    let n = hex_int(HEX_N);
    let d = hex_int(HEX_D);
    let p = hex_int(HEX_P);
    let q = hex_int(HEX_Q);
    let mut primes: alloc::vec::Vec<big::Int> = alloc::vec::Vec::with_capacity(2);
    primes.push(p);
    primes.push(q);
    PrivateKey {
        PublicKey: PublicKey { N: n, E: 65537 },
        D: d,
        Primes: slice::<big::Int>::__from_vec(primes),
        Precomputed: rsa::PrecomputedValues::default(),
    }
}

// SHA-256 digest of a fixed message, used as the signing input.
fn sha256_digest() -> slice<byte> {
    let mut h = sha256::New();
    let _ = h.Write(from_bytes(b"the quick brown fox"));
    h.Sum(slice::new())
}

fn write_result(idx: u8, label: &[u8], pass: bool) {
    syscall::Write(syscall::STDOUT, b"[".as_ptr(), 1);
    let d2 = b'0' + (idx % 10);
    if idx >= 10 {
        let d1 = b'0' + (idx / 10);
        let buf = [d1, d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    } else {
        let buf = [b' ', d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    }
    syscall::Write(syscall::STDOUT, b"] ".as_ptr(), 2);
    syscall::Write(syscall::STDOUT, label.as_ptr(), label.len());
    if pass {
        syscall::Write(syscall::STDOUT, b" PASS\n".as_ptr(), 6);
    } else {
        syscall::Write(syscall::STDOUT, b" FAIL\n".as_ptr(), 6);
    }
}

fn check(idx: u8, label: &[u8], pass: bool) {
    write_result(idx, label, pass);
    if !pass {
        fail();
    }
}

const TOTAL: u8 = 14;

#[goish::main]
fn main() {
    goish::go!(|| {
        // The hash registry must be populated before SignPSS/OAEP, which
        // resolve hash constructors via crypto::HashNew.
        goish::crypto::RegisterStandardHashes();
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            Println!("ok 14/14");
            syscall::Exit(0);
        } else {
            Println!("FAIL", f as i64, "of 14");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run_tests() {
    test_1_size();
    test_2_precompute();
    test_3_validate_good();
    test_4_validate_missing_primes();
    test_5_public();
    test_6_publickey_equal();
    test_7_privatekey_equal();
    test_8_pkcs1v15_encrypt();
    test_9_pkcs1v15_sign();
    test_10_pkcs1v15_verify_reject();
    test_11_oaep();
    test_12_pss();
    test_13_pss_verify_reject();
    test_14_generatekey();
}

fn test_1_size() {
    let key = test_key();
    // 512-bit modulus -> 64-byte size.
    check(1, b"PublicKey.Size() == 64       ", key.PublicKey.Size() == 64);
}

fn test_2_precompute() {
    let mut key = test_key();
    key.Precompute();
    let p = &key.Precomputed;
    let ok = p.Dp.Sign() > 0 && p.Dq.Sign() > 0 && p.Qinv.Sign() > 0;
    check(2, b"Precompute fills Dp/Dq/Qinv  ", ok);
}

fn test_3_validate_good() {
    let mut key = test_key();
    key.Precompute();
    let err = key.Validate();
    check(3, b"Validate ok on good key      ", err == goish::nil);
}

fn test_4_validate_missing_primes() {
    let key = test_key();
    // A single-prime key — Validate must complain.
    let mut one_prime: alloc::vec::Vec<big::Int> = alloc::vec::Vec::new();
    one_prime.push(key.Primes[0].clone());
    let mut k2 = key.clone();
    k2.Primes = slice::<big::Int>::__from_vec(one_prime);
    let err = k2.Validate();
    check(4, b"Validate fails <2 primes     ", err != goish::nil);
}

fn test_5_public() {
    let key = test_key();
    let pub_key = key.Public();
    let ok = pub_key.Equal(&key.PublicKey)
        && pub_key.N.Cmp(&key.PublicKey.N) == 0
        && pub_key.E == 65537;
    check(5, b"Public() == embedded pub     ", ok);
}

fn test_6_publickey_equal() {
    let key = test_key();
    let a = key.PublicKey.clone();
    let mut b = key.PublicKey.clone();
    let same = a.Equal(&b);
    b.E = 3; // differ
    let diff = a.Equal(&b);
    check(6, b"PublicKey.Equal eq/ne        ", same && !diff);
}

fn test_7_privatekey_equal() {
    let mut key = test_key();
    key.Precompute();
    let clone = key.clone();
    let same = key.Equal(&clone);

    let mut mutated = key.clone();
    let mut one = big::Int::new();
    one.SetInt64(1);
    let mut t = big::Int::new();
    t.Add(&mutated.D, &one);
    mutated.D = t;
    let diff = key.Equal(&mutated);

    check(7, b"PrivateKey.Equal eq/ne       ", same && !diff);
}

fn test_8_pkcs1v15_encrypt() {
    let mut key = test_key();
    key.Precompute();
    let mut rng = RandReader;

    let plain = from_bytes(b"hello rsa pkcs1v15");
    let (ct, e1) = rsa::EncryptPKCS1v15(&mut rng, &key.PublicKey, plain.clone());
    let (pt, e2) = rsa::DecryptPKCS1v15(&mut rng, &key, ct);

    let ok = e1 == goish::nil && e2 == goish::nil && bytes_eq(&pt, &plain);
    check(8, b"EncryptPKCS1v15->Decrypt     ", ok);
}

fn test_9_pkcs1v15_sign() {
    let mut key = test_key();
    key.Precompute();
    let mut rng = RandReader;

    let digest = sha256_digest();
    let (sig, e1) =
        rsa::SignPKCS1v15(&mut rng, &key, goish::crypto::SHA256, digest.clone());
    let ev = rsa::VerifyPKCS1v15(&key.PublicKey, goish::crypto::SHA256, digest, sig);

    let ok = e1 == goish::nil && ev == goish::nil;
    check(9, b"SignPKCS1v15->Verify         ", ok);
}

fn test_10_pkcs1v15_verify_reject() {
    let mut key = test_key();
    key.Precompute();
    let mut rng = RandReader;

    let digest = sha256_digest();
    let (sig, _) =
        rsa::SignPKCS1v15(&mut rng, &key, goish::crypto::SHA256, digest.clone());
    // Tamper with the signature.
    let mut sv: alloc::vec::Vec<byte> = (0..sig.Len()).map(|i| sig[i]).collect();
    sv[0] ^= 0xff;
    let bad = slice::<byte>::__from_vec(sv);
    let ev = rsa::VerifyPKCS1v15(&key.PublicKey, goish::crypto::SHA256, digest, bad);
    check(10, b"VerifyPKCS1v15 rejects bad   ", ev != goish::nil);
}

fn test_11_oaep() {
    let mut key = test_key();
    key.Precompute();
    let mut rng = RandReader;

    // SHA-1 OAEP fits a 512-bit key: maxMsg = 64 - 2*20 - 2 = 22 bytes.
    let plain = from_bytes(b"oaep round-trip");
    let mut h = sha1::New();
    let (ct, e1) =
        rsa::EncryptOAEP(&mut h, &mut rng, &key.PublicKey, plain.clone(), slice::new());
    let mut h2 = sha1::New();
    let (pt, e2) = rsa::DecryptOAEP(&mut h2, &mut rng, &key, ct, slice::new());

    let ok = e1 == goish::nil && e2 == goish::nil && bytes_eq(&pt, &plain);
    check(11, b"EncryptOAEP->DecryptOAEP     ", ok);
}

fn test_12_pss() {
    let mut key = test_key();
    key.Precompute();
    let mut rng = RandReader;

    let digest = sha256_digest();
    let (sig, e1) = rsa::SignPSS(
        &mut rng,
        &key,
        goish::crypto::SHA256,
        digest.clone(),
        None,
    );
    let ev = rsa::VerifyPSS(
        &key.PublicKey,
        goish::crypto::SHA256,
        digest,
        sig,
        None,
    );
    let ok = e1 == goish::nil && ev == goish::nil;
    check(12, b"SignPSS->VerifyPSS           ", ok);
}

fn test_13_pss_verify_reject() {
    let mut key = test_key();
    key.Precompute();
    let mut rng = RandReader;

    let digest = sha256_digest();
    let (sig, _) = rsa::SignPSS(
        &mut rng,
        &key,
        goish::crypto::SHA256,
        digest.clone(),
        None,
    );
    let mut sv: alloc::vec::Vec<byte> = (0..sig.Len()).map(|i| sig[i]).collect();
    sv[10] ^= 0xff;
    let bad = slice::<byte>::__from_vec(sv);
    let ev = rsa::VerifyPSS(&key.PublicKey, goish::crypto::SHA256, digest, bad, None);
    check(13, b"VerifyPSS rejects bad        ", ev != goish::nil);
}

fn test_14_generatekey() {
    // One real key generation at a small size (512 bits) to prove the
    // GenerateKey path works. Debug-build keygen is slow, so this is the
    // only generation in the suite.
    let mut rng = RandReader;
    let (key, err) = rsa::GenerateKey(&mut rng, 512);
    if err != goish::nil {
        check(14, b"GenerateKey(512) round-trips ", false);
        return;
    }

    let mut ok = key.PublicKey.E == 65537
        && key.Primes.Len() == 2
        && key.PublicKey.N.BitLen() == 512;

    // The generated key must Validate and round-trip a PKCS1v15 message.
    if ok {
        ok = key.Validate() == goish::nil;
    }
    if ok {
        let plain = from_bytes(b"generated key works");
        let (ct, e1) = rsa::EncryptPKCS1v15(&mut rng, &key.PublicKey, plain.clone());
        let (pt, e2) = rsa::DecryptPKCS1v15(&mut rng, &key, ct);
        ok = e1 == goish::nil && e2 == goish::nil && bytes_eq(&pt, &plain);
    }

    check(14, b"GenerateKey(512) round-trips ", ok);
}

fn bytes_eq(a: &slice<byte>, b: &slice<byte>) -> bool {
    if a.Len() != b.Len() {
        return false;
    }
    let mut i: goish::types::int = 0;
    while i < a.Len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

// Keep TOTAL referenced even though the literal counts are inline.
const _: u8 = TOTAL;
