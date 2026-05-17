// crypto_rsa_smoke — exercise the crypto/rsa CORE:
//   PublicKey / PrivateKey / PrecomputedValues, Size / Equal / Public,
//   Precompute, Validate, the raw encrypt/decrypt round-trip, and one
//   small GenerateKey to prove key generation works.
//
// The bulk of testing uses a HARDCODED, externally-verified 512-bit key
// (debug-build RSA keygen is slow), with exactly one GenerateKey(512).
//
// Coverage:
//   1. Hardcoded key: PublicKey.Size() == 64 bytes (512-bit modulus).
//   2. Precompute fills Dp/Dq/Qinv (non-zero).
//   3. Raw encrypt -> decrypt round-trips a small message.
//   4. decrypt rejects an out-of-range ciphertext (c >= N).
//   5. Validate passes on the good hardcoded key.
//   6. Validate fails on a key with <2 primes.
//   7. Public() returns a PublicKey equal to the embedded one.
//   8. PublicKey.Equal: equal vs differing E.
//   9. PrivateKey.Equal: a key equals its clone, differs after mutation.
//  10. GenerateKey(512): produces a valid key whose encrypt/decrypt round-trips.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::rand::RandReader;
use goish::crypto::rsa::{self, PrivateKey, PublicKey};
use goish::math::big;
use goish::{slice, syscall, Println};

const KB: usize = 1024;

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

#[goish::main]
fn main() {
    goish::go!(stack(256 * KB), || {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run_tests() {
    test_1_size();
    test_2_precompute();
    test_3_roundtrip();
    test_4_decrypt_rejects_oob();
    test_5_validate_good();
    test_6_validate_missing_primes();
    test_7_public();
    test_8_publickey_equal();
    test_9_privatekey_equal();
    test_10_generatekey();
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

fn test_3_roundtrip() {
    let mut key = test_key();
    key.Precompute();

    // Message m must satisfy 0 <= m < N.
    let mut m = big::Int::new();
    m.SetInt64(0x1234567890abcdef_i64);

    let c = rsa::__test_encrypt(&key.PublicKey, &m);
    let mut rr = RandReader;
    let (got, err) = rsa::__test_decrypt(&key, &mut rr, &c);

    let ok = err == goish::nil && got.Cmp(&m) == 0;
    check(3, b"raw encrypt->decrypt roundtrip", ok);
}

fn test_4_decrypt_rejects_oob() {
    let mut key = test_key();
    key.Precompute();
    // c == N is out of range; decrypt must return ErrDecryption.
    let c = key.PublicKey.N.clone();
    let mut rr = RandReader;
    let (_got, err) = rsa::__test_decrypt(&key, &mut rr, &c);
    check(4, b"decrypt rejects c >= N       ", err != goish::nil);
}

fn test_5_validate_good() {
    let mut key = test_key();
    key.Precompute();
    let err = key.Validate();
    check(5, b"Validate ok on good key      ", err == goish::nil);
}

fn test_6_validate_missing_primes() {
    let mut key = test_key();
    key.Precompute();
    // Drop down to a single prime — Validate must complain.
    let mut one_prime: alloc::vec::Vec<big::Int> = alloc::vec::Vec::new();
    one_prime.push(key.Primes[0].clone());
    key.Primes = slice::<big::Int>::__from_vec(one_prime);
    let err = key.Validate();
    check(6, b"Validate fails <2 primes     ", err != goish::nil);
}

fn test_7_public() {
    let key = test_key();
    let pub_key = key.Public();
    let ok = pub_key.Equal(&key.PublicKey)
        && pub_key.N.Cmp(&key.PublicKey.N) == 0
        && pub_key.E == 65537;
    check(7, b"Public() == embedded pub     ", ok);
}

fn test_8_publickey_equal() {
    let key = test_key();
    let a = key.PublicKey.clone();
    let mut b = key.PublicKey.clone();
    let same = a.Equal(&b);
    b.E = 3; // differ
    let diff = a.Equal(&b);
    check(8, b"PublicKey.Equal eq/ne        ", same && !diff);
}

fn test_9_privatekey_equal() {
    let mut key = test_key();
    key.Precompute();
    let clone = key.clone();
    let same = key.Equal(&clone);

    let mut mutated = key.clone();
    let mut d2 = mutated.D.clone();
    let mut one = big::Int::new();
    one.SetInt64(1);
    let mut t = big::Int::new();
    t.Add(&d2, &one);
    d2 = t;
    mutated.D = d2;
    let diff = key.Equal(&mutated);

    check(9, b"PrivateKey.Equal eq/ne       ", same && !diff);
}

fn test_10_generatekey() {
    // One real key generation at a small size (512 bits) to prove the
    // GenerateKey path works. Debug-build keygen is slow, so this is the
    // only generation in the suite.
    let mut rr = RandReader;
    let (key, err) = rsa::GenerateKey(&mut rr, 512);
    if err != goish::nil {
        check(10, b"GenerateKey(512) round-trips ", false);
        return;
    }

    let mut ok = key.PublicKey.E == 65537
        && key.Primes.Len() == 2
        && key.PublicKey.N.BitLen() == 512;

    // The generated key must Validate and round-trip a message.
    if ok {
        ok = key.Validate() == goish::nil;
    }
    if ok {
        let mut m = big::Int::new();
        m.SetInt64(0x0badc0de_i64);
        let c = rsa::__test_encrypt(&key.PublicKey, &m);
        let (got, derr) = rsa::__test_decrypt(&key, &mut rr, &c);
        ok = derr == goish::nil && got.Cmp(&m) == 0;
    }

    check(10, b"GenerateKey(512) round-trips ", ok);
}
