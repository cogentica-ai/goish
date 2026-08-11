// crypto_rsa_iface_smoke — the parts of the public crypto/rsa surface that
// crypto_rsa_smoke does not reach: the minimum-key-size gate, the
// `crypto.Signer` / `crypto.Decrypter` option bags, and the PKCS #1 v1.5
// padding this package (rather than the FIPS module) owns.
//
// Every expected value below came out of Go 1.25.5 itself, via
// `scripts/goref.sh crypto/rsa`, run against the same 512-bit key.
//
// Coverage:
//   1. GenerateKey(512) is refused, with Go's exact message —
//      rsa.go:250 checkKeySize.
//   2. EncryptPKCS1v15 with a 512-bit key is refused — checkPublicKeySize.
//   3. GODEBUG=rsa1024min=0 lifts both, exactly as it does in Go.
//   4. GenerateMultiPrimeKey(3, …) reports an error.
//   5. PrivateKey.Sign with crypto.SHA256 as opts signs PKCS #1 v1.5.
//   6. PrivateKey.Sign with *PSSOptions signs PSS — the signature verifies
//      with VerifyPSS and is rejected by VerifyPKCS1v15, which is what
//      distinguishes the two dispatch arms of rsa.go:158.
//   7. PrivateKey.Decrypt with no options does PKCS #1 v1.5.
//   8. PrivateKey.Decrypt with *OAEPOptions does OAEP.
//   9. PrivateKey.Decrypt with *PKCS1v15DecryptOptions returns a session
//      key of the requested length.
//  10. DecryptPKCS1v15 recovers the plaintext from a ciphertext Go's
//      EncryptPKCS1v15 produced.
//  11. SignPKCS1v15 is byte-for-byte Go's signature (it is deterministic).
//  12. PSSSaltLengthAuto resolves to the 30 bytes Go's PSSMaxSaltLength
//      reports for this key and SHA-256.
//  13. DecryptPKCS1v15SessionKey recovers a session key from a Go
//      ciphertext.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::rand::RandReader;
use goish::crypto::rsa::{self, PrivateKey, PublicKey};
use goish::crypto::{sha1, sha256};
use goish::fmt;
use goish::math::big;
use goish::types::byte;
use goish::{slice, syscall};

static FAILED: AtomicUsize = AtomicUsize::new(0);

// The same verified 512-bit RSA test key crypto_rsa_smoke uses.
const HEX_N: &str =
    "cf7d66032ac6618609a5950b45507b699d25682b60fec5215e4f6623177eb2b950b7319e68f5fa686ad475c77af452204e7fe4a877bec6fc8605ee54d8da13fb";
const HEX_D: &str =
    "0fe171255ce8c21e182eec3168a4b84d6511afdf62151dd167fe7bbac3d996a42511beadde7dd0395930885379d38eb50553979a60dd398ac7496fa2a751e1c1";
const HEX_P: &str = "dcf86e9a9e153e0843e1204627c32fa57e443eadcf3b1ad2ab973be5cddfb91d";
const HEX_Q: &str = "f061e34a29d282d957d988bede0fa09ce779751665fb968615d4024024780df7";

// Ground truth from Go 1.25.5 — `scripts/goref.sh crypto/rsa`, same key.
//
//   V15_CT   EncryptPKCS1v15(rand.Reader, pub, "hello rsa pkcs1v15")
//   V15_SIG  SignPKCS1v15(nil, priv, crypto.SHA256, sha256("the quick brown fox"))
//   SESS_CT  EncryptPKCS1v15(rand.Reader, pub, "0123456789abcdef")
//   PSS_AUTO fipsrsa.PSSMaxSaltLength(priv.PublicKey(), sha256.New())
const GO_V15_CT: &str =
    "0097f5a8c0e52a06a35fc420d51c6b07b69f25484de90e5c5c154e61488f3a385cfb2c806731bdcfa9086c72521a3d42ed88db8388cb3973c04c60a8226a8d9d";
const GO_V15_SIG: &str =
    "16570156f8cccc32bf11312671fa7476f122a293d2144b836e52b1f09e6b6a60d4ec0812c9e94671a0df7ed5063d2e5a6ed3a194dd27fbde9a1ac6e759b16c97";
const GO_SESS_CT: &str =
    "8576b2ec1e57c9633470bb436572037df635f25d7db659ba158cb62ad6257b69297cff9da3050216b414dc222bdac3c9653216431e868d7a1fc42234439457a7";
const GO_PSS_AUTO_SALT: goish::types::int = 30;
const GO_WEAK_KEY_MSG: &[u8] =
    b"crypto/rsa: 512-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)";

fn unhex(s: &str) -> slice<byte> {
    fn nib(c: u8) -> u8 {
        if c >= b'a' {
            return c - b'a' + 10;
        }
        c - b'0'
    }
    let b = s.as_bytes();
    let mut out: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(b.len() / 2);
    let mut i = 0usize;
    while i + 1 < b.len() {
        out.push(nib(b[i]) * 16 + nib(b[i + 1]));
        i += 2;
    }
    slice::<byte>::__from_vec(out)
}

fn hex_int(s: &str) -> big::Int {
    let mut z = big::Int::new();
    z.SetString(s, 16);
    z
}

fn from_bytes(b: &[u8]) -> slice<byte> {
    slice::<byte>::__from_vec(b.to_vec())
}

fn test_key() -> PrivateKey {
    let mut primes: alloc::vec::Vec<big::Int> = alloc::vec::Vec::with_capacity(2);
    primes.push(hex_int(HEX_P));
    primes.push(hex_int(HEX_Q));
    let mut key = PrivateKey {
        PublicKey: PublicKey {
            N: hex_int(HEX_N),
            E: 65537,
        },
        D: hex_int(HEX_D),
        Primes: slice::<big::Int>::__from_vec(primes),
        Precomputed: rsa::PrecomputedValues::default(),
    };
    key.Precompute();
    key
}

fn sha256_digest() -> slice<byte> {
    let mut h = sha256::New();
    let _ = h.Write(from_bytes(b"the quick brown fox"));
    h.Sum(slice::new())
}

fn check(idx: u8, label: &[u8], pass: bool) {
    syscall::Write(syscall::STDOUT, b"[".as_ptr(), 1);
    let d2 = b'0' + (idx % 10);
    let d1 = if idx >= 10 { b'0' + (idx / 10) } else { b' ' };
    let buf = [d1, d2];
    syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    syscall::Write(syscall::STDOUT, b"] ".as_ptr(), 2);
    syscall::Write(syscall::STDOUT, label.as_ptr(), label.len());
    if pass {
        syscall::Write(syscall::STDOUT, b" PASS\n".as_ptr(), 6);
    } else {
        syscall::Write(syscall::STDOUT, b" FAIL\n".as_ptr(), 6);
        FAILED.fetch_add(1, Ordering::AcqRel);
    }
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

#[goish::main]
fn main() {
    goish::go!(stack(64 * 1024), || {
        goish::crypto::RegisterStandardHashes();
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            fmt::Println!("ok 13/13");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", f as i64, "of 13");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run_tests() {
    // 1 + 2 run BEFORE the GODEBUG override — the gate must be live.
    test_1_generatekey_rejects_weak();
    test_2_encrypt_rejects_weak();
    test_3_godebug_lifts_the_gate();
    test_4_multiprime();
    test_5_sign_pkcs1v15();
    test_6_sign_pss();
    test_7_decrypt_default();
    test_8_decrypt_oaep();
    test_9_decrypt_session_key();
    test_10_decrypt_go_ciphertext();
    test_11_sign_matches_go();
    test_12_pss_auto_salt_is_go_s();
    test_13_session_key_from_go();
}

fn test_1_generatekey_rejects_weak() {
    let mut rng = RandReader;
    let (_, err) = rsa::GenerateKey(&mut rng, 512);
    let msg_ok = err != goish::nil && err.Error().as_bytes() == GO_WEAK_KEY_MSG;
    check(1, b"GenerateKey(512) refused     ", msg_ok);
}

fn test_2_encrypt_rejects_weak() {
    let mut rng = RandReader;
    let key = test_key();
    let (_, err) = rsa::EncryptPKCS1v15(&mut rng, &key.PublicKey, from_bytes(b"x"));
    check(2, b"EncryptPKCS1v15 refused 512  ", err != goish::nil);
}

fn test_3_godebug_lifts_the_gate() {
    // Go's own crypto/rsa tests do exactly this — t.Setenv("GODEBUG",
    // "rsa1024min=0"); see crypto/rsa/pkcs1v15_test.go:57.
    let _ = goish::os::Setenv("GODEBUG", "rsa1024min=0");
    let mut rng = RandReader;
    let key = test_key();
    let plain = from_bytes(b"weak keys re-enabled");
    let (ct, e1) = rsa::EncryptPKCS1v15(&mut rng, &key.PublicKey, plain.clone());
    let (pt, e2) = rsa::DecryptPKCS1v15(&mut rng, &key, ct);
    check(
        3,
        b"GODEBUG=rsa1024min=0 lifts   ",
        e1 == goish::nil && e2 == goish::nil && bytes_eq(&pt, &plain),
    );
}

fn test_4_multiprime() {
    let mut rng = RandReader;
    let (_, err) = rsa::GenerateMultiPrimeKey(&mut rng, 3, 2048);
    check(4, b"GenerateMultiPrimeKey(3) err ", err != goish::nil);
}

fn test_5_sign_pkcs1v15() {
    let mut rng = RandReader;
    let key = test_key();
    let digest = sha256_digest();
    // crypto.Hash satisfies crypto.SignerOpts, so this is the v1.5 arm.
    let (sig, e1) = key.Sign(&mut rng, digest.clone(), &goish::crypto::SHA256);
    let ev = rsa::VerifyPKCS1v15(&key.PublicKey, goish::crypto::SHA256, digest, sig);
    check(
        5,
        b"Sign(SHA256) -> PKCS1v15     ",
        e1 == goish::nil && ev == goish::nil,
    );
}

fn test_6_sign_pss() {
    let mut rng = RandReader;
    let key = test_key();
    let digest = sha256_digest();
    let opts = rsa::PSSOptions {
        SaltLength: rsa::PSSSaltLengthAuto,
        Hash: goish::crypto::SHA256,
    };
    let (sig, e1) = key.Sign(&mut rng, digest.clone(), &opts);
    let pss_ok = rsa::VerifyPSS(
        &key.PublicKey,
        goish::crypto::SHA256,
        digest.clone(),
        sig.clone(),
        Some(&opts),
    ) == goish::nil;
    // A PSS signature is not a v1.5 signature: this must be rejected.
    let v15_rejects =
        rsa::VerifyPKCS1v15(&key.PublicKey, goish::crypto::SHA256, digest, sig) != goish::nil;
    check(
        6,
        b"Sign(*PSSOptions) -> PSS     ",
        e1 == goish::nil && pss_ok && v15_rejects,
    );
}

fn test_7_decrypt_default() {
    let mut rng = RandReader;
    let key = test_key();
    let plain = from_bytes(b"decrypter default");
    let (ct, e1) = rsa::EncryptPKCS1v15(&mut rng, &key.PublicKey, plain.clone());
    let (pt, e2) = key.Decrypt(&mut rng, ct, None);
    check(
        7,
        b"Decrypt(nil opts) -> v1.5    ",
        e1 == goish::nil && e2 == goish::nil && bytes_eq(&pt, &plain),
    );
}

fn test_8_decrypt_oaep() {
    let mut rng = RandReader;
    let key = test_key();
    // SHA-1 OAEP fits a 512-bit key: maxMsg = 64 - 2*20 - 2 = 22 bytes.
    let plain = from_bytes(b"oaep via Decrypter");
    let label = from_bytes(b"ctx");
    let mut h = sha1::New();
    let (ct, e1) = rsa::EncryptOAEP(
        &mut h,
        &mut rng,
        &key.PublicKey,
        plain.clone(),
        label.clone(),
    );
    let opts: goish::crypto::DecrypterOpts = alloc::boxed::Box::new(rsa::OAEPOptions {
        Hash: goish::crypto::SHA1,
        MGFHash: goish::crypto::Hash(0),
        Label: label,
    });
    let (pt, e2) = key.Decrypt(&mut rng, ct, Some(&opts));
    check(
        8,
        b"Decrypt(*OAEPOptions)        ",
        e1 == goish::nil && e2 == goish::nil && bytes_eq(&pt, &plain),
    );
}

fn test_9_decrypt_session_key() {
    let mut rng = RandReader;
    let key = test_key();
    let session = from_bytes(b"0123456789abcdef");
    let (ct, e1) = rsa::EncryptPKCS1v15(&mut rng, &key.PublicKey, session.clone());
    let opts: goish::crypto::DecrypterOpts =
        alloc::boxed::Box::new(rsa::PKCS1v15DecryptOptions { SessionKeyLen: 16 });
    let (pt, e2) = key.Decrypt(&mut rng, ct, Some(&opts));
    check(
        9,
        b"Decrypt(*PKCS1v15Decrypt)    ",
        e1 == goish::nil && e2 == goish::nil && bytes_eq(&pt, &session),
    );
}

fn test_10_decrypt_go_ciphertext() {
    let mut rng = RandReader;
    let key = test_key();
    let (pt, err) = rsa::DecryptPKCS1v15(&mut rng, &key, unhex(GO_V15_CT));
    check(
        10,
        b"Decrypt Go v1.5 ciphertext   ",
        err == goish::nil && bytes_eq(&pt, &from_bytes(b"hello rsa pkcs1v15")),
    );
}

fn test_11_sign_matches_go() {
    let mut rng = RandReader;
    let key = test_key();
    let (sig, err) = rsa::SignPKCS1v15(
        &mut rng,
        &key,
        goish::crypto::SHA256,
        sha256_digest(),
    );
    check(
        11,
        b"SignPKCS1v15 == Go signature ",
        err == goish::nil && bytes_eq(&sig, &unhex(GO_V15_SIG)),
    );
}

fn test_12_pss_auto_salt_is_go_s() {
    let mut rng = RandReader;
    let key = test_key();
    let digest = sha256_digest();
    let auto = rsa::PSSOptions {
        SaltLength: rsa::PSSSaltLengthAuto,
        Hash: goish::crypto::SHA256,
    };
    let (sig, e1) = rsa::SignPSS(
        &mut rng,
        &key,
        goish::crypto::SHA256,
        digest.clone(),
        Some(&auto),
    );
    // Verifying with an explicit salt length only succeeds if the signer
    // picked exactly that many bytes.
    let exact = rsa::PSSOptions {
        SaltLength: GO_PSS_AUTO_SALT,
        Hash: goish::crypto::SHA256,
    };
    let ev = rsa::VerifyPSS(
        &key.PublicKey,
        goish::crypto::SHA256,
        digest.clone(),
        sig.clone(),
        Some(&exact),
    );
    // And one byte more must not verify.
    let off_by_one = rsa::PSSOptions {
        SaltLength: GO_PSS_AUTO_SALT - 1,
        Hash: goish::crypto::SHA256,
    };
    let ebad = rsa::VerifyPSS(
        &key.PublicKey,
        goish::crypto::SHA256,
        digest,
        sig,
        Some(&off_by_one),
    );
    check(
        12,
        b"PSS auto salt == Go's 30     ",
        e1 == goish::nil && ev == goish::nil && ebad != goish::nil,
    );
}

fn test_13_session_key_from_go() {
    let mut rng = RandReader;
    let key = test_key();
    let mut out: slice<byte> = slice::<byte>::__from_vec(alloc::vec![0u8; 16]);
    let err = rsa::DecryptPKCS1v15SessionKey(&mut rng, &key, unhex(GO_SESS_CT), &mut out);
    check(
        13,
        b"SessionKey from Go cipherxt  ",
        err == goish::nil && bytes_eq(&out, &from_bytes(b"0123456789abcdef")),
    );
}
