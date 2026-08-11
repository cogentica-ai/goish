// fips140_ecdsa_smoke — crypto/internal/fips140/ecdsa: deterministic
// signing (FIPS 186-5 / RFC 6979), verification, and the rejection paths.
//
// Deterministic ECDSA is the only variant that can be cross-checked at
// all: hedged Sign draws Z from the DRBG, so its output is different on
// every call by design. SignDeterministic is a pure function of the key
// and the hash, which makes every byte below comparable to Go's — and it
// exercises the same signGeneric/verifyGeneric path, plus the whole
// HMAC_DRBG, that hedged signing uses.
//
// Every expected value is what Go prints for the same input, via
// scripts/goref.sh (AGENTS.md §10). Nothing was transcribed.
//
// The public key Q is recomputed here with nistec rather than pasted, and
// then compared to Go's — so a curve-level disagreement shows up as a
// wrong Q instead of hiding inside a signature that still self-verifies.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::internal::fips140::ecdsa;
use goish::crypto::internal::fips140::nistec;
use goish::crypto::internal::fips140::sha256;
use goish::crypto::internal::fips140::sha512;
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

fn nm(curve: &str, case: &str) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(curve.len() + case.len() + 1);
    s.push_str(curve);
    s.push(' ');
    s.push_str(case);
    return s;
}

/// The same deterministic scalar the Go reference used.
fn scalar(n: usize, seed: byte) -> slice<byte> {
    let mut b: Vec<byte> = Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n {
        b.push((((i * 13 + 3) & 0xff) as byte) ^ seed);
        i += 1;
    }
    if n == 66 {
        b[0] &= 0x01;
    } else {
        b[0] &= 0x0f;
    }
    return slice::__from_vec(b);
}

/// The same deterministic message hash the Go reference used.
fn msg(n: usize) -> slice<byte> {
    let mut h: Vec<byte> = Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n {
        h.push(((i * 29 + 11) & 0xff) as byte);
        i += 1;
    }
    return slice::__from_vec(h);
}

fn run<P: ecdsa::Point>(name: &str, c: &ecdsa::Curve<P>, n: usize, Q: &slice<byte>, want: &[&str; 8]) {
    check(&nm(name, "generator multiple Q"), hx(Q), want[0]);

    let d = scalar(n, 0x00);
    let (k, err) = ecdsa::NewPrivateKey(c, &d, Q);
    check(&nm(name, "NewPrivateKey err"), fmt::Sprintf!("%v", err != goish::nil), "false");
    check(&nm(name, "private scalar"), hx(&k.Bytes()), want[1]);

    let hash = msg(64);
    let (sig, err) = ecdsa::SignDeterministic(c, sha512::NewHash, &k, &hash);
    check(&nm(name, "SignDeterministic sha512 err"), fmt::Sprintf!("%v", err != goish::nil), "false");
    check(&nm(name, "r (sha512)"), hx(&sig.R), want[2]);
    check(&nm(name, "s (sha512)"), hx(&sig.S), want[3]);
    let err = ecdsa::Verify(c, &k.PublicKey(), &hash, &sig);
    check(&nm(name, "Verify (sha512)"), fmt::Sprintf!("%v", err != goish::nil), "false");

    let h256 = msg(32);
    let (sig2, err) = ecdsa::SignDeterministic(c, sha256::NewHash, &k, &h256);
    check(&nm(name, "SignDeterministic sha256 err"), fmt::Sprintf!("%v", err != goish::nil), "false");
    check(&nm(name, "r (sha256)"), hx(&sig2.R), want[4]);
    check(&nm(name, "s (sha256)"), hx(&sig2.S), want[5]);
    let err = ecdsa::Verify(c, &k.PublicKey(), &h256, &sig2);
    check(&nm(name, "Verify (sha256)"), fmt::Sprintf!("%v", err != goish::nil), "false");

    // A tampered r must not verify.
    let mut rb: Vec<byte> = {
        let r: &[byte] = &sig.R;
        r.to_vec()
    };
    let last = rb.len() - 1;
    rb[last] ^= 1;
    let bad = ecdsa::Signature {
        R: slice::__from_vec(rb),
        S: sig.S.clone(),
    };
    let err = ecdsa::Verify(c, &k.PublicKey(), &hash, &bad);
    check(&nm(name, "tampered signature rejected"), fmt::Sprintf!("%v", err.Error()), want[6]);

    // r = 0 is rejected before any point arithmetic.
    let zero = ecdsa::Signature {
        R: slice::__from_vec(alloc::vec![0u8; n]),
        S: sig.S.clone(),
    };
    let err = ecdsa::Verify(c, &k.PublicKey(), &hash, &zero);
    check(&nm(name, "zero r rejected"), fmt::Sprintf!("%v", err.Error()), want[7]);
}

#[goish::main]
fn main() {
    {
        let mut q = nistec::NewP224Point();
        let _ = q.ScalarBaseMult(&scalar(28, 0x00));
        run("p224", ecdsa::P224(), 28, &q.Bytes(), &[P224_Q, P224_D, P224_R512, P224_S512, P224_R256, P224_S256, P224_BAD, P224_ZERO]);
    }

    {
        let mut q = nistec::NewP256Point();
        let _ = q.ScalarBaseMult(&scalar(32, 0x00));
        run("p256", ecdsa::P256(), 32, &q.Bytes(), &[P256_Q, P256_D, P256_R512, P256_S512, P256_R256, P256_S256, P256_BAD, P256_ZERO]);
    }

    {
        let mut q = nistec::NewP384Point();
        let _ = q.ScalarBaseMult(&scalar(48, 0x00));
        run("p384", ecdsa::P384(), 48, &q.Bytes(), &[P384_Q, P384_D, P384_R512, P384_S512, P384_R256, P384_S256, P384_BAD, P384_ZERO]);
    }

    {
        let mut q = nistec::NewP521Point();
        let _ = q.ScalarBaseMult(&scalar(66, 0x00));
        run("p521", ecdsa::P521(), 66, &q.Bytes(), &[P521_Q, P521_D, P521_R512, P521_S512, P521_R256, P521_S256, P521_BAD, P521_ZERO]);
    }

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_ecdsa_smoke OK\n");
}

const P224_Q: &str = "047306521918ee0767afcbda4e60ddbd0d4bd2f6b94a8c16be2e90d03268eba4\
                      e2449a9216ce9a5c78afc53b3cde92af8629afd22f8f096b8d";
const P224_D: &str = "03101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b485562";
const P224_R512: &str = "ffef49147390205592598fcb4e9126e366aa65a71e2b45aa9118dbde";
const P224_S512: &str = "bbb11d18e05402875e31226330f202863a6d119cc6230c0fd1311511";
const P224_R256: &str = "1e0a2d310a5337a51af0d99ba9a19f907300fb33b6ddfe6f86ba8904";
const P224_S256: &str = "49f401597d7be5748ef07f756e6b5239b19e50f1102f1222982c840f";
const P224_BAD: &str = "ecdsa: signature did not verify";
const P224_ZERO: &str = "ecdsa: invalid signature: r is zero";
const P256_Q: &str = "049aa0c8cf2c7d1a3aadf3cc1a9ae6ddb166d942d6725546f18a94a312ba297d\
                      7e0603f5365ac752648d1e8702cbd60ac61171c171b9d9f9686941227ff77083\
                      a9";
const P256_D: &str = "03101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b4855626f7c8996";
const P256_R512: &str = "a795910512841e8fd1f1b8731ca6bd837d5661988ab0aea8d0d6da50c78280e3";
const P256_S512: &str = "6b52761927fc4093746587d082c09c53d9b16d8623840b7431dc66bed0e25727";
const P256_R256: &str = "429eefe524603840e8c4e87f776b5b5d747dc4dbd4fec4c82509938026ef399a";
const P256_S256: &str = "b8481d67da09b381f911f13db1e50895d9f163baf0c0fddac843f3bc1e3aebfc";
const P256_BAD: &str = "ecdsa: signature did not verify";
const P256_ZERO: &str = "ecdsa: invalid signature: r is zero";
const P384_Q: &str = "0452c6243481b08a8ac29360ba811ddc312225e67ecd2056971aa615eccafd05\
                      3e426c11371027d3f05915e1ef9e5e85a5eeeb49c7163a683843758a6c0c42f6\
                      cd07f2ecb785ddaf555248cde8b14067c8604acb118475ea5cf6be0720b0d3e1\
                      b3";
const P384_D: &str = "03101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b4855626f7c8996\
                      a3b0bdcad7e4f1fe0b1825323f4c5966";
const P384_R512: &str = "5d0f196b9d520794d128accc40b84090bf1d061c5d314b4b49a460cd1adc7c7f\
                      8c3fce8989c29b814655c32d076e05fe";
const P384_S512: &str = "e73ebdf2a1ff04c485168ed01aec2489286543e01aa957946f4661f42e85de50\
                      10389ff5e9466873a8c2d0e85d1e5b5d";
const P384_R256: &str = "e98fa83236b0d4db5ef5177e79b38b4493b8f587331a990c07355d107de47c57\
                      7a1e392ab6f2c8f40bb3dd2ba3dba263";
const P384_S256: &str = "badef439069fae043f7bf59824a9b53d64936d508e2fc108cb08ec2024158627\
                      cfc6cf60e588a4fe2390807c2e4f472b";
const P384_BAD: &str = "ecdsa: signature did not verify";
const P384_ZERO: &str = "ecdsa: invalid signature: r is zero";
const P521_Q: &str = "040195f92e7e40ef0e9339c472a34e8acb2da4130311c0f8b2baf85e62267e0f\
                      5ca382ad17fc6e29df971623d210ba93a3b7d87a3406febc9ac6abe4954c9b90\
                      411f5800ae76a8ca4d1cd28254dc78d47faa6e053e1be860ce968e004a00c8ae\
                      52a3391a2ccf94aeba8565c591fa15ee82d98815a9a47ab58a9c1fb8d391637c\
                      e40473197f";
const P521_D: &str = "01101d2a3744515e6b7885929facb9c6d3e0edfa0714212e3b4855626f7c8996\
                      a3b0bdcad7e4f1fe0b1825323f4c596673808d9aa7b4c1cedbe8f5020f1c2936\
                      4350";
const P521_R512: &str = "009ab076d1996d06ac80dec13068c534543075c82773b964a779add53d9e1788\
                      e3b0614dda37949078f7542b5b8131078fd252c8b816092960a271c0e6871af4\
                      457b";
const P521_S512: &str = "0152fd027606d9f4f65a1b516dcf0886468987a1bbb7aac9cbfedd43d0da25b7\
                      1779f840925a1c51be5a4b31d2f11658070fda23570f051ed15f673d12f569c4\
                      122f";
const P521_R256: &str = "014678b154d81a311c72b28f8e6df6dde34987cd45563e2c95ddc32fb653992e\
                      34d971a3eeac504aee05830c440941db30b2d314e282fd7af316d3aff5de73fb\
                      531d";
const P521_S256: &str = "00f4628a47e1753a98cb4fc5faa9343135a32d17c4bc785b20ffc4dc0719937c\
                      fa59823a8fe7e6def5ed2c21d093a6b59b65227f89f17407a7da494f3ca4b0a7\
                      51da";
const P521_BAD: &str = "ecdsa: signature did not verify";
const P521_ZERO: &str = "ecdsa: invalid signature: r is zero";
