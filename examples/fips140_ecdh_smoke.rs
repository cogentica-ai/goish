// fips140_ecdh_smoke — crypto/internal/fips140/ecdh, the FIPS ECDH over
// the four NIST P curves.
//
// This is the first consumer of the nistec port, so it is also the first
// end-to-end check of it: a shared secret is only equal on both sides if
// ScalarBaseMult and ScalarMult agree about the group.
//
// Every expected value is what Go prints for the same input, via
// scripts/goref.sh (AGENTS.md §10). Nothing was transcribed.
//
// GenerateKey is deliberately not cross-checked: it routes through
// drbg.ReadWithReader, which calls randutil.MaybeReadByte on a non-default
// reader and so consumes a byte only about half the time. That makes it
// non-reproducible by design. It is still exercised below for the property
// that does hold — the key it returns must satisfy its own PCT.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::internal::fips140::ecdh;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::int;
use goish::io;
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

/// Same as `check`, when the expected value is itself computed.
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

/// The same deterministic key material the Go reference used.
fn key(n: usize, seed: byte) -> slice<byte> {
    let mut b: Vec<byte> = Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n {
        b.push((((i * 13 + 3) & 0xff) as byte) ^ seed);
        i += 1;
    }
    // P-521's order has 0x01 as its top byte; every other curve's is 0xff.
    if n == 66 {
        b[0] &= 0x01;
    } else {
        b[0] &= 0x0f;
    }
    return slice::__from_vec(b);
}

/// Everything the Go reference does per curve, in the same order.
fn one<P: ecdh::Point>(name: &str, c: &ecdh::Curve<P>, n: usize, want: &[&str; 9]) {
    let (a, err) = ecdh::NewPrivateKey(c, &key(n, 0x00));
    check(
        &nm(name, "NewPrivateKey a"),
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    let (b, err) = ecdh::NewPrivateKey(c, &key(n, 0x5a));
    check(
        &nm(name, "NewPrivateKey b"),
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );

    check(&nm(name, "pubA"), hx(&a.PublicKey().Bytes()), want[0]);
    check(&nm(name, "pubB"), hx(&b.PublicKey().Bytes()), want[1]);

    let (ab, err) = ecdh::ECDH(c, &a, &b.PublicKey());
    check(
        &nm(name, "ECDH ab err"),
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    check(&nm(name, "shared ab"), hx(&ab), want[2]);
    let (ba, err) = ecdh::ECDH(c, &b, &a.PublicKey());
    check(
        &nm(name, "ECDH ba err"),
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    check(&nm(name, "shared ba"), hx(&ba), want[3]);

    let (pk, err) = ecdh::NewPublicKey(c, &a.PublicKey().Bytes());
    check(
        &nm(name, "NewPublicKey err"),
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    check(&nm(name, "public key round trip"), hx(&pk.Bytes()), want[4]);

    let zero = slice::__from_vec(alloc::vec![0u8; n]);
    let (_, err) = ecdh::NewPrivateKey(c, &zero);
    check(
        &nm(name, "zero key rejected"),
        fmt::Sprintf!("%v", err.Error()),
        want[5],
    );
    let (_, err) = ecdh::NewPrivateKey(c, &c.N);
    check(
        &nm(name, "key == order rejected"),
        fmt::Sprintf!("%v", err.Error()),
        want[6],
    );
    let (_, err) = ecdh::NewPrivateKey(c, &slice::__from_vec(alloc::vec![0u8; n - 1]));
    check(
        &nm(name, "short key rejected"),
        fmt::Sprintf!("%v", err.Error()),
        want[7],
    );
    let (_, err) = ecdh::NewPublicKey(c, &slice::__from_vec(alloc::vec![0u8; 1]));
    check(
        &nm(name, "identity public key rejected"),
        fmt::Sprintf!("%v", err.Error()),
        want[8],
    );
}

/// `check` takes a &str name; this joins the curve to the case without
/// pulling in alloc::format! (which drags in _Unwind_Resume under
/// panic=abort).
fn nm(curve: &str, case: &str) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(curve.len() + case.len() + 1);
    s.push_str(curve);
    s.push(' ');
    s.push_str(case);
    return s;
}

/// A counting byte source. GenerateKey's output is not reproducible (see
/// the header), so this exists only to drive it deterministically enough
/// to reach the PCT.
struct counter {
    n: byte,
}

impl io::Reader for counter {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, goish::error) {
        let b: &mut [byte] = p;
        let mut i: usize = 0;
        while i < b.len() {
            b[i] = self.n;
            self.n = self.n.wrapping_add(31);
            i += 1;
        }
        return (int(b.len()), goish::nil.into());
    }
}

/// GenerateKey is not cross-checkable against Go, but two properties are
/// checkable here: the key it returns must round-trip through
/// NewPrivateKey to the same public key (which is what its own PCT
/// asserts), and it must be usable for an ECDH that agrees with a peer.
fn generated<P: ecdh::Point>(name: &str, c: &ecdh::Curve<P>, n: usize) {
    let mut r = counter { n: 7 };
    let (k, err) = ecdh::GenerateKey(c, &mut r);
    check(
        &nm(name, "GenerateKey err"),
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    check(
        &nm(name, "GenerateKey length"),
        fmt::Sprintf!("%v", k.Bytes().Len()),
        &itoa(n),
    );

    let (k2, err) = ecdh::NewPrivateKey(c, &k.Bytes());
    check(
        &nm(name, "regenerate err"),
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    checkSame(
        &nm(name, "generated key re-derives its public key"),
        hx(&k2.PublicKey().Bytes()),
        hx(&k.PublicKey().Bytes()),
    );

    // And it is a usable ECDH key: both sides must reach the same secret.
    let (peer, err) = ecdh::NewPrivateKey(c, &key(n, 0x11));
    check(
        &nm(name, "peer err"),
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    let (s1, _) = ecdh::ECDH(c, &k, &peer.PublicKey());
    let (s2, _) = ecdh::ECDH(c, &peer, &k.PublicKey());
    checkSame(
        &nm(name, "generated key agrees with peer"),
        hx(&s1),
        hx(&s2),
    );
}

/// Smallest possible decimal formatter — `fmt::Sprintf!("%d", …)` would
/// do, but the want side needs a &str.
fn itoa(mut v: usize) -> alloc::string::String {
    if v == 0 {
        return alloc::string::String::from("0");
    }
    let mut d: Vec<byte> = Vec::new();
    while v > 0 {
        d.push(b'0' + ((v % 10) as byte));
        v /= 10;
    }
    d.reverse();
    return alloc::string::String::from_utf8(d).unwrap();
}

#[goish::main]
fn main() {
    one(
        "p224",
        &ecdh::P224(),
        28,
        &[
            P224_PUBA, P224_PUBB, P224_AB, P224_BA, P224_RTPK, P224_ZERO, P224_ORDR, P224_SHRT,
            P224_INF,
        ],
    );

    one(
        "p256",
        &ecdh::P256(),
        32,
        &[
            P256_PUBA, P256_PUBB, P256_AB, P256_BA, P256_RTPK, P256_ZERO, P256_ORDR, P256_SHRT,
            P256_INF,
        ],
    );

    one(
        "p384",
        &ecdh::P384(),
        48,
        &[
            P384_PUBA, P384_PUBB, P384_AB, P384_BA, P384_RTPK, P384_ZERO, P384_ORDR, P384_SHRT,
            P384_INF,
        ],
    );

    one(
        "p521",
        &ecdh::P521(),
        66,
        &[
            P521_PUBA, P521_PUBB, P521_AB, P521_BA, P521_RTPK, P521_ZERO, P521_ORDR, P521_SHRT,
            P521_INF,
        ],
    );

    generated("p224", &ecdh::P224(), 28);
    generated("p256", &ecdh::P256(), 32);
    generated("p384", &ecdh::P384(), 48);
    generated("p521", &ecdh::P521(), 66);

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_ecdh_smoke OK\n");
}

const P224_PUBA: &str = "047306521918ee0767afcbda4e60ddbd0d4bd2f6b94a8c16be2e90d03268eba4\
                      e2449a9216ce9a5c78afc53b3cde92af8629afd22f8f096b8d";
const P224_PUBB: &str = "0440025ad73e50e6580aaea3b91b818d2a7946a4eb61902e5cd2e572f87897a0\
                      1df5a347905614fa08cf29945735c8e3645406adbedbced849";
const P224_AB: &str = "408d789ddde1da3943c3d5fad1e60c77553a852d56fb8f575c7bb733";
const P224_BA: &str = "408d789ddde1da3943c3d5fad1e60c77553a852d56fb8f575c7bb733";
const P224_RTPK: &str = "047306521918ee0767afcbda4e60ddbd0d4bd2f6b94a8c16be2e90d03268eba4\
                      e2449a9216ce9a5c78afc53b3cde92af8629afd22f8f096b8d";
const P224_ZERO: &str = "crypto/ecdh: invalid private key";
const P224_ORDR: &str = "crypto/ecdh: invalid private key";
const P224_SHRT: &str = "crypto/ecdh: invalid private key";
const P224_INF: &str = "crypto/ecdh: invalid public key";
const P256_PUBA: &str = "049aa0c8cf2c7d1a3aadf3cc1a9ae6ddb166d942d6725546f18a94a312ba297d\
                      7e0603f5365ac752648d1e8702cbd60ac61171c171b9d9f9686941227ff77083\
                      a9";
const P256_PUBB: &str = "04940ff03902c5fb7dd8bdf7b6124f66105e5911ceb96e369d4874b34e927ddf\
                      d13ae5572fb809d5e9c95cc53307c80acd9e3802ab7179cc163db4c5e4696fec\
                      b4";
const P256_AB: &str = "a09b8f3233878edefe75563b706283c411b5519ef4b7fb73738d6b755d784a00";
const P256_BA: &str = "a09b8f3233878edefe75563b706283c411b5519ef4b7fb73738d6b755d784a00";
const P256_RTPK: &str = "049aa0c8cf2c7d1a3aadf3cc1a9ae6ddb166d942d6725546f18a94a312ba297d\
                      7e0603f5365ac752648d1e8702cbd60ac61171c171b9d9f9686941227ff77083\
                      a9";
const P256_ZERO: &str = "crypto/ecdh: invalid private key";
const P256_ORDR: &str = "crypto/ecdh: invalid private key";
const P256_SHRT: &str = "crypto/ecdh: invalid private key";
const P256_INF: &str = "crypto/ecdh: invalid public key";
const P384_PUBA: &str = "0452c6243481b08a8ac29360ba811ddc312225e67ecd2056971aa615eccafd05\
                      3e426c11371027d3f05915e1ef9e5e85a5eeeb49c7163a683843758a6c0c42f6\
                      cd07f2ecb785ddaf555248cde8b14067c8604acb118475ea5cf6be0720b0d3e1\
                      b3";
const P384_PUBB: &str = "0418a91f3adec1b811c6e1d19afccb84f6992359e940e14f48e4338d3066fb28\
                      1e9af9fdad639ffc688f08551551d6db87deb208a3aff907284f281cb0c47c75\
                      df7d20b66ac4e43e1343baebf2263e849ec2554dba2708c01d8c62914a7d8db5\
                      d3";
const P384_AB: &str = "73f789e82ea991989292355f96a74272182c26dd6e5ca4fd53dc662aa38b6d39\
                      e2bc990b8101369fb69142be0672e618";
const P384_BA: &str = "73f789e82ea991989292355f96a74272182c26dd6e5ca4fd53dc662aa38b6d39\
                      e2bc990b8101369fb69142be0672e618";
const P384_RTPK: &str = "0452c6243481b08a8ac29360ba811ddc312225e67ecd2056971aa615eccafd05\
                      3e426c11371027d3f05915e1ef9e5e85a5eeeb49c7163a683843758a6c0c42f6\
                      cd07f2ecb785ddaf555248cde8b14067c8604acb118475ea5cf6be0720b0d3e1\
                      b3";
const P384_ZERO: &str = "crypto/ecdh: invalid private key";
const P384_ORDR: &str = "crypto/ecdh: invalid private key";
const P384_SHRT: &str = "crypto/ecdh: invalid private key";
const P384_INF: &str = "crypto/ecdh: invalid public key";
const P521_PUBA: &str = "040195f92e7e40ef0e9339c472a34e8acb2da4130311c0f8b2baf85e62267e0f\
                      5ca382ad17fc6e29df971623d210ba93a3b7d87a3406febc9ac6abe4954c9b90\
                      411f5800ae76a8ca4d1cd28254dc78d47faa6e053e1be860ce968e004a00c8ae\
                      52a3391a2ccf94aeba8565c591fa15ee82d98815a9a47ab58a9c1fb8d391637c\
                      e40473197f";
const P521_PUBB: &str = "0400567edb380d18777d37543038fb6b2e11387acd18362dba72c458b1bc2a2f\
                      a510ebc409fe6f7d1b52d921489bb7568932c46b198369cb959ff642abf985d9\
                      eac295016f6c52b219ab14a99062d77418476e768783b74fe9e27178dda39d50\
                      0e2b792e790524ae351636c3abdbaae8aa1525388ae7153d081577c9d9859798\
                      01440dccfc";
const P521_AB: &str = "01f4145cf251e891ec12108ab0cdbf36dc1f082d4381438f1d9b948c1a6b498e\
                      449dc91cfe5b1da269bccb8e74532a4086c8861e09b7c95e8183c1d2aa88a3c2\
                      252a";
const P521_BA: &str = "01f4145cf251e891ec12108ab0cdbf36dc1f082d4381438f1d9b948c1a6b498e\
                      449dc91cfe5b1da269bccb8e74532a4086c8861e09b7c95e8183c1d2aa88a3c2\
                      252a";
const P521_RTPK: &str = "040195f92e7e40ef0e9339c472a34e8acb2da4130311c0f8b2baf85e62267e0f\
                      5ca382ad17fc6e29df971623d210ba93a3b7d87a3406febc9ac6abe4954c9b90\
                      411f5800ae76a8ca4d1cd28254dc78d47faa6e053e1be860ce968e004a00c8ae\
                      52a3391a2ccf94aeba8565c591fa15ee82d98815a9a47ab58a9c1fb8d391637c\
                      e40473197f";
const P521_ZERO: &str = "crypto/ecdh: invalid private key";
const P521_ORDR: &str = "crypto/ecdh: invalid private key";
const P521_SHRT: &str = "crypto/ecdh: invalid private key";
const P521_INF: &str = "crypto/ecdh: invalid public key";
