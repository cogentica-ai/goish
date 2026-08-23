// dsa_smoke — crypto/dsa.
//
// DSA signing draws k from the reader, so a signature cannot be compared
// to Go's directly. Verify can: the signature below is constructed from a
// *fixed* k by the same arithmetic Sign performs, in both Go and goish, so
// r and s are comparable values and Verify's answer is comparable too.
//
// Every expected value is what Go prints for the same input, via
// scripts/goref.sh (AGENTS.md §10).
//
// One thing worth knowing, learned the hard way while writing the Go
// reference: a hand-picked `g` is not a generator of the order-q subgroup,
// and Verify then rejects every signature made under it. Go said so first
// — `ok = false` — which is why g here is derived as h^((p-1)/q) mod p,
// exactly as GenerateParameters derives it.
//
// goish's ModInverse cannot return Go's nil for "no inverse", so Verify
// checks gcd(s, q) == 1 directly. The zero-r and r == q cases below are
// what exercise the surrounding range checks.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::dsa;
use goish::fmt;
use goish::goslice::slice;
use goish::math::big::{Int, NewInt};
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

fn hexInt(s: &str) -> Int {
    let mut v = Int::default();
    let (_, ok) = v.SetString(s, 16);
    if !ok {
        panic!("hexInt");
    }
    return v;
}

fn params() -> dsa::Parameters {
    let p = hexInt(P_HEX);
    let q = hexInt(Q_HEX);
    // g = h^((p-1)/q) mod p with h = 2, as GenerateParameters derives it.
    let one = NewInt(1);
    let mut pm1 = Int::default();
    pm1.Sub(&p, &one);
    let mut e = Int::default();
    e.Div(&pm1, &q);
    let mut g = Int::default();
    g.Exp(&NewInt(2), &e, &p);
    return dsa::Parameters { P: p, Q: q, G: g };
}

fn hash() -> slice<byte> {
    return slice::__from_vec(alloc::vec![
        0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14
    ]);
}

#[goish::main]
fn main() {
    let pp = params();
    let x = hexInt("4B9B4F0C0A0E1E3B5D7F91A3C5E70912345678AB");
    let mut y = Int::default();
    y.Exp(&pp.G, &x, &pp.P);
    check("public key y", y.Text(16), Y_HEX);

    let pubKey = dsa::PublicKey {
        Parameters: pp.clone(),
        Y: y,
    };

    // Build the signature Sign would produce from this fixed k.
    let k = hexInt("2A3B4C5D6E7F80910A1B2C3D4E5F60718293A4B5");
    let mut two = NewInt(2);
    let mut qm2 = Int::default();
    qm2.Sub(&pp.Q, &two);
    let mut kInv = Int::default();
    kInv.Exp(&k, &qm2, &pp.Q);
    check("k inverse", kInv.Text(16), KINV_HEX);

    let mut r = Int::default();
    r.Exp(&pp.G, &k, &pp.P);
    let t = r.clone();
    r.Mod(&t, &pp.Q);
    check("signature r", r.Text(16), R_HEX);

    let mut z = Int::default();
    z.SetBytes(hash());
    let mut s = Int::default();
    s.Mul(&x, &r);
    let t = s.clone();
    s.Add(&t, &z);
    let t = s.clone();
    s.Mod(&t, &pp.Q);
    let t = s.clone();
    s.Mul(&t, &kInv);
    let t = s.clone();
    s.Mod(&t, &pp.Q);
    check("signature s", s.Text(16), S_HEX);

    check(
        "Verify accepts",
        fmt::Sprintf!("%v", dsa::Verify(&pubKey, &hash(), &r, &s)),
        "true",
    );

    // Tampering and the two range checks.
    let mut bad = Int::default();
    bad.Add(&r, &NewInt(1));
    check(
        "Verify rejects a tampered r",
        fmt::Sprintf!("%v", dsa::Verify(&pubKey, &hash(), &bad, &s)),
        "false",
    );
    check(
        "Verify rejects r = 0",
        fmt::Sprintf!("%v", dsa::Verify(&pubKey, &hash(), &NewInt(0), &s)),
        "false",
    );
    check(
        "Verify rejects r = q",
        fmt::Sprintf!("%v", dsa::Verify(&pubKey, &hash(), &pp.Q, &s)),
        "false",
    );

    // GenerateKey needs its parameters set; the guard is the cheap check.
    let mut empty = dsa::PrivateKey::default();
    let mut r0 = goish::crypto::rand::Reader;
    let err = dsa::GenerateKey(&mut empty, &mut r0);
    check(
        "GenerateKey without parameters",
        fmt::Sprintf!("%v", err.Error()),
        "crypto/dsa: parameters not set up before generating key",
    );

    // And with them, it produces a key that satisfies y = g^x mod p.
    let mut priv_ = dsa::PrivateKey::default();
    priv_.PublicKey.Parameters = pp.clone();
    let err = dsa::GenerateKey(&mut priv_, &mut r0);
    check(
        "GenerateKey err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    let mut recomputed = Int::default();
    recomputed.Exp(&pp.G, &priv_.X, &pp.P);
    check(
        "generated y = g^x mod p",
        fmt::Sprintf!("%v", recomputed.Cmp(&priv_.PublicKey.Y) == 0),
        "true",
    );

    // A signature from the generated key must verify.
    let (sr, ss, err) = dsa::Sign(&mut r0, &priv_, &hash());
    check("Sign err", fmt::Sprintf!("%v", err != goish::nil), "false");
    check(
        "generated key round trip",
        fmt::Sprintf!("%v", dsa::Verify(&priv_.PublicKey, &hash(), &sr, &ss)),
        "true",
    );

    let _ = two.SetInt64(2);
    let _: Vec<byte> = Vec::new();

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("dsa_smoke OK\n");
}

const P_HEX: &str = "A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A0\
                      4F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D8597261\
                      9AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC\
                      6F9D5C7B1A97E3D9D54ED7951FEF";
const Q_HEX: &str = "E1D3391245933D68A0714ED34BBCB7A1F422B9C1";
const Y_HEX: &str = "8832e5b398234a15a837c0490e54fc45680d6b616a49cfbbc97f633d5089c107577ddbd4b3d\
                      b9e2a89e1eae294eeebbad08c639e2720c3d9661af87a36217eeb89396e0a1ab86300d5be4cf\
                      fe21bbbb8c7b114fef535c6c5d5c34dded9c43bfee667c7cb2370f5c6b2f8e98fbbd6f13a180\
                      4f8f7f3df64770162cc5fe0d365dd";
const R_HEX: &str = "35b85bb134dcee588b408911bcee7715c6c15949";
const S_HEX: &str = "dc401d56a5a3d8b19cd23c4fab4590fbd5e96aec";
const KINV_HEX: &str = "a08e352366b0263fbec0f962192c557eb36e6410";
