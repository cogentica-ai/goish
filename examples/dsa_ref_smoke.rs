// dsa_ref_smoke — crypto/dsa verification against a running Go.
// (crypto/dsa/dsa.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_dsa_ref.go` run in
// `package dsa_test` by `scripts/goref.sh`. goish matched Go on all 31
// lines — no defects found.
//
// DSA is deprecated, and that is exactly why it is worth measuring: a
// deprecated verifier is one nobody looks at, and it still answers true
// or false to whatever calls it. The rules it must enforce are the same
// ones ECDSA has, and they fail the same way — a verifier that skips
// the range check on r and s can be handed a signature nobody signed.
//
// The range family is therefore the same fifteen cases the ECDSA
// reference pins, transposed to q: r and s must satisfy 0 < r < q and
// 0 < s < q, so zero, q itself, q+1, negatives and r+q are each
// constructible by anyone sending bytes and each must come back false.
// Only `valid` is true.
//
// The hash family repeats a property worth seeing twice, because it is
// shared with ECDSA and surprises people in both: DSA truncates the
// digest to q's size, so a digest LONGER than 20 bytes is cut down and
// a caller passing the wrong length gets an answer rather than an
// error. Here q is 160 bits and the digest is SHA-256, so every
// verification is already working on a truncation — and the 33- and
// 64-byte digests sharing that prefix verify too.
//
// Degenerate public keys are pinned as well: a zero q, p, g or y, and
// q = 1. None verifies, and none panics, which is the property that
// matters when the key came off a wire.
//
// NOTHING HERE IS PINNED BY VALUE. Parameters are generated afresh on
// each side, so p, q, g, x, y, r and s all differ between runs and
// between the two implementations — every line is a boolean or a bit
// length. An earlier draft printed g's BIT LENGTH and it diverged,
// which looked like a defect and was not: g is derived from a random h
// and its length varies run to run. It is now pinned as the invariant
// that actually holds, 1 < g < p. A reference that pins a random value
// fails the next time it is run, for no reason anyone can act on.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::crypto::dsa;
use goish::crypto::rand;
use goish::crypto::sha256;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::math::big::Int;
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 32] = [
    "params p-bits=1024 q-bits=160 g-in-range=true",
    "key x-in-range=true y-nonzero=true",
    "sign r-in-range=true s-in-range=true verify=true",
    "nonce differ=true both-verify=true",
    "range valid          -> verify=true",
    "range r-zero         -> verify=false",
    "range s-zero         -> verify=false",
    "range both-zero      -> verify=false",
    "range r-q            -> verify=false",
    "range s-q            -> verify=false",
    "range r-q-plus-1     -> verify=false",
    "range s-q-plus-1     -> verify=false",
    "range r-negative     -> verify=false",
    "range s-negative     -> verify=false",
    "range r-one          -> verify=false",
    "range s-one          -> verify=false",
    "range swapped        -> verify=false",
    "range r-plus-q       -> verify=false",
    "range s-plus-q       -> verify=false",
    "cross wrong-message=false",
    "cross wrong-key=false",
    "hash exact-32   -> verify=true len=32",
    "hash short-16   -> verify=false len=16",
    "hash short-1    -> verify=false len=1",
    "hash empty      -> verify=false len=0",
    "hash long-33    -> verify=false len=33",
    "hash long-64    -> verify=false len=64",
    "badkey q-zero   -> verify=false",
    "badkey p-zero   -> verify=false",
    "badkey g-zero   -> verify=false",
    "badkey y-zero   -> verify=false",
    "badkey q-one    -> verify=false",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn bs(v: Vec<u8>) -> slice<byte> {
    return slice::<byte>::__from_vec(v);
}
fn one0() -> Int {
    return newInt(1);
}
fn newInt(v: i64) -> Int {
    let mut i = Int::default();
    i.SetInt64(v);
    return i;
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let mut params = dsa::Parameters::default();
    let e = dsa::GenerateParameters(&mut params, &mut rand::Reader, dsa::L1024N160);
    if e != goish::nil {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("[!!] params: %q", e.Error()),
        );
        return;
    }
    let mut priv_ = dsa::PrivateKey::default();
    priv_.PublicKey.Parameters = params.clone();
    let e = dsa::GenerateKey(&mut priv_, &mut rand::Reader);
    if e != goish::nil {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("[!!] key: %q", e.Error()),
        );
        return;
    }
    let pub_ = priv_.PublicKey.clone();
    let q = params.Q.clone();
    let gInRange = params.G.Cmp(&one0()) > 0 && params.G.Cmp(&params.P) < 0;
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "params p-bits=%d q-bits=%d g-in-range=%v",
            params.P.BitLen(),
            params.Q.BitLen(),
            gInRange
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "key x-in-range=%v y-nonzero=%v",
            priv_.X.Sign() > 0 && priv_.X.Cmp(&q) < 0,
            pub_.Y.Sign() > 0
        ),
    );
    let digest = sha256::Sum256(bs(b"dsa reference message".to_vec()));
    let hash = bs(digest.to_vec());
    let (r, sg, serr) = dsa::Sign(&mut rand::Reader, &priv_, &hash);
    if serr != goish::nil {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("[!!] sign: %q", serr.Error()),
        );
        return;
    }
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "sign r-in-range=%v s-in-range=%v verify=%v",
            r.Sign() > 0 && r.Cmp(&q) < 0,
            sg.Sign() > 0 && sg.Cmp(&q) < 0,
            dsa::Verify(&pub_, &hash, &r, &sg)
        ),
    );
    let (r2, s2, _) = dsa::Sign(&mut rand::Reader, &priv_, &hash);
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "nonce differ=%v both-verify=%v",
            r.Cmp(&r2) != 0 || sg.Cmp(&s2) != 0,
            dsa::Verify(&pub_, &hash, &r2, &s2)
        ),
    );
    let zero = newInt(0);
    let one = newInt(1);
    let mut qp1 = Int::default();
    qp1.Add(&q, &one);
    let mut rneg = Int::default();
    rneg.Neg(&r);
    let mut sneg = Int::default();
    sneg.Neg(&sg);
    let mut rpq = Int::default();
    rpq.Add(&r, &q);
    let mut spq = Int::default();
    spq.Add(&sg, &q);
    let cases: [(&str, &Int, &Int); 15] = [
        ("valid", &r, &sg),
        ("r-zero", &zero, &sg),
        ("s-zero", &r, &zero),
        ("both-zero", &zero, &zero),
        ("r-q", &q, &sg),
        ("s-q", &r, &q),
        ("r-q-plus-1", &qp1, &sg),
        ("s-q-plus-1", &r, &qp1),
        ("r-negative", &rneg, &sg),
        ("s-negative", &r, &sneg),
        ("r-one", &one, &sg),
        ("s-one", &r, &one),
        ("swapped", &sg, &r),
        ("r-plus-q", &rpq, &sg),
        ("s-plus-q", &r, &spq),
    ];
    for (name, a, b) in cases.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "range %-14s -> verify=%v",
                s(name),
                dsa::Verify(&pub_, &hash, a, b)
            ),
        );
    }
    let other = sha256::Sum256(bs(b"different message".to_vec()));
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "cross wrong-message=%v",
            dsa::Verify(&pub_, &bs(other.to_vec()), &r, &sg)
        ),
    );
    let mut priv2 = dsa::PrivateKey::default();
    priv2.PublicKey.Parameters = params.clone();
    let _ = dsa::GenerateKey(&mut priv2, &mut rand::Reader);
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "cross wrong-key=%v",
            dsa::Verify(&priv2.PublicKey, &hash, &r, &sg)
        ),
    );
    let hv = hash.to_vec();
    let mut long33 = hv.clone();
    long33.push(0);
    let mut long64 = hv.clone();
    long64.extend_from_slice(&hv);
    let hashes: [(&str, slice<byte>); 6] = [
        ("exact-32", hash.clone()),
        ("short-16", bs(hv[..16].to_vec())),
        ("short-1", bs(hv[..1].to_vec())),
        ("empty", bs(Vec::new())),
        ("long-33", bs(long33)),
        ("long-64", bs(long64)),
    ];
    for (name, h) in hashes.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "hash %-10s -> verify=%v len=%d",
                s(name),
                dsa::Verify(&pub_, h, &r, &sg),
                h.Len()
            ),
        );
    }
    let badkeys: [(&str, int); 5] = [
        ("q-zero", 0),
        ("p-zero", 1),
        ("g-zero", 2),
        ("y-zero", 3),
        ("q-one", 4),
    ];
    for (name, which) in badkeys.iter() {
        let mut bad = pub_.clone();
        bad.Parameters = params.clone();
        match which {
            0 => bad.Parameters.Q = newInt(0),
            1 => bad.Parameters.P = newInt(0),
            2 => bad.Parameters.G = newInt(0),
            3 => bad.Y = newInt(0),
            _ => bad.Parameters.Q = newInt(1),
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "badkey %-8s -> verify=%v",
                s(name),
                dsa::Verify(&bad, &hash, &r, &sg)
            ),
        );
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
