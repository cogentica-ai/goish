// ecdsa_ref_smoke — crypto/ecdsa verification against a running Go.
// (crypto/ecdsa/ecdsa.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_ecdsa_ref.go` run in
// `package ecdsa_test` by `scripts/goref.sh`. goish matched Go on all
// 49 lines — no defects found.
//
// ECDSA is where a "does it round-trip" test is least informative:
// signing and verifying with the same code agrees with itself whatever
// the rules are. What decides whether a caller is safe is which HOSTILE
// inputs come back false, and there are two separate families.
//
// OUT OF RANGE BUT WELL-FORMED. r or s equal to zero, or equal to or
// above the group order n, are trivially constructible, and a verifier
// that forgets the range check can be talked into accepting them. This
// family has produced real CVEs in other stacks. Sixteen cases are
// pinned, including r+n and s+n — the same residue, a different
// integer.
//
// NOT VALID DER AT ALL. Fourteen byte strings that are not a SEQUENCE
// of two INTEGERs: truncated, over-long, retagged, indefinite-length,
// non-minimally-encoded, the raw 64-byte r||s concatenation that other
// stacks use, and a bare 70 zero bytes. Each must come back FALSE, not
// panic on a hostile length.
//
// The MALLEABILITY answer is pinned in the other direction, on purpose:
// for any valid (r, s) the pair (r, n-s) is also valid, and Go accepts
// both. There is no low-S rule in ECDSA — that is a Bitcoin consensus
// rule layered on top — so a port that "helpfully" rejected high-S
// would reject roughly half the signatures every Go peer produces.
// Anything needing one signature per message must enforce that above
// this layer, and this line is here so nobody mistakes the permissive
// answer for an oversight.
//
// The HASH family is the one worth reading twice. ECDSA truncates the
// digest to the curve order's bit length, so a signature made over a
// 32-byte hash ALSO verifies against a 33-, 48- or 64-byte digest that
// shares that 32-byte prefix — and `trunc long-sig-verifies-short`
// shows it the other way round too. A caller who passes the wrong
// digest length does not get an error; they get "valid" for a
// different byte string. Nothing in the API prevents it, so it is
// pinned where it can be seen.
//
// Signatures are NOT compared byte for byte. Go's nonce derivation is
// its own business and a port is not obliged to reproduce it — the
// `nonce differ=true` line pins that signatures are randomised and
// both still verify. What is compared is every verification DECISION,
// over signatures the smoke constructs itself from a key with a fixed
// D, so both sides hold the same key.
//
// All four curves are exercised, because a port can be right on P-256
// and wrong everywhere else.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::crypto::ecdsa;
use goish::crypto::elliptic;
use goish::crypto::rand;
use goish::crypto::sha256;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::math::big::Int;
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 49] = [
    "key d=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef x=471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714c y=dd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858",
    "key onCurve=true bitsize=256",
    "hash 503b33c32dd76673074ded7ed1e1a0e364b35c55443bccc228346ba90972de1a",
    "roundtrip verify=true r-in-range=true s-in-range=true",
    "range valid                -> verify=true",
    "range malleable-n-minus-s  -> verify=true",
    "range r-zero               -> verify=false",
    "range s-zero               -> verify=false",
    "range both-zero            -> verify=false",
    "range r-n                  -> verify=false",
    "range s-n                  -> verify=false",
    "range r-n-plus-1           -> verify=false",
    "range s-n-plus-1           -> verify=false",
    "range r-negative           -> verify=false",
    "range s-negative           -> verify=false",
    "range r-one                -> verify=false",
    "range s-one                -> verify=false",
    "range swapped              -> verify=false",
    "range r-plus-n             -> verify=false",
    "range s-plus-n             -> verify=false",
    "der nil                  -> verify=false",
    "der empty                -> verify=false",
    "der truncated-half       -> verify=false",
    "der truncated-last       -> verify=false",
    "der trailing-byte        -> verify=false",
    "der trailing-junk        -> verify=false",
    "der wrong-outer-tag      -> verify=false",
    "der raw-concat           -> verify=false",
    "der all-zero-70          -> verify=false",
    "der just-sequence        -> verify=false",
    "der one-integer          -> verify=false",
    "der three-integers       -> verify=false",
    "der indefinite-length    -> verify=false",
    "der non-minimal-length   -> verify=false",
    "hash exact-32       -> verify=true len=32",
    "hash short-16       -> verify=false len=16",
    "hash short-1        -> verify=false len=1",
    "hash empty          -> verify=false len=0",
    "hash long-48        -> verify=true len=48",
    "hash long-64        -> verify=true len=64",
    "hash prefix-match-33 -> verify=true len=33",
    "trunc long-sig-verifies-short=true",
    "key wrong-key-verify=false",
    "key off-curve=false off-curve-verify=false",
    "nonce differ=true both-verify=true",
    "curve P224  -> bits=224 verify=true tampered=false",
    "curve P256  -> bits=256 verify=true tampered=false",
    "curve P384  -> bits=384 verify=true tampered=false",
    "curve P521  -> bits=521 verify=true tampered=false",
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
fn hx(b: &slice<byte>) -> string {
    return hex::EncodeToString(&b.to_vec());
}
fn newInt(v: i64) -> Int {
    let mut i = Int::default();
    i.SetInt64(v);
    return i;
}
// DER INTEGER, exactly as encoding/asn1's makeBigInt renders one:
// minimal two's-complement, with the 0x00 / 0xff sign byte where the
// high bit would otherwise flip the sign.
fn derInt(x: &Int) -> Vec<u8> {
    let mut body: Vec<u8>;
    if x.Sign() < 0 {
        let mut m = Int::default();
        m.Neg(x);
        let mut one = newInt(1);
        let mm = m.clone();
        m.Sub(&mm, &one);
        let _ = &mut one;
        body = m.Bytes().to_vec();
        for b in body.iter_mut() {
            *b ^= 0xff;
        }
        if body.is_empty() || body[0] & 0x80 == 0 {
            body.insert(0, 0xff);
        }
    } else if x.Sign() == 0 {
        body = alloc::vec![0u8];
    } else {
        body = x.Bytes().to_vec();
        if body[0] & 0x80 != 0 {
            body.insert(0, 0x00);
        }
    }
    let mut out: Vec<u8> = Vec::new();
    out.push(0x02);
    derLen(&mut out, body.len());
    out.extend_from_slice(&body);
    return out;
}
fn derLen(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
        return;
    }
    let mut tmp: Vec<u8> = Vec::new();
    let mut v = n;
    while v > 0 {
        tmp.insert(0, (v & 0xff) as u8);
        v >>= 8;
    }
    out.push(0x80 | tmp.len() as u8);
    out.extend_from_slice(&tmp);
}
fn mkSig(r: &Int, s_: &Int) -> slice<byte> {
    let mut body = derInt(r);
    body.extend_from_slice(&derInt(s_));
    let mut out: Vec<u8> = Vec::new();
    out.push(0x30);
    derLen(&mut out, body.len());
    out.extend_from_slice(&body);
    return bs(out);
}
// Pull R and S back out of a DER signature. Only the shapes SignASN1
// produces are handled — this is a probe helper, not a parser.
fn splitSig(sig: &slice<byte>) -> (Int, Int) {
    let v = sig.to_vec();
    let mut i = 2usize;
    if v[1] & 0x80 != 0 {
        i = 2 + (v[1] & 0x7f) as usize;
    }
    let mut out: Vec<Int> = Vec::new();
    for _ in 0..2 {
        let len = v[i + 1] as usize;
        let start = i + 2;
        let mut n = Int::default();
        n.SetBytes(bs(v[start..start + len].to_vec()));
        out.push(n);
        i = start + len;
    }
    let b = out.pop().unwrap();
    let a = out.pop().unwrap();
    return (a, b);
}
fn padTo(b: &[u8], n: usize) -> Vec<u8> {
    if b.len() >= n {
        return b.to_vec();
    }
    let mut out = alloc::vec![0u8; n];
    out[n - b.len()..].copy_from_slice(b);
    return out;
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let curve = elliptic::P256();
    let n = curve.Params().N.clone();
    let mut d = Int::default();
    d.SetString(
        s("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
        16,
    );
    let dm = d.clone();
    d.Mod(&dm, &n);
    let (x, y) = curve.ScalarBaseMult(&d.Bytes());
    let pub_ = ecdsa::PublicKey {
        Curve: curve,
        X: x.clone(),
        Y: y.clone(),
    };
    let priv_ = ecdsa::PrivateKey {
        PublicKey: ecdsa::PublicKey {
            Curve: curve,
            X: x.clone(),
            Y: y.clone(),
        },
        D: d.clone(),
    };
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "key d=%s x=%s y=%s",
            d.Text(16),
            pub_.X.Text(16),
            pub_.Y.Text(16)
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "key onCurve=%v bitsize=%d",
            curve.IsOnCurve(&pub_.X, &pub_.Y),
            curve.Params().BitSize
        ),
    );
    let digest = sha256::Sum256(bs(b"ecdsa reference message".to_vec()));
    let hash = bs(digest.to_vec());
    chk(&mut failed, &mut ln, fmt::Sprintf!("hash %s", hx(&hash)));
    let (sig, err) = ecdsa::SignASN1(&mut rand::Reader, &priv_, &hash);
    if err != goish::nil {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("sign-err=%q", err.Error()),
        );
        return;
    }
    let (r, s_) = splitSig(&sig);
    let zero = newInt(0);
    let one = newInt(1);
    let rInRange = r.Sign() > 0 && r.Cmp(&n) < 0;
    let sInRange = s_.Sign() > 0 && s_.Cmp(&n) < 0;
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "roundtrip verify=%v r-in-range=%v s-in-range=%v",
            ecdsa::VerifyASN1(&pub_, &hash, &sig),
            rInRange,
            sInRange
        ),
    );
    let mut nMinusS = Int::default();
    nMinusS.Sub(&n, &s_);
    let mut nPlus1 = Int::default();
    nPlus1.Add(&n, &one);
    let mut rNeg = Int::default();
    rNeg.Neg(&r);
    let mut sNeg = Int::default();
    sNeg.Neg(&s_);
    let mut rPlusN = Int::default();
    rPlusN.Add(&r, &n);
    let mut sPlusN = Int::default();
    sPlusN.Add(&s_, &n);
    let cases: [(&str, &Int, &Int); 16] = [
        ("valid", &r, &s_),
        ("malleable-n-minus-s", &r, &nMinusS),
        ("r-zero", &zero, &s_),
        ("s-zero", &r, &zero),
        ("both-zero", &zero, &zero),
        ("r-n", &n, &s_),
        ("s-n", &r, &n),
        ("r-n-plus-1", &nPlus1, &s_),
        ("s-n-plus-1", &r, &nPlus1),
        ("r-negative", &rNeg, &s_),
        ("s-negative", &r, &sNeg),
        ("r-one", &one, &s_),
        ("s-one", &r, &one),
        ("swapped", &s_, &r),
        ("r-plus-n", &rPlusN, &s_),
        ("s-plus-n", &r, &sPlusN),
    ];
    for (name, a, b) in cases.iter() {
        let m = mkSig(a, b);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "range %-20s -> verify=%v",
                s(name),
                ecdsa::VerifyASN1(&pub_, &hash, &m)
            ),
        );
    }
    let sv = sig.to_vec();
    let mut trailingByte = sv.clone();
    trailingByte.push(0x00);
    let mut trailingJunk = sv.clone();
    trailingJunk.push(0xde);
    trailingJunk.push(0xad);
    let mut retagged = sv.clone();
    retagged[0] = 0x31;
    let mut rawConcat = padTo(&r.Bytes().to_vec(), 32);
    rawConcat.extend_from_slice(&padTo(&s_.Bytes().to_vec(), 32));
    let mut indef: Vec<u8> = alloc::vec![0x30, 0x80];
    indef.extend_from_slice(&sv[2..]);
    let mut nonMin: Vec<u8> = alloc::vec![0x30, 0x81, (sv.len() - 2) as u8];
    nonMin.extend_from_slice(&sv[2..]);
    let ders: [(&str, slice<byte>); 14] = [
        ("nil", bs(Vec::new())),
        ("empty", bs(Vec::new())),
        ("truncated-half", bs(sv[..sv.len() / 2].to_vec())),
        ("truncated-last", bs(sv[..sv.len() - 1].to_vec())),
        ("trailing-byte", bs(trailingByte)),
        ("trailing-junk", bs(trailingJunk)),
        ("wrong-outer-tag", bs(retagged)),
        ("raw-concat", bs(rawConcat)),
        ("all-zero-70", bs(alloc::vec![0u8; 70])),
        ("just-sequence", bs(alloc::vec![0x30, 0x00])),
        ("one-integer", bs(alloc::vec![0x30, 0x03, 0x02, 0x01, 0x01])),
        (
            "three-integers",
            bs(alloc::vec![
                0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03
            ]),
        ),
        ("indefinite-length", bs(indef)),
        ("non-minimal-length", bs(nonMin)),
    ];
    for (name, m) in ders.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "der %-20s -> verify=%v",
                s(name),
                ecdsa::VerifyASN1(&pub_, &hash, m)
            ),
        );
    }
    let hv = hash.to_vec();
    let mut long48 = hv.clone();
    long48.extend_from_slice(&hv[..16]);
    let mut long64 = hv.clone();
    long64.extend_from_slice(&hv);
    let mut long33 = hv.clone();
    long33.push(0x00);
    let hashes: [(&str, slice<byte>); 7] = [
        ("exact-32", hash.clone()),
        ("short-16", bs(hv[..16].to_vec())),
        ("short-1", bs(hv[..1].to_vec())),
        ("empty", bs(Vec::new())),
        ("long-48", bs(long48)),
        ("long-64", bs(long64)),
        ("prefix-match-33", bs(long33)),
    ];
    for (name, h) in hashes.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "hash %-14s -> verify=%v len=%d",
                s(name),
                ecdsa::VerifyASN1(&pub_, h, &sig),
                h.Len()
            ),
        );
    }
    {
        let mut longh = hv.clone();
        longh.push(0xff);
        let (s2, e2) = ecdsa::SignASN1(&mut rand::Reader, &priv_, &bs(longh));
        if e2 != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("trunc sign-err=%q", e2.Error()),
            );
        } else {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "trunc long-sig-verifies-short=%v",
                    ecdsa::VerifyASN1(&pub_, &hash, &s2)
                ),
            );
        }
    }
    {
        let mut d2 = Int::default();
        d2.Add(&d, &one);
        let (x2, y2) = curve.ScalarBaseMult(&d2.Bytes());
        let p2 = ecdsa::PublicKey {
            Curve: curve,
            X: x2,
            Y: y2,
        };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "key wrong-key-verify=%v",
                ecdsa::VerifyASN1(&p2, &hash, &sig)
            ),
        );
        let mut offx = Int::default();
        offx.Add(&pub_.X, &one);
        let off = ecdsa::PublicKey {
            Curve: curve,
            X: offx,
            Y: pub_.Y.clone(),
        };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "key off-curve=%v off-curve-verify=%v",
                curve.IsOnCurve(&off.X, &off.Y),
                ecdsa::VerifyASN1(&off, &hash, &sig)
            ),
        );
    }
    {
        let (a, _) = ecdsa::SignASN1(&mut rand::Reader, &priv_, &hash);
        let (b, _) = ecdsa::SignASN1(&mut rand::Reader, &priv_, &hash);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "nonce differ=%v both-verify=%v",
                hx(&a) != hx(&b),
                ecdsa::VerifyASN1(&pub_, &hash, &a) && ecdsa::VerifyASN1(&pub_, &hash, &b)
            ),
        );
    }
    let curves: [(&str, &'static (dyn elliptic::Curve + Send + Sync)); 4] = [
        ("P224", elliptic::P224()),
        ("P256", elliptic::P256()),
        ("P384", elliptic::P384()),
        ("P521", elliptic::P521()),
    ];
    for (name, crv) in curves.iter() {
        let (k, gerr) = ecdsa::GenerateKey(*crv, &mut rand::Reader);
        if gerr != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("curve %-5s -> genkey-err=%q", s(name), gerr.Error()),
            );
            continue;
        }
        let (sg, serr) = ecdsa::SignASN1(&mut rand::Reader, &k, &hash);
        if serr != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("curve %-5s -> sign-err=%q", s(name), serr.Error()),
            );
            continue;
        }
        let mut badv = sg.to_vec();
        badv.push(0x00);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "curve %-5s -> bits=%-3d verify=%v tampered=%v",
                s(name),
                crv.Params().BitSize,
                ecdsa::VerifyASN1(&k.PublicKey, &hash, &sg),
                ecdsa::VerifyASN1(&k.PublicKey, &hash, &bs(badv))
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
