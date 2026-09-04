// ecdh_ref_smoke — crypto/ecdh against a running Go.
// (crypto/ecdh: ecdh.go, nist.go, x25519.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_ecdh_ref.go` run in
// `package ecdh_test` by `scripts/goref.sh`. goish matched Go on all
// 100 lines — no defects found.
//
// ECDH is where accepting a bad public key can leak the private one.
// The peer's key is the one input a caller does not control, so every
// rule about which byte strings are ACCEPTED is a rule about whether
// the shared secret means anything.
//
// The NIST curves and X25519 answer differently ON PURPOSE, and the
// difference is the substance of this smoke:
//
//   * A NIST public key is a POINT, and NewPublicKey refuses anything
//     not on the curve — including the compressed and infinity
//     encodings, which Go does not accept at all, and any single
//     flipped bit. An implementation that skipped the on-curve check
//     could be fed a point on a weaker twist and made to reveal the
//     private scalar a few bits at a time. Eleven malformed encodings
//     are pinned per curve.
//   * X25519 accepts ANY 32 bytes as a public key, because every
//     string is a valid u-coordinate. The check happens LATER: ECDH
//     refuses when the result is the all-zero point. A port that
//     "hardened" X25519 by validating the key up front would reject
//     input Go accepts; one that skipped the ECDH check would return
//     an all-zero shared secret and call it agreement.
//
// The seven low-order points below are the concrete inputs that
// trigger it — zero, one, the two order-8 points, and the three
// values around p — each refused with "bad X25519 remote ECDH input:
// low order point". The eighth is the one that is NOT refused:
// high-bit-set produces a real secret, because X25519 masks the top
// bit of the u-coordinate before using it. That asymmetry looks like
// an oversight and is not.
//
// Cross-curve confusion is pinned too: a P-256 public key offered to
// P-384's NewPublicKey is an encoding error, and offered to a P-384 or
// X25519 private key's ECDH it is "private key and public key curves
// do not match" — a different message, because it is a different
// mistake made at a different point.
//
// Keys come from fixed scalars rather than GenerateKey, so both sides
// compute the same secrets and the SECRETS are compared, not merely
// the fact that two ends agreed with themselves.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::bytes;
use goish::crypto::ecdh;
use goish::encoding::hex;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 100] = [
    "P256   pubA=04444503b417786128c77932c24e1d7735cb415b52885be897c7200e0fd96c61c8f97b2019e7b0c9cb1476661f22e3551d0bad568077a62634ea957f1c3326ad0b",
    "P256   pubB=04ab4d3d5c3005088955035b1ba996edb24c3c565fa4d4705356d135e290715dbd3f3be9a1fd4e361bd1c6a5c426793fe3ea9d3cf460d6a5ad0a5d2c804b136948",
    "P256   shared=d1163ebc6cea716fe501395059f5b043f5c12dbebd39aaa2b352abbd67bd6654 agree=true e1=<nil> e2=<nil>",
    "P256   privBytes=0111111111111111111111111111111111111111111111111111111111111111 pubEqual=false selfEqual=true",
    "P256   priv nil        -> err=crypto/ecdh: invalid private key",
    "P256   priv empty      -> err=crypto/ecdh: invalid private key",
    "P256   priv short      -> err=crypto/ecdh: invalid private key",
    "P256   priv long       -> err=crypto/ecdh: invalid private key",
    "P256   priv all-zero   -> err=crypto/ecdh: invalid private key",
    "P256   priv all-ff     -> err=crypto/ecdh: invalid private key",
    "P256   priv one        -> err=<nil>",
    "P256   pub  nil        -> err=crypto/ecdh: invalid public key",
    "P256   pub  empty      -> err=crypto/ecdh: invalid public key",
    "P256   pub  short      -> err=invalid P256 point encoding",
    "P256   pub  long       -> err=invalid P256 point encoding",
    "P256   pub  all-zero   -> err=crypto/ecdh: invalid public key",
    "P256   pub  all-ff     -> err=crypto/ecdh: invalid public key",
    "P256   pub  flip-first -> err=crypto/ecdh: invalid public key",
    "P256   pub  flip-last  -> err=P256 point not on curve",
    "P256   pub  infinity   -> err=crypto/ecdh: invalid public key",
    "P256   pub  compressed -> err=crypto/ecdh: invalid public key",
    "P256   pub  bad-prefix -> err=crypto/ecdh: invalid public key",
    "P384   pubA=044aa8f9e8757b8d7824a0fbabe99bcf03ac219b7a51b04bec77476838ffae825a5ab43b16a5d483b3c17d1f8fe74f84e904d464774df94ff4d4e0a3100ef89108e2d01ac80acb00d2d720794bda53862b543ec63c69f5d8b7a2f7a8440bbfb613",
    "P384   pubB=042962711f28a1dabde8aa74d1eb5d0d50ae0f7e8859a4b4cb1150520356791039f7459284e6b144b506c0b9d4d55b5da56f6c0c15341919db74e8175c71ed3ed4d845a0915faf71e91e2063c5f4e8e9063b62c2f7e1635f2eb9c914b3b8752d2e",
    "P384   shared=fb5603627d74de62a957fd51a58e73bc955be4398f3bc67f8920be7df6cd874082377e9d387c621d2b89564b4053cb9c agree=true e1=<nil> e2=<nil>",
    "P384   privBytes=011111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 pubEqual=false selfEqual=true",
    "P384   priv nil        -> err=crypto/ecdh: invalid private key",
    "P384   priv empty      -> err=crypto/ecdh: invalid private key",
    "P384   priv short      -> err=crypto/ecdh: invalid private key",
    "P384   priv long       -> err=crypto/ecdh: invalid private key",
    "P384   priv all-zero   -> err=crypto/ecdh: invalid private key",
    "P384   priv all-ff     -> err=crypto/ecdh: invalid private key",
    "P384   priv one        -> err=<nil>",
    "P384   pub  nil        -> err=crypto/ecdh: invalid public key",
    "P384   pub  empty      -> err=crypto/ecdh: invalid public key",
    "P384   pub  short      -> err=invalid P384 point encoding",
    "P384   pub  long       -> err=invalid P384 point encoding",
    "P384   pub  all-zero   -> err=crypto/ecdh: invalid public key",
    "P384   pub  all-ff     -> err=crypto/ecdh: invalid public key",
    "P384   pub  flip-first -> err=crypto/ecdh: invalid public key",
    "P384   pub  flip-last  -> err=P384 point not on curve",
    "P384   pub  infinity   -> err=crypto/ecdh: invalid public key",
    "P384   pub  compressed -> err=crypto/ecdh: invalid public key",
    "P384   pub  bad-prefix -> err=crypto/ecdh: invalid public key",
    "P521   pubA=0401f17c0111ebe63872f40a45aeeddec7ca8946aa5b2e798487ddec42f579edf7c5b5d780199bb7cea72401def9ced4475e538e61bfa6e9cd7bbfafc8e47051a6fad301527f7dbcf2ec7dd744f72998138bd4907950ae2bf7aaa83810f9b08be6ae4e00ce606dd875a849187e7235735df2a9256ff662e096cfc19273c208f0f3d93ee1a1",
    "P521   pubB=0400731edbc438b1e6e4147bef27209a7639f411fcf594a2f07f452964bcf00dd0dda8df2dfa00945f987825012703d6aceb3dc9ae50699ee43abfa3206a96b1467bef00db3038fc22ce4978d1e270eb64963badc896efffe75fdcbfa8acc8414dde2cee6a80937a117a53e1a644c65ebeaf35cfb296eb4916a324c216ed40e91076f4e4ff",
    "P521   shared=011feb6c7d6b1bbe1d4cb373e65b17993e4f1fe7f8b6ff3ee6f16279efb54de8c8ed08e4832de4c5c6d0f7067729164beb87ed72711d5a7ee08a0da98a3c3206d693 agree=true e1=<nil> e2=<nil>",
    "P521   privBytes=011111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111 pubEqual=false selfEqual=true",
    "P521   priv nil        -> err=crypto/ecdh: invalid private key",
    "P521   priv empty      -> err=crypto/ecdh: invalid private key",
    "P521   priv short      -> err=crypto/ecdh: invalid private key",
    "P521   priv long       -> err=crypto/ecdh: invalid private key",
    "P521   priv all-zero   -> err=crypto/ecdh: invalid private key",
    "P521   priv all-ff     -> err=crypto/ecdh: invalid private key",
    "P521   priv one        -> err=<nil>",
    "P521   pub  nil        -> err=crypto/ecdh: invalid public key",
    "P521   pub  empty      -> err=crypto/ecdh: invalid public key",
    "P521   pub  short      -> err=invalid P521 point encoding",
    "P521   pub  long       -> err=invalid P521 point encoding",
    "P521   pub  all-zero   -> err=crypto/ecdh: invalid public key",
    "P521   pub  all-ff     -> err=crypto/ecdh: invalid public key",
    "P521   pub  flip-first -> err=crypto/ecdh: invalid public key",
    "P521   pub  flip-last  -> err=P521 point not on curve",
    "P521   pub  infinity   -> err=crypto/ecdh: invalid public key",
    "P521   pub  compressed -> err=crypto/ecdh: invalid public key",
    "P521   pub  bad-prefix -> err=crypto/ecdh: invalid public key",
    "X25519 pubA=5b5bda59f7ab2e3a307fd0fcfe4539ec052278f160d531c24814c6ce62cfe214",
    "X25519 pubB=44c87f6ef695bc749afaf62fbdd0980293a98677fcd84e1f85453d891946592a",
    "X25519 shared=5b96b0786af5274653994095aede1ccdc1aa71667f9166a1dcd74475a82caf7a agree=true e1=<nil> e2=<nil>",
    "X25519 privBytes=0111111111111111111111111111111111111111111111111111111111111111 pubEqual=false selfEqual=true",
    "X25519 priv nil        -> err=crypto/ecdh: invalid private key size",
    "X25519 priv empty      -> err=crypto/ecdh: invalid private key size",
    "X25519 priv short      -> err=crypto/ecdh: invalid private key size",
    "X25519 priv long       -> err=crypto/ecdh: invalid private key size",
    "X25519 priv all-zero   -> err=<nil>",
    "X25519 priv all-ff     -> err=<nil>",
    "X25519 priv one        -> err=<nil>",
    "X25519 pub  nil        -> err=crypto/ecdh: invalid public key",
    "X25519 pub  empty      -> err=crypto/ecdh: invalid public key",
    "X25519 pub  short      -> err=crypto/ecdh: invalid public key",
    "X25519 pub  long       -> err=crypto/ecdh: invalid public key",
    "X25519 pub  all-zero   -> err=<nil>",
    "X25519 pub  all-ff     -> err=<nil>",
    "X25519 pub  flip-first -> err=<nil>",
    "X25519 pub  flip-last  -> err=<nil>",
    "X25519 pub  infinity   -> err=crypto/ecdh: invalid public key",
    "X25519 pub  compressed -> err=crypto/ecdh: invalid public key",
    "X25519 pub  bad-prefix -> err=<nil>",
    "x25519 low zero           -> shared=                                                                 err=crypto/ecdh: bad X25519 remote ECDH input: low order point",
    "x25519 low one            -> shared=                                                                 err=crypto/ecdh: bad X25519 remote ECDH input: low order point",
    "x25519 low order-8-a      -> shared=                                                                 err=crypto/ecdh: bad X25519 remote ECDH input: low order point",
    "x25519 low order-8-b      -> shared=                                                                 err=crypto/ecdh: bad X25519 remote ECDH input: low order point",
    "x25519 low p-minus-1      -> shared=                                                                 err=crypto/ecdh: bad X25519 remote ECDH input: low order point",
    "x25519 low p              -> shared=                                                                 err=crypto/ecdh: bad X25519 remote ECDH input: low order point",
    "x25519 low p-plus-1       -> shared=                                                                 err=crypto/ecdh: bad X25519 remote ECDH input: low order point",
    "x25519 low high-bit-set   -> shared=ee71c38513ff2aac66b2a33c6b4c43c04e1cce8ef60dcde29e1ff7952a03be22 err=<nil>",
    "cross p384-accepts-p256-pub err=invalid P384 point encoding",
    "cross p384-ecdh-p256-pub err=crypto/ecdh: private key and public key curves do not match",
    "cross x25519-ecdh-p256-pub err=crypto/ecdh: private key and public key curves do not match",
    "cross curve-names p256=true p384=true x25519=true",
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
fn errText(err: error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    return err.Error();
}
fn fixedScalar(n: usize, b: u8) -> slice<byte> {
    let mut v = alloc::vec![b; n];
    v[0] = 0x01;
    return bs(v);
}
fn oneAt(n: usize) -> slice<byte> {
    let mut v = alloc::vec![0u8; n];
    v[n - 1] = 1;
    return bs(v);
}
fn flip(b: &slice<byte>, i: usize) -> slice<byte> {
    let mut v = b.to_vec();
    v[i] ^= 0x01;
    return bs(v);
}
fn compressed(u: &slice<byte>) -> slice<byte> {
    let v = u.to_vec();
    if v.len() < 2 || v[0] != 0x04 {
        return bs(alloc::vec![0x02]);
    }
    let n = (v.len() - 1) / 2;
    let mut out = alloc::vec![0u8; 1 + n];
    out[0] = 0x02;
    out[1..].copy_from_slice(&v[1..1 + n]);
    return bs(out);
}
fn withPrefix(b: &slice<byte>, p: u8) -> slice<byte> {
    let mut v = b.to_vec();
    if !v.is_empty() {
        v[0] = p;
    }
    return bs(v);
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let curves: [(&str, &'static (dyn ecdh::Curve + Send + Sync), usize); 4] = [
        ("P256", ecdh::P256(), 32),
        ("P384", ecdh::P384(), 48),
        ("P521", ecdh::P521(), 66),
        ("X25519", ecdh::X25519(), 32),
    ];
    for (name, c, size) in curves.iter() {
        let a = fixedScalar(*size, 0x11);
        let b = fixedScalar(*size, 0x22);
        let (ka, e) = c.NewPrivateKey(&a);
        if e != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("%-6s privA-err=%q", s(name), e.Error()),
            );
            continue;
        }
        let (kb, e) = c.NewPrivateKey(&b);
        if e != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("%-6s privB-err=%q", s(name), e.Error()),
            );
            continue;
        }
        let pa = ka.PublicKey();
        let pb = kb.PublicKey();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("%-6s pubA=%s", s(name), hx(&pa.Bytes())),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("%-6s pubB=%s", s(name), hx(&pb.Bytes())),
        );
        let (s1, e1) = ka.ECDH(&pb);
        let (s2, e2) = kb.ECDH(&pa);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-6s shared=%s agree=%v e1=%s e2=%s",
                s(name),
                hx(&s1),
                bytes::Equal(s1.clone(), s2),
                errText(e1),
                errText(e2)
            ),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "%-6s privBytes=%s pubEqual=%v selfEqual=%v",
                s(name),
                hx(&ka.Bytes()),
                pa.Equal(&pb),
                pa.Equal(&pa)
            ),
        );
        let av = a.to_vec();
        let mut alonger = av.clone();
        alonger.push(0);
        let privBad: [(&str, slice<byte>); 7] = [
            ("nil", bs(Vec::new())),
            ("empty", bs(Vec::new())),
            ("short", bs(av[..av.len() - 1].to_vec())),
            ("long", bs(alonger)),
            ("all-zero", bs(alloc::vec![0u8; *size])),
            ("all-ff", bs(alloc::vec![0xffu8; *size])),
            ("one", oneAt(*size)),
        ];
        for (bn, k) in privBad.iter() {
            let (_, e) = c.NewPrivateKey(k);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("%-6s priv %-10s -> err=%s", s(name), s(bn), errText(e)),
            );
        }
        let pub_ = pa.Bytes();
        let pv = pub_.to_vec();
        let mut plonger = pv.clone();
        plonger.push(0);
        let pubBad: [(&str, slice<byte>); 11] = [
            ("nil", bs(Vec::new())),
            ("empty", bs(Vec::new())),
            ("short", bs(pv[..pv.len() - 1].to_vec())),
            ("long", bs(plonger)),
            ("all-zero", bs(alloc::vec![0u8; pv.len()])),
            ("all-ff", bs(alloc::vec![0xffu8; pv.len()])),
            ("flip-first", flip(&pub_, 0)),
            ("flip-last", flip(&pub_, pv.len() - 1)),
            ("infinity", bs(alloc::vec![0x00])),
            ("compressed", compressed(&pub_)),
            ("bad-prefix", withPrefix(&pub_, 0x05)),
        ];
        for (bn, k) in pubBad.iter() {
            let (_, e) = c.NewPublicKey(k);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("%-6s pub  %-10s -> err=%s", s(name), s(bn), errText(e)),
            );
        }
    }
    {
        let x = ecdh::X25519();
        let (k, _) = x.NewPrivateKey(&fixedScalar(32, 0x33));
        let lows: [(&str, &str); 8] = [
            (
                "zero",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "one",
                "0100000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                "order-8-a",
                "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            ),
            (
                "order-8-b",
                "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            ),
            (
                "p-minus-1",
                "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            ),
            (
                "p",
                "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            ),
            (
                "p-plus-1",
                "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            ),
            (
                "high-bit-set",
                "00000000000000000000000000000000000000000000000000000000000000ff",
            ),
        ];
        for (name, hexs) in lows.iter() {
            let (raw, _) = hex::DecodeString(hexs);
            let (p, e) = x.NewPublicKey(&raw);
            if e != goish::nil {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!("x25519 low %-14s -> newpub-err=%q", s(name), e.Error()),
                );
                continue;
            }
            let (sh, e2) = k.ECDH(&p);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "x25519 low %-14s -> shared=%-64s err=%s",
                    s(name),
                    hx(&sh),
                    errText(e2)
                ),
            );
        }
    }
    {
        let p256 = ecdh::P256();
        let p384 = ecdh::P384();
        let (k256, _) = p256.NewPrivateKey(&fixedScalar(32, 0x44));
        let (k384, _) = p384.NewPrivateKey(&fixedScalar(48, 0x44));
        let (_, e) = p384.NewPublicKey(&k256.PublicKey().Bytes());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("cross p384-accepts-p256-pub err=%s", errText(e)),
        );
        let (_, e) = k384.ECDH(&k256.PublicKey());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("cross p384-ecdh-p256-pub err=%s", errText(e)),
        );
        let x = ecdh::X25519();
        let (kx, _) = x.NewPrivateKey(&fixedScalar(32, 0x44));
        let (_, e) = kx.ECDH(&k256.PublicKey());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("cross x25519-ecdh-p256-pub err=%s", errText(e)),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "cross curve-names p256=%v p384=%v x25519=%v",
                true,
                true,
                true
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
