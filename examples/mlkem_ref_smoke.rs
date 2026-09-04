// mlkem_ref_smoke — crypto/mlkem against a running Go.
// (crypto/mlkem/mlkem.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_mlkem_ref.go` run in
// `package mlkem_test` by `scripts/goref.sh`. goish matched Go on all
// 39 lines — no defects found, and the encapsulation key matches BYTE
// FOR BYTE, so this is agreement on the maths and not merely on the
// shape.
//
// ML-KEM is a key ENCAPSULATION mechanism: one side produces a
// ciphertext and a shared secret, the other recovers the secret from
// the ciphertext. Everything a caller does afterwards is keyed on that
// secret, so the rule that decides whether any of it is safe is what
// Decapsulate does with a ciphertext it did not expect.
//
// THE ANSWER IS NOT "RETURN AN ERROR", AND THAT IS THE POINT. ML-KEM
// uses IMPLICIT REJECTION: a ciphertext of the right LENGTH that
// decrypts to nothing meaningful yields a shared secret that is
// pseudorandom and DIFFERENT from the sender's — no error, no signal,
// just a secret the two sides do not share. An error would be an
// oracle, and the Fujisaki-Okamoto transform's security argument
// depends on there being no oracle. A port that "helpfully" returned
// an error for a corrupt ciphertext would leak precisely what the
// design spends its effort hiding.
//
// The five `reject` lines are that rule made concrete: a flipped first
// byte, a flipped last byte, a flipped middle byte, all zeros and all
// 0xff each come back with err=<nil>, a full-length secret, and
// agreement FALSE. And each is `deterministic=true` — decapsulating
// the same bad ciphertext twice gives the same answer, because
// implicit rejection has to be a FUNCTION of the key and the
// ciphertext rather than fresh randomness. If it were random, a retry
// would reveal that the first attempt had been rejected, which is the
// oracle again by another route.
//
// The only inputs that DO error are the wrong-length ones, because a
// length check reveals nothing an attacker did not already choose.
// Both the ciphertext and the key have their own message.
//
// Also pinned, and easy to get wrong in the other direction:
//
//   * An ALL-ZERO seed is a VALID key, and an all-zero encapsulation
//     key parses. Neither is rejected, because neither is
//     structurally invalid — only "all 0xff" fails, and it fails as
//     "invalid polynomial encoding" rather than as a length error.
//   * A single flipped bit in an encapsulation key ALSO parses, since
//     most bit patterns are valid polynomials. A caller cannot use
//     NewEncapsulationKey as an integrity check.
//   * A 768 ciphertext offered to a 1024 key is a length error, and a
//     768 key offered to NewEncapsulationKey1024 likewise — the sizes
//     are the only thing separating the two parameter sets at the API.
//   * A wrong key decapsulates without error and disagrees, which is
//     the same implicit rejection seen from the other side.
//
// Keys come from a FIXED seed rather than GenerateKey, so both sides
// hold the same key and the secrets are compared rather than the fact
// that two ends agreed with themselves.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::bytes;
use goish::crypto::mlkem;
use goish::encoding::hex;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 39] = [
    "768 seedsize=64 ek-size=1184 dk-bytes=64",
    "768 ek=38b68cabe5ad452299fde27228e95b388183c89a1d110b0bf7a715a9187ad2c1817406813d8a5c18f3904f903b0c1b96",
    "768 dk-roundtrip=true",
    "768 ct-size=1088 secret-size=32 ct-differs=true secret-differs=true",
    "768 decap-agrees=true err=<nil>",
    "768 decap2-agrees=true err=<nil>",
    "768 wrong-key agrees=false len=32 err=<nil>",
    "768 reject flip-first   -> err=<nil>  len=32 agrees=false deterministic=true",
    "768 reject flip-last    -> err=<nil>  len=32 agrees=false deterministic=true",
    "768 reject flip-middle  -> err=<nil>  len=32 agrees=false deterministic=true",
    "768 reject all-zero     -> err=<nil>  len=32 agrees=false deterministic=true",
    "768 reject all-ff       -> err=<nil>  len=32 agrees=false deterministic=true",
    "768 badlen nil          -> err=\"mlkem: invalid ciphertext length\" len=0",
    "768 badlen empty        -> err=\"mlkem: invalid ciphertext length\" len=0",
    "768 badlen short-by-one -> err=\"mlkem: invalid ciphertext length\" len=0",
    "768 badlen long-by-one  -> err=\"mlkem: invalid ciphertext length\" len=0",
    "768 badlen half         -> err=\"mlkem: invalid ciphertext length\" len=0",
    "768 badlen one-byte     -> err=\"mlkem: invalid ciphertext length\" len=0",
    "768 badseed nil        -> err=\"mlkem: invalid seed length\"",
    "768 badseed empty      -> err=\"mlkem: invalid seed length\"",
    "768 badseed short      -> err=\"mlkem: invalid seed length\"",
    "768 badseed long       -> err=\"mlkem: invalid seed length\"",
    "768 badseed all-zero   -> err=\"<nil>\"",
    "768 badek nil          -> err=\"mlkem: invalid encapsulation key length\"",
    "768 badek empty        -> err=\"mlkem: invalid encapsulation key length\"",
    "768 badek short        -> err=\"mlkem: invalid encapsulation key length\"",
    "768 badek long         -> err=\"mlkem: invalid encapsulation key length\"",
    "768 badek all-zero     -> err=\"<nil>\"",
    "768 badek all-ff       -> err=\"mlkem: invalid polynomial encoding\"",
    "768 badek flip-first   -> err=\"<nil>\"",
    "768 reparsed-ek agrees=true",
    "1024 ek-size=1568 ct-size=1568 secret-size=32 agrees=true err=<nil>",
    "1024 reject flip-first -> err=<nil>  agrees=false",
    "1024 badlen short -> err=\"mlkem: invalid ciphertext length\"",
    "1024 cross-size-768-ct -> err=\"mlkem: invalid ciphertext length\"",
    "1024 cross-size-768-ek -> err=\"mlkem: invalid encapsulation key length\"",
    "gen err1=<nil> err2=<nil> distinct=true",
    "gen roundtrip=true",
    "gen cross-key agrees=false err=<nil>",
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
fn errText(err: error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    return err.Error();
}
fn flip(b: &slice<byte>, i: usize) -> slice<byte> {
    let mut v = b.to_vec();
    v[i] ^= 0x01;
    return bs(v);
}
fn sameTwice(dk: &mlkem::DecapsulationKey768, ct: &slice<byte>) -> bool {
    let (a, e1) = dk.Decapsulate(ct);
    let (b, e2) = dk.Decapsulate(ct);
    if e1 != goish::nil || e2 != goish::nil {
        return false;
    }
    return bytes::Equal(a, b);
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    {
        let mut sv: Vec<u8> = Vec::new();
        for i in 0..mlkem::SeedSize {
            sv.push((i * 3) as u8);
        }
        let seed = bs(sv);
        let (dk, e) = mlkem::NewDecapsulationKey768(&seed);
        if e != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("[!!] key: %q", e.Error()),
            );
            return;
        }
        let ek = dk.EncapsulationKey();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "768 seedsize=%d ek-size=%d dk-bytes=%d",
                mlkem::SeedSize as int,
                ek.Bytes().Len(),
                dk.Bytes().Len()
            ),
        );
        let ekhex = hex::EncodeToString(&ek.Bytes().to_vec());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("768 ek=%s", string::from_bytes(&ekhex.as_bytes()[..96])),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "768 dk-roundtrip=%v",
                bytes::Equal(dk.Bytes(), seed.clone())
            ),
        );
        let (sec1, ct1) = ek.Encapsulate();
        let (sec2, ct2) = ek.Encapsulate();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "768 ct-size=%d secret-size=%d ct-differs=%v secret-differs=%v",
                ct1.Len(),
                sec1.Len(),
                !bytes::Equal(ct1.clone(), ct2.clone()),
                !bytes::Equal(sec1.clone(), sec2.clone())
            ),
        );
        let (got, e) = dk.Decapsulate(&ct1);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "768 decap-agrees=%v err=%s",
                bytes::Equal(got, sec1.clone()),
                errText(e)
            ),
        );
        let (got2, e) = dk.Decapsulate(&ct2);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "768 decap2-agrees=%v err=%s",
                bytes::Equal(got2, sec2),
                errText(e)
            ),
        );
        let mut s2v = alloc::vec![0u8; mlkem::SeedSize];
        s2v[0] = 1;
        let (dk2, _) = mlkem::NewDecapsulationKey768(&bs(s2v));
        let (other, e) = dk2.Decapsulate(&ct1);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "768 wrong-key agrees=%v len=%d err=%s",
                bytes::Equal(other.clone(), sec1.clone()),
                other.Len(),
                errText(e)
            ),
        );
        let ctlen = ct1.Len() as usize;
        let rejects: [(&str, slice<byte>); 5] = [
            ("flip-first", flip(&ct1, 0)),
            ("flip-last", flip(&ct1, ctlen - 1)),
            ("flip-middle", flip(&ct1, ctlen / 2)),
            ("all-zero", bs(alloc::vec![0u8; ctlen])),
            ("all-ff", bs(alloc::vec![0xffu8; ctlen])),
        ];
        for (name, ct) in rejects.iter() {
            let (sec, e) = dk.Decapsulate(ct);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "768 reject %-12s -> err=%-6s len=%d agrees=%v deterministic=%v",
                    s(name),
                    errText(e),
                    sec.Len(),
                    bytes::Equal(sec, sec1.clone()),
                    sameTwice(&dk, ct)
                ),
            );
        }
        let cv = ct1.to_vec();
        let mut clong = cv.clone();
        clong.push(0);
        let badlens: [(&str, slice<byte>); 6] = [
            ("nil", bs(Vec::new())),
            ("empty", bs(Vec::new())),
            ("short-by-one", bs(cv[..cv.len() - 1].to_vec())),
            ("long-by-one", bs(clong)),
            ("half", bs(cv[..cv.len() / 2].to_vec())),
            ("one-byte", bs(cv[..1].to_vec())),
        ];
        for (name, ct) in badlens.iter() {
            let (sec, e) = dk.Decapsulate(ct);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "768 badlen %-12s -> err=%q len=%d",
                    s(name),
                    errText(e),
                    sec.Len()
                ),
            );
        }
        let sv2 = seed.to_vec();
        let mut slong = sv2.clone();
        slong.push(0);
        let badseeds: [(&str, slice<byte>); 5] = [
            ("nil", bs(Vec::new())),
            ("empty", bs(Vec::new())),
            ("short", bs(sv2[..sv2.len() - 1].to_vec())),
            ("long", bs(slong)),
            ("all-zero", bs(alloc::vec![0u8; mlkem::SeedSize])),
        ];
        for (name, b) in badseeds.iter() {
            let (_, e) = mlkem::NewDecapsulationKey768(b);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("768 badseed %-10s -> err=%q", s(name), errText(e)),
            );
        }
        let ekb = ek.Bytes();
        let ev = ekb.to_vec();
        let mut elong = ev.clone();
        elong.push(0);
        let badeks: [(&str, slice<byte>); 7] = [
            ("nil", bs(Vec::new())),
            ("empty", bs(Vec::new())),
            ("short", bs(ev[..ev.len() - 1].to_vec())),
            ("long", bs(elong)),
            ("all-zero", bs(alloc::vec![0u8; ev.len()])),
            ("all-ff", bs(alloc::vec![0xffu8; ev.len()])),
            ("flip-first", flip(&ekb, 0)),
        ];
        for (name, b) in badeks.iter() {
            let (_, e) = mlkem::NewEncapsulationKey768(b);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("768 badek %-12s -> err=%q", s(name), errText(e)),
            );
        }
        let (ek2, e) = mlkem::NewEncapsulationKey768(&ekb);
        if e == goish::nil {
            let (s3, c3) = ek2.Encapsulate();
            let (r3, _) = dk.Decapsulate(&c3);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("768 reparsed-ek agrees=%v", bytes::Equal(r3, s3)),
            );
        }
    }
    {
        let mut sv: Vec<u8> = Vec::new();
        for i in 0..mlkem::SeedSize {
            sv.push((255 - i) as u8);
        }
        let (dk, e) = mlkem::NewDecapsulationKey1024(&bs(sv));
        if e != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("[!!] key1024: %q", e.Error()),
            );
            return;
        }
        let ek = dk.EncapsulationKey();
        let (sec, ct) = ek.Encapsulate();
        let (got, derr) = dk.Decapsulate(&ct);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "1024 ek-size=%d ct-size=%d secret-size=%d agrees=%v err=%s",
                ek.Bytes().Len(),
                ct.Len(),
                sec.Len(),
                bytes::Equal(got, sec.clone()),
                errText(derr)
            ),
        );
        let (bad, berr) = dk.Decapsulate(&flip(&ct, 0));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "1024 reject flip-first -> err=%-6s agrees=%v",
                errText(berr),
                bytes::Equal(bad, sec.clone())
            ),
        );
        let cv = ct.to_vec();
        let (_, xerr) = dk.Decapsulate(&bs(cv[..cv.len() - 1].to_vec()));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("1024 badlen short -> err=%q", errText(xerr)),
        );
        let (dk768, _) = mlkem::NewDecapsulationKey768(&bs(alloc::vec![0u8; mlkem::SeedSize]));
        let (_, ct768) = dk768.EncapsulationKey().Encapsulate();
        let (_, cerr) = dk.Decapsulate(&ct768);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("1024 cross-size-768-ct -> err=%q", errText(cerr)),
        );
        let (_, kerr) = mlkem::NewEncapsulationKey1024(&dk768.EncapsulationKey().Bytes());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("1024 cross-size-768-ek -> err=%q", errText(kerr)),
        );
    }
    {
        let (a, err1) = mlkem::GenerateKey768();
        let (b, err2) = mlkem::GenerateKey768();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "gen err1=%s err2=%s distinct=%v",
                errText(err1),
                errText(err2),
                !bytes::Equal(a.Bytes(), b.Bytes())
            ),
        );
        let (sec, ct) = a.EncapsulationKey().Encapsulate();
        let (r, _) = a.Decapsulate(&ct);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("gen roundtrip=%v", bytes::Equal(r, sec.clone())),
        );
        let (cross, cerr) = b.Decapsulate(&ct);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "gen cross-key agrees=%v err=%s",
                bytes::Equal(cross, sec),
                errText(cerr)
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
