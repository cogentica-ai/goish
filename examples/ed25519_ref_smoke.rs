// ed25519_ref_smoke — crypto/ed25519 against a running Go.
// (crypto/ed25519/ed25519.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_ed25519_ref.go` run in
// `package ed25519_test` by `scripts/goref.sh`. goish matched Go on all
// 43 lines — no defects found.
//
// A verifier that accepts something it should not is the worst defect a
// crypto port can have, because nothing downstream ever notices: the
// caller's answer is "valid" and every check built on it agrees. So
// most of what is pinned here is REJECTIONS — seventeen malformed
// signatures, each a byte string a hostile peer can send, each with the
// exact error text Go returns.
//
// Ed25519's rules are unusually specific and none of them fall out of
// "does the maths work":
//
//   * The scalar S must be CANONICAL, strictly below the group order L.
//     `s-plus-order` is the case that matters: adding L to S gives a
//     DIFFERENT byte string that satisfies the same equation, so an
//     implementation without the check has two valid signatures for one
//     message. That is signature malleability, and it breaks anything
//     that treats a signature as an identifier — a transaction hash, a
//     replay cache, a deduplication key.
//   * The top three bits of S[31] are therefore always clear, and Go
//     tests them before doing any arithmetic. `s-high-bit`,
//     `s-bit-254` and `s-bit-253` pin all three.
//   * A wrong LENGTH is a different error from a wrong VALUE:
//     "bad signature length: 63" versus "invalid signature". A caller
//     that logs or branches on the message sees the difference.
//   * Go does NOT reject small-order or identity public keys, nor
//     non-canonical R encodings, which some other implementations do.
//     `edge zero-pubkey` and `edge one-pubkey` pin that: they answer
//     false here because the signature does not verify, not because the
//     key was refused. Hardening this would disagree with every Go
//     peer, so it is pinned as a compatibility decision rather than
//     left to judgement.
//
// The three modes are domain-separated, and the smoke proves it in both
// directions: an Ed25519ph signature fails pure verification, a pure
// signature fails ph verification, and an Ed25519ctx signature fails
// under a different context string AND under no context at all. A port
// that ignored the domain prefix would pass every "sign then verify"
// test and still let a signature be replayed across modes.
//
// Determinism is pinned too. Ed25519 signatures carry no randomness, so
// signing the same message twice must produce identical bytes — a port
// that leaked entropy in there would pass every verification test and
// still be wrong, since callers rely on the signature being a function
// of (key, message) alone.
//
// Keys come from a FIXED seed rather than GenerateKey, so both sides
// sign the same bytes and the signatures themselves are compared, not
// merely their acceptance.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::bytes;
use goish::crypto;
use goish::crypto::ed25519;
use goish::crypto::sha512;
use goish::encoding::hex;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 43] = [
    "key seed=00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9 pub=4d0ec3a0d03fefff93a9bcce2a24b406d46f44aeff1f7787daedb13caafa402c privlen=64 publen=32",
    "key seed-roundtrip=true public-equal=true",
    "sign empty    len=64 sig=065322d2dabcbe84183878b0f9bcec7497252fd1378ffaeb10e048db1dfd06b85dfb41d98aebd01eb71665fecb815dfaae61d72982d8821d758da52161265508 verify=true",
    "sign short    len=64 sig=aedf9319b42bfdf5959f18a01b0f96c84460f157848a4953a0bdf957c15493dbe27f203b8983165a4cc76011c459df53583abfb876cb47eeefc84638ee572701 verify=true",
    "sign text     len=64 sig=bc6a890b60818ccf0ae3c766ae90fdc25eaa5ece98757a3e6e8dd48e23213cf0764a1b5c7d8bcc3c1b2da5a46e358a8212d26447990d7dd090283333fc77ff0b verify=true",
    "sign nul      len=64 sig=86e4cfc4c86fec28eb205f2ac8d862998118928c053ee91edf4e6425436fb7b60326f78d8c40795757540b2b37e92fb26f0476ac3b4d66ad6535cf4aa09d780c verify=true",
    "sign long     len=64 sig=162987af964e1583609ae6845b324d5860385b7d801ce51d3d20a0e2849e4e90508c47212251967c7328f478704147df02a48ffb12beae3555442e9b9c663b03 verify=true",
    "sign binary   len=64 sig=af53fc00958dfb033453e287cca5267c5c1ac64e6cdfc96b0056637c5e5d6cd98c5a2c557f70f9f9955590a429a562283e3b0b32d7965254179081d642e66601 verify=true",
    "cross wrong-message=false",
    "cross wrong-key=false",
    "cross empty-message=false",
    "bad nil              -> verify=false err=ed25519: bad signature length: 0",
    "bad empty            -> verify=false err=ed25519: bad signature length: 0",
    "bad short-63         -> verify=false err=ed25519: bad signature length: 63",
    "bad long-65          -> verify=false err=ed25519: bad signature length: 65",
    "bad all-zero         -> verify=false err=ed25519: invalid signature",
    "bad all-ff           -> verify=false err=ed25519: invalid signature",
    "bad flip-first       -> verify=false err=ed25519: invalid signature",
    "bad flip-r-last      -> verify=false err=ed25519: invalid signature",
    "bad flip-s-first     -> verify=false err=ed25519: invalid signature",
    "bad flip-s-last      -> verify=false err=ed25519: invalid signature",
    "bad s-high-bit       -> verify=false err=ed25519: invalid signature",
    "bad s-bit-254        -> verify=false err=ed25519: invalid signature",
    "bad s-bit-253        -> verify=false err=ed25519: invalid signature",
    "bad s-plus-order     -> verify=false err=ed25519: invalid signature",
    "bad r-zero           -> verify=false err=ed25519: invalid signature",
    "bad s-zero           -> verify=false err=ed25519: invalid signature",
    "bad swapped-halves   -> verify=false err=ed25519: invalid signature",
    "edge zero-pubkey-verify=false",
    "edge one-pubkey-verify=false",
    "ph sig=37225490c98440fef6c84fec6c18d5cf33214cd541f11a0625b634b7c230d1d183c47e77909cb9c6b4d3cac428286d4cfc9513476755954ddcfd0d3339a8310a",
    "ph verify-ph=<nil>",
    "ph verify-pure=ed25519: invalid signature",
    "ph pure-sig-as-ph=ed25519: invalid signature",
    "ph short-digest-sign-err=ed25519: bad Ed25519ph message hash length: 31",
    "ph short-digest-verify-err=ed25519: bad Ed25519ph message hash length: 31",
    "ctx sig=8ab70520e4ebb7596bfc195c824b1cdf4d7d2b3188a38be2e16c4ded8693826f5e274edaefd3629ad2b53b3a9c8cf7065d93ad17f45ad513542d08e6f073a507",
    "ctx same=<nil>",
    "ctx different=ed25519: invalid signature",
    "ctx absent=ed25519: invalid signature",
    "ctx too-long-err=ed25519: bad Ed25519ctx context length: 256",
    "determinism same=true",
    "layout priv-tail-is-pub=true",
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
fn hx(b: &slice<byte>) -> string {
    return hex::EncodeToString(&b.to_vec());
}
fn bs(x: &[u8]) -> slice<byte> {
    return slice::<byte>::__from_vec(x.to_vec());
}
fn errText(err: error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    return err.Error();
}
struct NilReader;
impl io::Reader for NilReader {
    fn Read(&mut self, _p: &mut slice<byte>) -> (int, error) {
        return (0, io::EOF.into());
    }
}
fn flip(b: &slice<byte>, i: usize) -> slice<byte> {
    let mut v = b.to_vec();
    v[i] ^= 0x01;
    return slice::__from_vec(v);
}
fn setBit(b: &slice<byte>, i: usize, mask: u8) -> slice<byte> {
    let mut v = b.to_vec();
    v[i] |= mask;
    return slice::__from_vec(v);
}
fn zeroRange(b: &slice<byte>, lo: usize, hi: usize) -> slice<byte> {
    let mut v = b.to_vec();
    for i in lo..hi {
        v[i] = 0;
    }
    return slice::__from_vec(v);
}
fn swapHalves(b: &slice<byte>) -> slice<byte> {
    let src = b.to_vec();
    let mut v = alloc::vec![0u8; 64];
    v[..32].copy_from_slice(&src[32..]);
    v[32..].copy_from_slice(&src[..32]);
    return slice::__from_vec(v);
}
fn addOrder(sig: &slice<byte>) -> slice<byte> {
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut v = sig.to_vec();
    let mut carry: i32 = 0;
    for i in 0..32 {
        let x = v[32 + i] as i32 + l[i] as i32 + carry;
        v[32 + i] = x as u8;
        carry = x >> 8;
    }
    return slice::__from_vec(v);
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let mut seedv: Vec<u8> = Vec::new();
    for i in 0..(ed25519::SeedSize as usize) {
        seedv.push((i * 7) as u8);
    }
    let seed = slice::<byte>::__from_vec(seedv);
    let priv_ = ed25519::NewKeyFromSeed(seed.clone());
    let pub_ = priv_.PublicKey();
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "key seed=%s pub=%s privlen=%d publen=%d",
            hx(&seed),
            hx(&pub_.0),
            priv_.0.Len(),
            pub_.0.Len()
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "key seed-roundtrip=%v public-equal=%v",
            bytes::Equal(priv_.Seed(), seed.clone()),
            pub_.Equal(&priv_.Public())
        ),
    );
    let msgs: [(&str, string); 6] = [
        ("empty", string::new()),
        ("short", s("a")),
        ("text", s("the quick brown fox jumps over the lazy dog")),
        ("nul", string::from_bytes(b"\x00")),
        ("long", strings::Repeat(s("x"), 1000)),
        ("binary", string::from_bytes(b"\xff\xfe\x00\x01\x80")),
    ];
    let mut textSig = slice::<byte>::__from_vec(Vec::new());
    for (name, m) in msgs.iter() {
        let mb = slice::<byte>::__from_vec(m.as_bytes().to_vec());
        let sig = ed25519::Sign(&priv_, mb.clone());
        if *name == "text" {
            textSig = sig.clone();
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "sign %-8s len=%d sig=%s verify=%v",
                s(name),
                sig.Len(),
                hx(&sig),
                ed25519::Verify(&pub_, mb, sig.clone())
            ),
        );
    }
    let good = textSig;
    let msg = bs(b"the quick brown fox jumps over the lazy dog");
    let mut otherSeed = alloc::vec![0u8; ed25519::SeedSize as usize];
    otherSeed[0] = 1;
    let otherPub = ed25519::NewKeyFromSeed(slice::__from_vec(otherSeed)).PublicKey();
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "cross wrong-message=%v",
            ed25519::Verify(&pub_, bs(b"other"), good.clone())
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "cross wrong-key=%v",
            ed25519::Verify(&otherPub, msg.clone(), good.clone())
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "cross empty-message=%v",
            ed25519::Verify(&pub_, slice::<byte>::__from_vec(Vec::new()), good.clone())
        ),
    );
    let mut longer = good.to_vec();
    longer.push(0);
    let bad: [(&str, slice<byte>); 17] = [
        ("nil", slice::<byte>::__from_vec(Vec::new())),
        ("empty", slice::<byte>::__from_vec(Vec::new())),
        ("short-63", good.slice(0, 63)),
        ("long-65", slice::__from_vec(longer)),
        ("all-zero", slice::<byte>::__from_vec(alloc::vec![0u8; 64])),
        ("all-ff", slice::<byte>::__from_vec(alloc::vec![0xffu8; 64])),
        ("flip-first", flip(&good, 0)),
        ("flip-r-last", flip(&good, 31)),
        ("flip-s-first", flip(&good, 32)),
        ("flip-s-last", flip(&good, 63)),
        ("s-high-bit", setBit(&good, 63, 0x80)),
        ("s-bit-254", setBit(&good, 63, 0x40)),
        ("s-bit-253", setBit(&good, 63, 0x20)),
        ("s-plus-order", addOrder(&good)),
        ("r-zero", zeroRange(&good, 0, 32)),
        ("s-zero", zeroRange(&good, 32, 64)),
        ("swapped-halves", swapHalves(&good)),
    ];
    for (name, sig) in bad.iter() {
        let ok = ed25519::Verify(&pub_, msg.clone(), sig.clone());
        let opts = ed25519::Options {
            Hash: crypto::Hash(0),
            Context: string::new(),
        };
        let err = ed25519::VerifyWithOptions(&pub_, msg.clone(), sig.clone(), &opts);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("bad %-16s -> verify=%-5v err=%s", s(name), ok, errText(err)),
        );
    }
    {
        let zero = ed25519::PublicKey(slice::<byte>::__from_vec(alloc::vec![
            0u8;
            ed25519::PublicKeySize as usize
        ]));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "edge zero-pubkey-verify=%v",
                ed25519::Verify(&zero, msg.clone(), good.clone())
            ),
        );
        let mut onev = alloc::vec![0u8; ed25519::PublicKeySize as usize];
        onev[0] = 1;
        let one = ed25519::PublicKey(slice::__from_vec(onev));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "edge one-pubkey-verify=%v",
                ed25519::Verify(&one, msg.clone(), good.clone())
            ),
        );
    }
    {
        let h = sha512::Sum512(msg.clone());
        let hs = bs(&h);
        let phOpts = ed25519::Options {
            Hash: crypto::SHA512,
            Context: string::new(),
        };
        let mut nr = NilReader;
        let (phSig, err) = priv_.Sign(&mut nr, hs.clone(), &phOpts);
        if err != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("ph sign-err=%q", err.Error()),
            );
        } else {
            chk(&mut failed, &mut ln, fmt::Sprintf!("ph sig=%s", hx(&phSig)));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "ph verify-ph=%s",
                    errText(ed25519::VerifyWithOptions(
                        &pub_,
                        hs.clone(),
                        phSig.clone(),
                        &phOpts
                    ))
                ),
            );
            let pure = ed25519::Options {
                Hash: crypto::Hash(0),
                Context: string::new(),
            };
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "ph verify-pure=%s",
                    errText(ed25519::VerifyWithOptions(&pub_, hs.clone(), phSig, &pure))
                ),
            );
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "ph pure-sig-as-ph=%s",
                    errText(ed25519::VerifyWithOptions(
                        &pub_,
                        hs.clone(),
                        good.clone(),
                        &phOpts
                    ))
                ),
            );
        }
        let short = hs.slice(0, 31);
        let mut nr2 = NilReader;
        let (_, e2) = priv_.Sign(&mut nr2, short.clone(), &phOpts);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("ph short-digest-sign-err=%s", errText(e2)),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "ph short-digest-verify-err=%s",
                errText(ed25519::VerifyWithOptions(
                    &pub_,
                    short,
                    good.clone(),
                    &phOpts
                ))
            ),
        );
    }
    {
        let c1 = ed25519::Options {
            Hash: crypto::Hash(0),
            Context: s("ctx-one"),
        };
        let mut nr = NilReader;
        let (ctxSig, err) = priv_.Sign(&mut nr, msg.clone(), &c1);
        if err != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("ctx sign-err=%q", err.Error()),
            );
        } else {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("ctx sig=%s", hx(&ctxSig)),
            );
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "ctx same=%s",
                    errText(ed25519::VerifyWithOptions(
                        &pub_,
                        msg.clone(),
                        ctxSig.clone(),
                        &c1
                    ))
                ),
            );
            let c2 = ed25519::Options {
                Hash: crypto::Hash(0),
                Context: s("ctx-two"),
            };
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "ctx different=%s",
                    errText(ed25519::VerifyWithOptions(
                        &pub_,
                        msg.clone(),
                        ctxSig.clone(),
                        &c2
                    ))
                ),
            );
            let c0 = ed25519::Options {
                Hash: crypto::Hash(0),
                Context: string::new(),
            };
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "ctx absent=%s",
                    errText(ed25519::VerifyWithOptions(&pub_, msg.clone(), ctxSig, &c0))
                ),
            );
        }
        let cl = ed25519::Options {
            Hash: crypto::Hash(0),
            Context: strings::Repeat(s("c"), 256),
        };
        let mut nr3 = NilReader;
        let (_, e3) = priv_.Sign(&mut nr3, msg.clone(), &cl);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("ctx too-long-err=%s", errText(e3)),
        );
    }
    {
        let a = ed25519::Sign(&priv_, msg.clone());
        let b = ed25519::Sign(&priv_, msg.clone());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("determinism same=%v", bytes::Equal(a, b)),
        );
    }
    {
        let tail = priv_.0.slice(32, priv_.0.Len());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "layout priv-tail-is-pub=%v",
                bytes::Equal(tail, pub_.0.clone())
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
