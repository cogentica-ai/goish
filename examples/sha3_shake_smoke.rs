// sha3_shake_smoke — SHAKE, cSHAKE and the SHA-3 marshal/Clone surface,
// i.e. everything the crypto/internal/fips140/sha3 extraction added.
//
// cSHAKE (SP 800-185) is entirely new: bytepad, leftEncode, newCShake and
// the init-block replay in Reset had no goish implementation before. A
// wrong leftEncode or a missing bytepad still produces well-formed-looking
// output, so every value here is pinned to a vector rather than compared
// against another goish call.
//
// The cSHAKE vectors are SP 800-185 samples #1 and #3, reproduced with an
// independent pure-Python Keccak that was first validated against
// hashlib's shake_128/shake_256/sha3_256/sha3_512.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::sha3;
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

fn b(s: &str) -> slice<byte> {
    return slice::__from_vec(s.as_bytes().to_vec());
}

fn raw(v: &[byte]) -> slice<byte> {
    return slice::__from_vec(v.to_vec());
}

fn hx(s: &slice<byte>) -> goish::string {
    let r: &[byte] = s;
    return hex::EncodeToString(r);
}

#[goish::main]
fn main() {
    // ── SHAKE (FIPS 202) ──────────────────────────────────────────────
    let mut s128 = sha3::NewSHAKE128();
    let _ = s128.Write(b("abc"));
    let mut out = alloc::vec![0u8; 32];
    s128.Read(&mut out);
    check(
        "SHAKE128(abc, 32)",
        hx(&raw(&out)),
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
    );

    let mut s256 = sha3::NewSHAKE256();
    let _ = s256.Write(b("abc"));
    let mut out = alloc::vec![0u8; 64];
    s256.Read(&mut out);
    check(
        "SHAKE256(abc, 64)",
        hx(&raw(&out)),
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739\
         d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
    );

    // Squeezing in pieces must equal one long read — it crosses the rate
    // boundary and re-permutes.
    let mut sp = sha3::NewSHAKE128();
    let _ = sp.Write(b("abc"));
    let mut acc: Vec<byte> = Vec::new();
    let cuts: [usize; 4] = [1, 7, 20, 4];
    let mut i = 0;
    while i < cuts.len() {
        let mut piece = alloc::vec![0u8; cuts[i]];
        sp.Read(&mut piece);
        acc.extend_from_slice(&piece);
        i += 1;
    }
    check(
        "SHAKE128 piecewise squeeze",
        hx(&raw(&acc)),
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
    );

    check(
        "SumSHAKE128 one-shot",
        hx(&sha3::SumSHAKE128(b("abc"), 32)),
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
    );

    // ── cSHAKE (SP 800-185) ───────────────────────────────────────────
    //
    // Sample #1: N empty, S = "Email Signature", X = 00 01 02 03, L = 256.
    let x = raw(&[0u8, 1, 2, 3]);
    let mut c128 = sha3::NewCSHAKE128(raw(&[]), b("Email Signature"));
    let _ = c128.Write(x.clone());
    let mut out = alloc::vec![0u8; 32];
    c128.Read(&mut out);
    check(
        "cSHAKE128 SP 800-185 #1",
        hx(&raw(&out)),
        "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5",
    );

    // Sample #3: same inputs at 256-bit strength, L = 512.
    let mut c256 = sha3::NewCSHAKE256(raw(&[]), b("Email Signature"));
    let _ = c256.Write(x.clone());
    let mut out = alloc::vec![0u8; 64];
    c256.Read(&mut out);
    check(
        "cSHAKE256 SP 800-185 #3",
        hx(&raw(&out)),
        "d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd1\
         64020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c",
    );

    // A non-empty N exercises the second leftEncode in the init block.
    let mut cn = sha3::NewCSHAKE128(b("MyFunc"), b("Custom"));
    let _ = cn.Write(b("goish"));
    let mut out = alloc::vec![0u8; 32];
    cn.Read(&mut out);
    check(
        "cSHAKE128 with N and S",
        hx(&raw(&out)),
        "63cd7827474e8f903b1b927cc4c8a06c6a7e649eaf4093724dc994f33a9eec3f",
    );

    // Empty N and S must be exactly SHAKE, which is what Go guarantees.
    let mut ce = sha3::NewCSHAKE128(raw(&[]), raw(&[]));
    let _ = ce.Write(b("abc"));
    let mut out = alloc::vec![0u8; 32];
    ce.Read(&mut out);
    check(
        "cSHAKE128 with empty N/S == SHAKE128",
        hx(&raw(&out)),
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
    );

    // Reset must replay the cSHAKE init block, not just zero the sponge —
    // if it forgot, the second pass would silently equal plain SHAKE.
    let mut cr = sha3::NewCSHAKE128(raw(&[]), b("Email Signature"));
    let _ = cr.Write(b("garbage"));
    cr.Reset();
    let _ = cr.Write(x.clone());
    let mut out = alloc::vec![0u8; 32];
    cr.Read(&mut out);
    check(
        "cSHAKE128 Reset replays the init block",
        hx(&raw(&out)),
        "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5",
    );

    // ── SHA-3 marshal / Clone ─────────────────────────────────────────
    let mut h = sha3::New256();
    let _ = h.Write(b("a"));
    let (st, err) = h.MarshalBinary();
    if err != goish::nil {
        fmt::Printf!("FAIL: SHA3.MarshalBinary returned %v\n", err);
        unsafe { FAILED = true };
    }
    check(
        "SHA3 marshaled state is 207 bytes",
        fmt::Sprintf!("%d", st.Len()),
        "207",
    );

    let mut r = sha3::New256();
    let err = r.UnmarshalBinary(st);
    if err != goish::nil {
        fmt::Printf!("FAIL: SHA3.UnmarshalBinary returned %v\n", err);
        unsafe { FAILED = true };
    }
    let _ = r.Write(b("bc"));
    check(
        "SHA3-256 marshal round-trip",
        hx(&r.Sum(slice::__from_vec(Vec::new()))),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    );

    // A SHAKE state must not load into a SHA-3 digest: different magic.
    let sm = sha3::NewSHAKE128();
    let (sst, _) = sm.MarshalBinary();
    let mut d2 = sha3::New256();
    let err = d2.UnmarshalBinary(sst);
    check(
        "SHA3 rejects a SHAKE state",
        fmt::Sprintf!("%v", err != goish::nil),
        "true",
    );

    // Clone must be independent.
    let mut base = sha3::New256();
    let _ = base.Write(b("shared"));
    let mut cl = base.Clone();
    let _ = cl.Write(b("A"));
    let _ = base.Write(b("B"));
    check(
        "SHA3 clone diverges",
        hx(&cl.Sum(slice::__from_vec(Vec::new()))),
        hex::EncodeToString(&sha3::Sum256(b("sharedA"))).as_ref(),
    );
    check(
        "SHA3 origin unaffected by clone",
        hx(&base.Sum(slice::__from_vec(Vec::new()))),
        hex::EncodeToString(&sha3::Sum256(b("sharedB"))).as_ref(),
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("sha3_shake_smoke OK\n");
}
