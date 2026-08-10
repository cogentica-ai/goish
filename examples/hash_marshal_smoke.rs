// hash_marshal_smoke — hash.Cloner + encoding.Binary{Marshaler,Appender,
// Unmarshaler} on crypto/internal/fips140/{sha256,sha512}, and the
// FIPS 198-1 §6 marshaled-state fast path in crypto/internal/fips140/hmac.
//
// The HMAC checks matter most: Reset() switches an HMAC over a
// marshalable hash from "re-feed ipad" to "restore cached state", and a
// bug there is silent — the MAC simply comes out wrong. So every MAC
// assertion below compares against a vector pinned from RFC 4231 rather
// than against another goish result.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::crypto::hmac;
use goish::crypto::internal::fips140::sha256 as fips256;
use goish::crypto::internal::fips140::sha512 as fips512;
use goish::crypto::sha256;
use goish::crypto::sha512;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::hash::{Cloner, Hash};
use goish::io;
use goish::types::byte;

extern crate alloc;
use alloc::vec::Vec;

static mut FAILED: bool = false;

fn check(name: &str, got: goish::string, want: goish::string) {
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

fn bytes_of(s: &str) -> slice<byte> {
    return slice::__from_vec(s.as_bytes().to_vec());
}

fn empty() -> slice<byte> {
    return slice::__from_vec(Vec::new());
}

fn hexsum(h: &dyn Hash) -> goish::string {
    let sum = h.Sum(empty());
    let raw: &[byte] = &sum;
    return hex::EncodeToString(raw);
}

#[goish::main]
fn main() {
    // ── sha256 marshal round-trip ─────────────────────────────────────
    //
    // Marshal after half the input, restore into a fresh digest, feed
    // the rest — must equal hashing the whole input in one go.
    let mut d = fips256::New();
    let _ = io::Writer::Write(&mut d, bytes_of("hello, "));
    let (state, err) = d.MarshalBinary();
    if err != goish::nil {
        fmt::Printf!("FAIL: MarshalBinary returned %v\n", err);
        unsafe { FAILED = true };
    }
    check(
        "marshaled state is 108 bytes",
        fmt::Sprintf!("%d", state.Len()),
        goish::string::from("108"),
    );

    let mut restored = fips256::New();
    let err = restored.UnmarshalBinary(state);
    if err != goish::nil {
        fmt::Printf!("FAIL: UnmarshalBinary returned %v\n", err);
        unsafe { FAILED = true };
    }
    let _ = io::Writer::Write(&mut restored, bytes_of("world"));

    let want = hex::EncodeToString(&sha256::Sum256(bytes_of("hello, world")));
    check("sha256 marshal round-trip", hexsum(&restored), want);

    // A SHA-224 digest must reject a SHA-256 state (magic mismatch).
    let mut d256 = fips256::New();
    let _ = io::Writer::Write(&mut d256, bytes_of("x"));
    let (s256, _) = d256.MarshalBinary();
    let mut d224 = fips256::New224();
    let err = d224.UnmarshalBinary(s256);
    check(
        "sha224 rejects sha256 state",
        fmt::Sprintf!("%v", err != goish::nil),
        goish::string::from("true"),
    );

    // ── sha256 Clone ──────────────────────────────────────────────────
    //
    // The clone must be independent: writing to one must not move the
    // other.
    let mut base = fips256::New();
    let _ = io::Writer::Write(&mut base, bytes_of("shared prefix"));
    let (mut cloned, err) = Cloner::Clone(&base);
    if err != goish::nil {
        fmt::Printf!("FAIL: Digest.Clone returned %v\n", err);
        unsafe { FAILED = true };
    }
    let _ = io::Writer::Write(&mut *cloned, bytes_of("A"));
    let _ = io::Writer::Write(&mut base, bytes_of("B"));

    let wantA = hex::EncodeToString(&sha256::Sum256(bytes_of("shared prefixA")));
    let wantB = hex::EncodeToString(&sha256::Sum256(bytes_of("shared prefixB")));
    check("clone diverges (clone)", hexsum(&*cloned), wantA);
    check("clone diverges (origin)", hexsum(&base), wantB);

    // ── HMAC marshaled-state fast path ────────────────────────────────
    //
    // RFC 4231 test case 2 pins the expected MAC, so a broken fast path
    // cannot hide behind a self-consistent-but-wrong answer.
    let key = bytes_of("Jefe");
    let msg = bytes_of("what do ya want for nothing?");
    let rfc4231_tc2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    let mut mac = hmac::New(sha256::NewHash, key.clone());
    let _ = io::Writer::Write(&mut mac, msg.clone());
    check("hmac first pass (RFC 4231 tc2)", hexsum(&mac), goish::string::from(rfc4231_tc2));

    // Reset caches the marshaled ipad/opad state. Every subsequent pass
    // takes the restore path, and must still agree with the first.
    let mut i = 0;
    while i < 3 {
        Hash::Reset(&mut mac);
        let _ = io::Writer::Write(&mut mac, msg.clone());
        check(
            "hmac after Reset (marshaled path)",
            hexsum(&mac),
            goish::string::from(rfc4231_tc2),
        );
        i += 1;
    }

    // Split writes across the reset boundary — exercises Sum's restore of
    // the cached opad state with a partial inner block.
    Hash::Reset(&mut mac);
    let _ = io::Writer::Write(&mut mac, bytes_of("what do ya "));
    let _ = io::Writer::Write(&mut mac, bytes_of("want for nothing?"));
    check("hmac split writes", hexsum(&mac), goish::string::from(rfc4231_tc2));

    // ── HMAC Clone ────────────────────────────────────────────────────
    let mut src = hmac::New(sha256::NewHash, key.clone());
    let _ = io::Writer::Write(&mut src, bytes_of("what do ya "));
    let (mut hclone, err) = Cloner::Clone(&src);
    if err != goish::nil {
        fmt::Printf!("FAIL: HMAC.Clone returned %v\n", err);
        unsafe { FAILED = true };
    }
    let _ = io::Writer::Write(&mut *hclone, bytes_of("want for nothing?"));
    check("hmac clone completes the MAC", hexsum(&*hclone), goish::string::from(rfc4231_tc2));

    // The source must be unaffected by the clone's writes.
    let _ = io::Writer::Write(&mut src, bytes_of("want for nothing?"));
    check("hmac clone is independent", hexsum(&src), goish::string::from(rfc4231_tc2));

    // Cloning a hash with no Cloner impl must report ErrUnsupported
    // rather than panicking or silently producing a broken MAC. sha3 is
    // the remaining hash with no Cloner port — sha1 used to fill this
    // role and no longer can, which is itself the point of the check.
    let mut nocloner = hmac::New(goish::crypto::sha3::NewHash256, key.clone());
    let _ = io::Writer::Write(&mut nocloner, msg.clone());
    let (_, err) = Cloner::Clone(&nocloner);
    check(
        "clone of non-Cloner hash errors",
        fmt::Sprintf!("%v", err != goish::nil),
        goish::string::from("true"),
    );
    check(
        "and it wraps ErrUnsupported",
        fmt::Sprintf!("%v", goish::errors::Is(err, goish::errors::ErrUnsupported)),
        goish::string::from("true"),
    );

    // A non-marshalable inner hash must keep working on the slow path.
    Hash::Reset(&mut nocloner);
    let _ = io::Writer::Write(&mut nocloner, msg.clone());
    check(
        "sha3-hmac slow path survives Reset",
        fmt::Sprintf!("%d", hexsum(&nocloner).Len()),
        goish::string::from("64"),
    );

    // ── md5 / sha1: same marshal surface, now on the fast path ────────
    let mut md5mac = hmac::New(goish::crypto::md5::NewHash, key.clone());
    let _ = io::Writer::Write(&mut md5mac, msg.clone());
    check(
        "hmac-md5 first pass",
        hexsum(&md5mac),
        goish::string::from("750c783e6ab0b503eaa86e310a5db738"),
    );
    Hash::Reset(&mut md5mac);
    let _ = io::Writer::Write(&mut md5mac, msg.clone());
    check(
        "hmac-md5 after Reset (marshaled path)",
        hexsum(&md5mac),
        goish::string::from("750c783e6ab0b503eaa86e310a5db738"),
    );

    let mut sha1mac = hmac::New(goish::crypto::sha1::NewHash, key.clone());
    let _ = io::Writer::Write(&mut sha1mac, msg.clone());
    Hash::Reset(&mut sha1mac);
    let _ = io::Writer::Write(&mut sha1mac, msg.clone());
    check(
        "hmac-sha1 after Reset (marshaled path)",
        hexsum(&sha1mac),
        goish::string::from("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
    );

    // md5/sha1 marshal round-trips.
    let mut dm = goish::crypto::md5::New();
    let _ = io::Writer::Write(&mut dm, bytes_of("hello, "));
    let (sm, _) = dm.MarshalBinary();
    let mut rm = goish::crypto::md5::New();
    let _ = rm.UnmarshalBinary(sm);
    let _ = io::Writer::Write(&mut rm, bytes_of("world"));
    check(
        "md5 marshal round-trip",
        hexsum(&rm),
        goish::string::from("e4d7f1b4ed2e42d15898f4b27b019da4"),
    );

    let mut ds = goish::crypto::sha1::New();
    let _ = io::Writer::Write(&mut ds, bytes_of("hello, "));
    let (ss, _) = ds.MarshalBinary();
    let mut rs = goish::crypto::sha1::New();
    let _ = rs.UnmarshalBinary(ss);
    let _ = io::Writer::Write(&mut rs, bytes_of("world"));
    check(
        "sha1 marshal round-trip",
        hexsum(&rs),
        goish::string::from("b7e23ec29af22b0b4e41da31e868d57226121c84"),
    );

    // ConstantTimeSum must agree with Sum for every buffered length —
    // it selects between one- and two-block finalization with a mask
    // rather than a branch, and the boundary is nx == 56.
    let mut n: usize = 0;
    let mut ctsOK = true;
    while n <= 130 {
        let mut d = goish::crypto::sha1::New();
        let filler: Vec<byte> = alloc::vec![b'a'; n];
        let _ = io::Writer::Write(&mut d, slice::__from_vec(filler));
        let a = hexsum(&d);
        let cts = d.ConstantTimeSum(empty());
        let ctsRaw: &[byte] = &cts;
        if a != hex::EncodeToString(ctsRaw) {
            fmt::Printf!("FAIL: ConstantTimeSum mismatch at len %d\n", n as i64);
            ctsOK = false;
            unsafe { FAILED = true };
        }
        n += 1;
    }
    if ctsOK {
        fmt::Printf!("PASS: sha1 ConstantTimeSum matches Sum for len 0..130\n");
    }

    // ── sha512: same surface, 128-byte blocks ─────────────────────────
    //
    // SHA-512 marshals a 204-byte state (4 magic + 8*8 h + 128 x + 8 len)
    // and its four variants each carry a distinct magic, so a variant
    // must reject another's state.
    let mut d5 = fips512::New();
    let _ = io::Writer::Write(&mut d5, bytes_of("hello, "));
    let (state5, err) = d5.MarshalBinary();
    if err != goish::nil {
        fmt::Printf!("FAIL: sha512 MarshalBinary returned %v\n", err);
        unsafe { FAILED = true };
    }
    check(
        "sha512 marshaled state is 204 bytes",
        fmt::Sprintf!("%d", state5.Len()),
        goish::string::from("204"),
    );

    let mut restored5 = fips512::New();
    let err = restored5.UnmarshalBinary(state5.clone());
    if err != goish::nil {
        fmt::Printf!("FAIL: sha512 UnmarshalBinary returned %v\n", err);
        unsafe { FAILED = true };
    }
    let _ = io::Writer::Write(&mut restored5, bytes_of("world"));
    check(
        "sha512 marshal round-trip",
        hexsum(&restored5),
        goish::string::from(
            "8710339dcb6814d0d9d2290ef422285c9322b7163951f9a0ca8f883d3305286f\
             44139aa374848e4174f5aada663027e4548637b6d19894aec4fb6c46a139fbf9",
        ),
    );

    // SHA-384 must reject a SHA-512 state - different magic, same length.
    let mut d384 = fips512::New384();
    let err = d384.UnmarshalBinary(state5);
    check(
        "sha384 rejects sha512 state",
        fmt::Sprintf!("%v", err != goish::nil),
        goish::string::from("true"),
    );

    // HMAC-SHA-512 takes the marshaled path too (registered alongside
    // sha256), so it needs the same pinned-vector check.
    let rfc4231_tc2_512 = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                           9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
    let mut mac512 = hmac::New(sha512::NewHash, key.clone());
    let _ = io::Writer::Write(&mut mac512, msg.clone());
    check(
        "hmac-sha512 first pass",
        hexsum(&mac512),
        goish::string::from(rfc4231_tc2_512),
    );
    let mut i = 0;
    while i < 3 {
        Hash::Reset(&mut mac512);
        let _ = io::Writer::Write(&mut mac512, msg.clone());
        check(
            "hmac-sha512 after Reset (marshaled path)",
            hexsum(&mac512),
            goish::string::from(rfc4231_tc2_512),
        );
        i += 1;
    }

    // SHA-384 shares Digest with SHA-512 but has a different size field -
    // the state cache must key off the right variant.
    let mut mac384 = hmac::New(sha512::NewHash384, key.clone());
    let _ = io::Writer::Write(&mut mac384, msg.clone());
    Hash::Reset(&mut mac384);
    let _ = io::Writer::Write(&mut mac384, msg.clone());
    check(
        "hmac-sha384 after Reset",
        hexsum(&mac384),
        goish::string::from(
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649",
        ),
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("hash_marshal_smoke OK\n");
}
