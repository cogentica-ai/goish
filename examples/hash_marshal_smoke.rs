// hash_marshal_smoke — hash.Cloner + encoding.Binary{Marshaler,Appender,
// Unmarshaler} on crypto/internal/fips140/sha256, and the FIPS 198-1 §6
// marshaled-state fast path in crypto/internal/fips140/hmac.
//
// The HMAC checks matter most: Reset() switches an HMAC over a
// marshalable hash from "re-feed ipad" to "restore cached state", and a
// bug there is silent — the MAC simply comes out wrong. Every assertion
// below compares a post-Reset MAC against a freshly constructed one.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::crypto::hmac;
use goish::crypto::internal::fips140::sha256 as fips256;
use goish::crypto::sha256;
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
    // rather than panicking or silently producing a broken MAC.
    let mut sha1mac = hmac::New(goish::crypto::sha1::NewHash, key.clone());
    let _ = io::Writer::Write(&mut sha1mac, msg.clone());
    let (_, err) = Cloner::Clone(&sha1mac);
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
    Hash::Reset(&mut sha1mac);
    let _ = io::Writer::Write(&mut sha1mac, msg.clone());
    check(
        "sha1-hmac slow path survives Reset",
        hexsum(&sha1mac),
        goish::string::from("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"),
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("hash_marshal_smoke OK\n");
}
