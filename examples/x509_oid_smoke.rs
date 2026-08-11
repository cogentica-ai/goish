// x509_oid_smoke — crypto/x509's OID type vs Go 1.25.5.
//
// Every expectation is `scripts/goref.sh crypto/x509` output. The cases
// cover each boundary oid.go branches on: the first-component packing
// (val<80 vs >=80, so "2.999" and "2.100.3" as well as "1.39"), base-128
// rollover, a component that does NOT fit in an int31
// ("1.2.18446744073709551615" — the whole reason OID exists rather than
// asn1.ObjectIdentifier), and the ten malformed strings Go rejects.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::x509::{OIDFromInts, ParseOID};
use goish::encoding::asn1::ObjectIdentifier;
use goish::goslice::slice;
use goish::{fmt, string};

static RAN: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(ok: bool, label: &'static str) {
    RAN.fetch_add(1, Ordering::AcqRel);
    if ok {
        fmt::Printf!("PASS: %s\n", string(label));
    } else {
        FAILED.fetch_add(1, Ordering::AcqRel);
        fmt::Printf!("FAIL: %s\n", string(label));
    }
}

/// Lowercase hex of `b`. Hand-rolled: `alloc::format!` is banned by
/// GOISH002 and pulls in unwinding this build cannot link.
fn hex(b: &slice<u8>) -> alloc::vec::Vec<u8> {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for x in b.as_ref().iter() {
        out.push(D[(x >> 4) as usize]);
        out.push(D[(x & 0xf) as usize]);
    }
    return out;
}

/// Parse `s`, then assert both its DER and its String round-trip.
fn round(s: &'static str, der: &'static str, label: &'static str) {
    let (o, err) = ParseOID(s);
    let (b, _) = o.MarshalBinary();
    check(
        err == goish::nil && hex(&b) == der.as_bytes() && o.String().as_bytes() == s.as_bytes(),
        label,
    );
}

fn bad(s: &'static str, label: &'static str) {
    let (_, err) = ParseOID(s);
    check(err != goish::nil, label);
}

#[goish::main]
fn main() {
    round("1.2.840.113549", "2a864886f70d", "ParseOID 1.2.840.113549");
    round("2.5.4.3", "550403", "ParseOID 2.5.4.3");
    round("0.0", "00", "ParseOID 0.0");
    round("1.39", "4f", "ParseOID 1.39 (first component packing)");
    round("2.999", "8837", "ParseOID 2.999 (val>=80 path)");
    round("2.100.3", "813403", "ParseOID 2.100.3");
    round("1.2.3.4.5.6.7.8.9", "2a03040506070809", "ParseOID 9 components");
    round(
        "2.16.840.1.101.3.4.2.1",
        "608648016503040201",
        "ParseOID 2.16.840.1.101.3.4.2.1",
    );
    // The component that does not fit an int31 — the whole point of OID.
    round(
        "1.2.18446744073709551615",
        "2a81ffffffffffffffff7f",
        "ParseOID uint64-max component (big.Int path)",
    );

    bad("", "ParseOID rejects empty");
    bad(".", "ParseOID rejects .");
    bad("1", "ParseOID rejects single component");
    bad("3.0", "ParseOID rejects first>2");
    bad("1.40", "ParseOID rejects second>=40 when first<2");
    bad("0.40", "ParseOID rejects 0.40");
    bad("1.2.", "ParseOID rejects trailing dot");
    bad(".1.2", "ParseOID rejects leading dot");
    bad("1..2", "ParseOID rejects empty component");
    bad("1.2.-3", "ParseOID rejects sign");

    let ints = |v: &[u64]| slice::__from_vec(v.to_vec());
    let (o, err) = OIDFromInts(ints(&[1, 2, 840, 113549]));
    let (b, _) = o.MarshalBinary();
    check(
        err == goish::nil && hex(&b) == b"2a864886f70d" && o.String().as_bytes() == b"1.2.840.113549",
        "OIDFromInts 1.2.840.113549",
    );
    let (o2, err2) = OIDFromInts(ints(&[2, 999]));
    let (b2, _) = o2.MarshalBinary();
    check(err2 == goish::nil && hex(&b2) == b"8837", "OIDFromInts 2.999");
    let (o3, err3) = OIDFromInts(ints(&[0, 0]));
    let (b3, _) = o3.MarshalBinary();
    check(err3 == goish::nil && hex(&b3) == b"00", "OIDFromInts 0.0");
    check(OIDFromInts(ints(&[1])).1 != goish::nil, "OIDFromInts rejects 1 component");
    check(OIDFromInts(ints(&[3, 1])).1 != goish::nil, "OIDFromInts rejects first>2");
    check(OIDFromInts(ints(&[1, 40])).1 != goish::nil, "OIDFromInts rejects 1.40");

    let (a, _) = ParseOID("1.2.840.113549");
    let (bb, _) = ParseOID("1.2.840.113549");
    let (c, _) = ParseOID("2.5.4.3");
    check(a.Equal(&bb), "Equal same");
    check(!a.Equal(&c), "Equal different");

    let want = ObjectIdentifier::New(slice::__from_vec(alloc::vec![1i64, 2, 840, 113549]));
    let other = ObjectIdentifier::New(slice::__from_vec(alloc::vec![2i64, 5, 4, 3]));
    check(a.EqualASN1OID(&want), "EqualASN1OID true");
    check(!a.EqualASN1OID(&other), "EqualASN1OID false");

    let (txt, _) = a.MarshalText();
    check(txt.as_ref() == b"1.2.840.113549", "MarshalText");

    let mut u = goish::crypto::x509::OID::default();
    let e = u.UnmarshalText(slice::__from_vec(b"2.5.4.3".to_vec()));
    check(e == goish::nil && u.String().as_bytes() == b"2.5.4.3", "UnmarshalText");

    let mut ub = goish::crypto::x509::OID::default();
    let e2 = ub.UnmarshalBinary(slice::__from_vec(alloc::vec![
        0x2au8, 0x86, 0x48, 0x86, 0xf7, 0x0d
    ]));
    check(
        e2 == goish::nil && ub.String().as_bytes() == b"1.2.840.113549",
        "UnmarshalBinary",
    );
    // A trailing continuation bit is not a valid DER OID.
    let mut bad_der = goish::crypto::x509::OID::default();
    check(
        bad_der.UnmarshalBinary(slice::__from_vec(alloc::vec![0x80u8])) != goish::nil,
        "UnmarshalBinary rejects non-minimal",
    );

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("x509_oid_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!("x509_oid_smoke FAILED %d of %d\n", failed as i64, ran as i64);
        goish::syscall::Exit(1);
    }
}
