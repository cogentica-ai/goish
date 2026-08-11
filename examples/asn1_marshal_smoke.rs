// asn1_marshal_smoke — encoding/asn1's DER encoding primitives vs Go 1.25.5.
//
// Every expectation below is `scripts/goref.sh encoding/asn1` output for
// base128IntLength / appendBase128Int / lengthLength / appendLength /
// appendTagAndLength. These five lay down every byte that the reflective
// Marshal layer will emit, so they are checked first and on their own.
//
// The cases cover each boundary the encoders branch on: base-128 rollover
// (127/128, 16383/16384), short vs long form length (127/128), the
// multi-byte length ladder (255/256/65535/65536/1<<24), high-tag form
// (tag 31 and 40), and all four tag classes.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::encoding::asn1::{
    TagAndLength, __appendBase128Int, __appendLength, __appendTagAndLength, __base128IntLength,
    __lengthLength,
};
use goish::fmt;
use goish::goslice::slice;
use goish::types::byte;

fn empty() -> slice<byte> {
    return slice::__from_vec(Vec::new());
}

static FAILED: AtomicUsize = AtomicUsize::new(0);
static RAN: AtomicUsize = AtomicUsize::new(0);

fn nib(c: u8) -> u8 {
    if c >= b'0' && c <= b'9' { return c - b'0'; }
    return c - b'a' + 10;
}

fn unhex(s: &str) -> Vec<byte> {
    let b = s.as_bytes();
    let mut out: Vec<byte> = Vec::new();
    let mut i = 0usize;
    while i + 1 < b.len() {
        out.push(nib(b[i]) * 16 + nib(b[i + 1]));
        i += 2;
    }
    return out;
}

fn check(ok: bool, label: &'static str, n: i64) {
    RAN.fetch_add(1, Ordering::AcqRel);
    if ok {
        fmt::Printf!("PASS: %s %d\n", goish::string(label), n);
    } else {
        FAILED.fetch_add(1, Ordering::AcqRel);
        fmt::Printf!("FAIL: %s %d\n", goish::string(label), n);
    }
}

#[goish::main]
fn main() {
    // base128IntLength / appendBase128Int
    let b128: [(i64, i64, &str); 10] = [
        (0, 1, "00"), (1, 1, "01"), (127, 1, "7f"), (128, 2, "8100"),
        (255, 2, "817f"), (256, 2, "8200"), (16383, 2, "ff7f"),
        (16384, 3, "818000"), (1048576, 3, "c08000"), (2147483647, 5, "87ffffff7f"),
    ];
    for &(n, wantLen, wantHex) in b128.iter() {
        let gotLen = __base128IntLength(n);
        let dst = __appendBase128Int(empty(), n);
        check(gotLen == wantLen && dst.__into_vec() == unhex(wantHex), "base128", n);
    }

    // lengthLength / appendLength
    let lens: [(i64, i64, &str); 9] = [
        (0, 1, "00"), (1, 1, "01"), (127, 1, "7f"), (128, 1, "80"), (255, 1, "ff"),
        (256, 2, "0100"), (65535, 2, "ffff"), (65536, 3, "010000"), (16777216, 4, "01000000"),
    ];
    for &(i, wantLL, wantHex) in lens.iter() {
        let gotLL = __lengthLength(i);
        let dst = __appendLength(empty(), i);
        check(gotLL == wantLL && dst.__into_vec() == unhex(wantHex), "length", i);
    }

    // appendTagAndLength
    let tls: [(i64, i64, i64, bool, &str); 9] = [
        (0, 2, 1, false, "0201"),
        (0, 16, 5, true, "3005"),
        (0, 4, 200, false, "0481c8"),
        (0, 6, 3, false, "0603"),
        (2, 0, 7, true, "a007"),
        (2, 31, 2, false, "9f1f02"),
        (1, 40, 300, true, "7f2882012c"),
        (3, 5, 128, false, "c58180"),
        (0, 3, 65536, false, "0383010000"),
    ];
    for &(class, tag, length, isCompound, wantHex) in tls.iter() {
        let t = TagAndLength { class, tag, length, isCompound };
        let dst = __appendTagAndLength(empty(), &t);
        check(dst.__into_vec() == unhex(wantHex), "tagAndLength tag=", tag);
    }

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("asn1_marshal_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!("asn1_marshal_smoke FAILED %d of %d\n", failed as i64, ran as i64);
        goish::syscall::Exit(1);
    }
}
