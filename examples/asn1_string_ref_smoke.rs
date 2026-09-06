// asn1_string_ref_smoke — BMPString, T61String and BitString, against
// a running Go 1.25.5.
//
// These decode text out of certificates, and no example named them.
// The reference is an IN-PACKAGE test (`package asn1` via
// scripts/goref.sh) because Go keeps `parseBMPString` and
// `parseT61String` unexported; goish exports them capitalised.
//
// All 14 lines match Go on the first run; nothing is fixed here. The
// case worth the file is the third BMPString rule:
//
//   d8 3d de 00   REFUSED — a WELL-FORMED UTF-16 surrogate pair for
//                 U+1F600. Go rejects any surrogate in a BMPString,
//                 pair or not, because BMP means the basic plane.
//   d8 3d 00 41   REFUSED — a lone surrogate.
//   00 41 00      REFUSED — odd length; UTF-16BE comes in pairs.
//   (empty)       accepted, "" with no error.
//
// A decoder written as "parse UTF-16BE" accepts the first of those and
// returns a perfectly good 😀 — a string Go would never produce from
// that certificate. Nothing downstream could tell the two apart.
//
// T61 is the other direction: Go decodes each byte as the code point of
// the same value, so e9 41 ff is "éAÿ" and no byte is ever invalid.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::encoding::asn1;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::types::{byte, int};


fn b(v: &[byte]) -> slice<byte> {
    return slice::__from_vec(v.to_vec());
}

fn hex(s: &slice<byte>) -> string {
    let mut o = string::from("");
    for x in s.iter() {
        o = o + fmt::Sprintf!("%02x", *x as int);
    }
    return o;
}

const GO: [&str; 14] = [
    "bmp-ascii                \"AB\" err=<nil>",
    "bmp-nonascii             \"é中\" err=<nil>",
    "bmp-odd-length           \"\" err=invalid BMPString",
    "bmp-empty                \"\" err=<nil>",
    "bmp-surrogate-pair       \"\" err=invalid BMPString",
    "bmp-lone-surrogate       \"\" err=invalid BMPString",
    "t61-ascii                \"hello\" err=<nil>",
    "t61-highbytes            \"éAÿ\" err=<nil>",
    "t61-empty                \"\" err=<nil>",
    "rightalign               80 -> 01",
    "rightalign               f0 -> 0f",
    "rightalign               ff80 -> 01ff",
    "rightalign                -> ",
    "bitstring-at             1 0 1 0",
];

static mut BAD: usize = 0;

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        unsafe { BAD += 1 };
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        unsafe { BAD += 1 };
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let mut show = |ln: &mut usize, tag: &str, v: &[byte]| {
        let (s, err) = asn1::ParseBMPString(b(v));
        chk(ln, &fmt::Sprintf!("%-24s %q err=%v", tag, s, err));
    };
    show(&mut ln, "bmp-ascii", &[0x00, 0x41, 0x00, 0x42]);
    show(&mut ln, "bmp-nonascii", &[0x00, 0xe9, 0x4e, 0x2d]);
    show(&mut ln, "bmp-odd-length", &[0x00, 0x41, 0x00]);
    show(&mut ln, "bmp-empty", &[]);
    show(&mut ln, "bmp-surrogate-pair", &[0xd8, 0x3d, 0xde, 0x00]);
    show(&mut ln, "bmp-lone-surrogate", &[0xd8, 0x3d, 0x00, 0x41]);

    let mut showT = |ln: &mut usize, tag: &str, v: &[byte]| {
        let (s, err) = asn1::ParseT61String(b(v));
        chk(ln, &fmt::Sprintf!("%-24s %q err=%v", tag, s, err));
    };
    showT(&mut ln, "t61-ascii", b"hello");
    showT(&mut ln, "t61-highbytes", &[0xe9, 0x41, 0xff]);
    showT(&mut ln, "t61-empty", &[]);

    let cases: [(&[byte], int); 4] = [
        (&[0x80], 1),
        (&[0xf0], 4),
        (&[0xff, 0x80], 9),
        (&[], 0),
    ];
    for (bytes, n) in cases.iter() {
        let bs = asn1::BitString { Bytes: b(bytes), BitLength: *n };
        chk(&mut ln, &fmt::Sprintf!("%-24s %s -> %s", "rightalign", hex(&bs.Bytes), hex(&bs.RightAlign())));
    }
    let bb = asn1::BitString { Bytes: b(&[0x82]), BitLength: 8 };
    chk(&mut ln, &fmt::Sprintf!("%-24s %d %d %d %d", "bitstring-at",
        bb.At(0) as int, bb.At(1) as int, bb.At(6) as int, bb.At(99) as int));
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        unsafe { BAD += 1 };
    }
    let bad = unsafe { BAD };
    if bad != 0 {
        // e2e_runner.sh: "rc=0 wins regardless of stdout content",
        // so printing the mismatch is not enough to fail CI.
        fmt::Printf!("[!!] %d row(s) diverge from Go\n", bad as i64);
        goish::os::Exit(1);
    }
}
