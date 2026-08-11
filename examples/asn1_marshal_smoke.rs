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
    BitString, TagAndLength, __appendBase128Int, __appendLength, __appendTagAndLength,
    __base128IntLength, __bitStringEncoder, __byteEncoder, __bytesEncoder, __encoder,
    __int64Encoder, __lengthLength, __makeIA5String, __makeNumericString,
    __makeObjectIdentifier, __makePrintableString, __makeUTF8String, __multiEncoder,
    __setEncoder, __stringEncoder, __taggedEncoder,
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


    // ─── encoder layer ────────────────────────────────────────────────
    //
    // Each case is `enc(e)` from the Go reference: allocate e.Len() bytes,
    // Encode into them, compare.
    fn encOf(e: &dyn __encoder) -> Vec<byte> {
        let mut dst = slice::__from_vec(alloc::vec![0u8; e.Len() as usize]);
        e.Encode(&mut dst);
        return dst.__into_vec();
    }

    check(encOf(&__byteEncoder(0x2a)) == unhex("2a"), "byteEncoder", 0x2a);
    let be = __bytesEncoder(slice::__from_vec(alloc::vec![1u8, 2, 3]));
    check(be.Len() == 3 && encOf(&be) == unhex("010203"), "bytesEncoder", 3);
    let se = __stringEncoder(goish::string("hi!"));
    check(se.Len() == 3 && encOf(&se) == unhex("686921"), "stringEncoder", 3);

    let ints: [(i64, i64, &str); 12] = [
        (0, 1, "00"), (1, 1, "01"), (127, 1, "7f"), (128, 2, "0080"),
        (-1, 1, "ff"), (-128, 1, "80"), (-129, 2, "ff7f"), (255, 2, "00ff"),
        (256, 2, "0100"), (-32768, 2, "8000"), (2147483647, 4, "7fffffff"),
        (-2147483648, 4, "80000000"),
    ];
    for &(n, wantLen, wantHex) in ints.iter() {
        let e = __int64Encoder(n);
        check(e.Len() == wantLen && encOf(&e) == unhex(wantHex), "int64Encoder", n);
    }

    let bits: [(&[u8], i64, i64, &str); 5] = [
        (&[0x80], 1, 2, "0780"), (&[0xf0], 4, 2, "04f0"), (&[0xff], 8, 2, "00ff"),
        (&[0xff, 0xc0], 10, 3, "06ffc0"), (&[], 0, 1, "00"),
    ];
    for &(by, bl, wantLen, wantHex) in bits.iter() {
        let e = __bitStringEncoder(BitString {
            Bytes: slice::__from_vec(by.to_vec()),
            BitLength: bl,
        });
        check(e.Len() == wantLen && encOf(&e) == unhex(wantHex), "bitStringEncoder bits=", bl);
    }

    let oids: [(&[i64], i64, &str); 5] = [
        (&[1, 2, 840, 113549, 1, 1, 11], 9, "2a864886f70d01010b"),
        (&[2, 5, 4, 3], 3, "550403"),
        (&[1, 3, 6, 1, 5, 5, 7, 3, 1], 8, "2b06010505070301"),
        (&[0, 0], 1, "00"),
        (&[2, 100, 3], 3, "813403"),
    ];
    for &(o, wantLen, wantHex) in oids.iter() {
        let (e, err) = __makeObjectIdentifier(slice::__from_vec(o.to_vec()));
        check(
            err == goish::nil && e.Len() == wantLen && encOf(&e) == unhex(wantHex),
            "makeObjectIdentifier len=",
            wantLen,
        );
    }
    for bad in [&[1i64][..], &[3, 1][..], &[1, 40][..], &[][..]].iter() {
        let (_, err) = __makeObjectIdentifier(slice::__from_vec(bad.to_vec()));
        check(err != goish::nil, "makeObjectIdentifier rejects", bad.len() as i64);
    }

    for &(s, ok) in [("hello", true), ("a*b", true), ("a&b", false), ("caf\u{e9}", false)].iter() {
        let (_, err) = __makePrintableString(s);
        check((err == goish::nil) == ok, "makePrintableString", ok as i64);
    }
    for &(s, ok) in [("ok", true), ("caf\u{e9}", false)].iter() {
        let (_, err) = __makeIA5String(s);
        check((err == goish::nil) == ok, "makeIA5String", ok as i64);
    }
    for &(s, ok) in [("123 456", true), ("12a", false)].iter() {
        let (_, err) = __makeNumericString(s);
        check((err == goish::nil) == ok, "makeNumericString", ok as i64);
    }
    let u = __makeUTF8String("caf\u{e9}");
    check(u.Len() == 5 && encOf(&u) == unhex("636166c3a9"), "makeUTF8String", 5);


    // ─── composite encoders ───────────────────────────────────────────
    fn bx(v: &[u8]) -> alloc::boxed::Box<dyn __encoder> {
        return alloc::boxed::Box::new(__bytesEncoder(slice::__from_vec(v.to_vec())));
    }

    // multiEncoder concatenates in order.
    let m = __multiEncoder::New(slice::__from_vec(alloc::vec![
        bx(&[0x01, 0x02]),
        bx(&[0x03]),
        alloc::boxed::Box::new(__byteEncoder(0xff)),
    ]));
    check(m.Len() == 4 && encOf(&m) == unhex("010203ff"), "multiEncoder", 4);

    // setEncoder sorts the encoded elements as octet strings (X690 11.6).
    let s1 = __setEncoder::New(slice::__from_vec(alloc::vec![
        bx(&[0x30, 0x02]),
        bx(&[0x02, 0x01, 0x05]),
        bx(&[0x0c, 0x01, 0x41]),
    ]));
    check(s1.Len() == 8 && encOf(&s1) == unhex("0201050c01413002"), "setEncoder sorts", 8);

    // Same first octet, differing lengths — the length octet decides.
    let s2 = __setEncoder::New(slice::__from_vec(alloc::vec![
        bx(&[0x04, 0x02, 0xff, 0xff]),
        bx(&[0x04, 0x01, 0x00]),
        bx(&[0x04, 0x03, 0x00, 0x00, 0x00]),
    ]));
    check(
        s2.Len() == 12 && encOf(&s2) == unhex("0401000402ffff0403000000"),
        "setEncoder length ordering",
        12,
    );

    // taggedEncoder: tag octets then body.
    let tagBuf = __appendTagAndLength(
        empty(),
        &TagAndLength { class: 0, tag: 2, length: 1, isCompound: false },
    );
    let te = __taggedEncoder::New(
        alloc::boxed::Box::new(__bytesEncoder(tagBuf)),
        alloc::boxed::Box::new(__int64Encoder(5)),
    );
    check(te.Len() == 3 && encOf(&te) == unhex("020105"), "taggedEncoder", 3);

    let tagBuf2 = __appendTagAndLength(
        empty(),
        &TagAndLength { class: 0, tag: 4, length: 3, isCompound: false },
    );
    let te2 = __taggedEncoder::New(
        alloc::boxed::Box::new(__bytesEncoder(tagBuf2)),
        bx(&[0xde, 0xad, 0xbe]),
    );
    check(te2.Len() == 5 && encOf(&te2) == unhex("0403deadbe"), "taggedEncoder octets", 5);

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("asn1_marshal_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!("asn1_marshal_smoke FAILED %d of %d\n", failed as i64, ran as i64);
        goish::syscall::Exit(1);
    }
}
