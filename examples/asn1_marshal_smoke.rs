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
    __makeBigInt, __makeGeneralizedTime, __makeUTCTime, __outsideUTCRange, __setEncoder,
    __stringEncoder, __stripTagAndLength, __taggedEncoder,
    getUniversalType, parseFieldParameters,
    Enumerated, Marshal, MarshalWithParams, ObjectIdentifier, RawValue,
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


// Go-shape fixtures for the Marshal cases; the `asn1:"…"` tags are what
// makeField reads back out of the reflect descriptor.
#[goish::reflect]
pub struct simple {
    pub A: i64,
    pub B: bool,
}

#[goish::reflect]
pub struct tagged {
    #[tag(r#"asn1:"tag:0""#)]
    pub A: i64,
    #[tag(r#"asn1:"explicit,tag:1""#)]
    pub B: i64,
}

#[goish::reflect]
pub struct optdefault {
    #[tag(r#"asn1:"optional,default:7""#)]
    pub A: i64,
    pub B: i64,
}

#[goish::reflect]
pub struct strs {
    #[tag(r#"asn1:"printable""#)]
    pub P: goish::string,
    #[tag(r#"asn1:"ia5""#)]
    pub I: goish::string,
    #[tag(r#"asn1:"utf8""#)]
    pub U: goish::string,
}

#[goish::reflect]
pub struct setish {
    #[tag(r#"asn1:"set""#)]
    pub S: goish::slice<i64>,
}

#[goish::reflect]
pub struct omit {
    #[tag(r#"asn1:"omitempty""#)]
    pub S: goish::slice<i64>,
    pub A: i64,
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


    // ─── parseFieldParameters (common.go) ─────────────────────────────
    //
    // Columns: optional, explicit, application, private, defaultValue,
    // tag, stringType, timeType, set, omitEmpty — as the Go reference
    // printed them.
    let fp: [(&str, bool, bool, bool, bool, Option<i64>, Option<i64>, i64, i64, bool, bool); 32] = [
        ("", false, false, false, false, None, None, 0, 0, false, false),
        ("optional", true, false, false, false, None, None, 0, 0, false, false),
        ("explicit", false, true, false, false, None, Some(0), 0, 0, false, false),
        ("generalized", false, false, false, false, None, None, 0, 24, false, false),
        ("utc", false, false, false, false, None, None, 0, 23, false, false),
        ("ia5", false, false, false, false, None, None, 22, 0, false, false),
        ("printable", false, false, false, false, None, None, 19, 0, false, false),
        ("numeric", false, false, false, false, None, None, 18, 0, false, false),
        ("utf8", false, false, false, false, None, None, 12, 0, false, false),
        ("set", false, false, false, false, None, None, 0, 0, true, false),
        ("application", false, false, true, false, None, Some(0), 0, 0, false, false),
        ("private", false, false, false, true, None, Some(0), 0, 0, false, false),
        ("omitempty", false, false, false, false, None, None, 0, 0, false, true),
        ("tag:5", false, false, false, false, None, Some(5), 0, 0, false, false),
        ("tag:0", false, false, false, false, None, Some(0), 0, 0, false, false),
        ("tag:-3", false, false, false, false, None, Some(-3), 0, 0, false, false),
        ("tag:notanumber", false, false, false, false, None, None, 0, 0, false, false),
        ("tag:", false, false, false, false, None, None, 0, 0, false, false),
        ("default:42", false, false, false, false, Some(42), None, 0, 0, false, false),
        ("default:-7", false, false, false, false, Some(-7), None, 0, 0, false, false),
        ("default:9223372036854775807", false, false, false, false, Some(9223372036854775807), None, 0, 0, false, false),
        ("default:bad", false, false, false, false, None, None, 0, 0, false, false),
        ("optional,explicit,tag:2", true, true, false, false, None, Some(2), 0, 0, false, false),
        ("explicit,tag:7", false, true, false, false, None, Some(7), 0, 0, false, false),
        ("tag:7,explicit", false, true, false, false, None, Some(7), 0, 0, false, false),
        ("application,tag:3", false, false, true, false, None, Some(3), 0, 0, false, false),
        ("private,tag:4", false, false, false, true, None, Some(4), 0, 0, false, false),
        ("optional,omitempty,set,utf8", true, false, false, false, None, None, 12, 0, true, true),
        ("unknown,optional", true, false, false, false, None, None, 0, 0, false, false),
        ("ia5,printable", false, false, false, false, None, None, 19, 0, false, false),
        ("utc,generalized", false, false, false, false, None, None, 0, 24, false, false),
        (",,optional,,", true, false, false, false, None, None, 0, 0, false, false),
    ];
    let mut idx: i64 = 0;
    for &(tagstr, opt, exp, app, priv_, dv, tg, st, tt, set, omit) in fp.iter() {
        let p = parseFieldParameters(tagstr);
        let ok = p.optional == opt
            && p.explicit == exp
            && p.application == app
            && p.private == priv_
            && p.defaultValue == dv
            && p.tag == tg
            && p.stringType == st
            && p.timeType == tt
            && p.set == set
            && p.omitEmpty == omit;
        check(ok, "parseFieldParameters #", idx);
        idx += 1;
    }


    // ─── type identity for getUniversalType ───────────────────────────
    //
    // Go's getUniversalType opens by matching six type identities. That
    // needs ObjectIdentifier and Enumerated to be defined types, not
    // aliases, and every one of them to have a reflect::Type. These
    // assertions are what makes that switch representable at all.
    use goish::reflect::{Kind, Reflect, TypeOfDyn};

    let oidT = TypeOfDyn::<ObjectIdentifier>();
    let intsT = TypeOfDyn::<slice<i64>>();
    check(
        oidT.Name().as_bytes() == b"ObjectIdentifier" && oidT.Kind() == Kind::Slice,
        "ObjectIdentifier has its own reflect::Type",
        0,
    );
    check(
        oidT.Name().as_bytes() != intsT.Name().as_bytes(),
        "ObjectIdentifier is distinguishable from slice<int>",
        0,
    );

    let enumT = TypeOfDyn::<Enumerated>();
    let intT = TypeOfDyn::<i64>();
    check(
        enumT.Name().as_bytes() == b"Enumerated" && enumT.Kind() == Kind::Int,
        "Enumerated has its own reflect::Type",
        0,
    );
    check(
        enumT.Name().as_bytes() != intT.Name().as_bytes(),
        "Enumerated is distinguishable from int",
        0,
    );

    let bsT = TypeOfDyn::<BitString>();
    check(
        bsT.Name().as_bytes() == b"BitString" && bsT.Kind() == Kind::Struct && bsT.NumField() == 2,
        "BitString has its own reflect::Type",
        2,
    );
    let rvT = TypeOfDyn::<goish::encoding::asn1::RawValue>();
    check(
        rvT.Name().as_bytes() == b"RawValue" && rvT.Kind() == Kind::Struct && rvT.NumField() == 5,
        "RawValue has its own reflect::Type",
        5,
    );

    // The values round-trip through reflect too.
    let oid = ObjectIdentifier::New(slice::__from_vec(alloc::vec![1i64, 2, 840]));
    check(oid.Len() == 3 && oid.String().as_bytes() == b"1.2.840", "OID String", 3);
    let oid2 = ObjectIdentifier::New(slice::__from_vec(alloc::vec![1i64, 2, 840]));
    check(oid.Equal(&oid2), "ObjectIdentifier.Equal is a method now", 0);
    // An ObjectIdentifier reflects as a *named* slice: Kind stays Slice
    // and the elements are still reachable, but Type().Name() survives —
    // without which makeBody cannot tell an OID from any other []int and
    // encodes it as a SEQUENCE OF INTEGER.
    let oidv = oid.__reflect_value();
    check(
        matches!(oidv, goish::reflect::Value::Named { .. })
            && oidv.Kind() == Kind::Slice
            && oidv.Type().Name().as_bytes() == b"ObjectIdentifier"
            && oidv.Len() == 3
            && oidv.Index(2).Int() == 840,
        "OID reflects as a named slice",
        0,
    );


    // ─── getUniversalType (common.go) ─────────────────────────────────
    //
    // Columns are the Go reference's (matchAny, tagNumber, isCompound, ok).
    // The six identity rows are the ones that were unrepresentable until
    // ObjectIdentifier and Enumerated became defined types and all six
    // gained a reflect::Type.
    fn gut(t: &goish::reflect::Type) -> (bool, i64, bool, bool) {
        return getUniversalType(t);
    }

    let ident: [(&'static str, goish::reflect::Type, bool, i64, bool, bool); 6] = [
        ("RawValue", TypeOfDyn::<RawValue>(), true, -1, false, true),
        ("ObjectIdentifier", TypeOfDyn::<ObjectIdentifier>(), false, 6, false, true),
        ("BitString", TypeOfDyn::<BitString>(), false, 3, false, true),
        ("time.Time", TypeOfDyn::<goish::time::Time>(), false, 23, false, true),
        ("Enumerated", TypeOfDyn::<Enumerated>(), false, 10, false, true),
        ("big.Int", TypeOfDyn::<goish::math::big::Int>(), false, 2, false, true),
    ];
    let mut k: i64 = 0;
    for (_, t, ma, tn, ic, ok) in ident.iter() {
        let g = gut(t);
        check(g == (*ma, *tn, *ic, *ok), "getUniversalType identity #", k);
        k += 1;
    }

    // Kind-driven rows.
    check(gut(&TypeOfDyn::<bool>()) == (false, 1, false, true), "gut bool", 1);
    check(gut(&TypeOfDyn::<i64>()) == (false, 2, false, true), "gut int", 2);
    check(gut(&TypeOfDyn::<i8>()) == (false, 2, false, true), "gut int8", 2);
    check(gut(&TypeOfDyn::<i16>()) == (false, 2, false, true), "gut int16", 2);
    check(gut(&TypeOfDyn::<i32>()) == (false, 2, false, true), "gut int32", 2);
    check(gut(&TypeOfDyn::<slice<byte>>()) == (false, 4, false, true), "gut []byte", 4);
    check(gut(&TypeOfDyn::<slice<i64>>()) == (false, 16, true, true), "gut []int", 16);
    check(gut(&TypeOfDyn::<goish::string>()) == (false, 19, false, true), "gut string", 19);
    check(gut(&TypeOfDyn::<u64>()) == (false, 0, false, false), "gut uint rejected", 0);
    check(gut(&TypeOfDyn::<f64>()) == (false, 0, false, false), "gut float64 rejected", 0);


    // ─── makeBigInt / stripTagAndLength ───────────────────────────────
    let bi: [(&str, i64, &str); 16] = [
        ("0", 1, "00"), ("1", 1, "01"), ("127", 1, "7f"), ("128", 2, "0080"),
        ("255", 2, "00ff"), ("256", 2, "0100"), ("32767", 2, "7fff"), ("32768", 3, "008000"),
        ("-1", 1, "ff"), ("-128", 1, "80"), ("-129", 2, "ff7f"), ("-255", 2, "ff01"),
        ("-256", 2, "ff00"), ("-32768", 2, "8000"),
        ("123456789012345678901234567890", 13, "018ee90ff6c373e0ee4e3f0ad2"),
        ("-123456789012345678901234567890", 13, "fe7116f0093c8c1f11b1c0f52e"),
    ];
    let mut bidx: i64 = 0;
    for &(dec, wantLen, wantHex) in bi.iter() {
        bidx += 1;
        let mut n = goish::math::big::Int::default();
        let ok = n.SetString(dec, 10);
        if !ok.1 { check(false, "big::Int::SetString", 0); continue; }
        let (e, err) = __makeBigInt(&n);
        check(
            err == goish::nil && e.Len() == wantLen && encOf(&*e) == unhex(wantHex),
            "makeBigInt #",
            bidx,
        );
    }

    let strips: [(&str, &str); 5] = [
        ("020105", "05"), ("0403deadbe", "deadbe"), ("30050203010203", "0203010203"),
        ("02", "02"), ("0481c8", ""),
    ];
    for &(inHex, wantHex) in strips.iter() {
        let got = __stripTagAndLength(slice::__from_vec(unhex(inHex)));
        check(got.__into_vec() == unhex(wantHex), "stripTagAndLength", 0);
    }


    // ─── UTCTime / GeneralizedTime ────────────────────────────────────
    //
    // goish's time is UTC-only, so these are the seven UTC rows of the Go
    // reference. Its three zoned rows — +0100 "240307090501+0100",
    // -0500 "240307090501-0500", +0130 "240307090501+0130" — are recorded
    // here for when goish's time grows zones; appendTimeCommon already
    // encodes them.
    let times: [(i64, i64, i64, i64, i64, i64, bool, &str, &str); 7] = [
        (1949, 12, 31, 23, 59, 59, true, "", "19491231235959Z"),
        (1950, 1, 1, 0, 0, 0, false, "500101000000Z", "19500101000000Z"),
        (1999, 12, 31, 23, 59, 59, false, "991231235959Z", "19991231235959Z"),
        (2000, 1, 1, 0, 0, 0, false, "000101000000Z", "20000101000000Z"),
        (2024, 3, 7, 9, 5, 1, false, "240307090501Z", "20240307090501Z"),
        (2049, 12, 31, 23, 59, 59, false, "491231235959Z", "20491231235959Z"),
        (2050, 1, 1, 0, 0, 0, true, "", "20500101000000Z"),
    ];
    for &(y, mo, d, h, mi, sec, outside, wantUTC, wantGen) in times.iter() {
        let tm = goish::time::Date(y, mo, d, h, mi, sec, 0, goish::time::UTC);
        check(__outsideUTCRange(tm) == outside, "outsideUTCRange y=", y);

        let (e, err) = __makeUTCTime(tm);
        if wantUTC.is_empty() {
            check(err != goish::nil, "makeUTCTime rejects y=", y);
        } else {
            check(
                err == goish::nil && encOf(&*e) == wantUTC.as_bytes().to_vec(),
                "makeUTCTime y=",
                y,
            );
        }

        let (e, err) = __makeGeneralizedTime(tm);
        check(
            err == goish::nil && encOf(&*e) == wantGen.as_bytes().to_vec(),
            "makeGeneralizedTime y=",
            y,
        );
    }

    // ─── Marshal / MarshalWithParams — every expectation from
    //     `scripts/goref.sh encoding/asn1` on Go 1.25.5 ──────────────────

    fn mh<T: goish::reflect::Reflect>(v: &T, want: &str, n: i64) {
        let (b, err) = Marshal(v);
        check(err == goish::nil && b.__into_vec() == unhex(want), "Marshal", n);
    }
    fn mp<T: goish::reflect::Reflect>(v: &T, params: &'static str, want: &str, n: i64) {
        let (b, err) = MarshalWithParams(v, params);
        check(
            err == goish::nil && b.__into_vec() == unhex(want),
            "MarshalWithParams",
            n,
        );
    }

    mh(&true, "0101ff", 1);
    mh(&false, "010100", 2);
    mh(&0_i64, "020100", 3);
    mh(&127_i64, "02017f", 4);
    mh(&128_i64, "02020080", 5);
    mh(&(-1_i64), "0201ff", 6);
    mh(&65535_i64, "020300ffff", 7);
    mh(&goish::string("hello"), "130568656c6c6f", 8);
    mh(
        &goish::string("user@example.com"),
        "0c1075736572406578616d706c652e636f6d",
        9,
    );
    mh(
        &slice::__from_vec(alloc::vec![1u8, 2, 3]),
        "0403010203",
        10,
    );
    mh(
        &ObjectIdentifier::New(slice::__from_vec(alloc::vec![1_i64, 2, 840, 113549])),
        "06062a864886f70d",
        11,
    );
    mh(
        &BitString {
            Bytes: slice::__from_vec(alloc::vec![0x80u8]),
            BitLength: 1,
        },
        "03020780",
        12,
    );
    mh(&Enumerated(4), "0a0104", 13);
    mh(&goish::math::big::NewInt(123456789), "0204075bcd15", 14);
    mh(&goish::math::big::NewInt(-42), "0201d6", 15);

    // time.Date(2026, 8, 11, 12, 0, 0, 0, UTC) and a post-2050 value that
    // forces GeneralizedTime.
    let tm = goish::time::Date(
        2026,
        goish::time::August,
        11,
        12,
        0,
        0,
        0,
        goish::time::UTC,
    );
    mh(&tm, "170d3236303831313132303030305a", 16);
    mp(&tm, "generalized", "180f32303236303831313132303030305a", 17);
    let tm2 = goish::time::Date(
        2051,
        goish::time::January,
        2,
        3,
        4,
        5,
        0,
        goish::time::UTC,
    );
    mh(&tm2, "180f32303531303130323033303430355a", 18);

    mh(&simple { A: 5, B: true }, "30060201050101ff", 19);
    mh(&tagged { A: 1, B: 2 }, "3008800101a103020102", 20);
    mh(&optdefault { A: 7, B: 1 }, "3003020101", 21);
    mh(&optdefault { A: 8, B: 1 }, "3006020108020101", 22);
    mh(
        &strs {
            P: goish::string("abc"),
            I: goish::string("a@b"),
            U: goish::string("h\u{e9}"),
        },
        "300f130361626316036140620c0368c3a9",
        23,
    );
    mh(
        &setish {
            S: slice::__from_vec(alloc::vec![3_i64, 1, 2]),
        },
        "300b3109020101020102020103",
        24,
    );
    mh(
        &omit {
            S: slice::__from_vec(alloc::vec![]),
            A: 9,
        },
        "3003020109",
        25,
    );
    mh(
        &omit {
            S: slice::__from_vec(alloc::vec![1_i64]),
            A: 9,
        },
        "30083003020101020109",
        26,
    );

    mh(
        &slice::__from_vec(alloc::vec![1_i64, 2, 3]),
        "3009020101020102020103",
        27,
    );
    mh(&slice::__from_vec(alloc::vec![] as alloc::vec::Vec<i64>), "3000", 28);
    mh(
        &slice::__from_vec(alloc::vec![goish::string("a"), goish::string("b")]),
        "3006130161130162",
        29,
    );

    mh(
        &RawValue {
            Class: 0,
            Tag: 2,
            IsCompound: false,
            Bytes: slice::__from_vec(alloc::vec![0x2au8]),
            FullBytes: slice::__from_vec(alloc::vec![]),
        },
        "02012a",
        30,
    );
    mh(
        &RawValue {
            Class: 0,
            Tag: 0,
            IsCompound: false,
            Bytes: slice::__from_vec(alloc::vec![]),
            FullBytes: slice::__from_vec(alloc::vec![0x02u8, 0x01, 0x2a]),
        },
        "02012a",
        31,
    );

    mp(&5_i64, "tag:2", "820105", 32);
    mp(&5_i64, "explicit,tag:2", "a203020105", 33);
    mp(&5_i64, "application,tag:3", "430105", 34);
    mp(&5_i64, "private,tag:4", "c40105", 35);
    mp(&goish::string("abc"), "ia5", "1603616263", 36);
    mp(&goish::string("123"), "numeric", "1203313233", 37);

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("asn1_marshal_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!("asn1_marshal_smoke FAILED %d of %d\n", failed as i64, ran as i64);
        goish::syscall::Exit(1);
    }
}
