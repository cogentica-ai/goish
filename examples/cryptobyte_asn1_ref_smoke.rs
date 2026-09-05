// cryptobyte_asn1_ref_smoke — the ASN.1 readers no example called,
// against a running Go 1.25.5.
//
// cryptobyte is what parses certificates and TLS messages, and thirteen
// of its exported readers were named by no example in the tree:
// ReadASN1BitString, ReadASN1Enum, ReadASN1ObjectIdentifier,
// ReadASN1Bytes, ReadAnyASN1Element, ReadASN1Int64WithTag,
// PeekASN1Tag, SkipASN1, SkipOptionalASN1, ReadOptionalASN1Boolean and
// friends. A parser that is too PERMISSIVE here accepts a malformed
// certificate and reports success, which is the direction that matters.
//
// All 13 lines match Go on the first run; nothing is fixed here. Three
// of them are the BIT STRING rules, which is where a plausible reader
// is too lax:
//
//   03 03 01 AB CC   accepted — 1 unused bit, and 0xCC's low bit is 0
//   03 03 01 AB CD   REFUSED — the padding bits in the final byte must
//                    be ZERO, and 0xCD has bit 0 set
//   03 02 09 FF      REFUSED — 9 unused bits, and the count must be 0-7
//   03 00            REFUSED — no room for the unused-bits octet
//
// Only the first of those four is obvious. A reader that skipped the
// padding-must-be-zero check would accept the second and hand back the
// same bytes, with nothing to show it had been lenient.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::crypto::cryptobyte::{self, asn1 as cbasn1};
use goish::encoding::asn1 as encoding_asn1;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::types::{byte, int};


fn s(b: &[byte]) -> cryptobyte::String {
    return cryptobyte::String(slice::__from_vec(b.to_vec()));
}

fn hex(b: &slice<byte>) -> string {
    let mut o = string::from("");
    for x in b.iter() {
        o = o + fmt::Sprintf!("%02x", *x as int);
    }
    return o;
}

const GO: [&str; 13] = [
    "bitstring                  ok=true bytes=abcc len=15",
    "bitstring-padnonzero       ok=false",
    "bitstring-badunused        ok=false",
    "bitstring-empty            ok=false",
    "enum                       ok=true v=5",
    "oid                        ok=true oid=1.2.840.113549",
    "peek                       int=true octet=false",
    "skip                       ok=true remaining=0402aabb",
    "skip-optional-absent       ok=true remaining=0402aabb",
    "optional-bool              ok=true v=true",
    "readasn1bytes              ok=true 010203",
    "readanyelement             ok=true elem=3003020109 rest=ff",
    "int64withtag               ok=true v=256",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let mut bs = s(&[0x03, 0x03, 0x01, 0xAB, 0xCC]);
    let mut b = encoding_asn1::BitString::default();
    let ok = bs.ReadASN1BitString(&mut b);
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v bytes=%s len=%d", "bitstring", ok, hex(&b.Bytes), b.BitLength as int));

    let mut sp = s(&[0x03, 0x03, 0x01, 0xAB, 0xCD]);
    let mut bp = encoding_asn1::BitString::default();
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v", "bitstring-padnonzero", sp.ReadASN1BitString(&mut bp)));

    let mut s2 = s(&[0x03, 0x02, 0x09, 0xFF]);
    let mut b2 = encoding_asn1::BitString::default();
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v", "bitstring-badunused", s2.ReadASN1BitString(&mut b2)));

    let mut s3 = s(&[0x03, 0x00]);
    let mut b3 = encoding_asn1::BitString::default();
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v", "bitstring-empty", s3.ReadASN1BitString(&mut b3)));

    let mut e = s(&[0x0a, 0x01, 0x05]);
    let mut ev: int = 0;
    let ok = e.ReadASN1Enum(&mut ev);
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v v=%d", "enum", ok, ev));

    let mut o = s(&[0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]);
    let mut oid = encoding_asn1::ObjectIdentifier::default();
    let ok = o.ReadASN1ObjectIdentifier(&mut oid);
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v oid=%v", "oid", ok, oid.String()));

    let mut p = s(&[0x02, 0x01, 0x07, 0x04, 0x02, 0xaa, 0xbb]);
    chk(&mut ln, &fmt::Sprintf!("%-26s int=%v octet=%v", "peek",
        p.PeekASN1Tag(cbasn1::INTEGER), p.PeekASN1Tag(cbasn1::OCTET_STRING)));
    let ok = p.SkipASN1(cbasn1::INTEGER);
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v remaining=%s", "skip", ok, hex(&p.0)));
    let ok = p.SkipOptionalASN1(cbasn1::INTEGER);
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v remaining=%s", "skip-optional-absent", ok, hex(&p.0)));

    let mut ob = s(&[0xa0, 0x03, 0x01, 0x01, 0xff]);
    let mut bv = false;
    let ok = ob.ReadOptionalASN1Boolean(&mut bv, cbasn1::Tag(0).ContextSpecific().Constructed(), false);
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v v=%v", "optional-bool", ok, bv));

    let mut rb = s(&[0x04, 0x03, 0x01, 0x02, 0x03]);
    let mut raw: slice<byte> = slice::new();
    let ok = rb.ReadASN1Bytes(&mut raw, cbasn1::OCTET_STRING);
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v %s", "readasn1bytes", ok, hex(&raw)));

    let mut el = s(&[0x30, 0x03, 0x02, 0x01, 0x09, 0xff]);
    let mut elem = cryptobyte::String::default();
    let mut tag = cbasn1::Tag(0);
    let ok = el.ReadAnyASN1Element(&mut elem, &mut tag);
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v elem=%s rest=%s", "readanyelement", ok, hex(&elem.0), hex(&el.0)));

    let mut i64s = s(&[0x02, 0x02, 0x01, 0x00]);
    let mut iv: i64 = 0;
    let ok = i64s.ReadASN1Int64WithTag(&mut iv, cbasn1::INTEGER);
    chk(&mut ln, &fmt::Sprintf!("%-26s ok=%v v=%d", "int64withtag", ok, iv));
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
