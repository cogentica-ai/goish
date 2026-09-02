// asn1_ref_smoke — encoding/asn1's DER parsers against a running Go.
// (encoding/asn1/asn1.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_asn1_ref.go` run in
// `package asn1` by `scripts/goref.sh` — an INTERNAL test, because the
// functions that matter here are unexported.
//
// encoding/asn1 parses DER that arrives inside X.509 certificates, so
// every input it sees came from somewhere the process did not choose,
// and goish had 3983 lines of it with no reference test. DER is a
// length-prefixed format, which means nearly all of its failure modes
// are the same shape: a length that does not match the data, and a
// parser that believes it. Go refuses each with a SPECIFIC message, and
// those messages are the contract — a port that answers "some error"
// cannot tell a caller whether a certificate was truncated, malformed,
// or merely of a type it does not handle.
//
// What is pinned, because a plausible port gets it wrong while every
// well-formed certificate still parses:
//
//   * DER is the CANONICAL encoding, not merely a valid one. A length
//     that could have been written in fewer bytes, a leading zero on a
//     positive integer, an indefinite length, a bit string with a
//     non-zero unused-bit count on an empty body — all are REFUSED, not
//     accepted-and-normalised. Accepting them is how two parsers come
//     to disagree about what one certificate says, which is the shape
//     of a whole family of certificate-confusion attacks.
//   * Integers are minimally encoded two's complement, so 0x80 is -128
//     while 0x0080 is a refusal rather than 128, and the int32/int64
//     overflow boundaries each have their own message.
//   * A tag byte of 0x1f introduces a multi-byte tag whose continuation
//     bytes are base-128 with the same no-leading-zero rule.
//   * The string types differ in exactly which bytes they refuse, and
//     PrintableString's set is the surprising one ('*' and '&' are out,
//     '\'' is in).
//   * UTCTime's two-digit year pivots at 50, and both time forms demand
//     a zone.
//
// goish matched Go on all 69 lines — every refusal, every error text,
// every boundary. For a DER parser that had never been diffed, that is
// the result worth recording.
//
// One gap was found and closed on the way: ObjectIdentifier had no fmt
// bridge at all, so `%v` on an OID did not compile. Go's OID satisfies
// Stringer, so `%v` prints the dotted form; certificate-handling code
// prints OIDs constantly, and goish could not print one.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::encoding::asn1;
use goish::errors;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::syscall;
use goish::time;
use goish::types::{byte, int};

fn b(v: &[u8]) -> slice<byte> {
    return slice::__from_vec(v.to_vec());
}
fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 69] = [
    "tagandlen bool-1            -> class=0 tag=1 compound=false len=1 off=2",
    "tagandlen int-1             -> class=0 tag=2 compound=false len=1 off=2",
    "tagandlen long-form-2       -> class=0 tag=4 compound=false len=256 off=4",
    "tagandlen indefinite        -> err=\"asn1: syntax error: indefinite length found (not DER)\"",
    "tagandlen non-minimal-len   -> err=\"asn1: structure error: non-minimal length\"",
    "tagandlen len-overflow      -> err=\"asn1: structure error: length too large\"",
    "tagandlen truncated-len     -> err=\"asn1: syntax error: truncated tag or length\"",
    "tagandlen empty             -> err=\"asn1: internal error in parseTagAndLength\"",
    "tagandlen tag-only          -> err=\"asn1: syntax error: truncated tag or length\"",
    "tagandlen high-tag          -> class=0 tag=128 compound=false len=0 off=4",
    "tagandlen high-tag-lead0    -> err=\"asn1: syntax error: integer is not minimally encoded\"",
    "tagandlen len-zero-longform -> err=\"asn1: syntax error: indefinite length found (not DER)\"",
    "int zero        -> i64=0                     err64=<nil>                    i32=0            err32=<nil>                    big=0",
    "int one         -> i64=1                     err64=<nil>                    i32=1            err32=<nil>                    big=1",
    "int 127         -> i64=127                   err64=<nil>                    i32=127          err32=<nil>                    big=127",
    "int neg128      -> i64=-128                  err64=<nil>                    i32=-128         err32=<nil>                    big=-128",
    "int 128         -> i64=128                   err64=<nil>                    i32=128          err32=<nil>                    big=128",
    "int neg1        -> i64=-1                    err64=<nil>                    i32=-1           err32=<nil>                    big=-1",
    "int lead-zero   -> check-err=\"asn1: structure error: integer not minimally-encoded\"",
    "int lead-ff     -> check-err=\"asn1: structure error: integer not minimally-encoded\"",
    "int empty       -> check-err=\"asn1: structure error: empty integer\"",
    "int maxint64    -> i64=9223372036854775807   err64=<nil>                    i32=0            err32=asn1: structure error: integer too large big=9223372036854775807",
    "int over-int64  -> i64=0                     err64=asn1: structure error: integer too large i32=0            err32=asn1: structure error: integer too large big=18446744073709551616",
    "bitstring empty           -> bits=0 bytes= at0=0 at1=0 atLast=0",
    "bitstring one-byte        -> bits=8 bytes=ff at0=1 at1=1 atLast=1",
    "bitstring 3-unused        -> bits=5 bytes=f8 at0=1 at1=1 atLast=1",
    "bitstring 8-unused        -> err=\"asn1: syntax error: invalid padding bits in BIT STRING\"",
    "bitstring empty-with-pad  -> err=\"asn1: syntax error: invalid padding bits in BIT STRING\"",
    "bitstring no-bytes        -> err=\"asn1: syntax error: zero length BIT STRING\"",
    "bitstring 9-unused        -> err=\"asn1: syntax error: invalid padding bits in BIT STRING\"",
    "oid 1.2.840.113549  -> 1.2.840.113549 str=1.2.840.113549",
    "oid 2.5.4.3         -> 2.5.4.3 str=2.5.4.3",
    "oid 0.0             -> 0.0 str=0.0",
    "oid 1.0             -> 1.0 str=1.0",
    "oid 2.999           -> 2.999 str=2.999",
    "oid empty           -> err=\"asn1: syntax error: zero length OBJECT IDENTIFIER\"",
    "oid trailing-cont   -> err=\"asn1: syntax error: truncated base 128 integer\"",
    "oid lead-zero-arc   -> err=\"asn1: syntax error: integer is not minimally encoded\"",
    "string printable printable-ok   -> \"Hello 'World'\"",
    "string printable printable-star -> \"a*b\"",
    "string printable printable-amp  -> \"a&b\"",
    "string printable printable-at   -> err=\"asn1: syntax error: PrintableString contains invalid character\"",
    "string ia5       ia5-ok         -> \"user@example.com\"",
    "string ia5       ia5-high       -> err=\"asn1: syntax error: IA5String contains invalid character\"",
    "string numeric   numeric-ok     -> \"12 34\"",
    "string numeric   numeric-bad    -> err=\"asn1: syntax error: NumericString contains invalid character\"",
    "string utf8      utf8-ok        -> \"日本語\"",
    "string utf8      utf8-bad       -> err=\"asn1: invalid UTF-8 string\"",
    "utctime \"910506164540-0700\" -> 1991-05-06T16:45:40-07:00",
    "utctime \"910506164540Z\"    -> 1991-05-06T16:45:40Z",
    "utctime \"9105061645Z\"      -> 1991-05-06T16:45:00Z",
    "utctime \"500101000000Z\"    -> 1950-01-01T00:00:00Z",
    "utctime \"490101000000Z\"    -> 2049-01-01T00:00:00Z",
    "utctime \"910506164540\"     -> err=\"parsing time \\\"910506164540\\\" as \\\"060102150405Z0700\\\": cannot parse \\\"\\\" as \\\"Z0700\\\"\"",
    "utctime \"a10506164540Z\"    -> err=\"parsing time \\\"a10506164540Z\\\" as \\\"060102150405Z0700\\\": cannot parse \\\"a10506164540Z\\\" as \\\"06\\\"\"",
    "utctime \"9105061645401Z\"   -> err=\"parsing time \\\"9105061645401Z\\\" as \\\"060102150405Z0700\\\": cannot parse \\\"1Z\\\" as \\\"Z0700\\\"\"",
    "utctime \"910506164540+0700\" -> 1991-05-06T16:45:40+07:00",
    "utctime \"910506164540-2500\" -> err=\"parsing time \\\"910506164540-2500\\\": time zone offset hour out of range\"",
    "gentime \"20100102030405Z\"      -> 2010-01-02T03:04:05Z",
    "gentime \"20100102030405+0607\"  -> 2010-01-02T03:04:05+06:07",
    "gentime \"20100102030405\"       -> err=\"parsing time \\\"20100102030405\\\" as \\\"20060102150405.999999999Z0700\\\": cannot parse \\\"\\\" as \\\"Z0700\\\"\"",
    "gentime \"20100102030405.123Z\"  -> 2010-01-02T03:04:05Z",
    "gentime \"201001020304Z\"        -> err=\"parsing time \\\"201001020304Z\\\" as \\\"20060102150405.999999999Z0700\\\": cannot parse \\\"Z\\\" as \\\"05\\\"\"",
    "gentime \"20101302030405Z\"      -> err=\"parsing time \\\"20101302030405Z\\\": month out of range\"",
    "bool false       -> false",
    "bool true        -> true",
    "bool non-canon   -> err=\"asn1: syntax error: invalid boolean\"",
    "bool empty       -> err=\"asn1: syntax error: invalid boolean\"",
    "bool two-bytes   -> err=\"asn1: syntax error: invalid boolean\"",
];

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
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

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;

    // 1
    let tl: [(&str, &[u8]); 12] = [
        ("bool-1", &[0x01, 0x01, 0xff]),
        ("int-1", &[0x02, 0x01, 0x2a]),
        ("long-form-2", &[0x04, 0x82, 0x01, 0x00]),
        ("indefinite", &[0x30, 0x80]),
        ("non-minimal-len", &[0x04, 0x81, 0x01, 0x61]),
        ("len-overflow", &[0x04, 0x85, 0x01, 0x01, 0x01, 0x01, 0x01]),
        ("truncated-len", &[0x04, 0x82, 0x01]),
        ("empty", &[]),
        ("tag-only", &[0x04]),
        ("high-tag", &[0x1f, 0x81, 0x00, 0x00]),
        ("high-tag-lead0", &[0x1f, 0x80, 0x01, 0x00]),
        ("len-zero-longform", &[0x04, 0x80]),
    ];
    for (name, v) in tl.iter() {
        let (ret, off, err) = asn1::ParseTagAndLength(b(v), 0);
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("tagandlen %-17s -> err=%q", s(name), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "tagandlen %-17s -> class=%d tag=%d compound=%v len=%d off=%d",
                s(name),
                ret.class,
                ret.tag,
                ret.isCompound,
                ret.length,
                off
            ),
        );
    }
    // 2
    let ints: [(&str, &[u8]); 11] = [
        ("zero", &[0x00]),
        ("one", &[0x01]),
        ("127", &[0x7f]),
        ("neg128", &[0x80]),
        ("128", &[0x00, 0x80]),
        ("neg1", &[0xff]),
        ("lead-zero", &[0x00, 0x01]),
        ("lead-ff", &[0xff, 0x80]),
        ("empty", &[]),
        (
            "maxint64",
            &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
        (
            "over-int64",
            &[0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ),
    ];
    for (name, v) in ints.iter() {
        let cerr = asn1::CheckInteger(b(v));
        if !cerr.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("int %-11s -> check-err=%q", s(name), cerr.Error()),
            );
            continue;
        }
        let (i64v, err64) = asn1::ParseInt64(b(v));
        let (i32v, err32) = asn1::ParseInt32(b(v));
        let (bi, errbi) = asn1::ParseBigInt(b(v));
        let bs = if errbi.IsNil() {
            bi.String()
        } else {
            s("err:") + errbi.Error()
        };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "int %-11s -> i64=%-21d err64=%-24v i32=%-12d err32=%-24v big=%s",
                s(name),
                i64v,
                err64,
                i32v as i64,
                err32,
                bs
            ),
        );
    }
    // 3
    let bits: [(&str, &[u8]); 7] = [
        ("empty", &[0x00]),
        ("one-byte", &[0x00, 0xff]),
        ("3-unused", &[0x03, 0xf8]),
        ("8-unused", &[0x08, 0xff]),
        ("empty-with-pad", &[0x03]),
        ("no-bytes", &[]),
        ("9-unused", &[0x09, 0xff]),
    ];
    for (name, v) in bits.iter() {
        let (bs, err) = asn1::ParseBitString(b(v));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("bitstring %-15s -> err=%q", s(name), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "bitstring %-15s -> bits=%d bytes=%x at0=%d at1=%d atLast=%d",
                s(name),
                bs.BitLength,
                bs.Bytes.clone(),
                bs.At(0),
                bs.At(1),
                bs.At(bs.BitLength - 1)
            ),
        );
    }
    // 4
    let oids: [(&str, &[u8]); 8] = [
        ("1.2.840.113549", &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d]),
        ("2.5.4.3", &[0x55, 0x04, 0x03]),
        ("0.0", &[0x00]),
        ("1.0", &[0x28]),
        ("2.999", &[0x88, 0x37]),
        ("empty", &[]),
        ("trailing-cont", &[0x2a, 0x86]),
        ("lead-zero-arc", &[0x2a, 0x80, 0x01]),
    ];
    for (name, v) in oids.iter() {
        let (oid, err) = asn1::ParseObjectIdentifier(b(v));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("oid %-15s -> err=%q", s(name), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("oid %-15s -> %v str=%s", s(name), oid.clone(), oid.String()),
        );
    }
    // 5
    let strs: [(&str, &[u8]); 10] = [
        ("printable-ok", b"Hello 'World'"),
        ("printable-star", b"a*b"),
        ("printable-amp", b"a&b"),
        ("printable-at", b"a@b"),
        ("ia5-ok", b"user@example.com"),
        ("ia5-high", &[b'a', 0x80, b'b']),
        ("numeric-ok", b"12 34"),
        ("numeric-bad", b"12a"),
        ("utf8-ok", "日本語".as_bytes()),
        ("utf8-bad", &[b'a', 0xff, b'b']),
    ];
    for (name, v) in strs.iter() {
        let (got, err, kind) = if name.starts_with("printable") {
            let (g, e) = asn1::ParsePrintableString(b(v));
            (g, e, "printable")
        } else if name.starts_with("ia5") {
            let (g, e) = asn1::ParseIA5String(b(v));
            (g, e, "ia5")
        } else if name.starts_with("numeric") {
            let (g, e) = asn1::ParseNumericString(b(v));
            (g, e, "numeric")
        } else {
            let (g, e) = asn1::ParseUTF8String(b(v));
            (g, e, "utf8")
        };
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("string %-9s %-14s -> err=%q", s(kind), s(name), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("string %-9s %-14s -> %q", s(kind), s(name), got),
        );
    }
    // 6
    for v in [
        "910506164540-0700",
        "910506164540Z",
        "9105061645Z",
        "500101000000Z",
        "490101000000Z",
        "910506164540",
        "a10506164540Z",
        "9105061645401Z",
        "910506164540+0700",
        "910506164540-2500",
    ] {
        let (tm, err) = asn1::ParseUTCTime(b(v.as_bytes()));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("utctime %-18q -> err=%q", s(v), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("utctime %-18q -> %s", s(v), tm.Format(time::RFC3339)),
        );
    }
    for v in [
        "20100102030405Z",
        "20100102030405+0607",
        "20100102030405",
        "20100102030405.123Z",
        "201001020304Z",
        "20101302030405Z",
    ] {
        let (tm, err) = asn1::ParseGeneralizedTime(b(v.as_bytes()));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("gentime %-22q -> err=%q", s(v), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("gentime %-22q -> %s", s(v), tm.Format(time::RFC3339)),
        );
    }
    // 7
    let bools: [(&str, &[u8]); 5] = [
        ("false", &[0x00]),
        ("true", &[0xff]),
        ("non-canon", &[0x01]),
        ("empty", &[]),
        ("two-bytes", &[0x00, 0x00]),
    ];
    for (name, v) in bools.iter() {
        let (val, err) = asn1::ParseBool(b(v));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("bool %-11s -> err=%q", s(name), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("bool %-11s -> %v", s(name), val),
        );
    }
    let _ = errors::nil;
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
