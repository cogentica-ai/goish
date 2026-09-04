// cryptobyte_ref_smoke — cryptobyte against a running Go.
// (vendor/golang.org/x/crypto/cryptobyte: string.go, asn1.go, builder.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_cryptobyte_ref.go` run in
// `package cryptobyte` by `scripts/goref.sh`.
//
// cryptobyte is the parsing primitive underneath crypto/x509 and
// crypto/tls: every certificate field and every handshake message is
// pulled out of a []byte by these methods. It is built so a parser
// CANNOT read past the end of what it was given — each read returns a
// bool and consumes nothing on failure — which makes the refusals the
// substance of the package rather than an edge case in it.
//
// 152 of 153 lines matched on the first run. The one that did not was
// NewFixedBuilder, and it was broken outright:
//
//   Go's NewBuilder keeps the caller's BACKING ARRAY, length and
//   capacity both. goish copied the contents out through a `&[byte]`,
//   which preserved the length and flattened the capacity to match it.
//   For a growing builder that is invisible. For a fixed one it is
//   fatal — the constructor exists precisely to bound writes by the
//   CAPACITY, so the idiomatic `NewFixedBuilder(make([]byte, 0, n))`
//   had room for nothing and failed on its first byte. Nothing in tree
//   called it, which is exactly why it could stay broken: an API whose
//   only use is by callers you have not written yet is one no existing
//   test can reach.
//
// The seven fixed-builder cases here all give the buffer a capacity
// larger than its length, because that difference IS the constructor,
// and they pin the bound in both directions: writing to capacity
// succeeds, one byte past it errors, and a prefilled buffer counts its
// existing contents.
//
// What else is pinned:
//
//   * Every fixed-width read against eight input lengths, checking the
//     REMAINDER as well as the bool — a failed read must consume
//     nothing, or a caller can half-parse.
//   * Length-prefixed reads whose prefix exceeds what is left. "u8-max"
//     and "u16-huge" are the shape of a hostile length field.
//   * ASN.1 INTEGER must be DER: minimal encoding, no non-sign leading
//     zero, no empty contents. Accepting a non-minimal integer means
//     two encodings of the same serial number, so a certificate can be
//     "the same" and "different" at once. Note that "non-minimal-0080"
//     IS accepted while "leading-zero-pad" is not — the rule is subtler
//     than "no leading zeros" and worth having in writing.
//   * An integer that does not FIT its destination fails rather than
//     truncating, in both signed and unsigned directions: max-uint64
//     reads as a uint64 and refuses as an int64.
//   * Indefinite length is refused (it is BER, not DER), long-form
//     lengths must be minimal, and a five-byte length is rejected.
//   * The builder's length back-patching across the 127/128 and
//     255/256 boundaries, where a one-byte placeholder has to GROW to
//     three and shift everything after it.
//   * UTCTime and GeneralizedTime, which decide whether a certificate
//     has expired, including the offset and fractional-second forms.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::crypto::cryptobyte::asn1 as cbasn1;
use goish::crypto::cryptobyte::{Builder, NewFixedBuilder, String as CBString};
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::syscall;
use goish::time;
use goish::types::{byte, int, int64, uint16, uint32, uint64, uint8};
const GO: [&str; 153] = [
    "u8   empty  -> ok=false v=0 rest=",
    "u16  empty  -> ok=false v=0 rest=",
    "u24  empty  -> ok=false v=0 rest=",
    "u32  empty  -> ok=false v=0 rest=",
    "u48  empty  -> ok=false v=0 rest=",
    "u64  empty  -> ok=false v=0 rest=",
    "rb3  empty  -> ok=false v= rest=",
    "skip4 empty -> ok=false rest= empty=true",
    "u8   one    -> ok=true  v=255 rest=",
    "u16  one    -> ok=false v=0 rest=ff",
    "u24  one    -> ok=false v=0 rest=ff",
    "u32  one    -> ok=false v=0 rest=ff",
    "u48  one    -> ok=false v=0 rest=ff",
    "u64  one    -> ok=false v=0 rest=ff",
    "rb3  one    -> ok=false v= rest=ff",
    "skip4 one   -> ok=false rest=ff empty=false",
    "u8   two    -> ok=true  v=1 rest=02",
    "u16  two    -> ok=true  v=258 rest=",
    "u24  two    -> ok=false v=0 rest=0102",
    "u32  two    -> ok=false v=0 rest=0102",
    "u48  two    -> ok=false v=0 rest=0102",
    "u64  two    -> ok=false v=0 rest=0102",
    "rb3  two    -> ok=false v= rest=0102",
    "skip4 two   -> ok=false rest=0102 empty=false",
    "u8   three  -> ok=true  v=1 rest=0203",
    "u16  three  -> ok=true  v=258 rest=03",
    "u24  three  -> ok=true  v=66051 rest=",
    "u32  three  -> ok=false v=0 rest=010203",
    "u48  three  -> ok=false v=0 rest=010203",
    "u64  three  -> ok=false v=0 rest=010203",
    "rb3  three  -> ok=true  v=010203 rest=",
    "skip4 three -> ok=false rest=010203 empty=false",
    "u8   four   -> ok=true  v=1 rest=020304",
    "u16  four   -> ok=true  v=258 rest=0304",
    "u24  four   -> ok=true  v=66051 rest=04",
    "u32  four   -> ok=true  v=16909060 rest=",
    "u48  four   -> ok=false v=0 rest=01020304",
    "u64  four   -> ok=false v=0 rest=01020304",
    "rb3  four   -> ok=true  v=010203 rest=04",
    "skip4 four  -> ok=true  rest= empty=true",
    "u8   six    -> ok=true  v=1 rest=0203040506",
    "u16  six    -> ok=true  v=258 rest=03040506",
    "u24  six    -> ok=true  v=66051 rest=040506",
    "u32  six    -> ok=true  v=16909060 rest=0506",
    "u48  six    -> ok=true  v=1108152157446 rest=",
    "u64  six    -> ok=false v=0 rest=010203040506",
    "rb3  six    -> ok=true  v=010203 rest=040506",
    "skip4 six   -> ok=true  rest=0506 empty=false",
    "u8   eight  -> ok=true  v=1 rest=02030405060708",
    "u16  eight  -> ok=true  v=258 rest=030405060708",
    "u24  eight  -> ok=true  v=66051 rest=0405060708",
    "u32  eight  -> ok=true  v=16909060 rest=05060708",
    "u48  eight  -> ok=true  v=1108152157446 rest=0708",
    "u64  eight  -> ok=true  v=72623859790382856 rest=",
    "rb3  eight  -> ok=true  v=010203 rest=0405060708",
    "skip4 eight -> ok=true  rest=05060708 empty=false",
    "u8   nine   -> ok=true  v=1 rest=0203040506070809",
    "u16  nine   -> ok=true  v=258 rest=03040506070809",
    "u24  nine   -> ok=true  v=66051 rest=040506070809",
    "u32  nine   -> ok=true  v=16909060 rest=0506070809",
    "u48  nine   -> ok=true  v=1108152157446 rest=070809",
    "u64  nine   -> ok=true  v=72623859790382856 rest=09",
    "rb3  nine   -> ok=true  v=010203 rest=040506070809",
    "skip4 nine  -> ok=true  rest=0506070809 empty=false",
    "lp u8-exact     -> ok=true  inner=616263   rest=",
    "lp u8-extra     -> ok=true  inner=616263   rest=64",
    "lp u8-short     -> ok=false inner=         rest=61",
    "lp u8-zero      -> ok=true  inner=         rest=ff",
    "lp u8-empty     -> ok=false inner=         rest=",
    "lp u8-len-only  -> ok=false inner=         rest=",
    "lp u8-max       -> ok=false inner=         rest=61",
    "lp u16-exact    -> ok=true  inner=616263   rest=",
    "lp u16-short    -> ok=false inner=         rest=61",
    "lp u16-huge     -> ok=false inner=         rest=616263",
    "lp u24-exact    -> ok=true  inner=616263   rest=",
    "lp u24-huge     -> ok=false inner=         rest=61",
    "int zero                 -> i64ok=true  i64=0                     u64ok=true  u64=0                    rest=",
    "int one                  -> i64ok=true  i64=1                     u64ok=true  u64=1                    rest=",
    "int 127                  -> i64ok=true  i64=127                   u64ok=true  u64=127                  rest=",
    "int 128                  -> i64ok=true  i64=128                   u64ok=true  u64=128                  rest=",
    "int neg-one              -> i64ok=true  i64=-1                    u64ok=false u64=0                    rest=",
    "int neg-128              -> i64ok=true  i64=-128                  u64ok=false u64=0                    rest=",
    "int neg-129              -> i64ok=true  i64=-129                  u64ok=false u64=0                    rest=",
    "int non-minimal-0080     -> i64ok=true  i64=128                   u64ok=true  u64=128                  rest=",
    "int leading-zero-pad     -> i64ok=false i64=0                     u64ok=false u64=0                    rest=",
    "int double-leading-zero  -> i64ok=false i64=0                     u64ok=false u64=0                    rest=",
    "int empty-contents       -> i64ok=false i64=0                     u64ok=false u64=0                    rest=",
    "int ff-pad-negative      -> i64ok=false i64=0                     u64ok=false u64=0                    rest=",
    "int max-int64            -> i64ok=true  i64=9223372036854775807   u64ok=true  u64=9223372036854775807  rest=",
    "int over-int64           -> i64ok=false i64=0                     u64ok=true  u64=9223372036854775808  rest=",
    "int max-uint64           -> i64ok=false i64=0                     u64ok=true  u64=18446744073709551615 rest=",
    "int wrong-tag            -> i64ok=false i64=0                     u64ok=false u64=0                    rest=",
    "int truncated-len        -> i64ok=false i64=0                     u64ok=false u64=0                    rest=02030101",
    "int trailing             -> i64ok=true  i64=1                     u64ok=true  u64=1                    rest=020102",
    "asn1 seq-empty              -> seq=true  inner=             any=true  tag=48 anyinner=             bool=false v=false bits=false bs= rest=",
    "asn1 seq-one-int            -> seq=true  inner=020101       any=true  tag=48 anyinner=020101       bool=false v=false bits=false bs= rest=",
    "asn1 seq-short              -> seq=false inner=             any=false tag=48 anyinner=             bool=false v=false bits=false bs= rest=3005020101",
    "asn1 seq-long-form-len      -> seq=false inner=             any=false tag=48 anyinner=             bool=false v=false bits=false bs= rest=308100",
    "asn1 seq-long-form-1        -> seq=false inner=             any=false tag=48 anyinner=             bool=false v=false bits=false bs= rest=30810103",
    "asn1 non-minimal-long-len   -> seq=false inner=             any=false tag=48 anyinner=             bool=false v=false bits=false bs= rest=3081007f",
    "asn1 indefinite-len         -> seq=false inner=             any=false tag=48 anyinner=             bool=false v=false bits=false bs= rest=30800201010000",
    "asn1 len-5-bytes            -> seq=false inner=             any=false tag=48 anyinner=             bool=false v=false bits=false bs= rest=3085000000000103",
    "asn1 nested                 -> seq=true  inner=3003020101   any=true  tag=48 anyinner=3003020101   bool=false v=false bits=false bs= rest=",
    "asn1 tag-mismatch           -> seq=false inner=020101       any=true  tag=49 anyinner=020101       bool=false v=false bits=false bs= rest=",
    "asn1 octet-string           -> seq=false inner=616263       any=true  tag=4 anyinner=616263       bool=false v=false bits=false bs= rest=",
    "asn1 octet-string-short     -> seq=false inner=             any=false tag=4 anyinner=             bool=false v=false bits=false bs= rest=040361",
    "asn1 boolean-true           -> seq=false inner=ff           any=true  tag=1 anyinner=ff           bool=true  v=true  bits=false bs= rest=",
    "asn1 boolean-false          -> seq=false inner=00           any=true  tag=1 anyinner=00           bool=true  v=false bits=false bs= rest=",
    "asn1 boolean-bad            -> seq=false inner=01           any=true  tag=1 anyinner=01           bool=false v=false bits=false bs= rest=",
    "asn1 boolean-long           -> seq=false inner=00ff         any=true  tag=1 anyinner=00ff         bool=false v=false bits=false bs= rest=",
    "asn1 bitstring              -> seq=false inner=04f0f0       any=true  tag=3 anyinner=04f0f0       bool=false v=false bits=false bs= rest=",
    "asn1 bitstring-empty        -> seq=false inner=00           any=true  tag=3 anyinner=00           bool=false v=false bits=true  bs= rest=",
    "asn1 bitstring-bad-pad      -> seq=false inner=             any=false tag=3 anyinner=             bool=false v=false bits=false bs= rest=030308f0",
    "asn1 bitstring-no-pad-byte  -> seq=false inner=             any=true  tag=3 anyinner=             bool=false v=false bits=false bs= rest=",
    "asn1 oid-rsa                -> seq=false inner=2a864886f70d010101 any=true  tag=6 anyinner=2a864886f70d010101 bool=false v=false bits=false bs= rest=",
    "asn1 oid-empty              -> seq=false inner=             any=true  tag=6 anyinner=             bool=false v=false bits=false bs= rest=",
    "asn1 oid-trailing-high-bit  -> seq=false inner=808080       any=true  tag=6 anyinner=808080       bool=false v=false bits=false bs= rest=",
    "asn1 null                   -> seq=false inner=             any=true  tag=5 anyinner=             bool=false v=false bits=false bs= rest=",
    "time utc-basic        -> utc=true  gen=false t=2020-01-02T03:04:05Z",
    "time utc-no-seconds   -> utc=true  gen=false t=2020-01-02T03:04:00Z",
    "time utc-offset       -> utc=true  gen=false t=2020-01-02T02:04:05Z",
    "time utc-bad          -> utc=false gen=false t=<zero>",
    "time gen-basic        -> utc=false gen=true  t=2020-01-02T03:04:05Z",
    "time gen-fractional   -> utc=false gen=false t=<zero>",
    "time gen-no-z         -> utc=false gen=false t=<zero>",
    "opt present            -> ok=true  present=true  inner=020101     optint-ok=true  v=1   rest=",
    "opt absent             -> ok=true  present=false inner=           optint-ok=true  v=-1  rest=020102",
    "opt empty-input        -> ok=true  present=false inner=           optint-ok=true  v=-1  rest=",
    "opt wrong-tag          -> ok=true  present=false inner=           optint-ok=true  v=-1  rest=a103020101",
    "opt present-bad-inner  -> ok=true  present=true  inner=0401ff     optint-ok=false v=0   rest=",
    "build fixed-widths -> 0102030405060708090a0b0c0d0e0f101112131415161718 err=<nil>",
    "build nested-prefix -> 0761626300026465 err=<nil>",
    "build u8-overflow -> n=0 err=cryptobyte: pending child length 256 exceeds 1-byte length prefix",
    "build fixed-exact           len=0 cap=4 write=4 -> n=4  out=00000000         err=<nil>",
    "build fixed-under           len=0 cap=8 write=4 -> n=4  out=00000000         err=<nil>",
    "build fixed-over            len=0 cap=4 write=5 -> n=0  out=                 err=cryptobyte: Builder is exceeding its fixed-size buffer",
    "build fixed-zero-cap        len=0 cap=0 write=1 -> n=0  out=                 err=cryptobyte: Builder is exceeding its fixed-size buffer",
    "build fixed-prefilled       len=2 cap=6 write=4 -> n=6  out=2e2e00000000     err=<nil>",
    "build fixed-prefilled-over  len=2 cap=6 write=5 -> n=0  out=                 err=cryptobyte: Builder is exceeding its fixed-size buffer",
    "build fixed-write-nothing   len=0 cap=4 write=0 -> n=0  out=                 err=<nil>",
    "build fixed-prefixed -> 03616263 err=<nil>",
    "build unwrite -> \"abcd\" err=<nil>",
    "build asn1-seq -> 300702010104026869 err=<nil>",
    "build asn1-roundtrip -> read=true inner=02010104026869",
    "build asn1-len 0      -> total=2      head=0400         ok=true  innerlen=0      err=<nil>",
    "build asn1-len 127    -> total=129    head=047f00000000 ok=true  innerlen=127    err=<nil>",
    "build asn1-len 128    -> total=131    head=048180000000 ok=true  innerlen=128    err=<nil>",
    "build asn1-len 255    -> total=258    head=0481ff000000 ok=true  innerlen=255    err=<nil>",
    "build asn1-len 256    -> total=260    head=048201000000 ok=true  innerlen=256    err=<nil>",
    "build asn1-len 300    -> total=304    head=0482012c0000 ok=true  innerlen=300    err=<nil>",
    "build asn1-len 65535  -> total=65539  head=0482ffff0000 ok=true  innerlen=65535  err=<nil>",
    "build asn1-len 65536  -> total=65541  head=048301000000 ok=true  innerlen=65536  err=<nil>",
    "build nested-grow -> 000a05696e6e65727461696c err=<nil>",
];

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

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn h(x: &str) -> slice<byte> {
    let mut clean: Vec<u8> = Vec::new();
    for b in x.as_bytes() {
        if *b != b' ' {
            clean.push(*b);
        }
    }
    let (out, _err) = hex::DecodeString(core::str::from_utf8(&clean).unwrap());
    return out;
}
fn hx(b: &slice<byte>) -> string {
    return hex::EncodeToString(&b.to_vec());
}
fn rest(x: &CBString) -> string {
    return hx(&x.0);
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let widths: [(&str, &str); 8] = [
        ("empty", ""),
        ("one", "ff"),
        ("two", "0102"),
        ("three", "010203"),
        ("four", "01020304"),
        ("six", "010203040506"),
        ("eight", "0102030405060708"),
        ("nine", "010203040506070809"),
    ];
    for (name, hexs) in widths.iter() {
        let d = h(hexs);
        let mut u8v: uint8 = 0;
        let mut u16v: uint16 = 0;
        let mut u24v: uint32 = 0;
        let mut u32v: uint32 = 0;
        let mut u48v: uint64 = 0;
        let mut u64v: uint64 = 0;
        let mut st = CBString::New(d.clone());
        let ok = st.ReadUint8(&mut u8v);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "u8   %-6s -> ok=%-5v v=%d rest=%s",
                s(name),
                ok,
                u8v,
                rest(&st)
            ),
        );
        let mut st = CBString::New(d.clone());
        let ok = st.ReadUint16(&mut u16v);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "u16  %-6s -> ok=%-5v v=%d rest=%s",
                s(name),
                ok,
                u16v,
                rest(&st)
            ),
        );
        let mut st = CBString::New(d.clone());
        let ok = st.ReadUint24(&mut u24v);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "u24  %-6s -> ok=%-5v v=%d rest=%s",
                s(name),
                ok,
                u24v,
                rest(&st)
            ),
        );
        let mut st = CBString::New(d.clone());
        let ok = st.ReadUint32(&mut u32v);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "u32  %-6s -> ok=%-5v v=%d rest=%s",
                s(name),
                ok,
                u32v,
                rest(&st)
            ),
        );
        let mut st = CBString::New(d.clone());
        let ok = st.ReadUint48(&mut u48v);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "u48  %-6s -> ok=%-5v v=%d rest=%s",
                s(name),
                ok,
                u48v,
                rest(&st)
            ),
        );
        let mut st = CBString::New(d.clone());
        let ok = st.ReadUint64(&mut u64v);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "u64  %-6s -> ok=%-5v v=%d rest=%s",
                s(name),
                ok,
                u64v,
                rest(&st)
            ),
        );
        let mut st = CBString::New(d.clone());
        let mut out = slice::<byte>::__from_vec(Vec::new());
        let ok = st.ReadBytes(&mut out, 3);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "rb3  %-6s -> ok=%-5v v=%s rest=%s",
                s(name),
                ok,
                hx(&out),
                rest(&st)
            ),
        );
        let mut st = CBString::New(d.clone());
        let ok = st.Skip(4);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "skip4 %-5s -> ok=%-5v rest=%s empty=%v",
                s(name),
                ok,
                rest(&st),
                st.Empty()
            ),
        );
    }
    let lps: [(&str, &str); 12] = [
        ("u8-exact", "03616263"),
        ("u8-extra", "0361626364"),
        ("u8-short", "0361"),
        ("u8-zero", "00ff"),
        ("u8-empty", ""),
        ("u8-len-only", "03"),
        ("u8-max", "ff61"),
        ("u16-exact", "0003616263"),
        ("u16-short", "000361"),
        ("u16-huge", "ffff616263"),
        ("u24-exact", "000003616263"),
        ("u24-huge", "ffffff61"),
    ];
    for (name, hexs) in lps.iter() {
        let d = h(hexs);
        let mut inner = CBString::New(slice::<byte>::__from_vec(Vec::new()));
        let mut st = CBString::New(d);
        let pfx = &name[..3];
        let ok = if pfx == "u8-" {
            st.ReadUint8LengthPrefixed(&mut inner)
        } else if pfx == "u16" {
            st.ReadUint16LengthPrefixed(&mut inner)
        } else {
            st.ReadUint24LengthPrefixed(&mut inner)
        };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "lp %-12s -> ok=%-5v inner=%-8s rest=%s",
                s(name),
                ok,
                rest(&inner),
                rest(&st)
            ),
        );
    }
    let ints: [(&str, &str); 18] = [
        ("zero", "020100"),
        ("one", "020101"),
        ("127", "02017f"),
        ("128", "0202 0080"),
        ("neg-one", "0201ff"),
        ("neg-128", "020180"),
        ("neg-129", "0202ff7f"),
        ("non-minimal-0080", "02020080"),
        ("leading-zero-pad", "0202 0001"),
        ("double-leading-zero", "0203000001"),
        ("empty-contents", "0200"),
        ("ff-pad-negative", "0202ffff"),
        ("max-int64", "02087fffffffffffffff"),
        ("over-int64", "0209 00 8000000000000000"),
        ("max-uint64", "0209 00 ffffffffffffffff"),
        ("wrong-tag", "040101"),
        ("truncated-len", "0203 0101"),
        ("trailing", "020101 020102"),
    ];
    for (name, hexs) in ints.iter() {
        let d = h(hexs);
        let mut i64v: int64 = 0;
        let mut u64v: uint64 = 0;
        let mut st = CBString::New(d.clone());
        let ok64 = st.ReadASN1Integer(&mut i64v);
        let mut st2 = CBString::New(d);
        let oku = st2.ReadASN1Integer(&mut u64v);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "int %-20s -> i64ok=%-5v i64=%-21d u64ok=%-5v u64=%-20d rest=%s",
                s(name),
                ok64,
                i64v,
                oku,
                u64v,
                rest(&st)
            ),
        );
    }
    let structs: [(&str, &str); 24] = [
        ("seq-empty", "3000"),
        ("seq-one-int", "3003020101"),
        ("seq-short", "3005020101"),
        ("seq-long-form-len", "308100 "),
        ("seq-long-form-1", "30810103"),
        ("non-minimal-long-len", "3081007f"),
        ("indefinite-len", "3080020101 0000"),
        ("len-5-bytes", "30850000000001 03"),
        ("nested", "3005300302 0101"),
        ("tag-mismatch", "3103020101"),
        ("octet-string", "0403616263"),
        ("octet-string-short", "040361"),
        ("boolean-true", "0101ff"),
        ("boolean-false", "010100"),
        ("boolean-bad", "010101"),
        ("boolean-long", "0102 00ff"),
        ("bitstring", "0303 04 f0f0"),
        ("bitstring-empty", "030100"),
        ("bitstring-bad-pad", "030308 f0"),
        ("bitstring-no-pad-byte", "0300"),
        ("oid-rsa", "06092a864886f70d010101"),
        ("oid-empty", "0600"),
        ("oid-trailing-high-bit", "060380 8080"),
        ("null", "0500"),
    ];
    for (name, hexs) in structs.iter() {
        let d = h(hexs);
        let empty = CBString::New(slice::<byte>::__from_vec(Vec::new()));
        let mut st = CBString::New(d.clone());
        let mut inner = empty.clone();
        let okSeq = st.ReadASN1(&mut inner, cbasn1::SEQUENCE);
        let mut st2 = CBString::New(d.clone());
        let mut anyTag = cbasn1::Tag(0);
        let mut anyInner = empty.clone();
        let okAny = st2.ReadAnyASN1(&mut anyInner, &mut anyTag);
        let mut st3 = CBString::New(d.clone());
        let mut b = false;
        let okBool = st3.ReadASN1Boolean(&mut b);
        let mut st4 = CBString::New(d);
        let mut bts = slice::<byte>::__from_vec(Vec::new());
        let okBits = st4.ReadASN1BitStringAsBytes(&mut bts);
        chk(&mut failed, &mut ln, fmt::Sprintf!(
            "asn1 %-22s -> seq=%-5v inner=%-12s any=%-5v tag=%d anyinner=%-12s bool=%-5v v=%-5v bits=%-5v bs=%s rest=%s",
            s(name), okSeq, rest(&inner), okAny, anyTag.0, rest(&anyInner),
            okBool, b, okBits, hx(&bts), rest(&st)
        ));
    }
    let times: [(&str, &str); 7] = [
        ("utc-basic", "170d3230303130323033303430355a"),
        ("utc-no-seconds", "170b323030313032303330345a"),
        ("utc-offset", "17113230303130323033303430352b30313030"),
        ("utc-bad", "170d78787878787878787878785a"),
        ("gen-basic", "180f32303230303130323033303430355a"),
        ("gen-fractional", "181332303230303130323033303430352e315a"),
        ("gen-no-z", "180e3230323030313032303330343035"),
    ];
    for (name, hexs) in times.iter() {
        let d = h(hexs);
        let mut tm = time::Time::default();
        let mut st = CBString::New(d.clone());
        let ok = st.ReadASN1UTCTime(&mut tm);
        let mut tm2 = time::Time::default();
        let mut st2 = CBString::New(d);
        let ok2 = st2.ReadASN1GeneralizedTime(&mut tm2);
        let show = if ok {
            tm.UTC().Format(s(time::RFC3339))
        } else if ok2 {
            tm2.UTC().Format(s(time::RFC3339))
        } else {
            s("<zero>")
        };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "time %-16s -> utc=%-5v gen=%-5v t=%s",
                s(name),
                ok,
                ok2,
                show
            ),
        );
    }
    let opts: [(&str, &str); 5] = [
        ("present", "a003020101"),
        ("absent", "020102"),
        ("empty-input", ""),
        ("wrong-tag", "a103020101"),
        ("present-bad-inner", "a0030401ff"),
    ];
    let ctag = cbasn1::Tag(0).Constructed().ContextSpecific();
    for (name, hexs) in opts.iter() {
        let d = h(hexs);
        let mut st = CBString::New(d.clone());
        let mut inner = CBString::New(slice::<byte>::__from_vec(Vec::new()));
        let mut present = false;
        let ok = st.ReadOptionalASN1(&mut inner, Some(&mut present), ctag);
        let mut st2 = CBString::New(d);
        let mut oi: int64 = 0;
        let ok2 = st2.ReadOptionalASN1Integer(&mut oi, ctag, -1i64);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "opt %-18s -> ok=%-5v present=%-5v inner=%-10s optint-ok=%-5v v=%-3d rest=%s",
                s(name),
                ok,
                present,
                rest(&inner),
                ok2,
                oi,
                rest(&st)
            ),
        );
    }
    {
        let mut b = goish::crypto::cryptobyte::NewBuilder(slice::<byte>::__from_vec(Vec::new()));
        b.AddUint8(1);
        b.AddUint16(0x0203);
        b.AddUint24(0x040506);
        b.AddUint32(0x0708090a);
        b.AddUint48(0x0b0c0d0e0f10);
        b.AddUint64(0x1112131415161718);
        let (out, err) = b.Bytes();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("build fixed-widths -> %s err=%s", hx(&out), errText(err)),
        );
    }
    {
        let mut b = goish::crypto::cryptobyte::NewBuilder(slice::<byte>::__from_vec(Vec::new()));
        b.AddUint8LengthPrefixed(|c: &mut Builder| {
            c.AddBytes(&slice::<byte>::__from_vec(b"abc".to_vec()));
            c.AddUint16LengthPrefixed(|d: &mut Builder| {
                d.AddBytes(&slice::<byte>::__from_vec(b"de".to_vec()));
            });
        });
        let (out, err) = b.Bytes();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("build nested-prefix -> %s err=%s", hx(&out), errText(err)),
        );
    }
    {
        let mut b = goish::crypto::cryptobyte::NewBuilder(slice::<byte>::__from_vec(Vec::new()));
        b.AddUint8LengthPrefixed(|c: &mut Builder| {
            c.AddBytes(&slice::<byte>::__from_vec(alloc::vec![0u8; 256]));
        });
        let (out, err) = b.Bytes();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("build u8-overflow -> n=%d err=%s", out.Len(), errText(err)),
        );
    }
    let fixed: [(&str, usize, usize, usize); 7] = [
        ("fixed-exact", 0, 4, 4),
        ("fixed-under", 0, 8, 4),
        ("fixed-over", 0, 4, 5),
        ("fixed-zero-cap", 0, 0, 1),
        ("fixed-prefilled", 2, 6, 4),
        ("fixed-prefilled-over", 2, 6, 5),
        ("fixed-write-nothing", 0, 4, 0),
    ];
    for (name, l, c, w) in fixed.iter() {
        let mut v: Vec<u8> = Vec::with_capacity(*c);
        for _ in 0..*l {
            v.push(0x2e);
        }
        let mut b = NewFixedBuilder(slice::<byte>::__from_vec(v));
        b.AddBytes(&slice::<byte>::__from_vec(alloc::vec![0u8; *w]));
        let (out, err) = b.Bytes();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "build %-21s len=%d cap=%d write=%d -> n=%-2d out=%-16s err=%s",
                s(name),
                *l as int,
                *c as int,
                *w as int,
                out.Len(),
                hx(&out),
                errText(err)
            ),
        );
    }
    {
        let mut b = NewFixedBuilder(slice::<byte>::__from_vec(Vec::with_capacity(4)));
        b.AddUint8LengthPrefixed(|c: &mut Builder| {
            c.AddBytes(&slice::<byte>::__from_vec(b"abc".to_vec()));
        });
        let (out, err) = b.Bytes();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("build fixed-prefixed -> %s err=%s", hx(&out), errText(err)),
        );
    }
    {
        let mut b = goish::crypto::cryptobyte::NewBuilder(slice::<byte>::__from_vec(Vec::new()));
        b.AddBytes(&slice::<byte>::__from_vec(b"abcdef".to_vec()));
        b.Unwrite(2);
        let (out, err) = b.Bytes();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "build unwrite -> %q err=%s",
                string::from_bytes(&out.to_vec()),
                errText(err)
            ),
        );
    }
    {
        let mut b = goish::crypto::cryptobyte::NewBuilder(slice::<byte>::__from_vec(Vec::new()));
        b.AddASN1(cbasn1::SEQUENCE, |c: &mut Builder| {
            c.AddBytes(&h("020101"));
            c.AddASN1(cbasn1::OCTET_STRING, |d: &mut Builder| {
                d.AddBytes(&slice::<byte>::__from_vec(b"hi".to_vec()));
            });
        });
        let (out, err) = b.Bytes();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("build asn1-seq -> %s err=%s", hx(&out), errText(err)),
        );
        let mut st = CBString::New(out);
        let mut inner = CBString::New(slice::<byte>::__from_vec(Vec::new()));
        let ok = st.ReadASN1(&mut inner, cbasn1::SEQUENCE);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("build asn1-roundtrip -> read=%v inner=%s", ok, rest(&inner)),
        );
    }
    for n in [0i64, 127, 128, 255, 256, 300, 65535, 65536] {
        let mut b = goish::crypto::cryptobyte::NewBuilder(slice::<byte>::__from_vec(Vec::new()));
        let nn = crate_usize(n);
        b.AddASN1(cbasn1::OCTET_STRING, |c: &mut Builder| {
            c.AddBytes(&slice::<byte>::__from_vec(alloc::vec![0u8; nn]));
        });
        let (out, err) = b.Bytes();
        let v = out.to_vec();
        let head = if v.len() > 6 { &v[..6] } else { &v[..] };
        let mut st = CBString::New(out.clone());
        let mut inner = CBString::New(slice::<byte>::__from_vec(Vec::new()));
        let ok = st.ReadASN1(&mut inner, cbasn1::OCTET_STRING);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "build asn1-len %-6d -> total=%-6d head=%-12s ok=%-5v innerlen=%-6d err=%s",
                n,
                out.Len(),
                hex::EncodeToString(head),
                ok,
                inner.0.Len(),
                errText(err)
            ),
        );
    }
    {
        let mut b = goish::crypto::cryptobyte::NewBuilder(slice::<byte>::__from_vec(Vec::new()));
        b.AddUint16LengthPrefixed(|c: &mut Builder| {
            c.AddUint8LengthPrefixed(|d: &mut Builder| {
                d.AddBytes(&slice::<byte>::__from_vec(b"inner".to_vec()));
            });
            c.AddBytes(&slice::<byte>::__from_vec(b"tail".to_vec()));
        });
        let (out, err) = b.Bytes();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("build nested-grow -> %s err=%s", hx(&out), errText(err)),
        );
    }
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
fn crate_usize(n: int64) -> usize {
    return goish::builtin::__make_size(n);
}
fn errText(err: goish::errors::error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    return err.Error();
}
