// base64_ref_smoke — encoding/base64 and encoding/base32 against a
// running Go. (encoding/base64/base64.go, encoding/base32/base32.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_base64_ref.go` run in
// `package base64_test` by `scripts/goref.sh`.
//
// These two decode data that arrived from somewhere else — a URL, a
// cookie, a JWT, a PEM body — so what they REFUSE matters as much as
// what they accept, and Go says exactly where the input went wrong:
// CorruptInputError carries the byte OFFSET, and this smoke pins every
// one of them.
//
// The rules a plausible port gets wrong while every round trip still
// works:
//
//   * Padding is part of the encoding, not decoration. StdEncoding
//     REQUIRES it and refuses a short final quantum; RawStdEncoding
//     refuses it when present. The two are not interchangeable, and a
//     decoder that tolerates both accepts strings Go rejects — which,
//     for anything that hashes or compares the decoded bytes, is how
//     two systems come to disagree about one token.
//   * The non-strict decoders IGNORE \r and \n ANYWHERE, including in
//     the middle of a quantum — that is what makes PEM work — and
//     ignore nothing else. A space is an error at its own offset.
//   * Strict() additionally refuses a final quantum whose unused
//     trailing bits are not zero, which is the canonicality check that
//     stops one value having two encodings: "Zg==" decodes but "Zh=="
//     is refused, even though both would give "f" without the check.
//   * The error OFFSET is the index of the offending byte, and for a
//     short input it is 0 rather than the last valid index — a
//     distinction only a reference test would settle.
//   * EncodedLen and DecodedLen differ between the padded and unpadded
//     encodings and are exact, not upper bounds, for the padded ones.
//
// goish matched Go on all 196 lines, first run, across four base64
// encodings and three base32 ones — including every offset, the custom
// alphabet, the custom pad byte, and base32's HexEncoding.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::encoding::base32;
use goish::encoding::base64;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::syscall;
use goish::types::{byte, int, rune};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn et(e: &error) -> string {
    if e.IsNil() {
        return s("<nil>");
    }
    return e.Error();
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 196] = [
    "enc std     \"\"        -> \"\"             elen=0 dlen=0",
    "enc std     \"f\"       -> \"Zg==\"         elen=4 dlen=3",
    "enc std     \"fo\"      -> \"Zm8=\"         elen=4 dlen=3",
    "enc std     \"foo\"     -> \"Zm9v\"         elen=4 dlen=3",
    "enc std     \"foob\"    -> \"Zm9vYg==\"     elen=8 dlen=6",
    "enc std     \"fooba\"   -> \"Zm9vYmE=\"     elen=8 dlen=6",
    "enc std     \"foobar\"  -> \"Zm9vYmFy\"     elen=8 dlen=6",
    "enc std     \"\\xff\\xef\\xfe\" -> \"/+/+\"         elen=4 dlen=3",
    "enc std     \"\\x00\\x00\\x00\" -> \"AAAA\"         elen=4 dlen=3",
    "enc std     \"sure.\"   -> \"c3VyZS4=\"     elen=8 dlen=6",
    "enc url     \"\"        -> \"\"             elen=0 dlen=0",
    "enc url     \"f\"       -> \"Zg==\"         elen=4 dlen=3",
    "enc url     \"fo\"      -> \"Zm8=\"         elen=4 dlen=3",
    "enc url     \"foo\"     -> \"Zm9v\"         elen=4 dlen=3",
    "enc url     \"foob\"    -> \"Zm9vYg==\"     elen=8 dlen=6",
    "enc url     \"fooba\"   -> \"Zm9vYmE=\"     elen=8 dlen=6",
    "enc url     \"foobar\"  -> \"Zm9vYmFy\"     elen=8 dlen=6",
    "enc url     \"\\xff\\xef\\xfe\" -> \"_-_-\"         elen=4 dlen=3",
    "enc url     \"\\x00\\x00\\x00\" -> \"AAAA\"         elen=4 dlen=3",
    "enc url     \"sure.\"   -> \"c3VyZS4=\"     elen=8 dlen=6",
    "enc rawstd  \"\"        -> \"\"             elen=0 dlen=0",
    "enc rawstd  \"f\"       -> \"Zg\"           elen=2 dlen=1",
    "enc rawstd  \"fo\"      -> \"Zm8\"          elen=3 dlen=2",
    "enc rawstd  \"foo\"     -> \"Zm9v\"         elen=4 dlen=3",
    "enc rawstd  \"foob\"    -> \"Zm9vYg\"       elen=6 dlen=4",
    "enc rawstd  \"fooba\"   -> \"Zm9vYmE\"      elen=7 dlen=5",
    "enc rawstd  \"foobar\"  -> \"Zm9vYmFy\"     elen=8 dlen=6",
    "enc rawstd  \"\\xff\\xef\\xfe\" -> \"/+/+\"         elen=4 dlen=3",
    "enc rawstd  \"\\x00\\x00\\x00\" -> \"AAAA\"         elen=4 dlen=3",
    "enc rawstd  \"sure.\"   -> \"c3VyZS4\"      elen=7 dlen=5",
    "enc rawurl  \"\"        -> \"\"             elen=0 dlen=0",
    "enc rawurl  \"f\"       -> \"Zg\"           elen=2 dlen=1",
    "enc rawurl  \"fo\"      -> \"Zm8\"          elen=3 dlen=2",
    "enc rawurl  \"foo\"     -> \"Zm9v\"         elen=4 dlen=3",
    "enc rawurl  \"foob\"    -> \"Zm9vYg\"       elen=6 dlen=4",
    "enc rawurl  \"fooba\"   -> \"Zm9vYmE\"      elen=7 dlen=5",
    "enc rawurl  \"foobar\"  -> \"Zm9vYmFy\"     elen=8 dlen=6",
    "enc rawurl  \"\\xff\\xef\\xfe\" -> \"_-_-\"         elen=4 dlen=3",
    "enc rawurl  \"\\x00\\x00\\x00\" -> \"AAAA\"         elen=4 dlen=3",
    "enc rawurl  \"sure.\"   -> \"c3VyZS4\"      elen=7 dlen=5",
    "dec std     \"Zg==\"     -> \"f\"",
    "dec std     \"Zm8=\"     -> \"fo\"",
    "dec std     \"Zm9v\"     -> \"foo\"",
    "dec std     \"Zg\"       -> err=\"illegal base64 data at input byte 0\"",
    "dec std     \"Zm8\"      -> err=\"illegal base64 data at input byte 0\"",
    "dec std     \"\"         -> \"\"",
    "dec std     \"=\"        -> err=\"illegal base64 data at input byte 0\"",
    "dec std     \"==\"       -> err=\"illegal base64 data at input byte 0\"",
    "dec std     \"===\"      -> err=\"illegal base64 data at input byte 0\"",
    "dec std     \"Z\"        -> err=\"illegal base64 data at input byte 0\"",
    "dec std     \"Zm9vYg==\" -> \"foob\"",
    "dec std     \"Zg=Z\"     -> err=\"illegal base64 data at input byte 2\"",
    "dec std     \"Z===\"     -> err=\"illegal base64 data at input byte 1\"",
    "dec std     \"Zm9v!\"    -> err=\"illegal base64 data at input byte 4\"",
    "dec std     \"Zm 9v\"    -> err=\"illegal base64 data at input byte 2\"",
    "dec std     \"Zm\\n9v\"   -> \"foo\"",
    "dec std     \"Zm\\r\\n9v\" -> \"foo\"",
    "dec std     \"-_8=\"     -> err=\"illegal base64 data at input byte 0\"",
    "dec std     \"+/8=\"     -> \"\\xfb\\xff\"",
    "dec std     \"Zm9vYmFy\" -> \"foobar\"",
    "dec url     \"Zg==\"     -> \"f\"",
    "dec url     \"Zm8=\"     -> \"fo\"",
    "dec url     \"Zm9v\"     -> \"foo\"",
    "dec url     \"Zg\"       -> err=\"illegal base64 data at input byte 0\"",
    "dec url     \"Zm8\"      -> err=\"illegal base64 data at input byte 0\"",
    "dec url     \"\"         -> \"\"",
    "dec url     \"=\"        -> err=\"illegal base64 data at input byte 0\"",
    "dec url     \"==\"       -> err=\"illegal base64 data at input byte 0\"",
    "dec url     \"===\"      -> err=\"illegal base64 data at input byte 0\"",
    "dec url     \"Z\"        -> err=\"illegal base64 data at input byte 0\"",
    "dec url     \"Zm9vYg==\" -> \"foob\"",
    "dec url     \"Zg=Z\"     -> err=\"illegal base64 data at input byte 2\"",
    "dec url     \"Z===\"     -> err=\"illegal base64 data at input byte 1\"",
    "dec url     \"Zm9v!\"    -> err=\"illegal base64 data at input byte 4\"",
    "dec url     \"Zm 9v\"    -> err=\"illegal base64 data at input byte 2\"",
    "dec url     \"Zm\\n9v\"   -> \"foo\"",
    "dec url     \"Zm\\r\\n9v\" -> \"foo\"",
    "dec url     \"-_8=\"     -> \"\\xfb\\xff\"",
    "dec url     \"+/8=\"     -> err=\"illegal base64 data at input byte 0\"",
    "dec url     \"Zm9vYmFy\" -> \"foobar\"",
    "dec rawstd  \"Zg==\"     -> err=\"illegal base64 data at input byte 2\"",
    "dec rawstd  \"Zm8=\"     -> err=\"illegal base64 data at input byte 3\"",
    "dec rawstd  \"Zm9v\"     -> \"foo\"",
    "dec rawstd  \"Zg\"       -> \"f\"",
    "dec rawstd  \"Zm8\"      -> \"fo\"",
    "dec rawstd  \"\"         -> \"\"",
    "dec rawstd  \"=\"        -> err=\"illegal base64 data at input byte 0\"",
    "dec rawstd  \"==\"       -> err=\"illegal base64 data at input byte 0\"",
    "dec rawstd  \"===\"      -> err=\"illegal base64 data at input byte 0\"",
    "dec rawstd  \"Z\"        -> err=\"illegal base64 data at input byte 0\"",
    "dec rawstd  \"Zm9vYg==\" -> err=\"illegal base64 data at input byte 6\"",
    "dec rawstd  \"Zg=Z\"     -> err=\"illegal base64 data at input byte 2\"",
    "dec rawstd  \"Z===\"     -> err=\"illegal base64 data at input byte 1\"",
    "dec rawstd  \"Zm9v!\"    -> err=\"illegal base64 data at input byte 4\"",
    "dec rawstd  \"Zm 9v\"    -> err=\"illegal base64 data at input byte 2\"",
    "dec rawstd  \"Zm\\n9v\"   -> \"foo\"",
    "dec rawstd  \"Zm\\r\\n9v\" -> \"foo\"",
    "dec rawstd  \"-_8=\"     -> err=\"illegal base64 data at input byte 0\"",
    "dec rawstd  \"+/8=\"     -> err=\"illegal base64 data at input byte 3\"",
    "dec rawstd  \"Zm9vYmFy\" -> \"foobar\"",
    "dec rawurl  \"Zg==\"     -> err=\"illegal base64 data at input byte 2\"",
    "dec rawurl  \"Zm8=\"     -> err=\"illegal base64 data at input byte 3\"",
    "dec rawurl  \"Zm9v\"     -> \"foo\"",
    "dec rawurl  \"Zg\"       -> \"f\"",
    "dec rawurl  \"Zm8\"      -> \"fo\"",
    "dec rawurl  \"\"         -> \"\"",
    "dec rawurl  \"=\"        -> err=\"illegal base64 data at input byte 0\"",
    "dec rawurl  \"==\"       -> err=\"illegal base64 data at input byte 0\"",
    "dec rawurl  \"===\"      -> err=\"illegal base64 data at input byte 0\"",
    "dec rawurl  \"Z\"        -> err=\"illegal base64 data at input byte 0\"",
    "dec rawurl  \"Zm9vYg==\" -> err=\"illegal base64 data at input byte 6\"",
    "dec rawurl  \"Zg=Z\"     -> err=\"illegal base64 data at input byte 2\"",
    "dec rawurl  \"Z===\"     -> err=\"illegal base64 data at input byte 1\"",
    "dec rawurl  \"Zm9v!\"    -> err=\"illegal base64 data at input byte 4\"",
    "dec rawurl  \"Zm 9v\"    -> err=\"illegal base64 data at input byte 2\"",
    "dec rawurl  \"Zm\\n9v\"   -> \"foo\"",
    "dec rawurl  \"Zm\\r\\n9v\" -> \"foo\"",
    "dec rawurl  \"-_8=\"     -> err=\"illegal base64 data at input byte 3\"",
    "dec rawurl  \"+/8=\"     -> err=\"illegal base64 data at input byte 0\"",
    "dec rawurl  \"Zm9vYmFy\" -> \"foobar\"",
    "strict \"Zg==\"   -> lax=\"f\"    laxerr=<nil>                        strict=\"f\"    stricterr=<nil>",
    "strict \"Zh==\"   -> lax=\"f\"    laxerr=<nil>                        strict=\"\"     stricterr=illegal base64 data at input byte 2",
    "strict \"Zm8=\"   -> lax=\"fo\"   laxerr=<nil>                        strict=\"fo\"   stricterr=<nil>",
    "strict \"Zm9=\"   -> lax=\"fo\"   laxerr=<nil>                        strict=\"\"     stricterr=illegal base64 data at input byte 3",
    "strict \"Zm9v\"   -> lax=\"foo\"  laxerr=<nil>                        strict=\"foo\"  stricterr=<nil>",
    "strict \"Zm\\n9v\" -> lax=\"foo\"  laxerr=<nil>                        strict=\"foo\"  stricterr=<nil>",
    "custom enc=\"_-_-\"",
    "withpad enc=\"Zg..\"",
    "withpad dec=\"f\" err=<nil>",
    "nopad enc=\"Zg\"",
    "len n=0 std-enc=0 std-dec=0 raw-enc=0 raw-dec=0",
    "len n=1 std-enc=4 std-dec=0 raw-enc=2 raw-dec=0",
    "len n=2 std-enc=4 std-dec=0 raw-enc=3 raw-dec=1",
    "len n=3 std-enc=4 std-dec=0 raw-enc=4 raw-dec=2",
    "len n=4 std-enc=8 std-dec=3 raw-enc=6 raw-dec=3",
    "len n=5 std-enc=8 std-dec=3 raw-enc=7 raw-dec=3",
    "len n=6 std-enc=8 std-dec=3 raw-enc=8 raw-dec=4",
    "len n=7 std-enc=12 std-dec=3 raw-enc=10 raw-dec=5",
    "len n=8 std-enc=12 std-dec=6 raw-enc=11 raw-dec=6",
    "b32enc std     \"\"       -> \"\"               elen=0",
    "b32enc std     \"f\"      -> \"MY======\"       elen=8",
    "b32enc std     \"fo\"     -> \"MZXQ====\"       elen=8",
    "b32enc std     \"foo\"    -> \"MZXW6===\"       elen=8",
    "b32enc std     \"foob\"   -> \"MZXW6YQ=\"       elen=8",
    "b32enc std     \"fooba\"  -> \"MZXW6YTB\"       elen=8",
    "b32enc std     \"foobar\" -> \"MZXW6YTBOI======\" elen=16",
    "b32enc hex     \"\"       -> \"\"               elen=0",
    "b32enc hex     \"f\"      -> \"CO======\"       elen=8",
    "b32enc hex     \"fo\"     -> \"CPNG====\"       elen=8",
    "b32enc hex     \"foo\"    -> \"CPNMU===\"       elen=8",
    "b32enc hex     \"foob\"   -> \"CPNMUOG=\"       elen=8",
    "b32enc hex     \"fooba\"  -> \"CPNMUOJ1\"       elen=8",
    "b32enc hex     \"foobar\" -> \"CPNMUOJ1E8======\" elen=16",
    "b32enc rawstd  \"\"       -> \"\"               elen=0",
    "b32enc rawstd  \"f\"      -> \"MY\"             elen=2",
    "b32enc rawstd  \"fo\"     -> \"MZXQ\"           elen=4",
    "b32enc rawstd  \"foo\"    -> \"MZXW6\"          elen=5",
    "b32enc rawstd  \"foob\"   -> \"MZXW6YQ\"        elen=7",
    "b32enc rawstd  \"fooba\"  -> \"MZXW6YTB\"       elen=8",
    "b32enc rawstd  \"foobar\" -> \"MZXW6YTBOI\"     elen=10",
    "b32dec std     \"MY======\"  -> \"f\"",
    "b32dec std     \"MZXQ====\"  -> \"fo\"",
    "b32dec std     \"MZXW6===\"  -> \"foo\"",
    "b32dec std     \"MY\"        -> err=\"illegal base32 data at input byte 0\"",
    "b32dec std     \"MZXQ\"      -> err=\"illegal base32 data at input byte 0\"",
    "b32dec std     \"\"          -> \"\"",
    "b32dec std     \"=\"         -> err=\"illegal base32 data at input byte 0\"",
    "b32dec std     \"MY=====\"   -> err=\"illegal base32 data at input byte 7\"",
    "b32dec std     \"MZXW6YTB\"  -> \"fooba\"",
    "b32dec std     \"MY======X\" -> \"f\"",
    "b32dec std     \"M1======\"  -> err=\"illegal base32 data at input byte 1\"",
    "b32dec std     \"MZ\\nXQ====\" -> \"fo\"",
    "b32dec hex     \"MY======\"  -> err=\"illegal base32 data at input byte 1\"",
    "b32dec hex     \"MZXQ====\"  -> err=\"illegal base32 data at input byte 1\"",
    "b32dec hex     \"MZXW6===\"  -> err=\"illegal base32 data at input byte 1\"",
    "b32dec hex     \"MY\"        -> err=\"illegal base32 data at input byte 1\"",
    "b32dec hex     \"MZXQ\"      -> err=\"illegal base32 data at input byte 1\"",
    "b32dec hex     \"\"          -> \"\"",
    "b32dec hex     \"=\"         -> err=\"illegal base32 data at input byte 0\"",
    "b32dec hex     \"MY=====\"   -> err=\"illegal base32 data at input byte 1\"",
    "b32dec hex     \"MZXW6YTB\"  -> err=\"illegal base32 data at input byte 1\"",
    "b32dec hex     \"MY======X\" -> err=\"illegal base32 data at input byte 1\"",
    "b32dec hex     \"M1======\"  -> \"\\xb0\"",
    "b32dec hex     \"MZ\\nXQ====\" -> err=\"illegal base32 data at input byte 1\"",
    "b32dec rawstd  \"MY======\"  -> err=\"illegal base32 data at input byte 2\"",
    "b32dec rawstd  \"MZXQ====\"  -> err=\"illegal base32 data at input byte 4\"",
    "b32dec rawstd  \"MZXW6===\"  -> err=\"illegal base32 data at input byte 5\"",
    "b32dec rawstd  \"MY\"        -> \"f\"",
    "b32dec rawstd  \"MZXQ\"      -> \"fo\"",
    "b32dec rawstd  \"\"          -> \"\"",
    "b32dec rawstd  \"=\"         -> err=\"illegal base32 data at input byte 0\"",
    "b32dec rawstd  \"MY=====\"   -> err=\"illegal base32 data at input byte 2\"",
    "b32dec rawstd  \"MZXW6YTB\"  -> \"fooba\"",
    "b32dec rawstd  \"MY======X\" -> err=\"illegal base32 data at input byte 2\"",
    "b32dec rawstd  \"M1======\"  -> err=\"illegal base32 data at input byte 1\"",
    "b32dec rawstd  \"MZ\\nXQ====\" -> err=\"illegal base32 data at input byte 4\"",
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

    let encs: [(&str, base64::Encoding); 4] = [
        ("std", base64::StdEncoding),
        ("url", base64::URLEncoding),
        ("rawstd", base64::RawStdEncoding),
        ("rawurl", base64::RawURLEncoding),
    ];
    // 1
    let ins: [&[u8]; 10] = [
        b"",
        b"f",
        b"fo",
        b"foo",
        b"foob",
        b"fooba",
        b"foobar",
        &[0xff, 0xef, 0xfe],
        &[0, 0, 0],
        b"sure.",
    ];
    for (name, e) in encs.iter() {
        for inp in ins.iter() {
            let out = e.EncodeToString(inp);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "enc %-7s %-9q -> %-14q elen=%d dlen=%d",
                    s(name),
                    slice::<byte>::__from_vec(inp.to_vec()),
                    out.clone(),
                    e.EncodedLen(inp.len() as int),
                    e.DecodedLen(out.Len())
                ),
            );
        }
    }
    // 2
    let decs: [&str; 20] = [
        "Zg==", "Zm8=", "Zm9v", "Zg", "Zm8", "", "=", "==", "===", "Z", "Zm9vYg==", "Zg=Z", "Z===",
        "Zm9v!", "Zm 9v", "Zm\n9v", "Zm\r\n9v", "-_8=", "+/8=", "Zm9vYmFy",
    ];
    for (name, e) in encs.iter() {
        for inp in decs.iter() {
            let (out, err) = e.DecodeString(s(inp));
            if !err.IsNil() {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!("dec %-7s %-10q -> err=%q", s(name), s(inp), err.Error()),
                );
                continue;
            }
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("dec %-7s %-10q -> %q", s(name), s(inp), out),
            );
        }
    }
    // 3
    let strict = base64::StdEncoding.Strict();
    for inp in ["Zg==", "Zh==", "Zm8=", "Zm9=", "Zm9v", "Zm\n9v"] {
        let (out, err) = base64::StdEncoding.DecodeString(s(inp));
        let (sout, serr) = strict.DecodeString(s(inp));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "strict %-8q -> lax=%-6q laxerr=%-28v strict=%-6q stricterr=%v",
                s(inp),
                out,
                et(&err),
                sout,
                et(&serr)
            ),
        );
    }
    // 4
    {
        let custom =
            base64::NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("custom enc=%q", custom.EncodeToString(&[0xff, 0xef, 0xfe])),
        );
        let with_pad = base64::StdEncoding.WithPadding('.' as rune);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("withpad enc=%q", with_pad.EncodeToString(b"f")),
        );
        let (out, err) = with_pad.DecodeString(s("Zg.."));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("withpad dec=%q err=%v", out, et(&err)),
        );
        let nopad = base64::StdEncoding.WithPadding(base64::NoPadding);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("nopad enc=%q", nopad.EncodeToString(b"f")),
        );
    }
    // 5
    for n in [0 as int, 1, 2, 3, 4, 5, 6, 7, 8] {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "len n=%d std-enc=%d std-dec=%d raw-enc=%d raw-dec=%d",
                n,
                base64::StdEncoding.EncodedLen(n),
                base64::StdEncoding.DecodedLen(n),
                base64::RawStdEncoding.EncodedLen(n),
                base64::RawStdEncoding.DecodedLen(n)
            ),
        );
    }
    // 6
    let b32: [(&str, base32::Encoding); 3] = [
        ("std", base32::StdEncoding),
        ("hex", base32::HexEncoding),
        ("rawstd", base32::StdEncoding.WithPadding(base32::NoPadding)),
    ];
    for (name, e) in b32.iter() {
        for inp in [
            &b""[..],
            &b"f"[..],
            &b"fo"[..],
            &b"foo"[..],
            &b"foob"[..],
            &b"fooba"[..],
            &b"foobar"[..],
        ] {
            let out = e.EncodeToString(slice::__from_vec(inp.to_vec()));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "b32enc %-7s %-8q -> %-16q elen=%d",
                    s(name),
                    slice::<byte>::__from_vec(inp.to_vec()),
                    out,
                    e.EncodedLen(inp.len() as int)
                ),
            );
        }
    }
    for (name, e) in b32.iter() {
        for inp in [
            "MY======",
            "MZXQ====",
            "MZXW6===",
            "MY",
            "MZXQ",
            "",
            "=",
            "MY=====",
            "MZXW6YTB",
            "MY======X",
            "M1======",
            "MZ\nXQ====",
        ] {
            let (out, err) = e.DecodeString(s(inp));
            if !err.IsNil() {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!("b32dec %-7s %-11q -> err=%q", s(name), s(inp), err.Error()),
                );
                continue;
            }
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("b32dec %-7s %-11q -> %q", s(name), s(inp), out),
            );
        }
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
