// encodedword_smoke — exercise mime's RFC 2047 encoded-words.
// (mime/encodedword.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_encodedword_ref.go` run inside `mime` by
// `scripts/goref.sh`.
//
// RFC 2047 caps an encoded-word at 75 characters, so a long UTF-8 value
// has to be split across several — and a multi-byte rune must never
// straddle the boundary. That splitting is the whole reason `bEncode`
// and `qEncode` exist as separate functions, and it is invisible to any
// test that only encodes short ASCII, which is why the long rows below
// carry Go's exact output.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::fmt;
use goish::gostring::string as gostring;
use goish::mime::encodedword::{BEncoding, QEncoding, WordDecoder};
use goish::syscall;
use goish::types::byte;

fn gb(s: &gostring) -> Vec<byte> {
    let c = goish::convert::bytes(s.clone());
    let r: &[byte] = &c;
    return r.to_vec();
}

fn gs(b: &[u8]) -> gostring {
    return gostring::from_bytes(b);
}

fn etext(e: &goish::errors::error) -> Vec<byte> {
    if e.IsNil() {
        return Vec::new();
    }
    return gb(&e.Error());
}

// (charset, input, BEncoding output, QEncoding output)
const ENCODE: [(&str, &[u8], &[u8], &[u8]); 16] = [
    ("UTF-8", b"", b"", b""),
    ("UTF-8", b"abc", b"abc", b"abc"),
    (
        "UTF-8",
        b"Hello, World!",
        b"Hello, World!",
        b"Hello, World!",
    ),
    (
        "UTF-8",
        "café".as_bytes(),
        b"=?UTF-8?b?Y2Fmw6k=?=",
        b"=?UTF-8?q?caf=C3=A9?=",
    ),
    (
        "UTF-8",
        "G\u{fc}ltig".as_bytes(),
        b"=?UTF-8?b?R8O8bHRpZw==?=",
        b"=?UTF-8?q?G=C3=BCltig?=",
    ),
    (
        "UTF-8",
        "\u{a1}Hola, se\u{f1}or!".as_bytes(),
        b"=?UTF-8?b?wqFIb2xhLCBzZcOxb3Ih?=",
        b"=?UTF-8?q?=C2=A1Hola,_se=C3=B1or!?=",
    ),
    (
        "UTF-8",
        "\u{65e5}\u{672c}\u{8a9e}".as_bytes(),
        b"=?UTF-8?b?5pel5pys6Kqe?=",
        b"=?UTF-8?q?=E6=97=A5=E6=9C=AC=E8=AA=9E?=",
    ),
    ("UTF-8", b"a\tb", b"a\tb", b"a\tb"),
    ("UTF-8", b"a=b?c_d", b"a=b?c_d", b"a=b?c_d"),
    (
        "UTF-8",
        b" leading and trailing ",
        b" leading and trailing ",
        b" leading and trailing ",
    ),
    // "é" x 40 — two base64 words, four Q words.
    (
        "UTF-8",
        b"\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\
\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\
\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\
\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9",
        b"=?UTF-8?b?w6nDqcOpw6nDqcOpw6nDqcOpw6nDqcOpw6nDqcOpw6nDqcOpw6nDqcOpw6k=?= \
=?UTF-8?b?w6nDqcOpw6nDqcOpw6nDqcOpw6nDqcOpw6nDqcOpw6nDqcOp?=",
        b"=?UTF-8?q?=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9?= \
=?UTF-8?q?=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9?= \
=?UTF-8?q?=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9?= \
=?UTF-8?q?=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9=C3=A9?=",
    ),
    // "a" x 100 + "é" — the split lands mid-ASCII, and the trailing
    // multi-byte rune must stay whole.
    (
        "UTF-8",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xc3\xa9",
        b"=?UTF-8?b?YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh?= \
=?UTF-8?b?YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh?= \
=?UTF-8?b?YWFhYWFhYWFhYcOp?=",
        b"=?UTF-8?q?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?= \
=?UTF-8?q?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=C3=A9?=",
    ),
    // "日" x 30 — every rune is three bytes, so no split may fall
    // inside one.
    (
        "UTF-8",
        b"\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\
\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\
\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\
\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\
\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\
\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5\xe6\x97\xa5",
        b"=?UTF-8?b?5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel?= \
=?UTF-8?b?5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel5pel?=",
        b"=?UTF-8?q?=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5?= \
=?UTF-8?q?=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5?= \
=?UTF-8?q?=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5?= \
=?UTF-8?q?=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5=E6=97=A5?= \
=?UTF-8?q?=E6=97=A5=E6=97=A5?=",
    ),
    // A non-UTF-8 charset is never split, however long the value.
    (
        "ISO-8859-1",
        b"caf\xe9",
        b"=?ISO-8859-1?b?Y2Fm6Q==?=",
        b"=?ISO-8859-1?q?caf=E9?=",
    ),
    (
        "US-ASCII",
        b"caf\xe9",
        b"=?US-ASCII?b?Y2Fm6Q==?=",
        b"=?US-ASCII?q?caf=E9?=",
    ),
    // The charset is echoed with its case preserved.
    (
        "utf-8",
        "café".as_bytes(),
        b"=?utf-8?b?Y2Fmw6k=?=",
        b"=?utf-8?q?caf=C3=A9?=",
    ),
];

// (word, decoded, error text)
const DECODE: [(&str, &[u8], &str); 17] = [
    ("=?UTF-8?q?caf=C3=A9?=", "café".as_bytes(), ""),
    ("=?UTF-8?b?Y2Fmw6k=?=", "café".as_bytes(), ""),
    ("=?utf-8?Q?caf=C3=A9?=", "café".as_bytes(), ""),
    ("=?UTF-8?B?Y2Fmw6k=?=", "café".as_bytes(), ""),
    // iso-8859-1 widens each byte to the rune of the same value.
    ("=?ISO-8859-1?q?caf=E9?=", "café".as_bytes(), ""),
    // us-ascii replaces every byte >= 0x80 with U+FFFD.
    ("=?US-ASCII?q?caf=E9?=", "caf\u{fffd}".as_bytes(), ""),
    ("=?US-ASCII?q?hello?=", b"hello", ""),
    ("=?UTF-8?q??=", b"", ""),
    ("=?UTF-8?q?a_b?=", b"a b", ""),
    (
        "=?UTF-8?x?abc?=",
        b"",
        "mime: invalid RFC 2047 encoded-word",
    ),
    ("=?UTF-8?q?=?=", b"", "mime: invalid RFC 2047 encoded-word"),
    ("=?UTF-8?q?=A?=", b"", "mime: invalid RFC 2047 encoded-word"),
    ("=?UTF-8?q?=ZZ?=", b"", "mime: invalid hex byte 0x5a"),
    ("=?UTF-8?q?abc", b"", "mime: invalid RFC 2047 encoded-word"),
    ("abc", b"", "mime: invalid RFC 2047 encoded-word"),
    // Decode takes one word, not a header.
    (
        "=?utf-8?q?ab?= =?utf-8?q?cd?=",
        b"",
        "mime: invalid RFC 2047 encoded-word",
    ),
    (
        "=?KOI8-R?q?abc?=",
        b"",
        "mime: unhandled charset \"KOI8-R\"",
    ),
];

// (header, decoded)
const HEADER: [(&str, &[u8]); 13] = [
    ("", b""),
    ("plain header", b"plain header"),
    ("=?UTF-8?q?caf=C3=A9?=", "café".as_bytes()),
    ("Subject: =?UTF-8?q?caf=C3=A9?=", "Subject: café".as_bytes()),
    // White space separating two encoded-words is deleted …
    ("=?UTF-8?q?a?= =?UTF-8?q?b?=", b"ab"),
    // … but only white space: anything else between them survives.
    ("=?UTF-8?q?a?=  x  =?UTF-8?q?b?=", b"a  x  b"),
    ("=?UTF-8?q?a?=\r\n =?UTF-8?q?b?=", b"ab"),
    ("before =?UTF-8?q?mid?= after", b"before mid after"),
    // A word that fails to decode is copied through verbatim, and
    // DecodeHeader still reports no error.
    ("=?UTF-8?x?bogus?= tail", b"=?UTF-8?x?bogus?= tail"),
    ("=?UTF-8?q?=ZZ?= tail", b"=?UTF-8?q?=ZZ?= tail"),
    (
        "=?utf-8?b?Y2Fmw6k=?= and =?iso-8859-1?q?caf=E9?=",
        "café and café".as_bytes(),
    ),
    ("=? bogus", b"=? bogus"),
    ("=?UTF-8?q?a?==?UTF-8?q?b?=", b"ab"),
];

#[goish::main]
fn main() {
    let mut failed = 0;
    let d = WordDecoder::new();

    // 1. BEncoding.Encode over all 16 Go vectors.
    {
        let mut ok = true;
        let mut i = 0;
        while i < ENCODE.len() {
            let (charset, input, want_b, _) = ENCODE[i];
            let got = BEncoding.Encode(gs(charset.as_bytes()), gs(input));
            if gb(&got) != want_b.to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 1] BEncoding.Encode         PASS");
        } else {
            fmt::Println!("[ 1] BEncoding.Encode         FAIL");
            failed += 1;
        }
    }

    // 2. QEncoding.Encode over the same vectors. ' ' becomes '_', and
    //    '=', '?' and '_' are always escaped.
    {
        let mut ok = true;
        let mut i = 0;
        while i < ENCODE.len() {
            let (charset, input, _, want_q) = ENCODE[i];
            let got = QEncoding.Encode(gs(charset.as_bytes()), gs(input));
            if gb(&got) != want_q.to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 2] QEncoding.Encode         PASS");
        } else {
            fmt::Println!("[ 2] QEncoding.Encode         FAIL");
            failed += 1;
        }
    }

    // 3. WordDecoder.Decode over 17 Go vectors, output only. iso-8859-1
    //    widens each byte to the rune of the same value; us-ascii turns
    //    every byte at or above 0x80 into U+FFFD.
    {
        let mut ok = true;
        let mut i = 0;
        while i < DECODE.len() {
            let (word, want, _) = DECODE[i];
            let (got, _) = d.Decode(gs(word.as_bytes()));
            if gb(&got) != want.to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 3] WordDecoder.Decode       PASS");
        } else {
            fmt::Println!("[ 3] WordDecoder.Decode       FAIL");
            failed += 1;
        }
    }

    // 4. The same table's error texts. A bad Q escape reports the
    //    offending byte; an unknown charset reports the charset with
    //    its case preserved and %q-quoted.
    {
        let mut ok = true;
        let mut i = 0;
        while i < DECODE.len() {
            let (word, _, want_err) = DECODE[i];
            let (_, err) = d.Decode(gs(word.as_bytes()));
            if etext(&err) != want_err.as_bytes().to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 4] Decode error texts       PASS");
        } else {
            fmt::Println!("[ 4] Decode error texts       FAIL");
            failed += 1;
        }
    }

    // 5. WordDecoder.DecodeHeader over 13 Go vectors. A word that fails
    //    to decode is copied through verbatim and is still not an
    //    error — DecodeHeader errors only when a CharsetReader does.
    {
        let mut ok = true;
        let mut i = 0;
        while i < HEADER.len() {
            let (header, want) = HEADER[i];
            let (got, err) = d.DecodeHeader(gs(header.as_bytes()));
            if !err.IsNil() || gb(&got) != want.to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 5] DecodeHeader             PASS");
        } else {
            fmt::Println!("[ 5] DecodeHeader             FAIL");
            failed += 1;
        }
    }

    // 6. Round-trip: everything the UTF-8 encoders emit, DecodeHeader
    //    reads back — including the values long enough to be split
    //    across several encoded-words, whose join is where a rune
    //    would break if a split fell inside one.
    {
        let mut ok = true;
        let mut i = 0;
        while i < ENCODE.len() {
            let (charset, input, _, _) = ENCODE[i];
            // A non-UTF-8 charset does not round-trip: `convert`
            // turns its bytes into UTF-8 runes.
            if charset != "UTF-8" && charset != "utf-8" {
                i += 1;
                continue;
            }
            let benc = BEncoding.Encode(gs(charset.as_bytes()), gs(input));
            let (bout, berr) = d.DecodeHeader(benc);
            let qenc = QEncoding.Encode(gs(charset.as_bytes()), gs(input));
            let (qout, qerr) = d.DecodeHeader(qenc);
            if !berr.IsNil() || !qerr.IsNil() {
                ok = false;
            }
            if gb(&bout) != input.to_vec() || gb(&qout) != input.to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 6] encode -> DecodeHeader   PASS");
        } else {
            fmt::Println!("[ 6] encode -> DecodeHeader   FAIL");
            failed += 1;
        }
    }

    // 7. The three unexported predicates, reached through the public
    //    API as Go's own tests reach them in-package.
    //
    //    `needsEncoding` lets a tab through but not a newline, so
    //    "a\tb" comes back unchanged (row 8 above) while "a\nb" is
    //    encoded. `isUTF8` folds case but does not accept "utf8", so a
    //    long value in charset "utf8" is emitted as ONE word however
    //    long it gets — only a UTF-8 charset is ever split.
    //    `hasNonWhitespace` is what deletes the white space between two
    //    encoded-words but keeps anything else (header rows 5 and 6).
    {
        let mut ok = true;

        let b_nl = BEncoding.Encode(gs(b"UTF-8"), gs(b"a\nb"));
        let q_nl = QEncoding.Encode(gs(b"UTF-8"), gs(b"a\nb"));
        if gb(&b_nl) != b"=?UTF-8?b?YQpi?=".to_vec() || gb(&q_nl) != b"=?UTF-8?q?a=0Ab?=".to_vec() {
            ok = false;
        }

        // "é" x 40 under charset "utf8" — not recognised as UTF-8, so
        // never split: one word, no separating space.
        let mut long: Vec<byte> = Vec::new();
        let mut k = 0;
        while k < 40 {
            long.extend_from_slice("é".as_bytes());
            k += 1;
        }
        let one = gb(&BEncoding.Encode(gs(b"utf8"), gs(&long)));
        if !one.starts_with(b"=?utf8?b?") || !one.ends_with(b"?=") || one.contains(&b' ') {
            ok = false;
        }
        // The same value under "UTF-8" *is* split, into two words.
        let two = gb(&BEncoding.Encode(gs(b"UTF-8"), gs(&long)));
        let mut spaces = 0;
        for c in two.iter() {
            if *c == b' ' {
                spaces += 1;
            }
        }
        if spaces != 1 {
            ok = false;
        }

        if ok {
            fmt::Println!("[ 7] needsEncoding/isUTF8     PASS");
        } else {
            fmt::Println!("[ 7] needsEncoding/isUTF8     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
