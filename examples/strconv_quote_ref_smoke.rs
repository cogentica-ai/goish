// strconv_quote_ref_smoke — strconv/quote.go against a running Go.
// (strconv/quote.go, strconv/isprint.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_strconv_quote_ref.go` run in
// `package strconv_test` by `scripts/goref.sh`, carried across as hex
// so not one byte is ambiguous.
//
// Quote, QuoteToASCII and QuoteToGraphic are three different functions.
// In Go they share `appendQuotedWith` and differ only in the ASCIIonly
// and graphicOnly flags, and the question those flags ask is
// `IsPrint`'s — a binary search over four generated range tables, not a
// rule about byte values.
//
// goish had one appender, ASCII-only by construction, and aliased the
// other five entry points onto it. Two consequences, both silent:
//
//   * Every non-ASCII byte was escaped as `\xHH` — per BYTE, not per
//     rune. `Quote("héllo")` gave `"h\xc3\xa9llo"` where Go gives
//     `"héllo"`, and `Quote("日本語")` was nine hex escapes. Anything
//     that renders a string with `%q` — every NumError, every wrapped
//     path in an os error — was mangling non-ASCII input.
//   * QuoteToASCII and QuoteToGraphic returned Quote's answer, so the
//     three were indistinguishable. Picking the right one could not
//     change anything.
//
// `IsPrint` was the root: it answered `true` for every valid codepoint
// above U+00FF, because the tables it needs were not in the tree.
// isprint.rs now carries all five of them, and the counts check below
// walks the entire 0..0x10FFFF code space so a table transcribed one
// entry short shows up as a number rather than a lucky miss.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::gostring::string;
use goish::strconv;
use goish::types::{byte, int, rune};
use goish::{fmt, syscall};

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// go: none — goish idiom: a `string` over exactly these bytes. The
//     inputs include truncated UTF-8, so this must not go through
//     `&str`.
fn sb(x: &[u8]) -> string {
    return string::from_bytes(x);
}

// go: none — goish idiom: a `slice<byte>` holding the given bytes, so
//     the Append* checks start from a non-empty destination.
fn bs(x: &[u8]) -> slice<byte> {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    v.extend_from_slice(x);
    return slice::__from_vec(v);
}

// (input, Quote, QuoteToASCII, QuoteToGraphic) — every field the
// exact bytes Go 1.25.5 produced, transported as hex and written
// back out here as byte-string literals.
const QCASES: [(&[u8], &[u8], &[u8], &[u8]); 28] = [
    (b"", b"\"\"", b"\"\"", b"\"\""),
    (b"hello", b"\"hello\"", b"\"hello\"", b"\"hello\""),
    (
        b"a\x09b\x0ac",
        b"\"a\\tb\\nc\"",
        b"\"a\\tb\\nc\"",
        b"\"a\\tb\\nc\"",
    ),
    (
        b"\"quoted\"",
        b"\"\\\"quoted\\\"\"",
        b"\"\\\"quoted\\\"\"",
        b"\"\\\"quoted\\\"\"",
    ),
    (
        b"back\\slash",
        b"\"back\\\\slash\"",
        b"\"back\\\\slash\"",
        b"\"back\\\\slash\"",
    ),
    (
        b"h\xc3\xa9llo",
        b"\"h\xc3\xa9llo\"",
        b"\"h\\u00e9llo\"",
        b"\"h\xc3\xa9llo\"",
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\"",
        b"\"\\u65e5\\u672c\\u8a9e\"",
        b"\"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\"",
    ),
    (
        b"emoji \xf0\x9f\x98\x80 here",
        b"\"emoji \xf0\x9f\x98\x80 here\"",
        b"\"emoji \\U0001f600 here\"",
        b"\"emoji \xf0\x9f\x98\x80 here\"",
    ),
    (
        b"\xc3\xbcn\xc3\xafc\xc3\xb6d\xc3\xa9",
        b"\"\xc3\xbcn\xc3\xafc\xc3\xb6d\xc3\xa9\"",
        b"\"\\u00fcn\\u00efc\\u00f6d\\u00e9\"",
        b"\"\xc3\xbcn\xc3\xafc\xc3\xb6d\xc3\xa9\"",
    ),
    (
        b"\x00\x01\x1f\x7f",
        b"\"\\x00\\x01\\x1f\\x7f\"",
        b"\"\\x00\\x01\\x1f\\x7f\"",
        b"\"\\x00\\x01\\x1f\\x7f\"",
    ),
    (b"\xc2\xad", b"\"\\u00ad\"", b"\"\\u00ad\"", b"\"\\u00ad\""),
    (
        b"\xe2\x80\x8b",
        b"\"\\u200b\"",
        b"\"\\u200b\"",
        b"\"\\u200b\"",
    ),
    (
        b"\xef\xbb\xbf",
        b"\"\\ufeff\"",
        b"\"\\ufeff\"",
        b"\"\\ufeff\"",
    ),
    (b"\xcd\xb8", b"\"\\u0378\"", b"\"\\u0378\"", b"\"\\u0378\""),
    (
        b"\xe0\xa1\xb0",
        b"\"\xe0\xa1\xb0\"",
        b"\"\\u0870\"",
        b"\"\xe0\xa1\xb0\"",
    ),
    (b"\xc2\xa0", b"\"\\u00a0\"", b"\"\\u00a0\"", b"\"\xc2\xa0\""),
    (
        b"\xc2\xa1",
        b"\"\xc2\xa1\"",
        b"\"\\u00a1\"",
        b"\"\xc2\xa1\"",
    ),
    (
        b"\xf0\x9d\x84\x9e",
        b"\"\xf0\x9d\x84\x9e\"",
        b"\"\\U0001d11e\"",
        b"\"\xf0\x9d\x84\x9e\"",
    ),
    (
        b"\xf3\xa0\x80\x81",
        b"\"\\U000e0001\"",
        b"\"\\U000e0001\"",
        b"\"\\U000e0001\"",
    ),
    (
        b"\xf4\x8f\xbf\xbf",
        b"\"\\U0010ffff\"",
        b"\"\\U0010ffff\"",
        b"\"\\U0010ffff\"",
    ),
    (
        b"\xff\xfe",
        b"\"\\xff\\xfe\"",
        b"\"\\xff\\xfe\"",
        b"\"\\xff\\xfe\"",
    ),
    (b"a\xffb", b"\"a\\xffb\"", b"\"a\\xffb\"", b"\"a\\xffb\""),
    (
        b"\xe4\xb8",
        b"\"\\xe4\\xb8\"",
        b"\"\\xe4\\xb8\"",
        b"\"\\xe4\\xb8\"",
    ),
    (
        b"\xc2\xa0\xe2\x80\x83",
        b"\"\\u00a0\\u2003\"",
        b"\"\\u00a0\\u2003\"",
        b"\"\xc2\xa0\xe2\x80\x83\"",
    ),
    (
        b"\xe3\x80\x80",
        b"\"\\u3000\"",
        b"\"\\u3000\"",
        b"\"\xe3\x80\x80\"",
    ),
    (
        b"\xe1\x9a\x80",
        b"\"\\u1680\"",
        b"\"\\u1680\"",
        b"\"\xe1\x9a\x80\"",
    ),
    (
        b"'single'",
        b"\"'single'\"",
        b"\"'single'\"",
        b"\"'single'\"",
    ),
    (
        b"mixed \"'` quotes",
        b"\"mixed \\\"'` quotes\"",
        b"\"mixed \\\"'` quotes\"",
        b"\"mixed \\\"'` quotes\"",
    ),
];

// (rune, QuoteRune, QuoteRuneToASCII, QuoteRuneToGraphic, IsPrint, IsGraphic)
const RCASES: [(rune, &[u8], &[u8], &[u8], bool, bool); 42] = [
    (0, b"'\\x00'", b"'\\x00'", b"'\\x00'", false, false),
    (7, b"'\\a'", b"'\\a'", b"'\\a'", false, false),
    (8, b"'\\b'", b"'\\b'", b"'\\b'", false, false),
    (12, b"'\\f'", b"'\\f'", b"'\\f'", false, false),
    (10, b"'\\n'", b"'\\n'", b"'\\n'", false, false),
    (13, b"'\\r'", b"'\\r'", b"'\\r'", false, false),
    (9, b"'\\t'", b"'\\t'", b"'\\t'", false, false),
    (11, b"'\\v'", b"'\\v'", b"'\\v'", false, false),
    (32, b"' '", b"' '", b"' '", true, true),
    (33, b"'!'", b"'!'", b"'!'", true, true),
    (39, b"'\\''", b"'\\''", b"'\\''", true, true),
    (34, b"'\"'", b"'\"'", b"'\"'", true, true),
    (92, b"'\\\\'", b"'\\\\'", b"'\\\\'", true, true),
    (126, b"'~'", b"'~'", b"'~'", true, true),
    (127, b"'\\x7f'", b"'\\x7f'", b"'\\x7f'", false, false),
    (128, b"'\\u0080'", b"'\\u0080'", b"'\\u0080'", false, false),
    (159, b"'\\u009f'", b"'\\u009f'", b"'\\u009f'", false, false),
    (160, b"'\\u00a0'", b"'\\u00a0'", b"'\xc2\xa0'", false, true),
    (161, b"'\xc2\xa1'", b"'\\u00a1'", b"'\xc2\xa1'", true, true),
    (173, b"'\\u00ad'", b"'\\u00ad'", b"'\\u00ad'", false, false),
    (255, b"'\xc3\xbf'", b"'\\u00ff'", b"'\xc3\xbf'", true, true),
    (256, b"'\xc4\x80'", b"'\\u0100'", b"'\xc4\x80'", true, true),
    (8203, b"'\\u200b'", b"'\\u200b'", b"'\\u200b'", false, false),
    (8232, b"'\\u2028'", b"'\\u2028'", b"'\\u2028'", false, false),
    (8233, b"'\\u2029'", b"'\\u2029'", b"'\\u2029'", false, false),
    (
        12288,
        b"'\\u3000'",
        b"'\\u3000'",
        b"'\xe3\x80\x80'",
        false,
        true,
    ),
    (
        5760,
        b"'\\u1680'",
        b"'\\u1680'",
        b"'\xe1\x9a\x80'",
        false,
        true,
    ),
    (
        65279,
        b"'\\ufeff'",
        b"'\\ufeff'",
        b"'\\ufeff'",
        false,
        false,
    ),
    (
        65533,
        b"'\xef\xbf\xbd'",
        b"'\\ufffd'",
        b"'\xef\xbf\xbd'",
        true,
        true,
    ),
    (
        65535,
        b"'\\uffff'",
        b"'\\uffff'",
        b"'\\uffff'",
        false,
        false,
    ),
    (
        65536,
        b"'\xf0\x90\x80\x80'",
        b"'\\U00010000'",
        b"'\xf0\x90\x80\x80'",
        true,
        true,
    ),
    (
        119070,
        b"'\xf0\x9d\x84\x9e'",
        b"'\\U0001d11e'",
        b"'\xf0\x9d\x84\x9e'",
        true,
        true,
    ),
    (
        917505,
        b"'\\U000e0001'",
        b"'\\U000e0001'",
        b"'\\U000e0001'",
        false,
        false,
    ),
    (
        1114111,
        b"'\\U0010ffff'",
        b"'\\U0010ffff'",
        b"'\\U0010ffff'",
        false,
        false,
    ),
    (
        -1,
        b"'\xef\xbf\xbd'",
        b"'\\ufffd'",
        b"'\xef\xbf\xbd'",
        false,
        false,
    ),
    (
        1114112,
        b"'\xef\xbf\xbd'",
        b"'\\ufffd'",
        b"'\xef\xbf\xbd'",
        false,
        false,
    ),
    (
        55296,
        b"'\xef\xbf\xbd'",
        b"'\\ufffd'",
        b"'\xef\xbf\xbd'",
        false,
        false,
    ),
    (888, b"'\\u0378'", b"'\\u0378'", b"'\\u0378'", false, false),
    (
        2160,
        b"'\xe0\xa1\xb0'",
        b"'\\u0870'",
        b"'\xe0\xa1\xb0'",
        true,
        true,
    ),
    (
        131072,
        b"'\xf0\xa0\x80\x80'",
        b"'\\U00020000'",
        b"'\xf0\xa0\x80\x80'",
        true,
        true,
    ),
    (
        195101,
        b"'\xf0\xaf\xa8\x9d'",
        b"'\\U0002fa1d'",
        b"'\xf0\xaf\xa8\x9d'",
        true,
        true,
    ),
    (
        195102,
        b"'\\U0002fa1e'",
        b"'\\U0002fa1e'",
        b"'\\U0002fa1e'",
        false,
        false,
    ),
];

// The six Append* forms, each starting from a dst of `<`.
const APPENDS: [(&str, &[u8]); 6] = [
    ("q", b"<\"h\xc3\xa9llo\""),
    ("qa", b"<\"h\\u00e9llo\""),
    ("qg", b"<\"\xc2\xa0\""),
    ("r", b"<'\xc3\xa9'"),
    ("ra", b"<'\\u00e9'"),
    ("rg", b"<'\xc2\xa0'"),
];

// Go: counts print=148998 graphic=149014
// (Num as given, the full NumError.Error() text)
const NUMERRORS: [(&[u8], &[u8]); 7] = [
    (b"12x", b"strconv.ParseInt: parsing \"12x\": invalid syntax"),
    (
        b"a\"b",
        b"strconv.ParseInt: parsing \"a\\\"b\": invalid syntax",
    ),
    (
        b"a\\b",
        b"strconv.ParseInt: parsing \"a\\\\b\": invalid syntax",
    ),
    (
        b"a\x0ab",
        b"strconv.ParseInt: parsing \"a\\nb\": invalid syntax",
    ),
    (
        b"h\xc3\xa9llo",
        b"strconv.ParseInt: parsing \"h\xc3\xa9llo\": invalid syntax",
    ),
    (
        b"\xe6\x97\xa5",
        b"strconv.ParseInt: parsing \"\xe6\x97\xa5\": invalid syntax",
    ),
    (
        b"\xff",
        b"strconv.ParseInt: parsing \"\\xff\": invalid syntax",
    ),
];

const WANT_PRINT_COUNT: int = 148998;
const WANT_GRAPHIC_COUNT: int = 149014;
// Go: every one of the 28 Quote outputs Unquotes back to its input.

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Quote. Printable runes stay themselves — UTF-8 and all — and
    //    only what IsPrint rejects is escaped. This is the check that
    //    was answering in hex escapes for every non-ASCII input.
    {
        let mut ok = true;
        let mut i = 0;
        while i < QCASES.len() {
            let (input, want, _, _) = QCASES[i];
            if strconv::Quote(sb(input)) != sb(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "Quote keeps printable runes whole");
    }

    // 2. QuoteToASCII escapes every rune >= 0x80, as `\uXXXX` or
    //    `\UXXXXXXXX` — NOT as the per-byte `\xHH` a byte-oriented
    //    appender produces.
    {
        let mut ok = true;
        let mut i = 0;
        while i < QCASES.len() {
            let (input, _, want, _) = QCASES[i];
            if strconv::QuoteToASCII(sb(input)) != sb(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 2", "QuoteToASCII escapes by rune");
    }

    // 3. QuoteToGraphic differs from Quote on exactly the isGraphic
    //    list: the Unicode spaces, which are graphic but not printable.
    {
        let mut ok = true;
        let mut i = 0;
        while i < QCASES.len() {
            let (input, _, _, want) = QCASES[i];
            if strconv::QuoteToGraphic(sb(input)) != sb(want) {
                ok = false;
            }
            i += 1;
        }
        // The three must not be interchangeable: at least one input
        // has to separate them, or the check above proves nothing.
        let mut separated = 0;
        let mut j = 0;
        while j < QCASES.len() {
            let (_, q, qa, qg) = QCASES[j];
            if q != qa || q != qg {
                separated += 1;
            }
            j += 1;
        }
        if separated < 3 {
            ok = false;
        }
        report(&mut failed, ok, " 3", "QuoteToGraphic is its own function");
    }

    // 4. The rune forms, over the boundaries: the C0 controls, DEL, the
    //    C1 block, the soft hyphen, the surrogate range, both ends of
    //    the BMP, an astral plane, and two out-of-range values that Go
    //    folds to U+FFFD.
    {
        let mut ok = true;
        let mut i = 0;
        while i < RCASES.len() {
            let (r, want_q, want_qa, want_qg, _, _) = RCASES[i];
            if strconv::QuoteRune(r) != sb(want_q) {
                ok = false;
            }
            if strconv::QuoteRuneToASCII(r) != sb(want_qa) {
                ok = false;
            }
            if strconv::QuoteRuneToGraphic(r) != sb(want_qg) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "QuoteRune at every boundary");
    }

    // 5. IsPrint and IsGraphic themselves, at those same runes. U+00A0
    //    is the shape of the whole distinction: graphic, not printable.
    {
        let mut ok = true;
        let mut i = 0;
        while i < RCASES.len() {
            let (r, _, _, _, want_print, want_graphic) = RCASES[i];
            if strconv::IsPrint(r) != want_print {
                ok = false;
            }
            if strconv::IsGraphic(r) != want_graphic {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 5", "IsPrint/IsGraphic at boundaries");
    }

    // 6. The counts over the ENTIRE code space. A range table missing
    //    one pair, or an off-by-one in the `i&^1` / `i|1` indexing,
    //    moves these numbers; nothing else in this file would notice.
    {
        let mut nprint: int = 0;
        let mut ngraphic: int = 0;
        let mut r: rune = 0;
        while r < 0x110000 {
            if strconv::IsPrint(r) {
                nprint += 1;
            }
            if strconv::IsGraphic(r) {
                ngraphic += 1;
            }
            r += 1;
        }
        let ok = nprint == WANT_PRINT_COUNT && ngraphic == WANT_GRAPHIC_COUNT;
        if !ok {
            fmt::Println!("   print", nprint, "want", WANT_PRINT_COUNT);
            fmt::Println!("   graphic", ngraphic, "want", WANT_GRAPHIC_COUNT);
        }
        report(&mut failed, ok, " 6", "the whole code space, counted");
    }

    // 7. The six Append* forms extend dst rather than replacing it, and
    //    each reaches its own appender.
    {
        let mut ok = true;
        let mut i = 0;
        while i < APPENDS.len() {
            let (which, want) = APPENDS[i];
            let got = match which {
                "q" => strconv::AppendQuote(bs(b"<"), sb(b"h\xc3\xa9llo")),
                "qa" => strconv::AppendQuoteToASCII(bs(b"<"), sb(b"h\xc3\xa9llo")),
                "qg" => strconv::AppendQuoteToGraphic(bs(b"<"), sb(b"\xc2\xa0")),
                "r" => strconv::AppendQuoteRune(bs(b"<"), 0xe9),
                "ra" => strconv::AppendQuoteRuneToASCII(bs(b"<"), 0xe9),
                _ => strconv::AppendQuoteRuneToGraphic(bs(b"<"), 0xa0),
            };
            if string::from_bytes(&got.__into_vec()) != sb(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 7", "Append* extend dst");
    }

    // 8. Everything Quote produces Unquotes back to what went in — Go
    //    returns a nil error for all 28, including the ones holding
    //    invalid UTF-8.
    {
        let mut ok = true;
        let mut i = 0;
        while i < QCASES.len() {
            let (input, _, _, _) = QCASES[i];
            let (back, err) = strconv::Unquote(strconv::Quote(sb(input)));
            if !err.IsNil() || back != sb(input) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 8", "Quote round-trips through Unquote");
    }

    // 9. NumError.Error renders Num with Quote, as Go does, not with a
    //    pair of bare double quotes around the raw bytes. goish's
    //    hand-rolled version left an embedded quote, backslash or
    //    newline unescaped — so the message could not be read back —
    //    and it could not use Quote until Quote was correct.
    {
        let mut ok = true;
        let mut i = 0;
        while i < NUMERRORS.len() {
            let (input, want) = NUMERRORS[i];
            let (_, err) = strconv::ParseInt(sb(input), 10, 64);
            if err.IsNil() || err.Error() != sb(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 9", "NumError.Error quotes its Num");
    }

    if failed == 0 {
        fmt::Println!("ok 9/9");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 9");
        syscall::Exit(1);
    }
}
