// fmt_quote_ref_smoke — fmt's %q against a running Go.
// (fmt/format.go, strconv/quote.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_fmt_quote_ref.go` run in `package
// fmt_test` by `scripts/goref.sh`, carried across as hex so no byte is
// ambiguous.
//
// Go's fmt does not quote for itself. `format.go`'s `fmtQ` hands the
// value to `strconv.AppendQuote`, `%+q` to `AppendQuoteToASCII`, and
// `fmtQc` hands a rune to `AppendQuoteRune`. goish had its own quoter
// in `fmt::write_quoted` — a third one, after strconv's and
// NumError's — and it got three separate things wrong:
//
//   * Every byte >= 0x80 became `\xHH`, per BYTE. `%q` of "héllo" was
//     "h\xc3\xa9llo".
//   * `%q` of a RUNE emitted the rune raw between two single quotes and
//     escaped nothing at all, so `%q` of '\n' was a literal newline
//     inside quotes, and `%q` of 0 embedded a NUL in the output.
//   * `%+q` was not a thing: the '+' flag was parsed and then dropped
//     for every verb but 'v', so `%+q` and `%q` were the same.
//
// All three now route to strconv, which is where Go puts them.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;
extern crate goish;

use goish::errors;
use goish::gostring::string;
use goish::types::{int, rune};
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

// go: none — goish idiom: a `string` over exactly these bytes. Some
//     inputs are truncated UTF-8, so this must not go through `&str`.
fn sb(x: &[u8]) -> string {
    return string::from_bytes(x);
}

// (input, %q, %+q, %q of []byte, %q of an error over it)
const SCASES: [(&[u8], &[u8], &[u8], &[u8], &[u8]); 15] = [
    (b"", b"\"\"", b"\"\"", b"\"\"", b"\"\""),
    (
        b"hello",
        b"\"hello\"",
        b"\"hello\"",
        b"\"hello\"",
        b"\"hello\"",
    ),
    (
        b"a\x09b\x0ac",
        b"\"a\\tb\\nc\"",
        b"\"a\\tb\\nc\"",
        b"\"a\\tb\\nc\"",
        b"\"a\\tb\\nc\"",
    ),
    (
        b"he said \"hi\"",
        b"\"he said \\\"hi\\\"\"",
        b"\"he said \\\"hi\\\"\"",
        b"\"he said \\\"hi\\\"\"",
        b"\"he said \\\"hi\\\"\"",
    ),
    (
        b"back\\slash",
        b"\"back\\\\slash\"",
        b"\"back\\\\slash\"",
        b"\"back\\\\slash\"",
        b"\"back\\\\slash\"",
    ),
    (
        b"h\xc3\xa9llo",
        b"\"h\xc3\xa9llo\"",
        b"\"h\\u00e9llo\"",
        b"\"h\xc3\xa9llo\"",
        b"\"h\xc3\xa9llo\"",
    ),
    (
        b"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e",
        b"\"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\"",
        b"\"\\u65e5\\u672c\\u8a9e\"",
        b"\"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\"",
        b"\"\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\"",
    ),
    (
        b"emoji \xf0\x9f\x98\x80",
        b"\"emoji \xf0\x9f\x98\x80\"",
        b"\"emoji \\U0001f600\"",
        b"\"emoji \xf0\x9f\x98\x80\"",
        b"\"emoji \xf0\x9f\x98\x80\"",
    ),
    (
        b"\x00\x01\x1f\x7f",
        b"\"\\x00\\x01\\x1f\\x7f\"",
        b"\"\\x00\\x01\\x1f\\x7f\"",
        b"\"\\x00\\x01\\x1f\\x7f\"",
        b"\"\\x00\\x01\\x1f\\x7f\"",
    ),
    (
        b"\xc2\xad",
        b"\"\\u00ad\"",
        b"\"\\u00ad\"",
        b"\"\\u00ad\"",
        b"\"\\u00ad\"",
    ),
    (
        b"\xe2\x80\x8b",
        b"\"\\u200b\"",
        b"\"\\u200b\"",
        b"\"\\u200b\"",
        b"\"\\u200b\"",
    ),
    (
        b"\xc2\xa0",
        b"\"\\u00a0\"",
        b"\"\\u00a0\"",
        b"\"\\u00a0\"",
        b"\"\\u00a0\"",
    ),
    (
        b"\xff\xfe",
        b"\"\\xff\\xfe\"",
        b"\"\\xff\\xfe\"",
        b"\"\\xff\\xfe\"",
        b"\"\\xff\\xfe\"",
    ),
    (
        b"a\xffb",
        b"\"a\\xffb\"",
        b"\"a\\xffb\"",
        b"\"a\\xffb\"",
        b"\"a\\xffb\"",
    ),
    (
        b"tab\x09here",
        b"\"tab\\there\"",
        b"\"tab\\there\"",
        b"\"tab\\there\"",
        b"\"tab\\there\"",
    ),
];

// (rune, %q, %+q, %c)
const RCASES: [(rune, &[u8], &[u8], &[u8]); 32] = [
    (0, b"'\\x00'", b"'\\x00'", b"\x00"),
    (7, b"'\\a'", b"'\\a'", b"\x07"),
    (8, b"'\\b'", b"'\\b'", b"\x08"),
    (12, b"'\\f'", b"'\\f'", b"\x0c"),
    (10, b"'\\n'", b"'\\n'", b"\x0a"),
    (13, b"'\\r'", b"'\\r'", b"\x0d"),
    (9, b"'\\t'", b"'\\t'", b"\x09"),
    (11, b"'\\v'", b"'\\v'", b"\x0b"),
    (32, b"' '", b"' '", b" "),
    (33, b"'!'", b"'!'", b"!"),
    (39, b"'\\''", b"'\\''", b"'"),
    (34, b"'\"'", b"'\"'", b"\""),
    (92, b"'\\\\'", b"'\\\\'", b"\\"),
    (65, b"'A'", b"'A'", b"A"),
    (126, b"'~'", b"'~'", b"~"),
    (127, b"'\\x7f'", b"'\\x7f'", b"\x7f"),
    (128, b"'\\u0080'", b"'\\u0080'", b"\xc2\x80"),
    (160, b"'\\u00a0'", b"'\\u00a0'", b"\xc2\xa0"),
    (161, b"'\xc2\xa1'", b"'\\u00a1'", b"\xc2\xa1"),
    (173, b"'\\u00ad'", b"'\\u00ad'", b"\xc2\xad"),
    (255, b"'\xc3\xbf'", b"'\\u00ff'", b"\xc3\xbf"),
    (256, b"'\xc4\x80'", b"'\\u0100'", b"\xc4\x80"),
    (8203, b"'\\u200b'", b"'\\u200b'", b"\xe2\x80\x8b"),
    (12288, b"'\\u3000'", b"'\\u3000'", b"\xe3\x80\x80"),
    (65533, b"'\xef\xbf\xbd'", b"'\\ufffd'", b"\xef\xbf\xbd"),
    (65535, b"'\\uffff'", b"'\\uffff'", b"\xef\xbf\xbf"),
    (
        65536,
        b"'\xf0\x90\x80\x80'",
        b"'\\U00010000'",
        b"\xf0\x90\x80\x80",
    ),
    (
        119070,
        b"'\xf0\x9d\x84\x9e'",
        b"'\\U0001d11e'",
        b"\xf0\x9d\x84\x9e",
    ),
    (
        1114111,
        b"'\\U0010ffff'",
        b"'\\U0010ffff'",
        b"\xf4\x8f\xbf\xbf",
    ),
    (-1, b"'\xef\xbf\xbd'", b"'\\ufffd'", b"\xef\xbf\xbd"),
    (1114112, b"'\xef\xbf\xbd'", b"'\\ufffd'", b"\xef\xbf\xbd"),
    (55296, b"'\xef\xbf\xbd'", b"'\\ufffd'", b"\xef\xbf\xbd"),
];

// Go: [%12q][%-12q] of "hi", then [%8q][%-8q] of 'x'.
const WANT_WIDTH: &[u8] = b"[        \"hi\"][\"hi\"        ]";
const WANT_WIDTH_RUNE: &[u8] = b"[     'x']['x'     ]";

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. `%q` of a string is `strconv.Quote`: printable runes stay
    //    themselves, UTF-8 and all.
    {
        let mut ok = true;
        let mut i = 0;
        while i < SCASES.len() {
            let (input, want, _, _, _) = SCASES[i];
            if fmt::Sprintf!("%q", sb(input)) != sb(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "%q of a string is strconv.Quote");
    }

    // 2. `%+q` is `strconv.QuoteToASCII` — a different answer for every
    //    non-ASCII input, and the same for every ASCII one.
    {
        let mut ok = true;
        let mut differed = 0;
        let mut i = 0;
        while i < SCASES.len() {
            let (input, q, want, _, _) = SCASES[i];
            if fmt::Sprintf!("%+q", sb(input)) != sb(want) {
                ok = false;
            }
            if q != want {
                differed += 1;
            }
            i += 1;
        }
        // If '+' were still being dropped, every row would agree. Go
        // separates exactly three of these: the ones holding a
        // PRINTABLE non-ASCII rune. A non-printable one is escaped by
        // both, and invalid UTF-8 is `\xHH` to both.
        if differed != 3 {
            ok = false;
        }
        report(&mut failed, ok, " 2", "%+q is QuoteToASCII, not %q");
    }

    // 3. `%q` of a []byte and of an error render the same text as `%q`
    //    of the string — Go quotes the bytes either way.
    {
        let mut ok = true;
        let mut i = 0;
        while i < SCASES.len() {
            let (input, _, _, want_b, want_e) = SCASES[i];
            let b = goish::convert::bytes(sb(input));
            if fmt::Sprintf!("%q", b) != sb(want_b) {
                ok = false;
            }
            if fmt::Sprintf!("%q", errors::New(sb(input))) != sb(want_e) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 3", "%q of []byte and of an error");
    }

    // 4. `%q` of a rune is `strconv.QuoteRune`: it ESCAPES. This is the
    //    check that used to emit a raw newline for '\n' and a raw NUL
    //    for 0.
    {
        let mut ok = true;
        let mut i = 0;
        while i < RCASES.len() {
            let (r, want, _, _) = RCASES[i];
            if fmt::Sprintf!("%q", r) != sb(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "%q of a rune escapes it");
    }

    // 5. `%+q` of a rune is QuoteRuneToASCII, and `%c` is the rune
    //    itself — including the out-of-range and surrogate values Go
    //    folds to U+FFFD.
    {
        let mut ok = true;
        let mut i = 0;
        while i < RCASES.len() {
            let (r, _, want_pq, want_c) = RCASES[i];
            if fmt::Sprintf!("%+q", r) != sb(want_pq) {
                ok = false;
            }
            if fmt::Sprintf!("%c", r) != sb(want_c) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 5", "%+q and %c of a rune");
    }

    // 6. Width and left-align still apply on top of the quoting — the
    //    padding counts the quotes and the escapes, not the input.
    {
        let mut ok = true;
        if fmt::Sprintf!("[%12q][%-12q]", "hi", "hi") != sb(WANT_WIDTH) {
            ok = false;
        }
        let x: rune = 0x78;
        if fmt::Sprintf!("[%8q][%-8q]", x, x) != sb(WANT_WIDTH_RUNE) {
            ok = false;
        }
        report(&mut failed, ok, " 6", "width applies over the quoting");
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
