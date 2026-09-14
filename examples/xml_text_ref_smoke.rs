// encoding/xml: Decoder.text — character data, CDATA and entities.
//
// Fourth slice. `text` is Go's 168-line reader for everything between
// tags: plain character data, the inside of a quoted attribute value,
// and CDATA sections, with entity expansion and newline folding. It is
// the last piece below `rawToken`.
//
// Every row came from Go 1.25.5 running the same call through the real
// Decoder inside a writable GOROOT copy (`scripts/goref.sh
// encoding/xml`), because `text` is unexported and takes the decoder's
// whole state. Committed as examples/testdata/xml_text_ref.txt. The
// output is compared as HEX, not as text, so a row that differs only by
// an invisible byte still reads as a diff.
//
// Four behaviours here are ones a reimplementation gets wrong, and each
// has its own row:
//
//   * `&#x` is hex; `&#X` is NOT. Go tests `b == 'x'` only, so
//     `&#X4a;` parses as a decimal entity with no digits and fails
//     "invalid character entity &# (no semicolon)".
//   * `]]>` is an ERROR in ordinary text, a TERMINATOR in CDATA, and
//     LEGAL inside a quoted string — three different answers to the
//     same three bytes, selected by the two parameters.
//   * `\r` and `\r\n` both fold to a single `\n`, which needs the
//     two-byte history; and an entity expansion RESETS that history, so
//     `]]` followed by `&gt;` is not a `]]>`.
//   * the character-range sweep runs at the END over the whole buffer,
//     not per input byte, because an entity can produce a rune the
//     input never contained — `&#0;` is how you see that.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use goish::encoding::xml;
use goish::fmt;
use goish::gostring::string;
use goish::types::{byte, int};

static mut PASS: int = 0;
static mut FAIL: int = 0;

fn trow(
    name: &'static str,
    input: &[byte],
    quote: int,
    cdata: bool,
    strict: bool,
    ents: &[(&str, &str)],
    want: &'static str,
) {
    let got = xml::xml::__text_script(input, quote, cdata, strict, ents);
    let ok = got == string::from_bytes(want.as_bytes());
    unsafe {
        if ok {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %s q=%v cdata=%v strict=%v\n     got  %s\n     want %s\n",
                name,
                quote,
                cdata,
                strict,
                got.clone(),
                want
            );
        }
    }
}

#[goish::main]
fn main() {
    trow("hello", &[0x68, 0x65, 0x6c, 0x6c, 0x6f], -1, false, true, &[], "68656c6c6f err=EOF off=5");
    trow("", &[], -1, false, true, &[], "nil err=EOF");
    trow("a<b", &[0x61, 0x3c, 0x62], -1, false, true, &[], "61 err=<nil> off=1");
    trow("a&lt;b", &[0x61, 0x26, 0x6c, 0x74, 0x3b, 0x62], -1, false, true, &[], "613c62 err=EOF off=6");
    trow("&lt;&gt;&amp;&apos;&quot;", &[0x26, 0x6c, 0x74, 0x3b, 0x26, 0x67, 0x74, 0x3b, 0x26, 0x61, 0x6d, 0x70, 0x3b, 0x26, 0x61, 0x70, 0x6f, 0x73, 0x3b, 0x26, 0x71, 0x75, 0x6f, 0x74, 0x3b], -1, false, true, &[], "3c3e262722 err=EOF off=25");
    trow("&#65;", &[0x26, 0x23, 0x36, 0x35, 0x3b], -1, false, true, &[], "41 err=EOF off=5");
    trow("&#x41;", &[0x26, 0x23, 0x78, 0x34, 0x31, 0x3b], -1, false, true, &[], "41 err=EOF off=6");
    trow("&#x4a;&#X4a;", &[0x26, 0x23, 0x78, 0x34, 0x61, 0x3b, 0x26, 0x23, 0x58, 0x34, 0x61, 0x3b], -1, false, true, &[], "nil err=XML syntax error on line 1: invalid character entity &# (no semicolon)");
    trow("&#0;", &[0x26, 0x23, 0x30, 0x3b], -1, false, true, &[], "nil err=XML syntax error on line 1: illegal character code U+0000");
    trow("&#xD7FF;&#xD800;", &[0x26, 0x23, 0x78, 0x44, 0x37, 0x46, 0x46, 0x3b, 0x26, 0x23, 0x78, 0x44, 0x38, 0x30, 0x30, 0x3b], -1, false, true, &[], "ed9fbfefbfbd err=EOF off=16");
    trow("&#1114112;", &[0x26, 0x23, 0x31, 0x31, 0x31, 0x34, 0x31, 0x31, 0x32, 0x3b], -1, false, true, &[], "nil err=XML syntax error on line 1: invalid character entity &#1114112;");
    trow("&unknown;", &[0x26, 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x3b], -1, false, true, &[], "nil err=XML syntax error on line 1: invalid character entity &unknown;");
    trow("&unknown;", &[0x26, 0x75, 0x6e, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x3b], -1, false, false, &[], "26756e6b6e6f776e3b err=EOF off=9");
    trow("&foo;", &[0x26, 0x66, 0x6f, 0x6f, 0x3b], -1, false, true, &[("foo", "FOO"), ("nl", "\n")], "464f4f err=EOF off=5");
    trow("&nl;", &[0x26, 0x6e, 0x6c, 0x3b], -1, false, true, &[("foo", "FOO"), ("nl", "\n")], "0a err=EOF off=4");
    trow("&bar;", &[0x26, 0x62, 0x61, 0x72, 0x3b], -1, false, true, &[("foo", "FOO"), ("nl", "\n")], "nil err=XML syntax error on line 1: invalid character entity &bar;");
    trow("&amp", &[0x26, 0x61, 0x6d, 0x70], -1, false, true, &[], "nil err=XML syntax error on line 1: unexpected EOF");
    trow("&amp x", &[0x26, 0x61, 0x6d, 0x70, 0x20, 0x78], -1, false, true, &[], "nil err=XML syntax error on line 1: invalid character entity &amp (no semicolon)");
    trow("&;", &[0x26, 0x3b], -1, false, true, &[], "nil err=XML syntax error on line 1: invalid character entity &;");
    trow("&#;", &[0x26, 0x23, 0x3b], -1, false, true, &[], "nil err=XML syntax error on line 1: invalid character entity &#;");
    trow("a]]>b", &[0x61, 0x5d, 0x5d, 0x3e, 0x62], -1, false, true, &[], "nil err=XML syntax error on line 1: unescaped ]]> not in CDATA section");
    trow("]]&#32;>", &[0x5d, 0x5d, 0x26, 0x23, 0x33, 0x32, 0x3b, 0x3e], -1, false, true, &[], "5d5d203e err=EOF off=8");
    trow("]]&#93;>", &[0x5d, 0x5d, 0x26, 0x23, 0x39, 0x33, 0x3b, 0x3e], -1, false, true, &[], "5d5d5d3e err=EOF off=8");
    trow("]]&gt;", &[0x5d, 0x5d, 0x26, 0x67, 0x74, 0x3b], -1, false, true, &[], "5d5d3e err=EOF off=6");
    trow("a]]>b", &[0x61, 0x5d, 0x5d, 0x3e, 0x62], -1, true, true, &[], "61 err=<nil> off=4");
    trow("a]]>b", &[0x61, 0x5d, 0x5d, 0x3e, 0x62], 34, false, true, &[], "615d5d3e62 err=EOF off=5");
    trow("abc", &[0x61, 0x62, 0x63], -1, true, true, &[], "nil err=XML syntax error on line 1: unexpected EOF in CDATA section");
    trow("ab]]>", &[0x61, 0x62, 0x5d, 0x5d, 0x3e], -1, true, true, &[], "6162 err=<nil> off=5");
    trow("say <U+0022>hi<U+0022>", &[0x73, 0x61, 0x79, 0x20, 0x22, 0x68, 0x69, 0x22], 34, false, true, &[], "73617920 err=<nil> off=5");
    trow("hi<U+0022> rest", &[0x68, 0x69, 0x22, 0x20, 0x72, 0x65, 0x73, 0x74], 34, false, true, &[], "6869 err=<nil> off=3");
    trow("hi<there", &[0x68, 0x69, 0x3c, 0x74, 0x68, 0x65, 0x72, 0x65], 34, false, true, &[], "nil err=XML syntax error on line 1: unescaped < inside quoted string");
    trow("a<U+000D>b", &[0x61, 0x0d, 0x62], -1, false, true, &[], "610a62 err=EOF off=3");
    trow("a<U+000D><U+000A>b", &[0x61, 0x0d, 0x0a, 0x62], -1, false, true, &[], "610a62 err=EOF off=4");
    trow("a<U+000A><U+000D>b", &[0x61, 0x0a, 0x0d, 0x62], -1, false, true, &[], "610a0a62 err=EOF off=4");
    trow("a<U+000D><U+000D><U+000A>b", &[0x61, 0x0d, 0x0d, 0x0a, 0x62], -1, false, true, &[], "610a0a62 err=EOF off=5");
    trow("<U+000B>", &[0x0b], -1, false, true, &[], "nil err=XML syntax error on line 1: illegal character code U+000B");
    trow("<U+0000>", &[0x00], -1, false, true, &[], "nil err=XML syntax error on line 1: illegal character code U+0000");
    trow("<U+00E9><U+4E16><U+754C>", &[0xc3, 0xa9, 0xe4, 0xb8, 0x96, 0xe7, 0x95, 0x8c], -1, false, true, &[], "c3a9e4b896e7958c err=EOF off=8");
    trow("raw 80", &[0x80], -1, false, true, &[], "nil err=XML syntax error on line 1: invalid UTF-8");
    trow("raw 61c3", &[0x61, 0xc3], -1, false, true, &[], "nil err=XML syntax error on line 1: invalid UTF-8");
    trow("raw 61c32862", &[0x61, 0xc3, 0x28, 0x62], -1, false, true, &[], "nil err=XML syntax error on line 1: invalid UTF-8");

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 41 {
            fmt::Printf!("FAIL ran %v rows, expected 41\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("xml_text_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
