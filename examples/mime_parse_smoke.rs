// mime_parse_smoke — exercise mime::ParseMediaType / FormatMediaType.
// (mime/mediatype.go, mime/grammar.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_mediatype_ref.go` run inside `mime` by
// `scripts/goref.sh`.
//
// The hard part is RFC 2231. A parameter value may be split across
// `name*0`, `name*1`, … and any piece may be percent-encoded by a
// further `*` suffix, with the charset carried on the first piece only
// — none of which is reachable from an ordinary Content-Type, so it is
// exactly what a port drops without noticing.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::fmt;
use goish::gomap::map;
use goish::gostring::string as gostring;
use goish::mime;
use goish::mime::grammar::{isTSpecial, isToken, isTokenChar};
use goish::string;
use goish::syscall;
use goish::types::byte;

fn gb(s: &gostring) -> Vec<byte> {
    let c = goish::convert::bytes(s.clone());
    let r: &[byte] = &c;
    return r.to_vec();
}

fn etext(e: &goish::errors::error) -> Vec<byte> {
    if e.IsNil() {
        return Vec::new();
    }
    return gb(&e.Error());
}

// (input, media type, sorted params, error text)
const PARSE: [(&str, &str, &[(&str, &str)], &str); 40] = [
    ("form-data", "form-data", &[], ""),
    ("form-data; name=foo", "form-data", &[("name", "foo")], ""),
    ("form-data; name=\"foo\"", "form-data", &[("name", "foo")], ""),
    ("FORM-DATA; Name=\"foo\"", "form-data", &[("name", "foo")], ""),
    (" form-data ; name=foo", "form-data", &[("name", "foo")], ""),
    (
        "form-data; key=value;  blah=\"value\";name=\"foo\" ",
        "form-data",
        &[("blah", "value"), ("key", "value"), ("name", "foo")],
        "",
    ),
    (
        "form-data; name=\"foo\"; filename=\"bar.txt\"",
        "form-data",
        &[("filename", "bar.txt"), ("name", "foo")],
        "",
    ),
    (
        "text/html; charset=utf-8",
        "text/html",
        &[("charset", "utf-8")],
        "",
    ),
    (
        "text/html; charset =utf-8",
        "text/html",
        &[("charset", "utf-8")],
        "",
    ),
    (
        "text/html; charset= utf-8",
        "text/html",
        &[("charset", "utf-8")],
        "",
    ),
    (
        "text/html;charset=utf-8;",
        "text/html",
        &[("charset", "utf-8")],
        "",
    ),
    (
        "text/html;charset=utf-8; ",
        "text/html",
        &[("charset", "utf-8")],
        "",
    ),
    (
        "text/html; charset=utf-8; charset=utf-8",
        "text/html",
        &[("charset", "utf-8")],
        "",
    ),
    (
        "text/html; charset=utf-8; charset=iso-8859-1",
        "",
        &[],
        "mime: duplicate parameter name",
    ),
    (
        "text/html; ; charset=utf-8",
        "text/html",
        &[],
        "mime: invalid media parameter",
    ),
    (
        "text/html; charset",
        "text/html",
        &[],
        "mime: invalid media parameter",
    ),
    (
        "text/html; charset=",
        "text/html",
        &[],
        "mime: invalid media parameter",
    ),
    (
        "text/html; charset=\"utf-8",
        "text/html",
        &[],
        "mime: invalid media parameter",
    ),
    ("text/html; charset=\";\"", "text/html", &[("charset", ";")], ""),
    (
        "text/html; charset=\"\\\"quoted\\\"\"",
        "text/html",
        &[("charset", "\"quoted\"")],
        "",
    ),
    (
        "application/x-stuff; title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A",
        "application/x-stuff",
        &[("title", "This is ***fun***")],
        "",
    ),
    (
        "application/x-stuff; title*0*=us-ascii'en'This%20is%20even%20; title*1=more%20; title*2*=%2A%2A%2Afun%2A%2A%2A%20; title*3=\"isn't it!\"",
        "application/x-stuff",
        &[("title", "This is even more%20***fun*** isn't it!")],
        "",
    ),
    (
        "attachment; filename*=UTF-8''foo-%c3%a4.html",
        "attachment",
        &[("filename", "foo-\u{e4}.html")],
        "",
    ),
    (
        "attachment; filename*=utf-8''foo-%c3%a4.html",
        "attachment",
        &[("filename", "foo-\u{e4}.html")],
        "",
    ),
    (
        "attachment; filename*=iso-8859-1''foo.html",
        "attachment",
        &[],
        "",
    ),
    ("attachment; filename*=''foo.html", "attachment", &[], ""),
    ("attachment; filename*=UTF-8''foo-%", "attachment", &[], ""),
    (
        "attachment; filename*0=\"foo\"; filename*1=\"bar.html\"",
        "attachment",
        &[("filename", "foobar.html")],
        "",
    ),
    (
        "attachment; filename*0*=UTF-8''foo-%c3%a4; filename*1=\".html\"",
        "attachment",
        &[("filename", "foo-\u{e4}.html")],
        "",
    ),
    ("x/y; z=\"\"", "x/y", &[("z", "")], ""),
    ("x/y; z=\"\\\\\"", "x/y", &[("z", "\\")], ""),
    (
        "x/y; z=\"C:\\dev\\go\\foo.txt\"",
        "x/y",
        &[("z", "C:\\dev\\go\\foo.txt")],
        "",
    ),
    ("bogus", "bogus", &[], ""),
    ("bogus/", "", &[], "mime: expected token after slash"),
    ("bogus//", "", &[], "mime: expected token after slash"),
    ("bogus /x", "", &[], "mime: expected slash after first token"),
    ("", "", &[], "mime: no media type"),
    (";", "", &[], "mime: no media type"),
    ("/", "", &[], "mime: no media type"),
    ("a/b c", "", &[], "mime: unexpected content after media subtype"),
];

// (type, params, formatted output)
const FORMAT: [(&str, &[(&str, &str)], &str); 14] = [
    ("noslash", &[("X", "Y")], "noslash; x=Y"),
    ("foo bar/baz", &[], ""),
    ("foo/bar baz", &[], ""),
    ("foo/BAR", &[], "foo/bar"),
    (
        "text/html",
        &[("charset", "utf-8")],
        "text/html; charset=utf-8",
    ),
    (
        "text/html",
        &[("a", "b"), ("charset", "")],
        "text/html; a=b; charset=\"\"",
    ),
    (
        "text/html",
        &[("boundary", "a b"), ("charset", "utf-8")],
        "text/html; boundary=\"a b\"; charset=utf-8",
    ),
    (
        "text/html",
        &[("charset", "\"quoted\"")],
        "text/html; charset=\"\\\"quoted\\\"\"",
    ),
    (
        "text/html",
        &[("charset", "back\\slash")],
        "text/html; charset=\"back\\\\slash\"",
    ),
    (
        "text/html",
        &[("charset", "\u{e4}")],
        "text/html; charset*=utf-8''%C3%A4",
    ),
    (
        "text/html",
        &[("charset", "a\tb")],
        "text/html; charset=\"a\tb\"",
    ),
    ("text/html", &[("bad key", "x")], ""),
    (
        "application/x-stuff",
        &[("title", "This is ***fun***")],
        "application/x-stuff; title=\"This is ***fun***\"",
    ),
    (
        "form-data",
        &[("name", "we\"ird\\name")],
        "form-data; name=\"we\\\"ird\\\\name\"",
    ),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ParseMediaType's media type, over all 40 Go vectors.
    {
        let mut ok = true;
        let mut i = 0;
        while i < PARSE.len() {
            let (input, want_mt, _, _) = PARSE[i];
            let (mt, _, _) = mime::ParseMediaType(string(input));
            if gb(&mt) != want_mt.as_bytes().to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 1] ParseMediaType type      PASS");
        } else {
            fmt::Println!("[ 1] ParseMediaType type      FAIL");
            failed += 1;
        }
    }

    // 2. The parameter maps, key by key. This is where RFC 2231's
    //    continuations live: `title*0*`/`title*1`/`title*2*` stitches
    //    into one value, and only the *first* piece carries a charset,
    //    so `more%20` stays percent-encoded in Go's answer too.
    {
        let mut ok = true;
        let mut i = 0;
        while i < PARSE.len() {
            let (input, _, want_params, _) = PARSE[i];
            let (_, params, _) = mime::ParseMediaType(string(input));
            if params.Len() as usize != want_params.len() {
                ok = false;
            }
            let mut j = 0;
            while j < want_params.len() {
                let (k, want_v) = want_params[j];
                let (got, found) = params.Get(string(k));
                if !found || gb(&got) != want_v.as_bytes().to_vec() {
                    ok = false;
                }
                j += 1;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 2] ParseMediaType params    PASS");
        } else {
            fmt::Println!("[ 2] ParseMediaType params    FAIL");
            failed += 1;
        }
    }

    // 3. The error texts. A duplicate parameter is only an error when
    //    the two values differ, and a trailing bare ';' is not an error
    //    at all — two rules with no natural default.
    {
        let mut ok = true;
        let mut i = 0;
        while i < PARSE.len() {
            let (input, _, _, want_err) = PARSE[i];
            let (_, _, err) = mime::ParseMediaType(string(input));
            if etext(&err) != want_err.as_bytes().to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 3] ParseMediaType errors    PASS");
        } else {
            fmt::Println!("[ 3] ParseMediaType errors    FAIL");
            failed += 1;
        }
    }

    // 4. FormatMediaType, over all 14 Go vectors — including the RFC
    //    2231 `charset*=utf-8''%C3%A4` form a non-ASCII value forces,
    //    and the empty string every standard violation produces.
    {
        let mut ok = true;
        let mut i = 0;
        while i < FORMAT.len() {
            let (typ, params, want) = FORMAT[i];
            let mut m: map<gostring, gostring> = map::new();
            let mut j = 0;
            while j < params.len() {
                let (k, v) = params[j];
                m.Set(string(k), string(v));
                j += 1;
            }
            let got = mime::FormatMediaType(string(typ), m);
            if gb(&got) != want.as_bytes().to_vec() {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 4] FormatMediaType          PASS");
        } else {
            fmt::Println!("[ 4] FormatMediaType          FAIL");
            failed += 1;
        }
    }

    // 5. Everything FormatMediaType emits, ParseMediaType reads back.
    {
        let mut ok = true;
        let mut i = 0;
        while i < FORMAT.len() {
            let (typ, params, want) = FORMAT[i];
            if want.is_empty() {
                i += 1;
                continue;
            }
            let (_, back, err) = mime::ParseMediaType(string(want));
            if !err.IsNil() {
                ok = false;
            }
            let mut j = 0;
            while j < params.len() {
                let (k, v) = params[j];
                let lower = goish::strings::ToLower(string(k));
                let (got, found) = back.Get(lower);
                if !found || gb(&got) != v.as_bytes().to_vec() {
                    ok = false;
                }
                j += 1;
            }
            let _ = typ;
            i += 1;
        }
        if ok {
            fmt::Println!("[ 5] Format -> Parse          PASS");
        } else {
            fmt::Println!("[ 5] Format -> Parse          FAIL");
            failed += 1;
        }
    }

    // 6. grammar.go's two character classes, as full 0..255 counts —
    //    Go computes them from a 128-bit bitmap where a shift of 64 or
    //    more silently yields zero, so every byte above 0x7F must be
    //    outside both classes.
    {
        let mut tsp = 0;
        let mut tok = 0;
        let mut c: u32 = 0;
        while c < 256 {
            if isTSpecial(c as byte) {
                tsp += 1;
            }
            if isTokenChar(c as byte) {
                tok += 1;
            }
            c += 1;
        }
        if tsp == 15 && tok == 79 {
            fmt::Println!("[ 6] tspecial/token classes   PASS");
        } else {
            fmt::Println!("[ 6] tspecial/token classes   FAIL");
            failed += 1;
        }
    }

    // 7. isToken: empty is not a token, and a byte above 0x7F is not a
    //    token character.
    {
        if !isToken(string("")) && isToken(string("abc")) && !isToken(string("a b")) {
            fmt::Println!("[ 7] isToken                  PASS");
        } else {
            fmt::Println!("[ 7] isToken                  FAIL");
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
