// textproto_ref_smoke — net/textproto against a running Go.
// (net/textproto/{header,reader,textproto}.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_textproto_ref.go` run in `package
// textproto_test` by `scripts/goref.sh`. The tables are GENERATED from
// that output rather than typed.
//
// textproto is what parses an HTTP header block. A key that
// canonicalises differently, or a continuation line folded differently,
// changes which handler sees which value — and the difference is
// silent, because both sides produce a map.
//
// 24 of its 38 ported functions matched Go by NAME only. Diffed line
// for line, the parsing was RIGHT throughout: the canonicaliser's
// hyphen rule and its refusal to touch a key with a space or a
// non-ASCII byte, the continuation folding for both a space and a tab,
// the empty-value and duplicate-key cases, the two malformed shapes and
// their errors, and the EOF an unterminated block returns alongside the
// headers it did read.
//
// One thing was wrong, and it is worth the whole exercise: two error
// messages were built with `Sprintf!("… {}", x)` — a RUST placeholder
// in a Go format string. `Sprintf` copies `{}` out literally and then
// reports the argument that went nowhere, so a malformed header read
//
//     malformed MIME header: missing colon: {}%!(EXTRA string="A 1")
//
// where Go says `missing colon: "A 1"`. Before the `%!(EXTRA …)`
// machinery landed earlier in this tree's history the trailing marker
// did not exist, so the message simply read `missing colon: {}` and
// nothing pointed at the mistake.
//
// A sweep for the same shape found three more, in net/mail, os/user and
// net/http's Range handling — the last emitting a `Content-Range:
// bytes */{}` header that no client can parse.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bufio;
use goish::bytes;
use goish::gostring::string;
use goish::net::textproto;
use goish::types::int;
use goish::{fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

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

// go: none — goish idiom: compare one result against Go's and name the
//     input, since every row here is a different header block.
fn eq(ok: &mut bool, input: &str, what: &str, got: string, want: &str) {
    if got != s(want) {
        fmt::Println!(
            "   ",
            fmt::Sprintf!("%q", s(input)),
            s(what),
            fmt::Sprintf!("got %q want %q", got, s(want))
        );
        *ok = false;
    }
}

const CANON: [(&str, &str); 26] = [
    ("", ""),
    ("a", "A"),
    ("A", "A"),
    ("accept", "Accept"),
    ("ACCEPT", "Accept"),
    ("Accept-Encoding", "Accept-Encoding"),
    ("accept-encoding", "Accept-Encoding"),
    ("ACCEPT-ENCODING", "Accept-Encoding"),
    ("aCcEpT-eNcOdInG", "Accept-Encoding"),
    ("x", "X"),
    ("-", "-"),
    ("a-", "A-"),
    ("-a", "-A"),
    ("a--b", "A--B"),
    ("content-type", "Content-Type"),
    ("www-authenticate", "Www-Authenticate"),
    ("etag", "Etag"),
    ("ETag", "Etag"),
    ("TE", "Te"),
    ("te", "Te"),
    ("user_agent", "User_agent"),
    ("user agent", "user agent"),
    ("a b", "a b"),
    ("héllo", "héllo"),
    ("x-1-2", "X-1-2"),
    ("1-a", "1-A"),
];

const MIME: [(&str, &str, &str); 13] = [
    ("A: 1\r\nB: 2\r\n\r\n", "", "map[A:[1] B:[2]]"),
    ("a: 1\r\na: 2\r\n\r\n", "", "map[A:[1 2]]"),
    ("A:1\r\n\r\n", "", "map[A:[1]]"),
    ("A:   spaced   \r\n\r\n", "", "map[A:[spaced]]"),
    (
        "A: one\r\n two\r\n\tthree\r\n\r\n",
        "",
        "map[A:[one two three]]",
    ),
    ("A: \r\n\r\n", "", "map[A:[]]"),
    ("A: 1\n B: 2\n\n", "", "map[A:[1 B: 2]]"),
    ("\r\n", "", "map[]"),
    ("A: 1\r\n", "EOF", "map[A:[1]]"),
    (
        "A 1\r\n\r\n",
        "malformed MIME header: missing colon: \"A 1\"",
        "map[]",
    ),
    (
        " A: 1\r\n\r\n",
        "malformed MIME header initial line:  A: 1",
        "map[]",
    ),
    ("A: 1\r\nA: 2\r\nB: 3\r\n\r\n", "", "map[A:[1 2] B:[3]]"),
    ("Empty:\r\n\r\n", "", "map[Empty:[]]"),
];

const LINE: [(&str, &str, &str, &str, &str); 6] = [
    ("one\r\ntwo\r\n", "one", "", "two", ""),
    ("one\ntwo\n", "one", "", "two", ""),
    ("one\r\n cont\r\nnext\r\n", "one", "", " cont", ""),
    ("one\r\n\tcont\r\n", "one", "", "\tcont", ""),
    ("\r\n", "", "", "", "EOF"),
    ("no-newline", "no-newline", "", "", "EOF"),
];

const CONT: [(&str, &str, &str, &str, &str); 6] = [
    ("one\r\ntwo\r\n", "one", "", "two", ""),
    ("one\ntwo\n", "one", "", "two", ""),
    ("one\r\n cont\r\nnext\r\n", "one cont", "", "next", ""),
    ("one\r\n\tcont\r\n", "one cont", "", "", "EOF"),
    ("\r\n", "", "", "", "EOF"),
    ("no-newline", "no-newline", "", "", "EOF"),
];

const TRIM: [(&str, &str, &str); 8] = [
    ("", "", ""),
    (" ", "", ""),
    (" a ", "a", "a"),
    ("\ta\t", "a", "a"),
    ("\r\na\r\n", "a", "a"),
    ("a b", "a b", "a b"),
    ("  ", "", ""),
    ("\t \r\n x \r\n \t", "x", "x"),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. CanonicalMIMEHeaderKey. Go title-cases each hyphen-separated
    //    run and returns the key UNCHANGED when it holds anything that
    //    is not a valid header-field byte — so "a b" and "héllo" come
    //    back as they went in, and "user_agent" becomes "User_agent"
    //    because '_' IS valid.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < CANON.len() {
            let (k, want) = CANON[i];
            eq(
                &mut ok,
                k,
                "CanonicalMIMEHeaderKey",
                textproto::CanonicalMIMEHeaderKey(k),
                want,
            );
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 1",
            "the canonicaliser, including what it leaves alone",
        );
    }

    // 2. MIMEHeader Get/Set/Add/Del/Values all canonicalise the key, so
    //    a lookup with different casing finds the same entry.
    {
        let mut ok = true;
        let mut h: textproto::MIMEHeader = goish::make!(map[string]slice<string>);
        textproto::Set(&mut h, "content-type", "text/plain");
        textproto::Add(&mut h, "Set-Cookie", "a=1");
        textproto::Add(&mut h, "set-cookie", "b=2");
        eq(
            &mut ok,
            "hdr",
            "Get",
            textproto::Get(&h, "Content-Type"),
            "text/plain",
        );
        let vs = textproto::Values(&h, "SET-COOKIE");
        if vs.len() != 2 || vs[0] != s("a=1") || vs[1] != s("b=2") {
            ok = false;
        }
        // Go: a missing key is "" and an EMPTY slice, never a panic.
        eq(
            &mut ok,
            "hdr",
            "Get missing",
            textproto::Get(&h, "nope"),
            "",
        );
        if textproto::Values(&h, "nope").len() != 0 {
            ok = false;
        }
        textproto::Del(&mut h, "CONTENT-TYPE");
        eq(
            &mut ok,
            "hdr",
            "after Del",
            textproto::Get(&h, "content-type"),
            "",
        );
        if h.Len() != 1 {
            ok = false;
        }
        report(
            &mut failed,
            ok,
            " 2",
            "the header map canonicalises on every path",
        );
    }

    // 3. ReadMIMEHeader over thirteen blocks: continuations folded with
    //    a space, duplicates appended, an empty value giving an EMPTY
    //    slice rather than one empty string, a missing colon and a
    //    leading space each with their own error, and an unterminated
    //    block returning EOF ALONGSIDE the headers it managed to read.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < MIME.len() {
            let (block, werr, wmap) = MIME[i];
            let mut r =
                textproto::NewReader(bufio::NewReader(bytes::NewReader(goish::bytes(block))));
            let (m, err) = r.ReadMIMEHeader();
            if werr.len() == 0 {
                if !err.IsNil() {
                    fmt::Println!(
                        "   ",
                        fmt::Sprintf!("%q", s(block)),
                        "unexpected",
                        err.Error()
                    );
                    ok = false;
                }
            } else if err.IsNil() || err.Error() != s(werr) {
                fmt::Println!(
                    "   ",
                    fmt::Sprintf!("%q", s(block)),
                    "err got",
                    if err.IsNil() { s("<nil>") } else { err.Error() },
                    "want",
                    s(werr)
                );
                ok = false;
            }
            eq(&mut ok, block, "map", fmt::Sprintf!("%v", m), wmap);
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 3",
            "ReadMIMEHeader, folded and malformed alike",
        );
    }

    // 4. ReadLine returns the continuation line AS IS, leading
    //    whitespace and all; ReadContinuedLine folds it onto the
    //    previous line with a single space, whether the fold was a
    //    space or a tab.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < LINE.len() {
            let (input, l1, e1, l2, e2) = LINE[i];
            let mut r =
                textproto::NewReader(bufio::NewReader(bytes::NewReader(goish::bytes(input))));
            let (g1, ge1) = r.ReadLine();
            let (g2, ge2) = r.ReadLine();
            eq(&mut ok, input, "ReadLine 1", g1, l1);
            eq(&mut ok, input, "ReadLine 2", g2, l2);
            if (e1.len() == 0) != ge1.IsNil() || (e2.len() == 0) != ge2.IsNil() {
                fmt::Println!("   ", fmt::Sprintf!("%q", s(input)), "ReadLine error shape");
                ok = false;
            }
            i += 1;
        }
        let mut k = 0usize;
        while k < CONT.len() {
            let (input, c1, e1, c2, e2) = CONT[k];
            let mut r =
                textproto::NewReader(bufio::NewReader(bytes::NewReader(goish::bytes(input))));
            let (g1, ge1) = r.ReadContinuedLine();
            let (g2, ge2) = r.ReadContinuedLine();
            eq(&mut ok, input, "ReadContinuedLine 1", g1, c1);
            eq(&mut ok, input, "ReadContinuedLine 2", g2, c2);
            if (e1.len() == 0) != ge1.IsNil() || (e2.len() == 0) != ge2.IsNil() {
                ok = false;
            }
            k += 1;
        }
        report(
            &mut failed,
            ok,
            " 4",
            "ReadLine keeps the fold, ReadContinuedLine folds it",
        );
    }

    // 5. TrimString and TrimBytes strip ' ', '\t', '\r' and '\n' from
    //    both ends and nothing from the middle.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < TRIM.len() {
            let (v, want, wantb) = TRIM[i];
            eq(&mut ok, v, "TrimString", textproto::TrimString(v), want);
            eq(
                &mut ok,
                v,
                "TrimBytes",
                string::from_bytes(&textproto::TrimBytes(goish::bytes(v))),
                wantb,
            );
            i += 1;
        }
        report(&mut failed, ok, " 5", "TrimString and TrimBytes");
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
