// mime_ref_smoke — mime against a running Go.
// (mime/{mediatype,type}.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_mime_ref.go` run in `package mime_test`
// by `scripts/goref.sh`. The tables are GENERATED from that output
// rather than typed.
//
// `ParseMediaType` reads a Content-Type and `FormatMediaType` writes
// one, and both have a long tail of RFC 2045 and RFC 2231 behaviour:
// case folding of the type but not the value, quoted strings with
// escapes, parameter continuations (`a*0`, `a*1`), percent-encoded
// charset-tagged values (`a*=us-ascii'en'hello%20world`), and a
// duplicate parameter name that must be an ERROR rather than a
// last-one-wins. A port that gets any of it wrong still returns a type
// and a map, so the mistake reaches the handler looking like data.
//
// `TypeByExtension` and `ExtensionsByType` matched Go by NAME only —
// the state in which `encoding/binary`'s Read and Write turned out to
// be stubs.
//
// The result: all 63 reference lines agree, across every case above
// plus the eleven malformed inputs and their exact error strings, the
// quoting and RFC 2231 encoding `FormatMediaType` chooses, and the
// built-in extension table in both directions.
//
// One divergence is by construction, not by accident, and it is why
// the table cases are here: Go builds its registry from the system MIME
// databases (/etc/mime.types and the freedesktop glob files) and caches
// it in a sync.Map, where goish ships a fixed table. The vectors chosen
// are the entries Go's own built-in list carries, so they agree on any
// machine; an extension only present in a system database would not.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gomap::map;
use goish::gostring::string;
use goish::mime;
use goish::types::int;
use goish::{fmt, syscall};

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
//     Content-Type it came from.
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

// go: none — goish idiom: render the parameter map the way the Go
//     reference does — sorted by key, `k="v"` joined by a space — so a
//     map whose iteration order is randomised still compares.
fn render(m: &map<string, string>) -> string {
    let mut keys: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    for (k, _) in m.__iter() {
        keys.push(k.clone());
    }
    keys.sort();
    let mut out = string::new();
    let mut i = 0usize;
    while i < keys.len() {
        if i > 0 {
            out = out + s(" ");
        }
        let (v, _) = m.Get(keys[i].clone());
        out = out + keys[i].clone() + s("=") + fmt::Sprintf!("%q", v);
        i += 1;
    }
    return out;
}

const PMT: [(&str, &str, &str, &str); 29] = [
    ("text/plain", "text/plain", "", ""),
    ("TEXT/PLAIN", "text/plain", "", ""),
    (
        "text/plain; charset=utf-8",
        "text/plain",
        "",
        "charset=\"utf-8\"",
    ),
    (
        "text/plain;charset=utf-8",
        "text/plain",
        "",
        "charset=\"utf-8\"",
    ),
    (
        "text/plain ; charset = utf-8",
        "text/plain",
        "",
        "charset=\"utf-8\"",
    ),
    (
        "text/plain; CHARSET=UTF-8",
        "text/plain",
        "",
        "charset=\"UTF-8\"",
    ),
    (
        "text/plain; charset=\"utf-8\"",
        "text/plain",
        "",
        "charset=\"utf-8\"",
    ),
    (
        "form-data; name=\"file\"; filename=\"a b.txt\"",
        "form-data",
        "",
        "filename=\"a b.txt\" name=\"file\"",
    ),
    (
        "form-data; name=file; filename=a.txt",
        "form-data",
        "",
        "filename=\"a.txt\" name=\"file\"",
    ),
    (
        "multipart/form-data; boundary=----WebKitFormBoundary",
        "multipart/form-data",
        "",
        "boundary=\"----WebKitFormBoundary\"",
    ),
    (
        "attachment; filename=\"foo\\\"bar.txt\"",
        "attachment",
        "",
        "filename=\"foo\\\"bar.txt\"",
    ),
    (
        "text/plain; a=1; b=2; a=3",
        "",
        "mime: duplicate parameter name",
        "",
    ),
    ("text/plain;", "text/plain", "", ""),
    (
        "text/plain; ;",
        "text/plain",
        "mime: invalid media parameter",
        "",
    ),
    (
        "text/plain; =v",
        "text/plain",
        "mime: invalid media parameter",
        "",
    ),
    (
        "text/plain; k=",
        "text/plain",
        "mime: invalid media parameter",
        "",
    ),
    ("", "", "mime: no media type", ""),
    ("/", "", "mime: no media type", ""),
    ("text", "text", "", ""),
    ("text/", "", "mime: expected token after slash", ""),
    ("/plain", "", "mime: no media type", ""),
    (
        "text/plain; charset",
        "text/plain",
        "mime: invalid media parameter",
        "",
    ),
    (
        "text/plain; charset=\"unterminated",
        "text/plain",
        "mime: invalid media parameter",
        "",
    ),
    ("application/x-Foo+bar", "application/x-foo+bar", "", ""),
    (
        "x-token/x-token; a*=us-ascii'en'hello%20world",
        "x-token/x-token",
        "",
        "a=\"hello world\"",
    ),
    (
        "x-token/x-token; a*0=one; a*1=two",
        "x-token/x-token",
        "",
        "a=\"onetwo\"",
    ),
    (
        "x-token/x-token; a*0*=us-ascii'en'one; a*1=two",
        "x-token/x-token",
        "",
        "a=\"onetwo\"",
    ),
    (
        "text/plain; charset=us-ascii (Plain text)",
        "text/plain",
        "mime: invalid media parameter",
        "",
    ),
    (
        "message/external-body; access-type=URL; URL*0=\"ftp://\"; URL*1=\"cs.utk.edu\"",
        "message/external-body",
        "",
        "access-type=\"URL\" url=\"ftp://cs.utk.edu\"",
    ),
];

const EXT: [(&str, &str); 16] = [
    (".html", "text/html; charset=utf-8"),
    (".HTML", "text/html; charset=utf-8"),
    (".css", "text/css; charset=utf-8"),
    (".js", "text/javascript; charset=utf-8"),
    (".json", "application/json"),
    (".png", "image/png"),
    (".txt", "text/plain; charset=utf-8"),
    (".xml", "text/xml; charset=utf-8"),
    (".svg", "image/svg+xml"),
    (".pdf", "application/pdf"),
    (".nope", ""),
    ("", ""),
    ("html", ""),
    (".gz", "application/gzip"),
    (".wasm", "application/wasm"),
    (".mjs", "text/javascript; charset=utf-8"),
];

const BYTYPE: [(&str, &str); 5] = [
    ("text/html", ".htm .html"),
    ("text/html; charset=utf-8", ".htm .html"),
    ("application/json", ".json"),
    ("image/png", ".png"),
    ("nope/nope", ""),
];

// The FormatMediaType results, in the order the smoke builds them.
const FMT: [&str; 13] = [
    "text/plain",
    "text/plain; charset=utf-8",
    "text/plain; charset=UTF-8",
    "text/plain; a=\"b c\"",
    "text/plain; a=\"b\\\"c\"",
    "text/plain; a=\"b\\\\c\"",
    "text/plain; a=\"\"",
    "form-data; filename=\"a b.txt\"; name=file",
    "text/plain; a=1; b=2",
    "text/plain; a*=utf-8''h%C3%A9llo",
    "",
    "",
    "",
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ParseMediaType over 29 Content-Types: the ordinary ones, the
    //    quoted and escaped ones, both RFC 2231 forms, and the eleven
    //    malformed inputs with their exact error strings.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < PMT.len() {
            let (input, wmt, werr, wparams) = PMT[i];
            let (mt, params, err) = mime::ParseMediaType(input);
            eq(&mut ok, input, "media type", mt, wmt);
            if werr.len() == 0 {
                if !err.IsNil() {
                    fmt::Println!(
                        "   ",
                        fmt::Sprintf!("%q", s(input)),
                        "unexpected",
                        err.Error()
                    );
                    ok = false;
                }
            } else if err.IsNil() || err.Error() != s(werr) {
                fmt::Println!(
                    "   ",
                    fmt::Sprintf!("%q", s(input)),
                    "err got",
                    if err.IsNil() { s("<nil>") } else { err.Error() },
                    "want",
                    s(werr)
                );
                ok = false;
            }
            eq(&mut ok, input, "params", render(&params), wparams);
            i += 1;
        }
        report(&mut failed, ok, " 1", "ParseMediaType, valid and malformed");
    }

    // 2. FormatMediaType. Go quotes a value holding a space, escapes a
    //    quote or a backslash, writes `a=""` for an empty value, and
    //    falls back to RFC 2231 (`a*=utf-8''…`) for anything non-ASCII.
    //    An invalid type or key produces "" — not a best-effort string.
    {
        let mut ok = true;
        let mk = |pairs: &[(&str, &str)]| -> map<string, string> {
            let mut m: map<string, string> = goish::make!(map[string]string);
            for (k, v) in pairs {
                m.Set(s(k), s(v));
            }
            m
        };
        let cases: [(&str, alloc::vec::Vec<(&str, &str)>); 13] = [
            ("text/plain", alloc::vec![]),
            ("text/plain", alloc::vec![("charset", "utf-8")]),
            ("TEXT/PLAIN", alloc::vec![("CHARSET", "UTF-8")]),
            ("text/plain", alloc::vec![("a", "b c")]),
            ("text/plain", alloc::vec![("a", "b\"c")]),
            ("text/plain", alloc::vec![("a", "b\\c")]),
            ("text/plain", alloc::vec![("a", "")]),
            (
                "form-data",
                alloc::vec![("name", "file"), ("filename", "a b.txt")],
            ),
            ("text/plain", alloc::vec![("a", "1"), ("b", "2")]),
            ("text/plain", alloc::vec![("a", "h\u{e9}llo")]),
            ("bad type", alloc::vec![]),
            ("text/plain", alloc::vec![("bad key", "v")]),
            ("", alloc::vec![("a", "b")]),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (t, pairs) = &cases[i];
            eq(
                &mut ok,
                t,
                "FormatMediaType",
                mime::FormatMediaType(*t, mk(pairs)),
                FMT[i],
            );
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 2",
            "FormatMediaType quotes and encodes as Go does",
        );
    }

    // 3. TypeByExtension is case-insensitive on the extension, requires
    //    the leading dot, and returns "" for anything it does not know.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < EXT.len() {
            let (e, want) = EXT[i];
            eq(
                &mut ok,
                e,
                "TypeByExtension",
                mime::TypeByExtension(e),
                want,
            );
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 3",
            "TypeByExtension, including its misses",
        );
    }

    // 4. ExtensionsByType goes the other way, ignoring any parameters
    //    on the type, and returns an empty list rather than an error
    //    for a type it does not know.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < BYTYPE.len() {
            let (ty, want) = BYTYPE[i];
            let (ex, err) = mime::ExtensionsByType(ty);
            if !err.IsNil() {
                ok = false;
            }
            let mut v: alloc::vec::Vec<string> = alloc::vec::Vec::new();
            let mut k = 0usize;
            while k < ex.len() {
                v.push(ex[k].clone());
                k += 1;
            }
            v.sort();
            let mut got = string::new();
            let mut j = 0usize;
            while j < v.len() {
                if j > 0 {
                    got = got + s(" ");
                }
                got = got + v[j].clone();
                j += 1;
            }
            eq(&mut ok, ty, "ExtensionsByType", got, want);
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 4",
            "ExtensionsByType ignores the parameters",
        );
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
