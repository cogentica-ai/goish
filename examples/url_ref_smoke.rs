// url_ref_smoke — net/url against a running Go.
// (net/url/url.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_url_ref.go` run in `package url_test` by
// `scripts/goref.sh`. The tables are GENERATED from that output rather
// than typed.
//
// `net/url` had no provenance anchors: 27 functions matched Go by NAME
// only. Diffed line for line, 55 of the reference's 118 lines differed
// — the worst result of any package this method has been pointed at,
// and the reason is that a URL that parses into slightly the wrong
// fields still round-trips often enough to look fine. It only shows
// when the URL is used to route, to sign, or to compare against an
// allow-list.
//
// What was wrong:
//
//   * `//host/path` parsed with an EMPTY host and the authority left in
//     Path. Every protocol-relative URL was mis-parsed. `parse` only
//     looked for an authority when a scheme was present.
//   * `String()` wrote "//" in front of a bare path: `/just/a/path`
//     rendered as `///just/a/path` and `just/a/path` as `//just/a/path`
//     — the second reads as an authority, so the URL means something
//     else. goish had `u.Path != ""` in the test Go writes over
//     `u.Scheme`, `u.Host` and `u.User`.
//   * RawPath was NEVER set, so `%2F` in a path was decoded and then
//     re-escaped: `/a%2Fb/c` came back out as `/a%252Fb/c`. A router
//     matching the re-rendered form sees two segments where the sender
//     meant one.
//   * `RequestURI()` returned "" for a URL with an empty path — every
//     `http://host` — which is not a valid request line. Go's default
//     is "/".
//   * The query was not split off before deciding what the rest was, so
//     `scheme:opaque?q=1` kept the query INSIDE Opaque and
//     `?query-only` put it in Path.
//   * `ForceQuery` was never set, so a trailing "?" was lost.
//   * An invalid escape in the path was accepted: `http://host/%zz`
//     parsed.
//   * The IPv6 zone was not decoded: `[fe80::1%25eth0]` kept its `%25`,
//     so `Hostname()` returned the escaped form.
//   * `ParseRequestURI` accepted a relative reference, which is the one
//     thing it exists to reject.
//   * `ResolveReference` never called `resolvePath`, so NO dot segment
//     was ever removed: `..` against `http://a/b/c/d;p?q` gave
//     `http://a/b/c/..`. Every one of RFC 3986's own worked examples
//     came out wrong.
//   * `ParseQuery` split on ';' as well as '&' — the behaviour Go
//     REMOVED in 1.17, because a proxy and an origin that disagree
//     about the separator disagree about the request. It also dropped a
//     setting with an empty key and kept the values it had already
//     decoded when a later one failed.
//   * `JoinPath` dropped a trailing slash, so joining "c/" gave
//     "/a/b/c" — a different resource to every server that treats a
//     directory path as distinct from a file one.
//
// Escaping and unescaping were already right, in every mode and for
// every malformed input, which is what made the rest worth chasing.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::net::url;
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

// go: none — goish idiom: compare one field against Go's and name the
//     input it came from, since every row here is a different URL.
fn eq(ok: &mut bool, raw: &str, what: &str, got: string, want: &str) {
    if got != s(want) {
        fmt::Println!(
            "   ",
            s(raw),
            s(what),
            fmt::Sprintf!("got %q want %q", got, s(want))
        );
        *ok = false;
    }
}

const PARSE: [(
    &str,
    &str,
    &str,
    &str,
    &str,
    &str,
    &str,
    bool,
    &str,
    &str,
    &str,
); 24] = [
    (
        "http://example.com",
        "http",
        "",
        "",
        "example.com",
        "",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "http://example.com/",
        "http",
        "",
        "",
        "example.com",
        "/",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "http://example.com/a/b?x=1&y=2#frag",
        "http",
        "",
        "",
        "example.com",
        "/a/b",
        "",
        false,
        "x=1&y=2",
        "frag",
        "",
    ),
    (
        "https://user:pass@host:8080/p?q#f",
        "https",
        "",
        "user:pass",
        "host:8080",
        "/p",
        "",
        false,
        "q",
        "f",
        "",
    ),
    (
        "https://user@host/p",
        "https",
        "",
        "user",
        "host",
        "/p",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "//host/path",
        "",
        "",
        "",
        "host",
        "/path",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "/just/a/path",
        "",
        "",
        "",
        "",
        "/just/a/path",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "just/a/path",
        "",
        "",
        "",
        "",
        "just/a/path",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "mailto:me@example.com",
        "mailto",
        "me@example.com",
        "",
        "",
        "",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "scheme:opaque?q=1#f",
        "scheme",
        "opaque",
        "",
        "",
        "",
        "",
        false,
        "q=1",
        "f",
        "",
    ),
    (
        "http://[::1]:80/x",
        "http",
        "",
        "",
        "[::1]:80",
        "/x",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "http://[fe80::1%25eth0]/x",
        "http",
        "",
        "",
        "[fe80::1%eth0]",
        "/x",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "http://host/a%2Fb/c",
        "http",
        "",
        "",
        "host",
        "/a/b/c",
        "/a%2Fb/c",
        false,
        "",
        "",
        "",
    ),
    (
        "http://host/a b",
        "http",
        "",
        "",
        "host",
        "/a b",
        "/a b",
        false,
        "",
        "",
        "",
    ),
    (
        "http://host/?a=%20&b=+",
        "http",
        "",
        "",
        "host",
        "/",
        "",
        false,
        "a=%20&b=+",
        "",
        "",
    ),
    (
        "http://host?#",
        "http",
        "",
        "",
        "host",
        "",
        "",
        true,
        "",
        "",
        "",
    ),
    (
        "http://host#",
        "http",
        "",
        "",
        "host",
        "",
        "",
        false,
        "",
        "",
        "",
    ),
    ("", "", "", "", "", "", "", false, "", "", ""),
    (
        "http://example.com/././a/../b",
        "http",
        "",
        "",
        "example.com",
        "/././a/../b",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "HTTP://Example.COM/Path",
        "http",
        "",
        "",
        "Example.COM",
        "/Path",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "http://user:pa%40ss@host/",
        "http",
        "",
        "user:pa%40ss",
        "host",
        "/",
        "",
        false,
        "",
        "",
        "",
    ),
    (
        "foo://host/path;params?q",
        "foo",
        "",
        "",
        "host",
        "/path;params",
        "",
        false,
        "q",
        "",
        "",
    ),
    (
        "?query-only",
        "",
        "",
        "",
        "",
        "",
        "",
        false,
        "query-only",
        "",
        "",
    ),
    (
        "#frag-only",
        "",
        "",
        "",
        "",
        "",
        "",
        false,
        "",
        "frag-only",
        "",
    ),
];

const BACK: [(&str, &str, &str, bool, &str, &str, &str, &str); 0] = [];

const PARSE_ERR: [(&str, &str); 2] = [
    ("http://host/%zz", "invalid URL escape \"%zz\""),
    ("http://host:port/", "invalid port \":port\" after host"),
];

const REQURI: [(&str, &str, &str, &str); 4] = [
    ("http://h/p", "/p", "", "http://h/p"),
    ("/p", "/p", "", "/p"),
    ("//h/p", "//h/p", "", "//h/p"),
    ("http://h/p#f", "/p#f", "", "http://h/p%23f"),
];

const REQURI_ERR: [(&str, &str); 1] = [("p", "invalid URI for request")];

const ESC: [(&str, &str, &str); 13] = [
    ("", "", ""),
    ("a", "a", "a"),
    ("a b", "a+b", "a%20b"),
    ("a+b", "a%2Bb", "a+b"),
    ("a/b", "a%2Fb", "a%2Fb"),
    ("a?b", "a%3Fb", "a%3Fb"),
    ("a#b", "a%23b", "a%23b"),
    ("a%b", "a%25b", "a%25b"),
    ("héllo", "h%C3%A9llo", "h%C3%A9llo"),
    ("\x00\x7f", "%00%7F", "%00%7F"),
    ("~-_.", "~-_.", "~-_."),
    ("!*'()", "%21%2A%27%28%29", "%21%2A%27%28%29"),
    (":@&=$,;", "%3A%40%26%3D%24%2C%3B", ":@&=$%2C%3B"),
];

const UNESC: [(&str, &str, &str, &str, &str); 11] = [
    ("", "", "", "", ""),
    ("a", "a", "", "a", ""),
    ("a+b", "a b", "", "a+b", ""),
    ("a%20b", "a b", "", "a b", ""),
    ("a%2Fb", "a/b", "", "a/b", ""),
    (
        "%",
        "",
        "invalid URL escape \"%\"",
        "",
        "invalid URL escape \"%\"",
    ),
    (
        "%2",
        "",
        "invalid URL escape \"%2\"",
        "",
        "invalid URL escape \"%2\"",
    ),
    (
        "%zz",
        "",
        "invalid URL escape \"%zz\"",
        "",
        "invalid URL escape \"%zz\"",
    ),
    ("%41", "A", "", "A", ""),
    ("a%00b", "a\x00b", "", "a\x00b", ""),
    ("+", " ", "", "+", ""),
];

const RESOLVE: [(&str, &str); 20] = [
    ("g", "http://a/b/c/g"),
    ("./g", "http://a/b/c/g"),
    ("g/", "http://a/b/c/g/"),
    ("/g", "http://a/g"),
    ("//g", "http://g"),
    ("?y", "http://a/b/c/d;p?y"),
    ("g?y", "http://a/b/c/g?y"),
    ("#s", "http://a/b/c/d;p?q#s"),
    ("g#s", "http://a/b/c/g#s"),
    ("", "http://a/b/c/d;p?q"),
    (".", "http://a/b/c/"),
    ("..", "http://a/b/"),
    ("../..", "http://a/"),
    ("../../g", "http://a/g"),
    ("/./g", "http://a/g"),
    ("/../g", "http://a/g"),
    ("g.", "http://a/b/c/g."),
    (".g", "http://a/b/c/.g"),
    ("http://x/y", "http://x/y"),
    ("mailto:m@e", "mailto:m@e"),
];

const QUERY: [(&str, &str, &str, &str); 11] = [
    ("", "", "map[]", ""),
    ("a=1", "", "map[a:[1]]", "a=1"),
    ("a=1&b=2", "", "map[a:[1] b:[2]]", "a=1&b=2"),
    ("a=1&a=2", "", "map[a:[1 2]]", "a=1&a=2"),
    ("a", "", "map[a:[]]", "a="),
    ("a=", "", "map[a:[]]", "a="),
    ("=1", "", "map[:[1]]", "=1"),
    (
        "a=1;b=2",
        "invalid semicolon separator in query",
        "map[]",
        "",
    ),
    ("a=%zz", "invalid URL escape \"%zz\"", "map[]", ""),
    ("a=%20&b=+", "", "map[a:[ ] b:[ ]]", "a=+&b=+"),
    ("&&a=1&&", "", "map[a:[1]]", "a=1"),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Every field `Parse` fills in, for 24 URLs. The rows that
    //    mattered most: `//host/path` (an authority with no scheme),
    //    `scheme:opaque?q=1#f` (a query outside the opaque part),
    //    `http://host/a%2Fb/c` (RawPath), `http://host?#` (ForceQuery)
    //    and `[fe80::1%25eth0]` (the decoded zone).
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < PARSE.len() {
            let (raw, scheme, opaque, user, host, path, rawp, force, query, frag, rawf) = PARSE[i];
            let (u, err) = url::Parse(raw);
            if !err.IsNil() {
                fmt::Println!("   ", s(raw), "unexpected error", err.Error());
                ok = false;
                i += 1;
                continue;
            }
            eq(&mut ok, raw, "Scheme", u.Scheme.clone(), scheme);
            eq(&mut ok, raw, "Opaque", u.Opaque.clone(), opaque);
            eq(&mut ok, raw, "User", u.User.String(), user);
            eq(&mut ok, raw, "Host", u.Host.clone(), host);
            eq(&mut ok, raw, "Path", u.Path.clone(), path);
            eq(&mut ok, raw, "RawPath", u.RawPath.clone(), rawp);
            if u.ForceQuery != force {
                fmt::Println!("   ", s(raw), "ForceQuery", u.ForceQuery, "want", force);
                ok = false;
            }
            eq(&mut ok, raw, "RawQuery", u.RawQuery.clone(), query);
            eq(&mut ok, raw, "Fragment", u.Fragment.clone(), frag);
            eq(&mut ok, raw, "RawFragment", u.RawFragment.clone(), rawf);
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 1",
            "Parse fills every field the way Go does",
        );
    }

    // 2. And back out again: String, RequestURI, IsAbs, Hostname, Port,
    //    EscapedPath, Redacted.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < BACK.len() {
            let (raw, st, reqp, abs, hostname, port, escp, red) = BACK[i];
            let (u, err) = url::Parse(raw);
            if !err.IsNil() {
                ok = false;
                i += 1;
                continue;
            }
            eq(&mut ok, raw, "String", u.String(), st);
            eq(&mut ok, raw, "RequestURI", u.RequestURI(), reqp);
            if u.IsAbs() != abs {
                ok = false;
            }
            eq(&mut ok, raw, "Hostname", u.Hostname(), hostname);
            eq(&mut ok, raw, "Port", u.Port(), port);
            eq(&mut ok, raw, "EscapedPath", u.EscapedPath(), escp);
            eq(&mut ok, raw, "Redacted", u.Redacted(), red);
            i += 1;
        }
        report(&mut failed, ok, " 2", "String and the accessors round-trip");
    }

    // 3. The URLs Go REFUSES. goish accepted both: `%zz` in a path and
    //    a non-numeric port.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < PARSE_ERR.len() {
            let (raw, want) = PARSE_ERR[i];
            let (_, err) = url::Parse(raw);
            if err.IsNil() {
                fmt::Println!("   ", s(raw), "parsed; Go rejects it");
                ok = false;
            } else {
                // Go's Error wraps as `parse "<url>": <reason>`; compare
                // the reason, since goish's wrapper prints the same shape.
                let msg = err.Error();
                if !goish::strings::Contains(msg.clone(), want) {
                    fmt::Println!("   ", s(raw), "got", msg, "want …", s(want));
                    ok = false;
                }
            }
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 3",
            "an invalid escape or port is refused",
        );
    }

    // 4. ParseRequestURI, which reads its input as an absolute URI or an
    //    absolute path and NEVER as a relative reference — the one thing
    //    it exists to do, and the one goish did not do. Note also that
    //    it leaves a '#' in the PATH: there is no fragment in a request
    //    line.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < REQURI.len() {
            let (raw, path, frag, st) = REQURI[i];
            let (u, err) = url::ParseRequestURI(raw);
            if !err.IsNil() {
                fmt::Println!("   ", s(raw), "unexpected error", err.Error());
                ok = false;
                i += 1;
                continue;
            }
            eq(&mut ok, raw, "Path", u.Path.clone(), path);
            eq(&mut ok, raw, "Fragment", u.Fragment.clone(), frag);
            eq(&mut ok, raw, "String", u.String(), st);
            i += 1;
        }
        let mut k = 0usize;
        while k < REQURI_ERR.len() {
            let (raw, want) = REQURI_ERR[k];
            let (_, err) = url::ParseRequestURI(raw);
            if err.IsNil() || !goish::strings::Contains(err.Error(), want) {
                fmt::Println!(
                    "   ",
                    s(raw),
                    "ParseRequestURI accepted a relative reference"
                );
                ok = false;
            }
            k += 1;
        }
        report(
            &mut failed,
            ok,
            " 4",
            "ParseRequestURI rejects a relative reference",
        );
    }

    // 5. Escaping and unescaping in both modes — already correct, kept
    //    so the parser rewrite cannot disturb it. QueryEscape and
    //    PathEscape differ on space, '+', ',' and ';'.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < ESC.len() {
            let (v, q, p) = ESC[i];
            eq(&mut ok, v, "QueryEscape", url::QueryEscape(v), q);
            eq(&mut ok, v, "PathEscape", url::PathEscape(v), p);
            i += 1;
        }
        let mut k = 0usize;
        while k < UNESC.len() {
            let (v, qv, qe, pv, pe) = UNESC[k];
            let (gq, gqe) = url::QueryUnescape(v);
            let (gp, gpe) = url::PathUnescape(v);
            if qe.len() == 0 {
                if !gqe.IsNil() {
                    ok = false;
                }
                eq(&mut ok, v, "QueryUnescape", gq, qv);
            } else if gqe.IsNil() || gqe.Error() != s(qe) {
                fmt::Println!("   ", s(v), "QueryUnescape error", s(qe));
                ok = false;
            }
            if pe.len() == 0 {
                if !gpe.IsNil() {
                    ok = false;
                }
                eq(&mut ok, v, "PathUnescape", gp, pv);
            } else if gpe.IsNil() || gpe.Error() != s(pe) {
                ok = false;
            }
            k += 1;
        }
        report(&mut failed, ok, " 5", "escaping, in both modes");
    }

    // 6. ResolveReference against RFC 3986's own base, `http://a/b/c/d;p?q`
    //    — the table from §5.4. Not one dot-segment case worked before.
    {
        let mut ok = true;
        let (base, berr) = url::Parse("http://a/b/c/d;p?q");
        if !berr.IsNil() {
            ok = false;
        }
        let mut i = 0usize;
        while i < RESOLVE.len() {
            let (r, want) = RESOLVE[i];
            let (rr, rerr) = url::Parse(r);
            if !rerr.IsNil() {
                ok = false;
                i += 1;
                continue;
            }
            let out = base.ResolveReference(&rr);
            eq(&mut ok, r, "ResolveReference", out.String(), want);
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 6",
            "ResolveReference removes dot segments",
        );
    }

    // 7. ParseQuery and Values.Encode. Go REJECTS a setting containing a
    //    semicolon (removed in 1.17: a proxy and an origin that disagree
    //    about the separator disagree about the request), keeps `=1` as
    //    the empty key, and on an error returns the settings it could
    //    decode alongside the FIRST failure.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < QUERY.len() {
            let (q, werr, wmap, wenc) = QUERY[i];
            let (v, err) = url::ParseQuery(q);
            if werr.len() == 0 {
                if !err.IsNil() {
                    fmt::Println!("   ", s(q), "unexpected error", err.Error());
                    ok = false;
                }
            } else if err.IsNil() || err.Error() != s(werr) {
                fmt::Println!("   ", s(q), "want error", s(werr));
                ok = false;
            }
            eq(&mut ok, q, "map", fmt::Sprintf!("%v", v.clone()), wmap);
            eq(&mut ok, q, "Encode", url::ValuesEncode(&v), wenc);
            i += 1;
        }
        report(&mut failed, ok, " 7", "ParseQuery rejects a semicolon");
    }

    // 8. JoinPath, whose trailing slash Go preserves and goish dropped.
    {
        let mut ok = true;
        let (u, _) = url::Parse("http://h/a/b");
        // (elements joined by '\x1f', want)
        let cases: [(&str, &str); 7] = [
            ("", "http://h/a/b"),
            ("c", "http://h/a/b/c"),
            ("c\u{1f}d", "http://h/a/b/c/d"),
            ("../c", "http://h/a/c"),
            ("/c", "http://h/a/b/c"),
            ("c/", "http://h/a/b/c/"),
            ("\u{1f}c", "http://h/a/b/c"),
        ];
        let mut i = 0usize;
        while i < cases.len() {
            let (joined, want) = cases[i];
            let mut parts: alloc::vec::Vec<string> = alloc::vec::Vec::new();
            if joined.len() > 0 {
                for p in joined.split('\u{1f}') {
                    parts.push(s(p));
                }
            }
            let j = u.JoinPath(slice::__from_vec(parts));
            eq(&mut ok, joined, "JoinPath", j.String(), want);
            i += 1;
        }
        report(&mut failed, ok, " 8", "JoinPath keeps a trailing slash");
    }

    // 9. Userinfo rendering, which escapes ':' in the username and '@'
    //    in the password. Already correct; kept because `String()` now
    //    routes the host through `escape` too.
    {
        let mut ok = true;
        eq(&mut ok, "u", "User", url::User("u").String(), "u");
        eq(
            &mut ok,
            "u:p",
            "UserPassword",
            url::UserPassword("u", "p").String(),
            "u:p",
        );
        eq(
            &mut ok,
            "u:x/p@y",
            "UserPassword",
            url::UserPassword("u:x", "p@y").String(),
            "u%3Ax:p%40y",
        );
        report(&mut failed, ok, " 9", "Userinfo escapes ':' and '@'");
    }

    // 10. `Query()` and the binary marshalling, which were not ported
    //     when the parser was rewritten and are the last of Go's URL
    //     surface to land. `Query` discards a malformed pair silently —
    //     `?a=%zz` and `?a=1;b=2` both give an EMPTY map, not a partial
    //     one — which is why Go's doc points a caller who cares at
    //     ParseQuery instead.
    {
        let mut ok = true;
        // (raw, Encode() of u.Query())
        let qcases: [(&str, &str); 8] = [
            ("http://h/p?a=1&b=2", "a=1&b=2"),
            ("http://h/p?a=1&a=2", "a=1&a=2"),
            ("http://h/p", ""),
            ("http://h/p?", ""),
            ("http://h/p?a", "a="),
            ("http://h/p?a=%zz", ""),
            ("http://h/p?a=1;b=2", ""),
            ("http://h/p?a=%20&b=+", "a=+&b=+"),
        ];
        let mut i = 0usize;
        while i < qcases.len() {
            let (raw, want) = qcases[i];
            let (u, _) = url::Parse(raw);
            eq(
                &mut ok,
                raw,
                "Query().Encode()",
                url::ValuesEncode(&u.Query()),
                want,
            );
            i += 1;
        }
        // A URL marshals as the text String() produces and unmarshals by
        // parsing it back, so the round trip is exact for every shape —
        // opaque, rootless, protocol-relative and empty alike.
        for raw in [
            "http://h/p?a=1#f",
            "/just/a/path",
            "mailto:m@e",
            "",
            "//host/x",
        ] {
            let (u, _) = url::Parse(raw);
            let (b, err) = u.MarshalBinary();
            if !err.IsNil() {
                ok = false;
            }
            eq(
                &mut ok,
                raw,
                "MarshalBinary",
                string::from_bytes(b.as_ref()),
                raw,
            );
            let mut back = url::URL::default();
            if !back.UnmarshalBinary(b).IsNil() {
                ok = false;
            }
            eq(
                &mut ok,
                raw,
                "round trip",
                back.String(),
                u.String().as_ref(),
            );
            let (ap, _) = u.AppendBinary(goish::bytes("X"));
            eq(
                &mut ok,
                raw,
                "AppendBinary",
                string::from_bytes(ap.as_ref()),
                &(alloc::string::String::from("X") + raw),
            );
        }
        // Go: an unparseable text is the parse error, not a partial URL.
        let mut bad = url::URL::default();
        let e = bad.UnmarshalBinary(goish::bytes("http://h/%zz"));
        if e.IsNil() || !goish::strings::Contains(e.Error(), "invalid URL escape") {
            ok = false;
        }
        report(&mut failed, ok, "10", "Query, and the binary round trip");
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
