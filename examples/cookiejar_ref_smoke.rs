// cookiejar_ref_smoke — net/http/cookiejar against a running Go.
// (net/http/cookiejar/jar.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_cookiejar_ref.go` run in
// `package cookiejar_test` by `scripts/goref.sh`.
//
// A cookie jar decides which host each cookie is sent to. Getting that
// wrong is not a formatting bug: a cookie scoped too widely is sent to
// a site that should never see it, and one scoped too narrowly logs a
// user out with no error anywhere. The rules live in Domain and Path
// matching, and they are asymmetric in ways that are easy to get
// backwards — so this is measured through the public API, which is the
// level at which the mistake would actually bite.
//
// goish matched Go on all 44 lines. The rules it gets right:
//
//   * A cookie with NO Domain is HOST-ONLY: it goes back only to the
//     exact host that set it, and not to that host's subdomains.
//   * A cookie WITH a Domain goes to that domain AND all subdomains,
//     and a leading dot is stripped so Domain=.a.com and Domain=a.com
//     mean the same thing. The asymmetry is the point: adding a Domain
//     WIDENS the scope, which is the opposite of what the syntax
//     suggests.
//   * A host cannot set a cookie for a domain it is not under —
//     a.example.com setting Domain=other.com is dropped entirely, so it
//     reaches neither host.
//   * Path matching is a prefix match on SEGMENT boundaries: /foo
//     matches /foo, /foo/ and /foo/bar but not /foobar, and the default
//     path is the request path's directory, so a cookie set at /a/b/c
//     is not sent to /a/.
//   * A Secure cookie is withheld from an http:// URL.
//   * Setting the same name again replaces it, and setting it with
//     Max-Age<0 deletes it.
//   * The host is matched case-insensitively and the port is ignored,
//     so a cookie set on x.com:8080 is sent to x.com:9090.
//   * An IP host is host-only even when it names itself in Domain.
//
// One Go behaviour is deliberately exercised rather than asserted as
// desirable: with no PublicSuffixList configured, neither jar can
// refuse a cookie set for a public suffix. Go's own documentation says
// so, and the reference records what a caller gets by default.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::net::http;
use goish::net::http::cookiejar;
use goish::net::url;
use goish::syscall;
use goish::types::int;

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 44] = [
    "jar host-only              http://a.example.com/        -> [k=1]",
    "jar host-only              http://b.a.example.com/      -> []",
    "jar host-only              http://example.com/          -> []",
    "jar host-only              http://other.com/            -> []",
    "jar with-domain            http://a.example.com/        -> [k=1]",
    "jar with-domain            http://b.example.com/        -> [k=1]",
    "jar with-domain            http://example.com/          -> [k=1]",
    "jar with-domain            http://notexample.com/       -> []",
    "jar leading-dot            http://a.example.com/        -> [k=1]",
    "jar leading-dot            http://example.com/          -> [k=1]",
    "jar foreign-domain         http://a.example.com/        -> []",
    "jar foreign-domain         http://other.com/            -> []",
    "jar superdomain-of-self    http://a.b.example.com/      -> [k=1]",
    "jar superdomain-of-self    http://b.example.com/        -> [k=1]",
    "jar superdomain-of-self    http://example.com/          -> []",
    "jar paths                  http://x.com/foo             -> [k=1]",
    "jar paths                  http://x.com/foo/            -> [k=1]",
    "jar paths                  http://x.com/foo/bar         -> [k=1]",
    "jar paths                  http://x.com/foobar          -> []",
    "jar paths                  http://x.com/                -> []",
    "jar paths                  http://x.com/fo              -> []",
    "jar default-path           http://x.com/a/b/c           -> [k=1]",
    "jar default-path           http://x.com/a/b/            -> [k=1]",
    "jar default-path           http://x.com/a/b             -> [k=1]",
    "jar default-path           http://x.com/a/              -> []",
    "jar default-path           http://x.com/                -> []",
    "jar secure                 https://x.com/               -> [k=1]",
    "jar secure                 http://x.com/                -> []",
    "jar delete-maxage          http://x.com/                -> []",
    "jar overwrite              http://x.com/                -> [k=2]",
    "jar two-cookies            http://x.com/                -> [a=1 b=2]",
    "jar same-name-diff-path    http://x.com/                -> [k=root]",
    "jar same-name-diff-path    http://x.com/sub/            -> [k=sub k=root]",
    "jar ip-host                http://127.0.0.1/            -> [k=1]",
    "jar ip-host                http://127.0.0.2/            -> []",
    "jar ip-with-domain         http://127.0.0.1/            -> [k=1]",
    "jar port-ignored           http://x.com/                -> [k=1]",
    "jar port-ignored           http://x.com:9090/           -> [k=1]",
    "jar case-host              http://x.com/                -> [k=1]",
    "jar case-host              http://X.COM/                -> [k=1]",
    "jar empty-name             parse-err=http: invalid cookie name",
    "jar empty-name             http://x.com/                -> []",
    "jar non-http-scheme        ftp://x.com/                 -> []",
    "jar non-http-scheme        http://x.com/                -> []",
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

    // (name, setup steps as (from-url, set-cookie lines), read urls)
    let cases: [(&str, &[(&str, &[&str])], &[&str]); 18] = [
        (
            "host-only",
            &[("http://a.example.com/", &["k=1"])],
            &[
                "http://a.example.com/",
                "http://b.a.example.com/",
                "http://example.com/",
                "http://other.com/",
            ],
        ),
        (
            "with-domain",
            &[("http://a.example.com/", &["k=1; Domain=example.com"])],
            &[
                "http://a.example.com/",
                "http://b.example.com/",
                "http://example.com/",
                "http://notexample.com/",
            ],
        ),
        (
            "leading-dot",
            &[("http://a.example.com/", &["k=1; Domain=.example.com"])],
            &["http://a.example.com/", "http://example.com/"],
        ),
        (
            "foreign-domain",
            &[("http://a.example.com/", &["k=1; Domain=other.com"])],
            &["http://a.example.com/", "http://other.com/"],
        ),
        (
            "superdomain-of-self",
            &[("http://a.b.example.com/", &["k=1; Domain=b.example.com"])],
            &[
                "http://a.b.example.com/",
                "http://b.example.com/",
                "http://example.com/",
            ],
        ),
        (
            "paths",
            &[("http://x.com/foo/bar", &["k=1; Path=/foo"])],
            &[
                "http://x.com/foo",
                "http://x.com/foo/",
                "http://x.com/foo/bar",
                "http://x.com/foobar",
                "http://x.com/",
                "http://x.com/fo",
            ],
        ),
        (
            "default-path",
            &[("http://x.com/a/b/c", &["k=1"])],
            &[
                "http://x.com/a/b/c",
                "http://x.com/a/b/",
                "http://x.com/a/b",
                "http://x.com/a/",
                "http://x.com/",
            ],
        ),
        (
            "secure",
            &[("https://x.com/", &["k=1; Secure"])],
            &["https://x.com/", "http://x.com/"],
        ),
        (
            "delete-maxage",
            &[
                ("http://x.com/", &["k=1"]),
                ("http://x.com/", &["k=2; Max-Age=-1"]),
            ],
            &["http://x.com/"],
        ),
        (
            "overwrite",
            &[("http://x.com/", &["k=1"]), ("http://x.com/", &["k=2"])],
            &["http://x.com/"],
        ),
        (
            "two-cookies",
            &[("http://x.com/", &["a=1", "b=2"])],
            &["http://x.com/"],
        ),
        (
            "same-name-diff-path",
            &[
                ("http://x.com/", &["k=root; Path=/"]),
                ("http://x.com/sub/", &["k=sub; Path=/sub"]),
            ],
            &["http://x.com/", "http://x.com/sub/"],
        ),
        (
            "ip-host",
            &[("http://127.0.0.1/", &["k=1"])],
            &["http://127.0.0.1/", "http://127.0.0.2/"],
        ),
        (
            "ip-with-domain",
            &[("http://127.0.0.1/", &["k=1; Domain=127.0.0.1"])],
            &["http://127.0.0.1/"],
        ),
        (
            "port-ignored",
            &[("http://x.com:8080/", &["k=1"])],
            &["http://x.com/", "http://x.com:9090/"],
        ),
        (
            "case-host",
            &[("http://X.CoM/", &["k=1"])],
            &["http://x.com/", "http://X.COM/"],
        ),
        (
            "empty-name",
            &[("http://x.com/", &["=v"])],
            &["http://x.com/"],
        ),
        (
            "non-http-scheme",
            &[("ftp://x.com/", &["k=1"])],
            &["ftp://x.com/", "http://x.com/"],
        ),
    ];
    for (name, steps, reads) in cases.iter() {
        let (jar, _) = cookiejar::New(None);
        for (from, lines) in steps.iter() {
            let (u, err) = url::Parse(s(from));
            if !err.IsNil() {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!("jar %-22s setup-err=%v", s(name), err),
                );
                continue;
            }
            let mut cs: alloc::vec::Vec<http::Cookie> = alloc::vec::Vec::new();
            for line in lines.iter() {
                let (ck, err) = http::ParseSetCookie(s(line));
                if !err.IsNil() {
                    chk(
                        &mut failed,
                        &mut ln,
                        fmt::Sprintf!("jar %-22s parse-err=%v", s(name), err),
                    );
                    continue;
                }
                cs.push(ck);
            }
            jar.SetCookies(&u, slice::__from_vec(cs));
        }
        for r in reads.iter() {
            let (u, _) = url::Parse(s(r));
            let got = jar.Cookies(&u);
            let mut parts = string::default();
            for i in 0..got.Len() {
                if i > 0 {
                    parts = parts + s(" ");
                }
                parts = parts + got[i].Name.clone() + s("=") + got[i].Value.clone();
            }
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("jar %-22s %-28s -> [%s]", s(name), s(r), parts),
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
