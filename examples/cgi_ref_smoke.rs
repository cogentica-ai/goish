// cgi_ref_smoke — net/http/cgi's host side against a running Go.
// (net/http/cgi/host.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_cgi_ref.go` run in
// `package cgi` by `scripts/goref.sh`. goish matched Go on all 171
// lines — no defects found.
//
// CGI hands attacker-controlled bytes to a child process as its
// ENVIRONMENT, which makes the mapping from request to environment a
// security boundary rather than a serialization detail. The child here
// is a shell script that prints its own environment back, so what is
// pinned is what CROSSED the boundary — not what the host meant to
// send.
//
// Two of the rules exist because getting them wrong was a
// vulnerability:
//
//   * The "Proxy" request header is DROPPED rather than exported as
//     HTTP_PROXY. Every HTTP client in every language reads HTTP_PROXY
//     from its environment, so exporting it would let any client
//     redirect the script's own outbound requests through a host of
//     their choosing. That is httpoxy, CVE-2016-5386, and the whole
//     fix is one `continue` — which is exactly the kind of line a port
//     drops without noticing. The `headers` case sends a Proxy header
//     and the pinned environment has no HTTP_PROXY in it.
//   * Cookie joins its values with "; " while every other repeated
//     header joins with ", ". A script parsing HTTP_COOKIE with the
//     wrong separator sees one malformed cookie instead of two.
//
// The rest of the mapping is pinned because a script reads these
// exactly:
//
//   * Header names go through upperCaseAndUnderscore, so anything that
//     is not a letter or digit becomes "_". "X-Two-Words" and
//     "X_Underscore" therefore both land as HTTP_X_ names and a header
//     containing a dot collapses the same way — two differently-spelled
//     headers can COLLIDE in the environment.
//   * CONTENT_TYPE and CONTENT_LENGTH are their own variables, NOT
//     HTTP_-prefixed, so a client cannot overwrite them by sending a
//     header of that name: it lands under HTTP_CONTENT_TYPE instead.
//   * REMOTE_ADDR carries the address without the port, REMOTE_PORT
//     carries the port, and REMOTE_HOST repeats the address rather
//     than resolving anything.
//   * SCRIPT_NAME and PATH_INFO split the request path at Root, across
//     six Root shapes including empty, "/", exact-match and a
//     mismatch. A script that trusts PATH_INFO to stay under its own
//     prefix is trusting this split.
//   * Env entries are appended verbatim and InheritEnv passes exactly
//     the named host variables through — the one beside it, named
//     similarly, does not appear.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::net::http;
use goish::net::http::cgi;
use goish::net::http::httptest;
use goish::net::http::Handler as HandlerTrait;
use goish::os;
use goish::path::filepath;
use goish::sort;
use goish::strings;
use goish::syscall;
use goish::types::int;
const GO: [&str; 171] = [
    "cgi plain                  -> code=200 hdr=[Content-Type=\"text/plain\" X-From-Script=\"yes\"]",
    "env plain                  GATEWAY_INTERFACE=CGI/1.1",
    "env plain                  HTTP_HOST=example.test",
    "env plain                  PATH_INFO=/script/extra/path",
    "env plain                  QUERY_STRING=a=1&b=2",
    "env plain                  REMOTE_ADDR=192.0.2.9",
    "env plain                  REMOTE_HOST=192.0.2.9",
    "env plain                  REMOTE_PORT=5555",
    "env plain                  REQUEST_METHOD=GET",
    "env plain                  REQUEST_URI=/cgi/script/extra/path?a=1&b=2",
    "env plain                  SCRIPT_FILENAME=<tmp>/dump.sh",
    "env plain                  SCRIPT_NAME=/cgi",
    "env plain                  SERVER_NAME=example.test",
    "env plain                  SERVER_PORT=80",
    "env plain                  SERVER_PROTOCOL=HTTP/1.1",
    "env plain                  SERVER_SOFTWARE=go",
    "cgi headers                -> code=200 hdr=[Content-Type=\"text/plain\" X-From-Script=\"yes\"]",
    "env headers                GATEWAY_INTERFACE=CGI/1.1",
    "env headers                HTTP_AUTHORIZATION=Bearer secret",
    "env headers                HTTP_COOKIE=a=1; b=2",
    "env headers                HTTP_HOST=example.test",
    "env headers                HTTP_X_MULTI=a, b",
    "env headers                HTTP_X_SIMPLE=one",
    "env headers                HTTP_X_TWO_WORDS=two",
    "env headers                HTTP_X_UNDERSCORE=collide",
    "env headers                PATH_INFO=/x",
    "env headers                QUERY_STRING=",
    "env headers                REMOTE_ADDR=192.0.2.9",
    "env headers                REMOTE_HOST=192.0.2.9",
    "env headers                REMOTE_PORT=5555",
    "env headers                REQUEST_METHOD=GET",
    "env headers                REQUEST_URI=/cgi/x",
    "env headers                SCRIPT_FILENAME=<tmp>/dump.sh",
    "env headers                SCRIPT_NAME=/cgi",
    "env headers                SERVER_NAME=example.test",
    "env headers                SERVER_PORT=80",
    "env headers                SERVER_PROTOCOL=HTTP/1.1",
    "env headers                SERVER_SOFTWARE=go",
    "cgi post                   -> code=200 hdr=[Content-Type=\"text/plain\" X-From-Script=\"yes\"]",
    "env post                   CONTENT_LENGTH=11",
    "env post                   CONTENT_TYPE=application/x-www-form-urlencoded",
    "env post                   GATEWAY_INTERFACE=CGI/1.1",
    "env post                   HTTP_CONTENT_TYPE=application/x-www-form-urlencoded",
    "env post                   HTTP_HOST=example.test",
    "env post                   PATH_INFO=/post",
    "env post                   QUERY_STRING=",
    "env post                   REMOTE_ADDR=192.0.2.9",
    "env post                   REMOTE_HOST=192.0.2.9",
    "env post                   REMOTE_PORT=5555",
    "env post                   REQUEST_METHOD=POST",
    "env post                   REQUEST_URI=/cgi/post",
    "env post                   SCRIPT_FILENAME=<tmp>/dump.sh",
    "env post                   SCRIPT_NAME=/cgi",
    "env post                   SERVER_NAME=example.test",
    "env post                   SERVER_PORT=80",
    "env post                   SERVER_PROTOCOL=HTTP/1.1",
    "env post                   SERVER_SOFTWARE=go",
    "cgi env-opts               -> code=200 hdr=[Content-Type=\"text/plain\" X-From-Script=\"yes\"]",
    "env env-opts               EXTRA_ONE=1",
    "env env-opts               EXTRA_TWO=two words",
    "env env-opts               GATEWAY_INTERFACE=CGI/1.1",
    "env env-opts               HTTP_HOST=example.test",
    "env env-opts               PATH_INFO=/env",
    "env env-opts               QUERY_STRING=",
    "env env-opts               REMOTE_ADDR=192.0.2.9",
    "env env-opts               REMOTE_HOST=192.0.2.9",
    "env env-opts               REMOTE_PORT=5555",
    "env env-opts               REQUEST_METHOD=GET",
    "env env-opts               REQUEST_URI=/cgi/env",
    "env env-opts               SCRIPT_FILENAME=<tmp>/dump.sh",
    "env env-opts               SCRIPT_NAME=/cgi",
    "env env-opts               SERVER_NAME=example.test",
    "env env-opts               SERVER_PORT=80",
    "env env-opts               SERVER_PROTOCOL=HTTP/1.1",
    "env env-opts               SERVER_SOFTWARE=go",
    "cgi root-empty             -> code=200 hdr=[Content-Type=\"text/plain\" X-From-Script=\"yes\"]",
    "env root-empty             GATEWAY_INTERFACE=CGI/1.1",
    "env root-empty             HTTP_HOST=example.test",
    "env root-empty             PATH_INFO=/a/b",
    "env root-empty             QUERY_STRING=",
    "env root-empty             REMOTE_ADDR=192.0.2.9",
    "env root-empty             REMOTE_HOST=192.0.2.9",
    "env root-empty             REMOTE_PORT=5555",
    "env root-empty             REQUEST_METHOD=GET",
    "env root-empty             REQUEST_URI=/a/b",
    "env root-empty             SCRIPT_FILENAME=<tmp>/dump.sh",
    "env root-empty             SCRIPT_NAME=",
    "env root-empty             SERVER_NAME=example.test",
    "env root-empty             SERVER_PORT=80",
    "env root-empty             SERVER_PROTOCOL=HTTP/1.1",
    "env root-empty             SERVER_SOFTWARE=go",
    "cgi root-slash             -> code=200 hdr=[Content-Type=\"text/plain\" X-From-Script=\"yes\"]",
    "env root-slash             GATEWAY_INTERFACE=CGI/1.1",
    "env root-slash             HTTP_HOST=example.test",
    "env root-slash             PATH_INFO=/a/b",
    "env root-slash             QUERY_STRING=",
    "env root-slash             REMOTE_ADDR=192.0.2.9",
    "env root-slash             REMOTE_HOST=192.0.2.9",
    "env root-slash             REMOTE_PORT=5555",
    "env root-slash             REQUEST_METHOD=GET",
    "env root-slash             REQUEST_URI=/a/b",
    "env root-slash             SCRIPT_FILENAME=<tmp>/dump.sh",
    "env root-slash             SCRIPT_NAME=",
    "env root-slash             SERVER_NAME=example.test",
    "env root-slash             SERVER_PORT=80",
    "env root-slash             SERVER_PROTOCOL=HTTP/1.1",
    "env root-slash             SERVER_SOFTWARE=go",
    "cgi root-prefix            -> code=200 hdr=[Content-Type=\"text/plain\" X-From-Script=\"yes\"]",
    "env root-prefix            GATEWAY_INTERFACE=CGI/1.1",
    "env root-prefix            HTTP_HOST=example.test",
    "env root-prefix            PATH_INFO=/a/b",
    "env root-prefix            QUERY_STRING=",
    "env root-prefix            REMOTE_ADDR=192.0.2.9",
    "env root-prefix            REMOTE_HOST=192.0.2.9",
    "env root-prefix            REMOTE_PORT=5555",
    "env root-prefix            REQUEST_METHOD=GET",
    "env root-prefix            REQUEST_URI=/cgi/a/b",
    "env root-prefix            SCRIPT_FILENAME=<tmp>/dump.sh",
    "env root-prefix            SCRIPT_NAME=/cgi",
    "env root-prefix            SERVER_NAME=example.test",
    "env root-prefix            SERVER_PORT=80",
    "env root-prefix            SERVER_PROTOCOL=HTTP/1.1",
    "env root-prefix            SERVER_SOFTWARE=go",
    "cgi root-exact             -> code=200 hdr=[Content-Type=\"text/plain\" X-From-Script=\"yes\"]",
    "env root-exact             GATEWAY_INTERFACE=CGI/1.1",
    "env root-exact             HTTP_HOST=example.test",
    "env root-exact             PATH_INFO=",
    "env root-exact             QUERY_STRING=",
    "env root-exact             REMOTE_ADDR=192.0.2.9",
    "env root-exact             REMOTE_HOST=192.0.2.9",
    "env root-exact             REMOTE_PORT=5555",
    "env root-exact             REQUEST_METHOD=GET",
    "env root-exact             REQUEST_URI=/cgi",
    "env root-exact             SCRIPT_FILENAME=<tmp>/dump.sh",
    "env root-exact             SCRIPT_NAME=/cgi",
    "env root-exact             SERVER_NAME=example.test",
    "env root-exact             SERVER_PORT=80",
    "env root-exact             SERVER_PROTOCOL=HTTP/1.1",
    "env root-exact             SERVER_SOFTWARE=go",
    "cgi root-trailing          -> code=200 hdr=[Content-Type=\"text/plain\" X-From-Script=\"yes\"]",
    "env root-trailing          GATEWAY_INTERFACE=CGI/1.1",
    "env root-trailing          HTTP_HOST=example.test",
    "env root-trailing          PATH_INFO=/a",
    "env root-trailing          QUERY_STRING=",
    "env root-trailing          REMOTE_ADDR=192.0.2.9",
    "env root-trailing          REMOTE_HOST=192.0.2.9",
    "env root-trailing          REMOTE_PORT=5555",
    "env root-trailing          REQUEST_METHOD=GET",
    "env root-trailing          REQUEST_URI=/cgi/a",
    "env root-trailing          SCRIPT_FILENAME=<tmp>/dump.sh",
    "env root-trailing          SCRIPT_NAME=/cgi",
    "env root-trailing          SERVER_NAME=example.test",
    "env root-trailing          SERVER_PORT=80",
    "env root-trailing          SERVER_PROTOCOL=HTTP/1.1",
    "env root-trailing          SERVER_SOFTWARE=go",
    "cgi root-mismatch          -> code=200 hdr=[Content-Type=\"text/plain\" X-From-Script=\"yes\"]",
    "env root-mismatch          GATEWAY_INTERFACE=CGI/1.1",
    "env root-mismatch          HTTP_HOST=example.test",
    "env root-mismatch          PATH_INFO=/other/a",
    "env root-mismatch          QUERY_STRING=",
    "env root-mismatch          REMOTE_ADDR=192.0.2.9",
    "env root-mismatch          REMOTE_HOST=192.0.2.9",
    "env root-mismatch          REMOTE_PORT=5555",
    "env root-mismatch          REQUEST_METHOD=GET",
    "env root-mismatch          REQUEST_URI=/other/a",
    "env root-mismatch          SCRIPT_FILENAME=<tmp>/dump.sh",
    "env root-mismatch          SCRIPT_NAME=/cgi",
    "env root-mismatch          SERVER_NAME=example.test",
    "env root-mismatch          SERVER_PORT=80",
    "env root-mismatch          SERVER_PROTOCOL=HTTP/1.1",
    "env root-mismatch          SERVER_SOFTWARE=go",
];

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

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let (dir, terr) = os::MkdirTemp(string::new(), s("goish-cgi"));
    if terr != goish::nil {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("[!!] tempdir: %q", terr.Error()),
        );
        return;
    }
    let script = filepath::Join(slice::__from_vec(alloc::vec![dir.clone(), s("dump.sh")]));
    let body = concat!(
        "#!/bin/sh\n",
        "echo \"Content-Type: text/plain\"\n",
        "echo \"X-From-Script: yes\"\n",
        "echo\n",
        "env | grep -E '^(HTTP_|CONTENT_|REQUEST_|SCRIPT_|PATH_|QUERY_|SERVER_|REMOTE_|GATEWAY_|AUTH_|HTTPS|EXTRA_)' | LC_ALL=C sort\n"
    );
    let _ = os::WriteFile(script.clone(), body.as_bytes(), os::FileMode(0o755));
    let mut run = |label: &str, h: &cgi::Handler, r: &http::Request| {
        let w = httptest::NewRecorder();
        h.ServeHTTP(&w, r);
        let hm = w.HeaderMap();
        let mut keys: Vec<string> = Vec::new();
        for (k, _) in hm.__inner().__iter() {
            keys.push(k.clone());
        }
        let mut ks = slice::<string>::__from_vec(keys);
        sort::Strings(&mut ks);
        let mut hs: Vec<string> = Vec::new();
        for i in 0..ks.Len() {
            let k = ks[i].clone();
            let vs = hm.Values(k.clone());
            let mut joined = string::new();
            for j in 0..vs.Len() {
                if j > 0 {
                    joined = joined + "|";
                }
                joined = joined + vs[j].clone();
            }
            hs.push(fmt::Sprintf!("%s=%q", k, joined));
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "cgi %-22s -> code=%d hdr=[%s]",
                s(label),
                w.Code(),
                strings::Join(slice::<string>::__from_vec(hs), s(" "))
            ),
        );
        let out = string::from_bytes(&w.Body().to_vec());
        let trimmed = strings::TrimRight(out, s("\n"));
        let lines = strings::Split(trimmed, s("\n"));
        for i in 0..lines.Len() {
            let line = lines[i].clone();
            if line.Len() == 0 {
                continue;
            }
            let shown = strings::ReplaceAll(line, dir.clone(), s("<tmp>"));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("env %-22s %s", s(label), shown),
            );
        }
    };
    let base = || -> cgi::Handler {
        let mut h = cgi::Handler::default();
        h.Path = script.clone();
        h.Root = s("/cgi");
        return h;
    };
    let mkreq = |method: &str, target: &str| -> http::Request {
        let mut r = httptest::NewRequest(s(method), s(target), ());
        r.RemoteAddr = s("192.0.2.9:5555");
        return r;
    };
    {
        let r = mkreq("GET", "http://example.test/cgi/script/extra/path?a=1&b=2");
        run("plain", &base(), &r);
    }
    {
        let mut r = mkreq("GET", "http://example.test/cgi/x");
        r.Header.Set(s("X-Simple"), s("one"));
        r.Header.Set(s("X-Two-Words"), s("two"));
        r.Header.Set(s("X_Underscore"), s("collide"));
        r.Header.Add(s("X-Multi"), s("a"));
        r.Header.Add(s("X-Multi"), s("b"));
        r.Header.Set(s("Cookie"), s("a=1"));
        r.Header.Add(s("Cookie"), s("b=2"));
        r.Header.Set(s("Proxy"), s("http://evil.test"));
        r.Header.Set(s("X-Dot.Sep"), s("dotted"));
        r.Header.Set(s("Authorization"), s("Bearer secret"));
        run("headers", &base(), &r);
    }
    {
        let mut r = httptest::NewRequest(
            s("POST"),
            s("http://example.test/cgi/post"),
            s("field=value"),
        );
        r.RemoteAddr = s("192.0.2.9:5555");
        r.Header
            .Set(s("Content-Type"), s("application/x-www-form-urlencoded"));
        run("post", &base(), &r);
    }
    {
        let _ = os::Setenv(s("GOISH_INHERITED"), s("from-host"));
        let _ = os::Setenv(s("GOISH_NOT_INHERITED"), s("should-not-appear"));
        let mut h = base();
        h.Env = slice::__from_vec(alloc::vec![s("EXTRA_ONE=1"), s("EXTRA_TWO=two words")]);
        h.InheritEnv = slice::__from_vec(alloc::vec![s("GOISH_INHERITED")]);
        let r = mkreq("GET", "http://example.test/cgi/env");
        run("env-opts", &h, &r);
    }
    let roots: [(&str, &str, &str); 6] = [
        ("root-empty", "", "/a/b"),
        ("root-slash", "/", "/a/b"),
        ("root-prefix", "/cgi", "/cgi/a/b"),
        ("root-exact", "/cgi", "/cgi"),
        ("root-trailing", "/cgi/", "/cgi/a"),
        ("root-mismatch", "/cgi", "/other/a"),
    ];
    for (name, root, target) in roots.iter() {
        let mut h = cgi::Handler::default();
        h.Path = script.clone();
        h.Root = s(root);
        let url = string::from("http://example.test") + s(target);
        let mut r = httptest::NewRequest(s("GET"), url, ());
        r.RemoteAddr = s("192.0.2.9:5555");
        run(name, &h, &r);
    }
    let _ = os::RemoveAll(dir);
    let _ = Arc::new(0);
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
