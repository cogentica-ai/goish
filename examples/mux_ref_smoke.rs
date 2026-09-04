// mux_ref_smoke — net/http's ServeMux against a running Go.
// (net/http/server.go, net/http/pattern.go, net/http/routing_tree.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_mux_ref.go` run in
// `package http_test` by `scripts/goref.sh`.
//
// ServeMux decides which handler a request reaches. That is a routing
// question right up until an authenticating middleware is registered on
// one pattern and not another, at which point it is an authorisation
// question: a request that matches the wrong pattern skips the checks
// the right one would have applied.
//
// What this pins, and what it caught:
//
//   * PRECEDENCE. Go 1.22 replaced the old prefix rules with a pattern
//     language in which the MOST SPECIFIC pattern wins — "specific"
//     meaning it matches a strict subset of the other's requests, not
//     that it is longer or was registered first. "/a/{x}/c" beats
//     "/a/", "GET /m" beats nothing on a PUT, and a method-specific
//     miss is 405-with-Allow rather than 404.
//   * THE PATH IS CLEANED BEFORE MATCHING, AS A REDIRECT. A handler
//     never sees "/a/../b"; the caller gets a 301 to "/a/b" and asks
//     again. A mux that matched first and cleaned later would let
//     "/admin/../public" reach the admin handler.
//   * ALL OF IT HAPPENS ON THE ESCAPED PATH. This is the half goish had
//     wrong, and it was wrong in both directions at once. goish cleaned
//     the DECODED path and compared it against the escaped one, so:
//       - every request carrying any percent-escape got a 301 to its
//         own URL. "/v/a%20b/c" redirected to "/v/a%20b/c", forever.
//       - "%2F" decodes to "/", so an encoded slash was treated as a
//         separator: "/v/%2F/2" collapsed to "/v/2" and redirected
//         there. A request for a segment named "/" was answered with a
//         different resource — the proxy/origin disagreement that path
//         confusion is made of.
//     Go splits segments on the escaped path and unescapes each segment
//     afterwards, so "%2F" is never a separator; a segment that
//     unescapes to exactly "/" collides with the trailing-slash
//     sentinel and matches no single wildcard at all, which is why
//     "/v/%2F/2" is a 404 while "/v/%2Fx/2" is a 200.
//   * THE INVERSE, WHICH IS NOT A BUG TO FIX. Because cleaning happens
//     on the escaped path, an ENCODED dot segment is not a dot segment:
//     "/clean/%2e%2e/admin" is not cleaned, matches "/clean/", and the
//     handler is then handed r.URL.Path = "/clean/../admin" with the
//     ".." intact. Anything doing its own prefix check on r.URL.Path
//     downstream of the mux has to cope with that itself. Go does this
//     deliberately and goish now matches it.
//   * THE REPORTED PATTERN. On a trailing-slash redirect Go names the
//     pattern the slash WOULD have hit ("/m/{$}"), not the redirect
//     target ("/m/"), and callers log or branch on that string.
//   * THE DOUBLE-ESCAPE QUIRK. The cleaned-path redirect is built from
//     Path alone, so a surviving "%2F" is re-escaped on the way out:
//     "/v/%2F//x" redirects to "/v/%252F/x". Pinned as-is — a redirect
//     target that differs from Go's is a redirect somewhere else.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::fmt;
use goish::gostring::string;
use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::{Handler, ResponseWriter};
use goish::syscall;
use goish::types::int;
const GO: [&str; 47] = [
    "route GET   /          -> code=200 pat=\"/\"          body=\"/\"",
    "route GET   /a         -> code=200 pat=\"/a\"         body=\"/a\"",
    "route GET   /a/        -> code=200 pat=\"/a/\"        body=\"/a/\"",
    "route GET   /a/b       -> code=200 pat=\"/a/b\"       body=\"/a/b\"",
    "route GET   /a/z       -> code=200 pat=\"/a/{x}\"     body=\"/a/{x}\"",
    "route GET   /a/z/c     -> code=200 pat=\"/a/{x}/c\"   body=\"/a/{x}/c\"",
    "route GET   /a/b/c     -> code=200 pat=\"/a/{x}/c\"   body=\"/a/{x}/c\"",
    "route GET   /b/x/y/z   -> code=200 pat=\"/b/{x...}\"  body=\"/b/{x...}\"",
    "route GET   /b/        -> code=200 pat=\"/b/{x...}\"  body=\"/b/{x...}\"",
    "route GET   /m         -> code=200 pat=\"GET /m\"     body=\"GET /m\"",
    "route POST  /m         -> code=200 pat=\"POST /m\"    body=\"POST /m\"",
    "route PUT   /m         -> code=301 pat=\"/m/{$}\"     body=\"\"",
    "route GET   /m/        -> code=200 pat=\"/m/{$}\"     body=\"/m/{$}\"",
    "route GET   /m/x       -> code=200 pat=\"/\"          body=\"/\"",
    "route GET   /zzz       -> code=200 pat=\"/\"          body=\"/\"",
    "route HEAD  /m         -> code=200 pat=\"GET /m\"     body=\"GET /m\"",
    "host  example.com    -> code=200 body=\"example.com/host\"",
    "host  other.example  -> code=200 body=\"/\"",
    "bind  /v/1/2       -> code=200 body=\"a=\\\"1\\\" b=\\\"2\\\"\" loc=\"\"",
    "bind  /v/1         -> code=404 body=\"404 page not found\\n\" loc=\"\"",
    "bind  /v/1/2/3     -> code=404 body=\"404 page not found\\n\" loc=\"\"",
    "bind  /v//2        -> code=301 body=\"<a href=\\\"/v/2\\\">Moved Permanently</a>.\\n\\n\" loc=\"/v/2\"",
    "bind  /v/%2F/2     -> code=404 body=\"404 page not found\\n\" loc=\"\"",
    "bind  /v/a%20b/c   -> code=200 body=\"a=\\\"a b\\\" b=\\\"c\\\"\" loc=\"\"",
    "bind  /v/%2Fx/2    -> code=200 body=\"a=\\\"/x\\\" b=\\\"2\\\"\" loc=\"\"",
    "bind  /v/%2F//x    -> code=301 body=\"<a href=\\\"/v/%252F/x\\\">Moved Permanently</a>.\\n\\n\" loc=\"/v/%252F/x\"",
    "bind  /v/a+b/c     -> code=200 body=\"a=\\\"a+b\\\" b=\\\"c\\\"\" loc=\"\"",
    "bind  /v/%41/%42   -> code=200 body=\"a=\\\"A\\\" b=\\\"B\\\"\" loc=\"\"",
    "bind  /w/          -> code=200 body=\"rest=\\\"\\\"\" loc=\"\"",
    "bind  /w/x/y       -> code=200 body=\"rest=\\\"x/y\\\"\" loc=\"\"",
    "bind  /w           -> code=301 body=\"<a href=\\\"/w/\\\">Moved Permanently</a>.\\n\\n\" loc=\"/w/\"",
    "bind  /w/a%20b     -> code=200 body=\"rest=\\\"a b\\\"\" loc=\"\"",
    "bind  /w/%2F       -> code=200 body=\"rest=\\\"/\\\"\" loc=\"\"",
    "clean /clean/          -> code=200 loc=\"\"                 body=\"clean:/clean/\"",
    "clean /clean//x        -> code=301 loc=\"/clean/x\"         body=\"<a href=\\\"/clean/x\\\">Moved Permanently</a>.\\n\\n\"",
    "clean /clean/./x       -> code=301 loc=\"/clean/x\"         body=\"<a href=\\\"/clean/x\\\">Moved Permanently</a>.\\n\\n\"",
    "clean /clean/../admin  -> code=301 loc=\"/admin\"           body=\"<a href=\\\"/admin\\\">Moved Permanently</a>.\\n\\n\"",
    "clean /admin           -> code=200 loc=\"\"                 body=\"ADMIN\"",
    "clean //admin          -> code=301 loc=\"/admin\"           body=\"<a href=\\\"/admin\\\">Moved Permanently</a>.\\n\\n\"",
    "clean /admin/          -> code=404 loc=\"\"                 body=\"404 page not found\\n\"",
    "clean /./admin         -> code=301 loc=\"/admin\"           body=\"<a href=\\\"/admin\\\">Moved Permanently</a>.\\n\\n\"",
    "clean /a/../admin      -> code=301 loc=\"/admin\"           body=\"<a href=\\\"/admin\\\">Moved Permanently</a>.\\n\\n\"",
    "clean /clean/%2e%2e/admin -> code=200 loc=\"\"                 body=\"clean:/clean/../admin\"",
    "clean /clean/..%2fadmin -> code=200 loc=\"\"                 body=\"clean:/clean/../admin\"",
    "clean /admin%2F        -> code=404 loc=\"\"                 body=\"404 page not found\\n\"",
    "clean /clean/%2E./admin -> code=200 loc=\"\"                 body=\"clean:/clean/../admin\"",
    "clean /clean/x/../../admin -> code=301 loc=\"/admin\"           body=\"<a href=\\\"/admin\\\">Moved Permanently</a>.\\n\\n\"",
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
    // 1. Precedence between overlapping patterns.
    {
        let mux = http::NewServeMux();
        for p in [
            "/",
            "/a",
            "/a/",
            "/a/b",
            "/a/{x}",
            "/a/{x}/c",
            "/b/{x...}",
            "GET /m",
            "POST /m",
            "/m/{$}",
            "example.com/host",
        ] {
            let pp = s(p);
            mux.HandleFunc(
                s(p),
                move |w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &http::Request| {
                    let _ = w.Write(goish::slice::__from_vec(pp.as_bytes().to_vec()));
                },
            );
        }
        for (method, target) in [
            ("GET", "/"),
            ("GET", "/a"),
            ("GET", "/a/"),
            ("GET", "/a/b"),
            ("GET", "/a/z"),
            ("GET", "/a/z/c"),
            ("GET", "/a/b/c"),
            ("GET", "/b/x/y/z"),
            ("GET", "/b/"),
            ("GET", "/m"),
            ("POST", "/m"),
            ("PUT", "/m"),
            ("GET", "/m/"),
            ("GET", "/m/x"),
            ("GET", "/zzz"),
            ("HEAD", "/m"),
        ] {
            let url = string::from("http://other.example") + s(target);
            let r = httptest::NewRequest(s(method), url, ());
            let w = httptest::NewRecorder();
            mux.ServeHTTP(&w, &r);
            let (_, pat) = mux.Handler(&r);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "route %-5s %-10s -> code=%d pat=%-12q body=%q",
                    s(method),
                    s(target),
                    w.Code(),
                    pat,
                    w.Body()
                ),
            );
        }
        for host in ["example.com", "other.example"] {
            let url = string::from("http://") + s(host) + s("/host");
            let r = httptest::NewRequest(s("GET"), url, ());
            let w = httptest::NewRecorder();
            mux.ServeHTTP(&w, &r);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "host  %-14s -> code=%d body=%q",
                    s(host),
                    w.Code(),
                    w.Body()
                ),
            );
        }
    }
    // 2. Wildcards and the values they bind.
    {
        let mux = http::NewServeMux();
        mux.HandleFunc(
            s("/v/{a}/{b}"),
            |w: &(dyn ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                let out = fmt::Sprintf!("a=%q b=%q", r.PathValue(s("a")), r.PathValue(s("b")));
                let _ = w.Write(goish::slice::__from_vec(out.as_bytes().to_vec()));
            },
        );
        mux.HandleFunc(
            s("/w/{rest...}"),
            |w: &(dyn ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                let out = fmt::Sprintf!("rest=%q", r.PathValue(s("rest")));
                let _ = w.Write(goish::slice::__from_vec(out.as_bytes().to_vec()));
            },
        );
        for target in [
            "/v/1/2",
            "/v/1",
            "/v/1/2/3",
            "/v//2",
            "/v/%2F/2",
            "/v/a%20b/c",
            "/v/%2Fx/2",
            "/v/%2F//x",
            "/v/a+b/c",
            "/v/%41/%42",
            "/w/",
            "/w/x/y",
            "/w",
            "/w/a%20b",
            "/w/%2F",
        ] {
            let url = string::from("http://x") + s(target);
            let r = httptest::NewRequest(s("GET"), url, ());
            let w = httptest::NewRecorder();
            mux.ServeHTTP(&w, &r);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "bind  %-12s -> code=%d body=%q loc=%q",
                    s(target),
                    w.Code(),
                    w.Body(),
                    w.HeaderMap().Get(s("Location"))
                ),
            );
        }
    }
    // 3. Path cleaning happens BEFORE matching, as a redirect.
    {
        let mux = http::NewServeMux();
        mux.HandleFunc(
            s("/clean/"),
            |w: &(dyn ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                let out = fmt::Sprintf!("clean:%s", r.URL.Path.clone());
                let _ = w.Write(goish::slice::__from_vec(out.as_bytes().to_vec()));
            },
        );
        mux.HandleFunc(
            s("/admin"),
            |w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &http::Request| {
                let _ = w.Write(goish::slice::__from_vec(b"ADMIN".to_vec()));
            },
        );
        for target in [
            "/clean/",
            "/clean//x",
            "/clean/./x",
            "/clean/../admin",
            "/admin",
            "//admin",
            "/admin/",
            "/./admin",
            "/a/../admin",
            "/clean/%2e%2e/admin",
            "/clean/..%2fadmin",
            "/admin%2F",
            "/clean/%2E./admin",
            "/clean/x/../../admin",
        ] {
            let url = string::from("http://x") + s(target);
            let r = httptest::NewRequest(s("GET"), url, ());
            let w = httptest::NewRecorder();
            mux.ServeHTTP(&w, &r);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "clean %-16s -> code=%d loc=%-18q body=%q",
                    s(target),
                    w.Code(),
                    w.HeaderMap().Get(s("Location")),
                    w.Body()
                ),
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
