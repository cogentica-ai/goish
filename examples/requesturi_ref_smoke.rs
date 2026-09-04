// requesturi_ref_smoke — the outbound HTTP request LINE against a running Go.
// (net/http/request.go Request.write, net/url/url.go URL.RequestURI)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_requri_ref.go` run in
// `package http_test` by `scripts/goref.sh`. The echo server reports
// r.RequestURI — the request line as RECEIVED — so this measures what
// crossed the socket, not what the client meant to send.
//
// The request line is the one part of an outbound request that a client
// writes verbatim and a server parses positionally. What goes in it has
// to be the ESCAPED form of the URL and nothing else. Go builds it from
// url.URL.RequestURI(): EscapedPath plus the raw query, or Opaque.
//
// goish wrote url.URL.Path and RawQuery instead — the DECODED path —
// and that broke the request line three different ways:
//
//   * "%2F" was written back as "/", so a request for "/a%2Fb" arrived
//     at the server as "/a/b". A different resource, and precisely the
//     client/server disagreement that path confusion is made of.
//   * A non-ASCII path went out as raw UTF-8, "/☃" rather than
//     "/%E2%98%83", which is not a valid request target at all.
//   * A path containing a SPACE — "/a b", or the "/a%20b" that decodes
//     to it — put a space in the middle of the request line. The server
//     read a malformed line and closed, so the request failed as
//     "unexpected EOF", naming nothing. Every such URL was simply
//     unfetchable.
//
// RequestURI() was already correct, already handled Opaque, the
// "//"-prefix case and the empty-path "/" default. Nothing called it.
//
// The `ctl` cases are the reason the escaping is a security property
// rather than a cosmetic one. A CR or LF reaching the request line ends
// it early and everything after is read as HEADERS — request splitting,
// from whatever built the URL. Go's answer is that EscapedPath
// percent-encodes them first: "/a\r\nX-Injected: yes\r\n" goes out as
// "/a%0D%0AX-Injected:%20yes%0D%0A", one path segment, no injection.
// Go also keeps an explicit control-character refusal behind that for
// the Opaque path, which goish now carries too.
//
// Note "//double": the server here is a BARE handler, not a ServeMux,
// because a mux would clean the doubled slash and answer a redirect —
// measuring the mux instead of the request line.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::ResponseWriter;
use goish::net::url;
use goish::strings;
use goish::syscall;
use goish::types::int;
const GO: [&str; 44] = [
    "parse /a%2Fb         -> Path=\"/a/b\"       RawPath=\"/a%2Fb\"     Escaped=\"/a%2Fb\"       RequestURI=\"/a%2Fb\"",
    "get   /a%2Fb         -> code=200 saw=\"/a%2Fb\"",
    "parse /%E2%98%83     -> Path=\"/☃\"         RawPath=\"\"           Escaped=\"/%E2%98%83\"   RequestURI=\"/%E2%98%83\"",
    "get   /%E2%98%83     -> code=200 saw=\"/%E2%98%83\"",
    "parse /a%20b         -> Path=\"/a b\"       RawPath=\"\"           Escaped=\"/a%20b\"       RequestURI=\"/a%20b\"",
    "get   /a%20b         -> code=200 saw=\"/a%20b\"",
    "parse /plain         -> Path=\"/plain\"     RawPath=\"\"           Escaped=\"/plain\"       RequestURI=\"/plain\"",
    "get   /plain         -> code=200 saw=\"/plain\"",
    "parse /a b           -> Path=\"/a b\"       RawPath=\"/a b\"       Escaped=\"/a%20b\"       RequestURI=\"/a%20b\"",
    "get   /a b           -> code=200 saw=\"/a%20b\"",
    "parse /a+b           -> Path=\"/a+b\"       RawPath=\"\"           Escaped=\"/a+b\"         RequestURI=\"/a+b\"",
    "get   /a+b           -> code=200 saw=\"/a+b\"",
    "parse /%2e%2e/x      -> Path=\"/../x\"      RawPath=\"/%2e%2e/x\"  Escaped=\"/%2e%2e/x\"    RequestURI=\"/%2e%2e/x\"",
    "get   /%2e%2e/x      -> code=200 saw=\"/%2e%2e/x\"",
    "parse /x?q=1         -> Path=\"/x\"         RawPath=\"\"           Escaped=\"/x\"           RequestURI=\"/x?q=1\"",
    "get   /x?q=1         -> code=200 saw=\"/x?q=1\"",
    "parse /x?q=a%20b     -> Path=\"/x\"         RawPath=\"\"           Escaped=\"/x\"           RequestURI=\"/x?q=a%20b\"",
    "get   /x?q=a%20b     -> code=200 saw=\"/x?q=a%20b\"",
    "parse /x?q=a+b       -> Path=\"/x\"         RawPath=\"\"           Escaped=\"/x\"           RequestURI=\"/x?q=a+b\"",
    "get   /x?q=a+b       -> code=200 saw=\"/x?q=a+b\"",
    "parse /%00           -> Path=\"/\\x00\"      RawPath=\"\"           Escaped=\"/%00\"         RequestURI=\"/%00\"",
    "get   /%00           -> code=200 saw=\"/%00\"",
    "parse /%41           -> Path=\"/A\"         RawPath=\"/%41\"       Escaped=\"/%41\"         RequestURI=\"/%41\"",
    "get   /%41           -> code=200 saw=\"/%41\"",
    "parse /a%3Fb         -> Path=\"/a?b\"       RawPath=\"\"           Escaped=\"/a%3Fb\"       RequestURI=\"/a%3Fb\"",
    "get   /a%3Fb         -> code=200 saw=\"/a%3Fb\"",
    "parse /a%23b         -> Path=\"/a#b\"       RawPath=\"\"           Escaped=\"/a%23b\"       RequestURI=\"/a%23b\"",
    "get   /a%23b         -> code=200 saw=\"/a%23b\"",
    "parse /#frag         -> Path=\"/\"          RawPath=\"\"           Escaped=\"/\"            RequestURI=\"/\"",
    "get   /#frag         -> code=200 saw=\"/\"",
    "parse /x?a=1#f       -> Path=\"/x\"         RawPath=\"\"           Escaped=\"/x\"           RequestURI=\"/x?a=1\"",
    "get   /x?a=1#f       -> code=200 saw=\"/x?a=1\"",
    "parse /dir/          -> Path=\"/dir/\"      RawPath=\"\"           Escaped=\"/dir/\"        RequestURI=\"/dir/\"",
    "get   /dir/          -> code=200 saw=\"/dir/\"",
    "parse //double       -> Path=\"//double\"   RawPath=\"\"           Escaped=\"//double\"     RequestURI=\"//double\"",
    "get   //double       -> code=200 saw=\"//double\"",
    "parse /tr%61iling    -> Path=\"/trailing\"  RawPath=\"/tr%61iling\" Escaped=\"/tr%61iling\"  RequestURI=\"/tr%61iling\"",
    "get   /tr%61iling    -> code=200 saw=\"/tr%61iling\"",
    "ctl cr           -> code=200 saw=\"/a%0Db\"",
    "ctl lf           -> code=200 saw=\"/a%0Ab\"",
    "ctl crlf-header  -> code=200 saw=\"/a%0D%0AX-Injected:%20yes%0D%0A\"",
    "ctl nul          -> code=200 saw=\"/a%00b\"",
    "ctl del          -> code=200 saw=\"/a%7Fb\"",
    "ctl tab          -> code=200 saw=\"/a%09b\"",
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
struct EchoURI;
impl http::Handler for EchoURI {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &http::Request) {
        let _ = w.Write(slice::__from_vec(r.RequestURI.as_bytes().to_vec()));
    }
}

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    // A bare Handler, NOT a ServeMux: the mux would clean "//double"
    // and answer a redirect, which measures the mux rather than the
    // request line.
    let srv = httptest::NewServer(Arc::new(EchoURI) as Arc<dyn http::Handler>);
    let base = srv.URL();
    let host = strings::TrimPrefix(base.clone(), s("http://"));
    let trimAddr = |x: string| -> string {
        return strings::ReplaceAll(x, host.clone(), s("ADDR"));
    };
    for p in [
        "/a%2Fb",
        "/%E2%98%83",
        "/a%20b",
        "/plain",
        "/a b",
        "/a+b",
        "/%2e%2e/x",
        "/x?q=1",
        "/x?q=a%20b",
        "/x?q=a+b",
        "/%00",
        "/%41",
        "/a%3Fb",
        "/a%23b",
        "/#frag",
        "/x?a=1#f",
        "/dir/",
        "//double",
        "/tr%61iling",
    ] {
        let (u, perr) = url::Parse(base.clone() + s(p));
        if perr != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("parse %-14s -> err=%q", s(p), perr.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "parse %-14s -> Path=%-12q RawPath=%-12q Escaped=%-14q RequestURI=%q",
                s(p),
                u.Path.clone(),
                u.RawPath.clone(),
                u.EscapedPath(),
                u.RequestURI()
            ),
        );
        let (mut resp, err) = http::Get(base.clone() + s(p));
        if err != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("get   %-14s -> err=%s", s(p), trimAddr(err.Error())),
            );
            continue;
        }
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "get   %-14s -> code=%d saw=%q",
                s(p),
                resp.StatusCode,
                string::from_bytes(&body.to_vec())
            ),
        );
    }
    let ctls: [(&str, &str); 6] = [
        ("cr", "/a\rb"),
        ("lf", "/a\nb"),
        ("crlf-header", "/a\r\nX-Injected: yes\r\n"),
        ("nul", "/a\u{0}b"),
        ("del", "/a\u{7f}b"),
        ("tab", "/a\tb"),
    ];
    for (name, path) in ctls.iter() {
        let (mut u, _) = url::Parse(base.clone());
        u.Path = s(path);
        let (mut req, rerr) = http::NewRequest(s("GET"), s("http://x/"), ());
        if rerr != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("ctl %-12s -> newreq-err=%q", s(name), rerr.Error()),
            );
            continue;
        }
        req.URL = u;
        let c = http::Client::default();
        let (mut resp, err): (http::Response, error) = c.Do(&req);
        if err != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("ctl %-12s -> err=%s", s(name), trimAddr(err.Error())),
            );
            continue;
        }
        let (body, _) = io::ReadAll(&mut resp.Body);
        let _ = io::Closer::Close(&mut resp.Body);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "ctl %-12s -> code=%d saw=%q",
                s(name),
                resp.StatusCode,
                string::from_bytes(&body.to_vec())
            ),
        );
    }
    Arc::clone(&srv).Close();
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
