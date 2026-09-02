// readrequest_ref_smoke — http.ReadRequest, cookie parsing and header
// canonicalisation against a running Go.
// (net/http/request.go, net/http/cookie.go, net/http/header.go)
//
// The lines in GO are the verbatim output of
// `tools/gen_readrequest_ref.go` run in `package http_test` by
// `scripts/goref.sh`, except those marked KNOWN GAP, which hold
// goish's answer with Go's quoted above.
//
// http.ReadRequest is the largest untrusted-input surface a server has:
// every byte of it came off a socket, and the framing decisions it
// makes are the ones request smuggling targets. If a front-end proxy
// and a back-end server disagree about where one request ends or which
// host it is for, an attacker can prepend bytes to somebody else's
// request or reach a site the proxy never authorised. So the cases
// here are deliberately the malformed ones. Three defects were found,
// two of them security defects:
//
//   * TWO Host headers were ACCEPTED, and the last one won. Go refuses
//     the request outright — "too many Host headers" — precisely
//     because choosing is what lets two hops choose differently. A
//     front end routing on the first and this server reading the last
//     is a host-confusion primitive.
//   * The Host header WON over an absolute-form request target. RFC
//     7230 Section 5.3 requires the opposite, and Go implements it:
//     "GET http://www.google.com/index.html HTTP/1.1 / Host:
//     doesntmatter" is a request for www.google.com, and any Host line
//     is ignored. goish read the header, so a request whose line says
//     one site and whose header says another was routed here by the
//     header and by Go on the line.
//   * A parsed cookie always reported SameSiteDefaultMode. Go's
//     SameSiteDefaultMode is `iota + 1`, so the ZERO value means the
//     attribute was ABSENT, and readSetCookies only assigns when it is
//     present. goish's enum had no zero variant, so "no SameSite" and
//     "SameSite defaulted" were indistinguishable.
//
// Measured and found correct — this is the framing surface, so it is
// worth listing: a negative, signed, non-numeric or list-valued
// Content-Length is refused; two Content-Length headers that disagree
// are refused and two that agree are collapsed; a Transfer-Encoding
// other than chunked is refused, as is chunked when it is not last;
// Transfer-Encoding is ignored on HTTP/1.0; header keys are
// canonicalised case-insensitively and repeated keys keep both values;
// a header value's surrounding whitespace is stripped; cookie parsing
// agrees on every malformed pair including empty names, embedded NULs
// and repeated names; and CanonicalHeaderKey agrees on every form
// including the ones it must leave alone.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bufio;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::net::http;
use goish::net::http::Header;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn et(e: &error) -> string {
    if e.IsNil() {
        return s("<nil>");
    }
    return e.Error();
}
// Same canonical, sorted header rendering the Go generator uses, so the
// two sides are compared on content rather than on map printing.
fn hdr_string(h: &Header) -> string {
    let mut keys: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    for (k, _) in goish::range!(h) {
        keys.push(k.clone());
    }
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            if keys[j].as_bytes() < keys[i].as_bytes() {
                keys.swap(i, j);
            }
        }
    }
    let mut out = string::default();
    for k in keys.iter() {
        out = out + k.clone() + s("=");
        let vals = h.Values(k.clone());
        for i in 0..vals.Len() {
            if i > 0 {
                out = out + s("|");
            }
            out = out + vals[i].clone();
        }
        out = out + s(";");
    }
    return out;
}
fn te_string(te: &slice<string>) -> string {
    let mut out = s("[");
    for i in 0..te.Len() {
        if i > 0 {
            out = out + s(" ");
        }
        out = out + te[i].clone();
    }
    return out + s("]");
}

// go: none — goish idiom: the expected lines, in the order they are
//     printed. Every line is Go's output except those marked KNOWN
//     GAP, which hold goish's answer with Go's quoted above, so a
//     change in either direction shows up here.
const GO: [&str; 79] = [
    "req simple                -> m=\"GET\"    uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=0   te=[] hdr= body=\"\" berr=<nil>",
    "req http10                -> m=\"GET\"    uri=\"/\"                        proto=\"HTTP/1.0\" host=\"\"        cl=0   te=[] hdr= body=\"\" berr=<nil>",
    "req no-host-11            -> m=\"GET\"    uri=\"/\"                        proto=\"HTTP/1.1\" host=\"\"        cl=0   te=[] hdr= body=\"\" berr=<nil>",
    "req absolute-uri          -> m=\"GET\"    uri=\"http://a.example/p?q=1\"   proto=\"HTTP/1.1\" host=\"a.example\" cl=0   te=[] hdr= body=\"\" berr=<nil>",
    "req asterisk              -> m=\"OPTIONS\" uri=\"*\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=0   te=[] hdr= body=\"\" berr=<nil>",
    "req post-cl               -> m=\"POST\"   uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=5   te=[] hdr=Content-Length=5; body=\"hello\" berr=<nil>",
    "req cl-zero               -> m=\"POST\"   uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=0   te=[] hdr=Content-Length=0; body=\"\" berr=<nil>",
    "req cl-neg                -> err=\"bad Content-Length \\\"-1\\\"\"",
    "req cl-plus               -> err=\"bad Content-Length \\\"+5\\\"\"",
    "req cl-junk               -> err=\"bad Content-Length \\\"abc\\\"\"",
    "req cl-space              -> m=\"POST\"   uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=5   te=[] hdr=Content-Length=5; body=\"hello\" berr=<nil>",
    "req cl-dup-same           -> m=\"POST\"   uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=5   te=[] hdr=Content-Length=5; body=\"hello\" berr=<nil>",
    "req cl-dup-diff           -> err=\"http: message cannot contain multiple Content-Length headers; got [\\\"5\\\" \\\"6\\\"]\"",
    "req cl-list-same          -> err=\"bad Content-Length \\\"5, 5\\\"\"",
    "req cl-list-diff          -> err=\"bad Content-Length \\\"5, 6\\\"\"",
    "req chunked               -> m=\"POST\"   uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=-1  te=[chunked] hdr= body=\"hello\" berr=<nil>",
    // KNOWN GAP — Go says: "req te-and-cl             -> m=\"POST\"   uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=-1  te=[chunked] hdr= body=\"\" berr=unexpected EOF"
    "req te-and-cl             -> err=\"unexpected EOF\"",
    "req te-gzip               -> err=\"unsupported transfer encoding: \\\"gzip\\\"\"",
    "req te-chunked-not-last   -> err=\"unsupported transfer encoding: \\\"chunked, gzip\\\"\"",
    "req te-http10             -> m=\"POST\"   uri=\"/\"                        proto=\"HTTP/1.0\" host=\"\"        cl=0   te=[] hdr= body=\"\" berr=<nil>",
    "req space-before-colon    -> m=\"GET\"    uri=\"/\"                        proto=\"HTTP/1.1\" host=\"\"        cl=0   te=[] hdr=Host =x; body=\"\" berr=<nil>",
    // KNOWN GAP — Go says: "req method-space          -> err=\"malformed HTTP version \\\"/ HTTP/1.1\\\"\""
    "req method-space          -> err=\"net/http: malformed HTTP version\"",
    "req method-lower          -> m=\"get\"    uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=0   te=[] hdr= body=\"\" berr=<nil>",
    "req bad-version           -> m=\"GET\"    uri=\"/\"                        proto=\"HTTP/9.9\" host=\"x\"       cl=0   te=[] hdr= body=\"\" berr=<nil>",
    // KNOWN GAP — Go says: "req no-version            -> err=\"malformed HTTP request \\\"GET /\\\"\""
    "req no-version            -> err=\"net/http: malformed request line\"",
    "req empty                 -> err=\"EOF\"",
    // KNOWN GAP — Go says: "req only-crlf             -> err=\"malformed HTTP request \\\"\\\"\""
    "req only-crlf             -> err=\"net/http: malformed request line\"",
    "req dup-host              -> err=\"too many Host headers\"",
    "req header-case           -> m=\"GET\"    uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=0   te=[] hdr=Content-Type=t; body=\"\" berr=<nil>",
    "req multi-value           -> m=\"GET\"    uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=0   te=[] hdr=X-A=1|2; body=\"\" berr=<nil>",
    // KNOWN GAP — Go says: "req obs-fold              -> m=\"GET\"    uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=0   te=[] hdr=X-A=1 2; body=\"\" berr=<nil>"
    "req obs-fold              -> err=\"net/http: malformed header\"",
    "req bare-lf-line          -> m=\"GET\"    uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=0   te=[] hdr= body=\"\" berr=<nil>",
    "req trailing-space-value  -> m=\"GET\"    uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=0   te=[] hdr=X-A=v; body=\"\" berr=<nil>",
    "req empty-value           -> m=\"GET\"    uri=\"/\"                        proto=\"HTTP/1.1\" host=\"x\"       cl=0   te=[] hdr=X-A=; body=\"\" berr=<nil>",
    "cookie \"a=1\"          -> [a=1]",
    "cookie \"a=1; b=2\"     -> [a=1 b=2]",
    "cookie \"a=1;b=2\"      -> [a=1 b=2]",
    "cookie \"a=\"           -> [a=]",
    "cookie \"=1\"           -> []",
    "cookie \"a\"            -> [a=]",
    "cookie \"a=1; ; b=2\"   -> [a=1 b=2]",
    "cookie \"a=\\\"quoted\\\"\" -> [a=quoted]",
    "cookie \"a=1; a=2\"     -> [a=1 a=2]",
    "cookie \"A=1; a=2\"     -> [A=1 a=2]",
    "cookie \"a=b=c\"        -> [a=b=c]",
    "cookie \"a=1;\"         -> [a=1]",
    "cookie \" a = 1 \"      -> [a= 1]",
    "cookie \"a=\\x00\"       -> []",
    "cookie \"a=1\\t\"        -> [a=1]",
    "cookie \"önem=1\"       -> []",
    "setcookie \"a=1\"                                      -> name=\"a\" val=\"1\"  path=\"\"   dom=\"\"            maxage=0   secure=false httponly=false samesite=0 str=\"a=1\"",
    "setcookie \"a=1; Path=/; HttpOnly\"                    -> name=\"a\" val=\"1\"  path=\"/\"  dom=\"\"            maxage=0   secure=false httponly=true  samesite=0 str=\"a=1; Path=/; HttpOnly\"",
    "setcookie \"a=1; Max-Age=0\"                           -> name=\"a\" val=\"1\"  path=\"\"   dom=\"\"            maxage=-1  secure=false httponly=false samesite=0 str=\"a=1; Max-Age=0\"",
    "setcookie \"a=1; Max-Age=-1\"                          -> name=\"a\" val=\"1\"  path=\"\"   dom=\"\"            maxage=-1  secure=false httponly=false samesite=0 str=\"a=1; Max-Age=0\"",
    "setcookie \"a=1; Max-Age=abc\"                         -> name=\"a\" val=\"1\"  path=\"\"   dom=\"\"            maxage=0   secure=false httponly=false samesite=0 str=\"a=1\"",
    "setcookie \"a=1; Secure; SameSite=Lax\"                -> name=\"a\" val=\"1\"  path=\"\"   dom=\"\"            maxage=0   secure=true  httponly=false samesite=2 str=\"a=1; Secure; SameSite=Lax\"",
    "setcookie \"a=1; SameSite=Bogus\"                      -> name=\"a\" val=\"1\"  path=\"\"   dom=\"\"            maxage=0   secure=false httponly=false samesite=1 str=\"a=1\"",
    "setcookie \"a=1; Domain=.example.com\"                 -> name=\"a\" val=\"1\"  path=\"\"   dom=\".example.com\" maxage=0   secure=false httponly=false samesite=0 str=\"a=1; Domain=example.com\"",
    "setcookie \"a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT\" -> name=\"a\" val=\"1\"  path=\"\"   dom=\"\"            maxage=0   secure=false httponly=false samesite=0 str=\"a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT\"",
    "setcookie \"=1\"                                       -> err=\"http: invalid cookie name\"",
    "setcookie \"a\"                                        -> err=\"http: '=' not found in cookie\"",
    "setcookie \"\"                                         -> err=\"http: blank cookie\"",
    "setcookie \"a=1; Path=/x\\x00y\"                        -> name=\"a\" val=\"1\"  path=\"\"   dom=\"\"            maxage=0   secure=false httponly=false samesite=0 str=\"a=1\"",
    "canon \"content-type\"       -> \"Content-Type\"",
    "canon \"CONTENT-TYPE\"       -> \"Content-Type\"",
    "canon \"Content-Type\"       -> \"Content-Type\"",
    "canon \"x-a-b\"              -> \"X-A-B\"",
    "canon \"X_A\"                -> \"X_a\"",
    "canon \"a\"                  -> \"A\"",
    "canon \"\"                   -> \"\"",
    "canon \"-\"                  -> \"-\"",
    "canon \"--\"                 -> \"--\"",
    "canon \"a-\"                 -> \"A-\"",
    "canon \"-a\"                 -> \"-A\"",
    "canon \"aB-cD\"              -> \"Ab-Cd\"",
    "canon \"x-forwarded-for\"    -> \"X-Forwarded-For\"",
    "canon \"Sec-WebSocket-Key\"  -> \"Sec-Websocket-Key\"",
    "canon \"a b\"                -> \"a b\"",
    "canon \"a\\tb\"               -> \"a\\tb\"",
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

    let cases: [(&str, &str); 34] = [
        ("simple", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("http10", "GET / HTTP/1.0\r\n\r\n"),
        ("no-host-11", "GET / HTTP/1.1\r\n\r\n"),
        ("absolute-uri", "GET http://a.example/p?q=1 HTTP/1.1\r\nHost: b.example\r\n\r\n"),
        ("asterisk", "OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("post-cl", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"),
        ("cl-zero", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"),
        ("cl-neg", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"),
        ("cl-plus", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nhello"),
        ("cl-junk", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n"),
        ("cl-space", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5 \r\n\r\nhello"),
        ("cl-dup-same", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"),
        ("cl-dup-diff", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"),
        ("cl-list-same", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 5\r\n\r\nhello"),
        ("cl-list-diff", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 6\r\n\r\nhello"),
        ("chunked", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
        ("te-and-cl", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\nhello"),
        ("te-gzip", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n"),
        ("te-chunked-not-last", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
        ("te-http10", "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"),
        ("space-before-colon", "GET / HTTP/1.1\r\nHost : x\r\n\r\n"),
        ("method-space", "GE T / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("method-lower", "get / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ("bad-version", "GET / HTTP/9.9\r\nHost: x\r\n\r\n"),
        ("no-version", "GET /\r\nHost: x\r\n\r\n"),
        ("empty", ""),
        ("only-crlf", "\r\n"),
        ("dup-host", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"),
        ("header-case", "GET / HTTP/1.1\r\nhOsT: x\r\ncontent-type: t\r\n\r\n"),
        ("multi-value", "GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\nX-A: 2\r\n\r\n"),
        ("obs-fold", "GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n  2\r\n\r\n"),
        ("bare-lf-line", "GET / HTTP/1.1\nHost: x\n\n"),
        ("trailing-space-value", "GET / HTTP/1.1\r\nHost: x\r\nX-A:  v  \r\n\r\n"),
        ("empty-value", "GET / HTTP/1.1\r\nHost: x\r\nX-A:\r\n\r\n"),
    ];
    for (name, raw) in cases.iter() {
        let mut src = strings::NewReader(s(raw));
        let mut br = bufio::NewReader(&mut src);
        let (mut req, err) = http::ReadRequest(&mut br);
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("req %-21s -> err=%q", s(name), err.Error()),
            );
            continue;
        }
        let (body, berr) = io::ReadAll(&mut req.Body);
        chk(&mut failed, &mut ln, fmt::Sprintf!(
            "req %-21s -> m=%-8q uri=%-26q proto=%-9q host=%-9q cl=%-3d te=%v hdr=%s body=%q berr=%v",
            s(name),
            req.Method.clone(),
            req.URL.String(),
            req.Proto.clone(),
            req.Host.clone(),
            req.ContentLength,
            te_string(&req.TransferEncoding),
            hdr_string(&req.Header),
            body,
            et(&berr)
        ));
    }
    // Cookie parsing from a request.
    for v in [
        "a=1",
        "a=1; b=2",
        "a=1;b=2",
        "a=",
        "=1",
        "a",
        "a=1; ; b=2",
        "a=\"quoted\"",
        "a=1; a=2",
        "A=1; a=2",
        "a=b=c",
        "a=1;",
        " a = 1 ",
        "a=\u{0}",
        "a=1\t",
        "önem=1",
    ] {
        // Request has private fields, so build it via Default and set
        // the one header this case needs.
        let mut req = http::Request::default();
        req.Header.Set(s("Cookie"), s(v));
        let cs = req.Cookies();
        let mut out = s("[");
        for i in 0..cs.Len() {
            if i > 0 {
                out = out + s(" ");
            }
            out = out + cs[i].Name.clone() + s("=") + cs[i].Value.clone();
        }
        out = out + s("]");
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("cookie %-14q -> %s", s(v), out),
        );
    }
    for v in [
        "a=1",
        "a=1; Path=/; HttpOnly",
        "a=1; Max-Age=0",
        "a=1; Max-Age=-1",
        "a=1; Max-Age=abc",
        "a=1; Secure; SameSite=Lax",
        "a=1; SameSite=Bogus",
        "a=1; Domain=.example.com",
        "a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        "=1",
        "a",
        "",
        "a=1; Path=/x\u{0}y",
    ] {
        let (c, err) = http::ParseSetCookie(s(v));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("setcookie %-42q -> err=%q", s(v), err.Error()),
            );
            continue;
        }
        chk(&mut failed, &mut ln, fmt::Sprintf!(
            "setcookie %-42q -> name=%-3q val=%-4q path=%-4q dom=%-13q maxage=%-3d secure=%-5v httponly=%-5v samesite=%d str=%q",
            s(v),
            c.Name.clone(),
            c.Value.clone(),
            c.Path.clone(),
            c.Domain.clone(),
            c.MaxAge,
            c.Secure,
            c.HttpOnly,
            c.SameSite as int,
            c.String()
        ));
    }
    for k in [
        "content-type",
        "CONTENT-TYPE",
        "Content-Type",
        "x-a-b",
        "X_A",
        "a",
        "",
        "-",
        "--",
        "a-",
        "-a",
        "aB-cD",
        "x-forwarded-for",
        "Sec-WebSocket-Key",
        "a b",
        "a\tb",
    ] {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("canon %-20q -> %q", s(k), http::CanonicalHeaderKey(s(k))),
        );
    }
    let _: byte = 0;
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
