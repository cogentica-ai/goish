// http_newrequest_host_smoke — NewRequest must normalise an empty
// colon:port.
//
// Reference: Go 1.25.5 net/http, measured by
// tools/gen_newrequest_host_ref.go.
//
// Go: "The host's colon:port should be normalized. See Issue 14836."
// (request.go:910). That line is the ONLY caller of removeEmptyPort in
// Go's tree. goish had removeEmptyPort ported, anchored to
// http.go:115-120, and exercised by http_helpers_smoke — and
// NewRequest did not call it, so "http://example.com:/p" kept its
// trailing colon all the way onto the wire as `Host: example.com:`.
//
// RFC 3986 6.2.3 says the empty port is equivalent to no port, so a
// peer is entitled to treat the two as the same origin — and entitled
// not to. Anything keying on the Host header (a virtual-host lookup, a
// cache, a signed request whose canonical form includes the host) sees
// two different strings for one server.
//
// The cases that must NOT change are the point of the other seven:
// removeEmptyPort strips a trailing colon only when the host actually
// HAS a port section, and Go decides that with
// `LastIndex(s, ":") > LastIndex(s, "]")` so that an IPv6 literal's
// internal colons do not count. `:80` and `:0` keep their ports —
// port zero is a real port here, not an empty one — and a bare `[::1]`
// is left alone.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string;
use goish::net::http;
use goish::types::int;

const GO: [&str; 10] = [
    "http://example.com/p           urlhost=\"example.com\" host=\"example.com\"",
    "http://example.com:/p          urlhost=\"example.com\" host=\"example.com\"",
    "http://example.com:80/p        urlhost=\"example.com:80\" host=\"example.com:80\"",
    "https://example.com:/p         urlhost=\"example.com\" host=\"example.com\"",
    "http://example.com:0/p         urlhost=\"example.com:0\" host=\"example.com:0\"",
    "http://[::1]:/p                urlhost=\"[::1]\" host=\"[::1]\"",
    "http://[::1]/p                 urlhost=\"[::1]\" host=\"[::1]\"",
    "http://[::1]:8080/p            urlhost=\"[::1]:8080\" host=\"[::1]:8080\"",
    "http://user:pw@example.com:/p  urlhost=\"example.com\" host=\"example.com\"",
    "http://example.com:/           urlhost=\"example.com\" host=\"example.com\"",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let urls: [&str; 10] = [
        "http://example.com/p",
        "http://example.com:/p",
        "http://example.com:80/p",
        "https://example.com:/p",
        "http://example.com:0/p",
        "http://[::1]:/p",
        "http://[::1]/p",
        "http://[::1]:8080/p",
        "http://user:pw@example.com:/p",
        "http://example.com:/",
    ];
    let mut ln: usize = 0;
    for u in urls.iter() {
        let (req, err) = http::NewRequest("GET", string::from(*u), goish::nil);
        if !err.IsNil() {
            chk(&mut ln, &fmt::Sprintf!("%-30s err=%v", string::from(*u), err));
            continue;
        }
        chk(&mut ln, &fmt::Sprintf!("%-30s urlhost=%q host=%q",
            string::from(*u), req.URL.Host, req.Host));
    }
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
