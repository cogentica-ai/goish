// http_request_header_injection_smoke — a CR or LF in an OUTGOING
// request header must not reach the wire.
//
// The sibling of http_header_injection_smoke next to this file, which
// covers the RESPONSE side: a handler injecting a header into what the
// server writes. That one's own header calls itself the third of three
// independent injection sites goish had fixed. This is a fourth, in
// the other direction, and it was still open.
//
// Go validates outgoing headers and trailers in Transport.roundTrip
// (transport.go:597) before anything is dialled. goish had
// `validateHeaders` ported and anchored to that exact Go function, and
// CALLED FROM NOWHERE — so every malformed shape below went onto the
// wire verbatim.
//
// That is request smuggling. A caller that puts attacker-controlled
// text into a header value — a forwarded user agent, a tenant id, a
// filename — lets the attacker close the header block with CRLF and
// begin a second request inside the first. The victim is whatever
// parses the connection next: a proxy, a cache, or the origin.
//
// Measured: Go refuses five of six shapes before dialling, and goish
// refused NONE. The sixth is a valid header and is the control that
// must still go through.
//
// Note which LAYER this drives, because the first version of this
// measurement got it wrong. `Request.Write` does not validate in Go
// either — checking that found Go "injecting" too and would have
// concluded goish was fine. The defence lives in the Transport, so the
// test calls `Client.Do` against a closed port: a request that reaches
// the network fails with a connection error, and one rejected earlier
// fails with "invalid header".
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string;
use goish::net::http;
use goish::strings;
use goish::time;
use goish::types::int;

const GO: [&str; 6] = [
    "plain            rejected-before-dial=false",
    "crlf-in-value    rejected-before-dial=true",
    "lf-in-value      rejected-before-dial=true",
    "cr-in-value      rejected-before-dial=true",
    "nul-in-value     rejected-before-dial=true",
    "crlf-in-key      rejected-before-dial=true",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!(
            "[!!] line %d\n  got  %q\n  want %q\n",
            *ln as int + 1,
            got,
            GO[*ln]
        );
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let cases: [(&str, &str, &str); 6] = [
        ("plain", "X-Ok", "value"),
        ("crlf-in-value", "X-Bad", "a\r\nX-Injected: 1"),
        ("lf-in-value", "X-Bad", "a\nX-Injected: 1"),
        ("cr-in-value", "X-Bad", "a\rX-Injected: 1"),
        ("nul-in-value", "X-Bad", "a\u{0}b"),
        ("crlf-in-key", "X-Bad\r\nX-Injected", "v"),
    ];
    let mut c = http::Client::default();
    c.Timeout = time::Second * 2;
    for (name, k, v) in cases.iter() {
        let (req, err) = http::NewRequest("GET", "http://127.0.0.1:1/p", goish::nil);
        if !err.IsNil() {
            chk(&mut ln, &fmt::Sprintf!("%-16s newrequest-err", *name));
            continue;
        }
        let mut req = req;
        req.Header.Set(string::from(*k), string::from(*v));
        let (_resp, err) = c.Do(&mut req);
        let es = if err.IsNil() {
            string::from("nil")
        } else {
            err.Error()
        };
        chk(
            &mut ln,
            &fmt::Sprintf!(
                "%-16s rejected-before-dial=%v",
                *name,
                strings::Contains(&es, "invalid header")
            ),
        );
    }

    if ln != GO.len() {
        fmt::Printf!(
            "[!!] produced %d lines, pinned %d\n",
            ln as int,
            GO.len() as int
        );
    }
}
