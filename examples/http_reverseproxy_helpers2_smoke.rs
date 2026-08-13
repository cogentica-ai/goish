// httputil upgradeType / cleanQueryParams against Go 1.25.5.
// Expected values from a goref run of the real unexported functions.
//
// Both are proxy-safety helpers, and both edges matter:
//
//   upgradeType requires BOTH an Upgrade: header AND the Upgrade
//   token in Connection:. An Upgrade: with Connection: keep-alive is
//   NOT an upgrade — treating it as one is how a proxy is talked into
//   hijacking a plain HTTP connection.
//
//   cleanQueryParams passes a safe query through byte-for-byte and
//   re-encodes anything ambiguous. A semicolon or a malformed escape
//   re-encodes to "" here, because Go's ParseQuery ERRORS on those
//   and Encode of the empty result is empty — the proxy forwards no
//   query rather than one the backend might parse differently.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::net::http::httputil;
use goish::{fmt, string, syscall};

fn hdr(conn: &'static str, upg: &'static str) -> http::Header {
    let mut h = http::Header::new();
    if conn != "" {
        h.Set(string("Connection"), string(conn));
    }
    if upg != "" {
        h.Set(string("Upgrade"), string(upg));
    }
    return h;
}

fn eq(got: string, want: &str, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what, ": got ", got, " want ", want);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    eq(httputil::upgradeType(&hdr("Upgrade", "websocket")), "websocket",
       "upgradeType Connection=Upgrade", &mut bad);
    eq(httputil::upgradeType(&hdr("upgrade", "websocket")), "websocket",
       "upgradeType Connection=upgrade (lowercase token)", &mut bad);
    eq(httputil::upgradeType(&hdr("keep-alive, Upgrade", "websocket")), "websocket",
       "upgradeType Connection=keep-alive, Upgrade (multi-token)", &mut bad);
    eq(httputil::upgradeType(&hdr("keep-alive", "websocket")), "",
       "upgradeType Connection=keep-alive only", &mut bad);
    eq(httputil::upgradeType(&hdr("", "websocket")), "",
       "upgradeType no Connection", &mut bad);
    eq(httputil::upgradeType(&hdr("Upgrade", "")), "",
       "upgradeType no Upgrade header", &mut bad);

    let cq: [(&'static str, &str); 7] = [
        ("a=1&b=2", "a=1&b=2"),
        ("", ""),
        ("a=1;b=2", ""),   // semicolon: not a separator since Go 1.17
        ("a=%zz", ""),     // malformed escape
        ("a=%2", ""),      // truncated escape
        ("a=%2Fb", "a=%2Fb"), // valid escape passes through untouched
        ("b=2&a=1", "b=2&a=1"), // order preserved when already safe
    ];
    for (q, want) in cq.iter() {
        eq(httputil::cleanQueryParams(string(*q)), want, "cleanQueryParams", &mut bad);
    }

    if bad == 0 {
        fmt::Println!("RP_HELPERS2_OK 13/13");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
