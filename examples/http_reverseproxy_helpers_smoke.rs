// http_reverseproxy_helpers_smoke — net/http/httputil/reverseproxy.go's
// pure helpers: singleJoiningSlash (:222), copyHeader (:294), ishex
// (:877), hopHeaders (:189) and removeHopByHopHeaders (:588).
//
// All values are Go 1.25.5 output via scripts/goref.sh
// net/http/httputil.
//
// removeHopByHopHeaders is the one that matters for a proxy's
// security, and its two passes must run in Go's ORDER:
//
//   1. RFC 7230 §6.1 — the Connection header NAMES the hop-by-hop
//      headers for this hop, so those are deleted first, while
//      Connection is still there to be read.
//   2. RFC 2616 §13.5.1 — the fixed list is deleted, and that list
//      INCLUDES Connection itself.
//
// Reversing them deletes Connection before reading it, so anything it
// named — "X-Custom" below, standing in for a header a front-end
// added for this hop only — is forwarded to the backend instead of
// stripped.
//
// copyHeader uses Add, not Set: a key present in both source and
// destination ends up with BOTH sets of values.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http::header::Header;
use goish::net::http::httputil::reverseproxy::{
    copyHeader, ishex, removeHopByHopHeaders, singleJoiningSlash,
};
use goish::{fmt, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. singleJoiningSlash — exactly one '/' at the join.
    {
        let cases: &[(&str, &str, &str)] = &[
            ("/a", "/b", "/a/b"),
            ("/a/", "/b", "/a/b"),
            ("/a", "b", "/a/b"),
            ("/a/", "b", "/a/b"),
            ("", "", "/"),
            ("/", "/", "/"),
        ];
        let mut bad = 0;
        for (a, b, want) in cases {
            let got = singleJoiningSlash(string(*a), string(*b));
            if got != *want {
                fmt::Println!("     singleJoiningSlash(", *a, ",", *b, ") = ", got);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[1] singleJoiningSlash, 6 cases vs Go  PASS");
        } else {
            failed += 1;
        }
    }

    // 2. copyHeader appends rather than replacing.
    {
        let mut dst = Header::new();
        dst.Set(string("X"), string("1"));
        let mut src = Header::new();
        src.Set(string("X"), string("2"));
        src.Set(string("Y"), string("a"));
        src.Add(string("Y"), string("b"));
        copyHeader(&mut dst, &src);
        let x = dst.Values(string("X"));
        let y = dst.Values(string("Y"));
        if x.Len() == 2 && x[0] == "1" && x[1] == "2" && y.Len() == 2 && y[0] == "a" && y[1] == "b" {
            fmt::Println!("[2] copyHeader appends, not replaces  PASS");
        } else {
            fmt::Println!("[2] copyHeader  FAIL x=", x.Len(), " y=", y.Len());
            failed += 1;
        }
    }

    // 3. ishex.
    {
        let yes: &[u8] = b"0123456789abcdefABCDEF";
        let no: &[u8] = b"gGzZ !\x00";
        let mut bad = 0;
        for c in yes {
            if !ishex(*c) {
                bad += 1;
            }
        }
        for c in no {
            if ishex(*c) {
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[3] ishex  PASS");
        } else {
            fmt::Println!("[3] ishex  FAIL ", bad);
            failed += 1;
        }
    }

    // 4. removeHopByHopHeaders strips both the Connection-named
    //    headers and the fixed list, leaving only end-to-end ones.
    {
        let mut h = Header::new();
        h.Set(string("Connection"), string("X-Custom, Keep-Alive"));
        h.Set(string("X-Custom"), string("secret"));
        h.Set(string("Keep-Alive"), string("timeout=5"));
        h.Set(string("Proxy-Connection"), string("close"));
        h.Set(string("Te"), string("trailers"));
        h.Set(string("Trailer"), string("X-T"));
        h.Set(string("Transfer-Encoding"), string("chunked"));
        h.Set(string("Upgrade"), string("websocket"));
        h.Set(string("X-Keep"), string("yes"));
        removeHopByHopHeaders(&mut h);
        // Go leaves exactly X-Keep.
        let gone = [
            "Connection", "X-Custom", "Keep-Alive", "Proxy-Connection",
            "Te", "Trailer", "Transfer-Encoding", "Upgrade",
        ];
        let mut bad = 0;
        for k in gone.iter() {
            if h.has(string(*k)) {
                fmt::Println!("     still present: ", *k);
                bad += 1;
            }
        }
        if !h.has(string("X-Keep")) {
            fmt::Println!("     X-Keep was removed");
            bad += 1;
        }
        if bad == 0 && h.Len() == 1 {
            fmt::Println!("[4] removeHopByHopHeaders leaves only X-Keep  PASS");
        } else {
            fmt::Println!("[4] removeHopByHopHeaders  FAIL len=", h.Len() as i64);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 4");
        syscall::Exit(1);
    }
}
