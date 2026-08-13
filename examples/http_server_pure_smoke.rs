// http_server_pure_smoke — net/http/server.go's pure helpers:
// cleanPath (:2308), stripHostPort (:2327), foreachHeaderElement
// (:2003), validNextProto (:3565), numLeadingCRorLF (:4067) and
// tlsRecordHeaderLooksLikeHTTP (:2062).
//
// Every expectation is Go 1.25.5 output via scripts/goref.sh net/http.
//
// cleanPath is not path.Clean. path.Clean strips a trailing slash
// except at root; cleanPath puts it BACK, because to a ServeMux "/dir"
// and "/dir/" are different patterns and collapsing them silently
// reroutes requests. Note "/a//" cleans to "/a/", not "/a".
//
// stripHostPort's two surprises both come from net.SplitHostPort: a
// bare IPv6 literal "[::1]" has no port so it is returned WITH its
// brackets, while "[::1]:80" loses them and yields "::1"; and
// ":80" yields the empty string, not ":80".

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::goslice::slice;
use goish::net::http::server::{
    cleanPath, foreachHeaderElement, numLeadingCRorLF, stripHostPort,
    tlsRecordHeaderLooksLikeHTTP, validNextProto, bufferBeforeChunkingSize, copyBufPoolSize,
    debugServerConnections, errTooLarge, extraHeaderKeys, maxPostHandlerReadBytes,
    nextProtoUnencryptedHTTP2, rstAvoidanceDelay, shutdownPollIntervalMax, ConnStateString,
    StateActive, StateClosed, StateHijacked, StateIdle, StateNew, TrailerPrefix,
};
use goish::errors;
use goish::time;
use goish::{fmt, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    macro_rules! check {
        ($n:expr, $bad:expr) => {
            if $bad == 0 {
                fmt::Println!($n, "  PASS");
            } else {
                fmt::Println!($n, "  FAIL");
                failed += 1;
            }
        };
    }

    // 1. cleanPath — trailing slash preserved.
    {
        let cases: &[(&str, &str)] = &[
            ("", "/"), ("/", "/"), ("a", "/a"), ("/a", "/a"), ("/a/", "/a/"),
            ("//a//b//", "/a/b/"), ("/a/./b", "/a/b"), ("/a/../b", "/b"),
            ("/a/..", "/"), ("/..", "/"), ("a/b/", "/a/b/"), ("/a//", "/a/"),
            ("/./", "/"),
        ];
        let mut bad = 0;
        for (p, want) in cases {
            let got = cleanPath(string(*p));
            if got != *want {
                fmt::Println!("     cleanPath(", *p, ") = ", got, " want ", *want);
                bad += 1;
            }
        }
        check!("[1] cleanPath, 13 cases vs Go", bad);
    }

    // 2. stripHostPort.
    {
        let cases: &[(&str, &str)] = &[
            ("example.com", "example.com"),
            ("example.com:80", "example.com"),
            ("[::1]:80", "::1"),
            ("[::1]", "[::1]"),
            ("a:b:c", "a:b:c"),
            ("", ""),
            (":80", ""),
        ];
        let mut bad = 0;
        for (h, want) in cases {
            let got = stripHostPort(string(*h));
            if got != *want {
                fmt::Println!("     stripHostPort(", *h, ") = ", got, " want ", *want);
                bad += 1;
            }
        }
        check!("[2] stripHostPort, 7 cases vs Go", bad);
    }

    // 3. foreachHeaderElement — trims, drops empties, and passes a
    //    comma-free value through WHOLE without splitting.
    {
        let cases: &[(&str, &[&str])] = &[
            ("", &[]),
            ("  ", &[]),
            ("gzip", &["gzip"]),
            (" gzip ", &["gzip"]),
            ("gzip, deflate", &["gzip", "deflate"]),
            ("gzip,,deflate", &["gzip", "deflate"]),
            (",", &[]),
            ("a , b", &["a", "b"]),
        ];
        let mut bad = 0;
        for (v, want) in cases {
            let mut got: Vec<string> = Vec::new();
            foreachHeaderElement(string(*v), |e| got.push(e));
            if got.len() != want.len() {
                fmt::Println!("     foreachHeaderElement(", *v, ") n=", got.len() as i64);
                bad += 1;
                continue;
            }
            for i in 0..want.len() {
                if got[i] != want[i] {
                    fmt::Println!("     foreachHeaderElement(", *v, ") elem wrong");
                    bad += 1;
                }
            }
        }
        check!("[3] foreachHeaderElement, 8 cases vs Go", bad);
    }

    // 4. validNextProto — case-sensitive, so "HTTP/1.1" IS a next proto.
    {
        let cases: &[(&str, bool)] = &[
            ("", false), ("http/1.1", false), ("http/1.0", false),
            ("h2", true), ("HTTP/1.1", true),
        ];
        let mut bad = 0;
        for (p, want) in cases {
            if validNextProto(string(*p)) != *want {
                fmt::Println!("     validNextProto(", *p, ") wrong");
                bad += 1;
            }
        }
        check!("[4] validNextProto, 5 cases vs Go", bad);
    }

    // 5. numLeadingCRorLF — counts only the LEADING run.
    {
        let cases: &[(&str, i64)] = &[
            ("", 0), ("\r\n\r\nGET", 4), ("GET", 0), ("\nGET", 1),
            ("\r", 1), ("x\r\n", 0),
        ];
        let mut bad = 0;
        for (v, want) in cases {
            let got = numLeadingCRorLF(slice::from(v.as_bytes()));
            if got != *want {
                fmt::Println!("     numLeadingCRorLF n=", got, " want ", *want);
                bad += 1;
            }
        }
        check!("[5] numLeadingCRorLF, 6 cases vs Go", bad);
    }

    // 6. tlsRecordHeaderLooksLikeHTTP — exact, case-sensitive prefixes.
    //    A real TLS handshake record (0x16 0x03 ...) must not match.
    {
        let yes: &[&str] = &["GET /", "HEAD ", "POST ", "PUT /", "OPTIO"];
        let no: &[&str] = &["\x16\x03\x01\x00\x00", "get /"];
        let mut bad = 0;
        for h in yes {
            let mut a: [goish::types::byte; 5] = [0; 5];
            a.copy_from_slice(&h.as_bytes()[..5]);
            if !tlsRecordHeaderLooksLikeHTTP(a) {
                fmt::Println!("     want true: ", *h);
                bad += 1;
            }
        }
        for h in no {
            let mut a: [goish::types::byte; 5] = [0; 5];
            a.copy_from_slice(&h.as_bytes()[..5]);
            if tlsRecordHeaderLooksLikeHTTP(a) {
                fmt::Println!("     want false: ", *h);
                bad += 1;
            }
        }
        check!("[6] tlsRecordHeaderLooksLikeHTTP, 7 cases vs Go", bad);
    }

    // 7. ConnState.String — the five states, and Go's behaviour for a
    //    value outside them. Go indexes a map directly, so an unknown
    //    state yields the map's zero value: the EMPTY string, NOT a
    //    "ConnState(7)" rendering. A Display impl that formatted the
    //    number would look more helpful and diverge.
    {
        let cases: &[(i64, &str)] = &[
            (StateNew, "new"),
            (StateActive, "active"),
            (StateIdle, "idle"),
            (StateHijacked, "hijacked"),
            (StateClosed, "closed"),
            (7, ""),
            (-1, ""),
        ];
        let mut bad = 0;
        for (c, want) in cases {
            let got = ConnStateString(*c);
            if got != *want {
                fmt::Println!("     ConnState(", *c, ") = ", got, " want ", *want);
                bad += 1;
            }
        }
        check!("[7] ConnState.String, 7 cases vs Go", bad);
    }

    // 8. server.go's constants and sentinels.
    //
    //    rstAvoidanceDelay is 500ms, NOT 1ns. scripts/goref.sh reports
    //    1ns because it compiles the package's tests too, and
    //    export_test.go:331 sets it to the minimum "to shake out
    //    timing bugs". The source value is what ships. This is the
    //    documented goref trap, caught here in the wild.
    {
        let mut bad = 0;
        if TrailerPrefix != "Trailer:" { bad += 1; }
        if bufferBeforeChunkingSize != 2048 { bad += 1; }
        if debugServerConnections { bad += 1; }
        if copyBufPoolSize != 32768 { bad += 1; }
        if maxPostHandlerReadBytes != 262144 { bad += 1; }
        if nextProtoUnencryptedHTTP2 != "unencrypted_http2" { bad += 1; }
        let e: errors::error = errTooLarge.into();
        if e.Error() != "http: request too large" { bad += 1; }
        if rstAvoidanceDelay() != time::Duration(500_000_000) { bad += 1; }
        if shutdownPollIntervalMax() != time::Duration(500_000_000) { bad += 1; }
        let ks = extraHeaderKeys();
        if ks.Len() != 3
            || string::from_bytes(&ks[0]) != "Content-Type"
            || string::from_bytes(&ks[1]) != "Connection"
            || string::from_bytes(&ks[2]) != "Transfer-Encoding"
        {
            bad += 1;
        }
        check!("[8] server.go constants + sentinels vs Go", bad);
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 8");
        syscall::Exit(1);
    }
}
