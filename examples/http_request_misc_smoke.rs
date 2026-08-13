// http_request_misc_smoke — small net/http/request.go declarations:
// badStringError (:96), reqWriteExcludeHeader (:98), defaultUserAgent
// (:545), errMissingHost (:577), removeZone (:794) and
// requestMethodUsuallyLacksBody (:1566).
//
// Every expected value is Go 1.25.5 output via scripts/goref.sh
// net/http.
//
// removeZone is the one with teeth. An IPv6 zone identifier
// ("%en0", or its percent-encoded "%25en0" form) is meaningful only on
// the local machine and must never reach a Host header. The stripping
// is bracket-anchored and index-based, not a split on '%':
//
//   * an unbracketed host is returned untouched, so "fe80::1%en0"
//     keeps its '%' — it is not a literal IPv6 host;
//   * the search for '%' runs only over the text BEFORE the last ']',
//     so trailing text survives: "[a%b]c" -> "[a]c";
//   * a missing ']' means no change at all.
//
// badStringError formats with %q, so the value is Go-quoted and an
// embedded quote is escaped — the reason it is safe to put an
// attacker-controlled method or version into the message.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http::request::{
    badStringError, defaultUserAgent, errMissingHost, removeZone, reqWriteExcludeHeader,
    requestMethodUsuallyLacksBody,
};
use goish::{errors, fmt, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. removeZone, 10 cases pinned to Go.
    {
        let cases: &[(&str, &str)] = &[
            ("[fe80::1%en0]", "[fe80::1]"),
            ("[fe80::1%25en0]", "[fe80::1]"),
            ("[::1]", "[::1]"),
            ("example.com", "example.com"),
            ("[fe80::1", "[fe80::1"),
            ("fe80::1%en0", "fe80::1%en0"),
            ("[]", "[]"),
            ("[%]", "[]"),
            ("[a%b]c", "[a]c"),
            ("", ""),
        ];
        let mut bad = 0;
        for (input, want) in cases {
            let got = removeZone(string(*input));
            if got != *want {
                fmt::Println!("     removeZone(", *input, ") = ", got, " want ", *want);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[1] removeZone, 10 cases vs Go  PASS");
        } else {
            failed += 1;
        }
    }

    // 2. requestMethodUsuallyLacksBody — exact, case-sensitive set.
    {
        let yes: &[&str] = &["GET", "HEAD", "DELETE", "OPTIONS", "PROPFIND", "SEARCH"];
        let no: &[&str] = &["POST", "PUT", "get", ""];
        let mut bad = 0;
        for m in yes {
            if !requestMethodUsuallyLacksBody(string(*m)) {
                fmt::Println!("     want true: ", *m);
                bad += 1;
            }
        }
        for m in no {
            if requestMethodUsuallyLacksBody(string(*m)) {
                fmt::Println!("     want false: ", *m);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[2] requestMethodUsuallyLacksBody  PASS");
        } else {
            failed += 1;
        }
    }

    // 3. badStringError quotes the value, escaping embedded quotes.
    {
        let a = badStringError(string("invalid method"), string("BAD METHOD"));
        let b = badStringError(string("malformed HTTP version"), string("HTTP/\"x"));
        if a.Error() == "invalid method \"BAD METHOD\""
            && b.Error() == "malformed HTTP version \"HTTP/\\\"x\""
        {
            fmt::Println!("[3] badStringError quotes and escapes  PASS");
        } else {
            fmt::Println!("[3] badStringError  FAIL a=", a, " b=", b);
            failed += 1;
        }
    }

    // 4. The constants match Go.
    {
        let e: errors::error = errMissingHost.into();
        if defaultUserAgent == "Go-http-client/1.1"
            && e.Error() == "http: Request.Write on Request with no Host or URL set"
        {
            fmt::Println!("[4] defaultUserAgent + errMissingHost  PASS");
        } else {
            fmt::Println!("[4] constants  FAIL");
            failed += 1;
        }
    }

    // 5. reqWriteExcludeHeader holds exactly the five Go names — the
    //    headers Request.Write emits from its own fields, so writing
    //    them from the Header map too would duplicate them.
    {
        let m = reqWriteExcludeHeader();
        let want: &[&str] = &[
            "Host",
            "User-Agent",
            "Content-Length",
            "Transfer-Encoding",
            "Trailer",
        ];
        let mut bad = 0;
        for k in want {
            let (v, ok) = m.Get(string(*k));
            if !ok || !v {
                fmt::Println!("     missing: ", *k);
                bad += 1;
            }
        }
        let (_, extra) = m.Get(string("Content-Type"));
        if bad == 0 && m.Len() == 5 && !extra {
            fmt::Println!("[5] reqWriteExcludeHeader is exactly 5 names  PASS");
        } else {
            fmt::Println!("[5] reqWriteExcludeHeader  FAIL len=", m.Len());
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 5");
        syscall::Exit(1);
    }
}
