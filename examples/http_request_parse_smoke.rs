// http_request_parse_smoke — net/http/request.go's request-line
// parsers: ParseHTTPVersion (:817), validMethod (:906) and
// parseBasicAuth (:987).
//
// All 26 expectations are Go 1.25.5 output via scripts/goref.sh
// net/http.
//
// Each of the three is stricter or looser than it first looks, and the
// cases below are chosen where a plausible implementation diverges:
//
//   * ParseHTTPVersion needs BOTH digits — "HTTP/1" and "HTTP/2" are
//     rejected — takes exactly one digit each side, so "HTTP/01.1" and
//     "HTTP/1.10" fail, and is case-sensitive and whitespace-exact:
//     "http/1.1" and a trailing space both fail. It does NOT bound the
//     numbers, so "HTTP/9.9" parses.
//   * validMethod checks RFC 7230's `token` GRAMMAR, not a list of
//     known methods, so lowercase "get" and the nonsense "a!b" are
//     both valid while "GET,POST" is not — the comma is not a tchar.
//   * parseBasicAuth's scheme match is case-INSENSITIVE ("basic",
//     "BASIC"), but the decoded payload must contain a colon, so a
//     credential with no colon ("dXNlcg==" -> "user") is rejected
//     rather than being read as a username with an empty password.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http::request::{idnaASCII, parseBasicAuth, parseRequestLine, validMethod, ParseHTTPVersion};
use goish::{fmt, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ParseHTTPVersion.
    {
        let cases: &[(&str, i64, i64, bool)] = &[
            ("HTTP/1.1", 1, 1, true),
            ("HTTP/1.0", 1, 0, true),
            ("HTTP/2.0", 2, 0, true),
            ("HTTP/9.9", 9, 9, true),
            ("HTTP/1", 0, 0, false),
            ("HTTP/01.1", 0, 0, false),
            ("HTTP/1.10", 0, 0, false),
            ("http/1.1", 0, 0, false),
            ("HTTP/1.1 ", 0, 0, false),
            ("", 0, 0, false),
        ];
        let mut bad = 0;
        for (v, wmaj, wmin, wok) in cases {
            let (maj, min, ok) = ParseHTTPVersion(string(*v));
            if maj != *wmaj || min != *wmin || ok != *wok {
                fmt::Println!("     ParseHTTPVersion(", *v, ") = ", maj, " ", min, " ", ok);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[1] ParseHTTPVersion, 10 cases vs Go  PASS");
        } else {
            failed += 1;
        }
    }

    // 2. validMethod — grammar, not a method list.
    {
        let cases: &[(&str, bool)] = &[
            ("GET", true),
            ("get", true),
            ("M-SEARCH", true),
            ("a!b", true),
            ("", false),
            ("GE T", false),
            ("GET\n", false),
            ("GET,POST", false),
        ];
        let mut bad = 0;
        for (m, want) in cases {
            if validMethod(string(*m)) != *want {
                fmt::Println!("     validMethod(", *m, ") wrong");
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[2] validMethod, 8 cases vs Go  PASS");
        } else {
            failed += 1;
        }
    }

    // 3. parseBasicAuth — case-insensitive scheme, colon required.
    {
        let cases: &[(&str, &str, &str, bool)] = &[
            ("Basic dXNlcjpwYXNz", "user", "pass", true),
            ("basic dXNlcjpwYXNz", "user", "pass", true),
            ("BASIC dXNlcjpwYXNz", "user", "pass", true),
            ("Basic", "", "", false),
            ("Bearer x", "", "", false),
            ("Basic !!!", "", "", false),
            ("Basic dXNlcg==", "", "", false),
            ("", "", "", false),
        ];
        let mut bad = 0;
        for (a, wu, wp, wok) in cases {
            let (u, p, ok) = parseBasicAuth(string(*a));
            if ok != *wok || u != *wu || p != *wp {
                fmt::Println!("     parseBasicAuth(", *a, ") = ", u, " ", p, " ", ok);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[3] parseBasicAuth, 8 cases vs Go  PASS");
        } else {
            failed += 1;
        }
    }

    // 4. parseRequestLine — two cuts, each on the FIRST space.
    //    The consequences are worth pinning: a URI containing a space
    //    does NOT fail here, it makes the remainder the proto
    //    ("GET /a b HTTP/1.1" -> proto "b HTTP/1.1"), and trailing junk
    //    rides along the same way. Both are rejected later by
    //    ParseHTTPVersion, which is why that one is whitespace-exact.
    //    Two spaces alone parse as three empty fields with ok=true.
    {
        let cases: &[(&str, &str, &str, &str, bool)] = &[
            ("GET /path HTTP/1.1", "GET", "/path", "HTTP/1.1", true),
            ("GET / HTTP/1.0", "GET", "/", "HTTP/1.0", true),
            ("GET /a b HTTP/1.1", "GET", "/a", "b HTTP/1.1", true),
            ("GET /p HTTP/1.1 extra", "GET", "/p", "HTTP/1.1 extra", true),
            ("GET  HTTP/1.1", "GET", "", "HTTP/1.1", true),
            ("  ", "", "", "", true),
            ("GET /path", "", "", "", false),
            ("GET", "", "", "", false),
            ("", "", "", "", false),
        ];
        let mut bad = 0;
        for (line, wm, wu, wp, wok) in cases {
            let (m, u, p, ok) = parseRequestLine(string(*line));
            if ok != *wok || m != *wm || u != *wu || p != *wp {
                fmt::Println!("     parseRequestLine(", *line, ") wrong");
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[4] parseRequestLine, 9 cases vs Go  PASS");
        } else {
            failed += 1;
        }
    }

    // 5. idnaASCII — the ASCII fast path is exact; a non-ASCII host is
    //    REJECTED rather than punycoded, because goish does not port
    //    x/net/idna. Pinned so the divergence is visible, and so the
    //    day idna lands this assertion has to be flipped deliberately.
    {
        let (a, ae) = idnaASCII(string("example.com"));
        let (b, be) = idnaASCII(string("xn--exmple-cua.com"));
        let (_c, ce) = idnaASCII(string("ex\u{00e4}mple.com"));
        if ae == goish::nil
            && a == "example.com"
            && be == goish::nil
            && b == "xn--exmple-cua.com"
            && ce != goish::nil
        {
            fmt::Println!("[5] idnaASCII ASCII exact, non-ASCII rejected  PASS");
        } else {
            fmt::Println!("[5] idnaASCII  FAIL");
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
