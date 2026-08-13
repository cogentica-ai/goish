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
    StateActive, StateClosed, StateHijacked, StateIdle, StateNew, TrailerPrefix, badRequestError,
    extraHeader, getCopyBuf, htmlReplacer, putCopyBuf, statusError,
};
use goish::bytes;
use goish::errors::ErrorTrait;
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

    // 9. statusError / badRequestError. Go renders these as
    //    "<StatusText>: <text>", and Go's own comment constrains the
    //    text: "plain text WITHOUT user info or other embedded
    //    errors" — it reaches the client verbatim, so echoing a parse
    //    error into it would leak internals.
    //
    //    The 999 case is the one worth pinning: StatusText has no
    //    entry, so the message begins with a bare ": ". Rendering
    //    "Status 999" instead would look tidier and diverge.
    {
        let mut bad = 0;
        if badRequestError(string("missing required Host header")).Error()
            != "Bad Request: missing required Host header" { bad += 1; }
        if badRequestError(string("invalid header name")).Error()
            != "Bad Request: invalid header name" { bad += 1; }
        let e404 = statusError { code: 404, text: string("nope") };
        let e500 = statusError { code: 500, text: string("boom") };
        let e999 = statusError { code: 999, text: string("x") };
        if e404.Error() != "Not Found: nope" { bad += 1; }
        if e500.Error() != "Internal Server Error: boom" { bad += 1; }
        if e999.Error() != ": x" { bad += 1; }
        check!("[9] statusError / badRequestError vs Go", bad);
    }

    // 10. htmlReplacer — the escaper Redirect's body and dirList's
    //     link text share. Quoting `'` and `"` is NOT optional: both
    //     callers interpolate into an href ATTRIBUTE, where a bare
    //     quote escapes it. The last case is the one that shows why:
    //     a script tag with a quoted attribute inside is fully
    //     neutralised.
    {
        let cases: &[(&str, &str)] = &[
            ("<a>", "&lt;a&gt;"),
            ("a&b", "a&amp;b"),
            ("a\"b", "a&#34;b"),
            ("a'b", "a&#39;b"),
            ("plain", "plain"),
            ("", ""),
            (
                "<script>alert(\"x&y\")</script>",
                "&lt;script&gt;alert(&#34;x&amp;y&#34;)&lt;/script&gt;",
            ),
        ];
        let r = htmlReplacer();
        let mut bad = 0;
        for (input, want) in cases {
            let got = r.Replace(string(*input));
            if got != *want {
                fmt::Println!("     htmlReplacer(", *input, ") = ", got);
                bad += 1;
            }
        }
        check!("[10] htmlReplacer, 7 cases vs Go", bad);
    }

    // 11. The copy-buffer pool hands out a full-size buffer and
    //     REJECTS a short one on return — Go panics rather than
    //     accepting it, because the pool holds fixed arrays and a
    //     short buffer would later be handed out as if full length.
    {
        let b = getCopyBuf();
        let mut bad = 0;
        if b.Len() != copyBufPoolSize {
            fmt::Println!("     getCopyBuf len=", b.Len());
            bad += 1;
        }
        putCopyBuf(b);
        check!("[11] getCopyBuf/putCopyBuf round trip", bad);
    }

    // 12. extraHeader.Write — the headers the response writer emits
    //     from its own fields rather than the Header map.
    //
    //     Two things are pinned because they are easy to get wrong:
    //     the ORDER (Date and Content-Length first, then Content-Type,
    //     Connection, Transfer-Encoding — matching extraHeaderKeys),
    //     and that an EMPTY value writes NOTHING rather than a header
    //     with an empty value. "empty-string ct" produces no output at
    //     all, which is why date/contentLength are byte slices in Go:
    //     absent and empty must be distinguishable.
    {
        let mk = |ct: &'static str, conn: &'static str, te: &'static str, date: &'static str, cl: &'static str| -> string {
            let h = extraHeader {
                contentType: string(ct),
                connection: string(conn),
                transferEncoding: string(te),
                date: slice::from(date.as_bytes()),
                contentLength: slice::from(cl.as_bytes()),
            };
            let mut buf = bytes::Buffer::new();
            h.Write(&mut buf);
            return string::from_bytes(&buf.Bytes());
        };
        let cases: &[(string, &str)] = &[
            (mk("", "", "", "", ""), ""),
            (mk("text/plain", "", "", "", ""), "Content-Type: text/plain\r\n"),
            (
                mk("text/plain", "close", "chunked", "", ""),
                "Content-Type: text/plain\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n",
            ),
            (
                mk("", "", "", "Mon, 01 Jan 2024 00:00:00 GMT", "42"),
                "Date: Mon, 01 Jan 2024 00:00:00 GMT\r\nContent-Length: 42\r\n",
            ),
            (
                mk("text/html", "keep-alive", "identity", "D", "7"),
                "Date: D\r\nContent-Length: 7\r\nContent-Type: text/html\r\nConnection: keep-alive\r\nTransfer-Encoding: identity\r\n",
            ),
        ];
        let mut bad = 0;
        for (got, want) in cases {
            if got != *want {
                fmt::Println!("     extraHeader.Write got: ", got.clone());
                bad += 1;
            }
        }
        check!("[12] extraHeader.Write, 5 cases vs Go", bad);
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 12");
        syscall::Exit(1);
    }
}
