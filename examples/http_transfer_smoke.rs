// http_transfer_smoke — net/http/transfer.go framing rules.
//
// Every expected value below was produced by running the real Go
// 1.25.5 net/http package under scripts/goref.sh, not transcribed
// from memory. The interesting cases are the request-smuggling
// hardening ones in fixLength and parseTransferEncoding.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::transfer::{body, transferWriter, 
    bodyAllowedForStatus, chunked, fixLength, fixTrailer, isIdentity, isUnsupportedTEError,
    noResponseBodyExpected, parseContentLength, shouldClose, suppressedHeaders, transferReader,
};
use goish::net::http::Header;
use goish::{slice, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

fn strs(v: &[&'static str]) -> slice<string> {
    let mut out: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    for s in v {
        out.push(string(*s));
    }
    return slice::<string>::__from_vec(out);
}

fn hdr(key: &'static str, vals: &[&'static str]) -> Header {
    let mut h = Header::new();
    for v in vals {
        h.Add(string(key), string(*v));
    }
    return h;
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    // ── noResponseBodyExpected ── Go: only exact "HEAD"
    check(
        "noResponseBodyExpected is exact-match on HEAD",
        noResponseBodyExpected(string("HEAD"))
            && !noResponseBodyExpected(string("head"))
            && !noResponseBodyExpected(string("GET"))
            && !noResponseBodyExpected(string("")),
        string(""),
    );

    // ── bodyAllowedForStatus ── Go: 99 and 205 DO allow a body
    {
        let cases: &[(i64, bool)] = &[
            (99, true),
            (100, false),
            (150, false),
            (199, false),
            (200, true),
            (204, false),
            (205, true),
            (304, false),
            (305, true),
            (404, true),
        ];
        let mut bad = string("");
        for (st, want) in cases {
            let got = bodyAllowedForStatus(*st as goish::int);
            if got != *want {
                bad = fmt::Sprintf!("%d: got %v want %v", *st, got, *want);
            }
        }
        check("bodyAllowedForStatus over 10 statuses", bad.Len() == 0, bad);
    }

    // ── chunked / isIdentity ── case-SENSITIVE, first element only
    check(
        "chunked is first-element-only and case-sensitive",
        chunked(&strs(&["chunked"]))
            && chunked(&strs(&["chunked", "gzip"]))
            && !chunked(&strs(&["gzip", "chunked"]))
            && !chunked(&strs(&["CHUNKED"]))
            && !chunked(&slice::<string>::new()),
        string(""),
    );
    check(
        "isIdentity requires exactly one \"identity\"",
        isIdentity(&strs(&["identity"]))
            && !isIdentity(&strs(&["identity", "chunked"]))
            && !isIdentity(&strs(&["chunked"])),
        string(""),
    );

    // ── suppressedHeaders ──
    {
        let s304 = suppressedHeaders(304);
        let s204 = suppressedHeaders(204);
        let s200 = suppressedHeaders(200);
        let s100 = suppressedHeaders(100);
        check(
            "suppressedHeaders: 304 drops 3, no-body drops 2, 200 drops none",
            s304.Len() == 3
                && s304[0 as goish::int] == "Content-Type"
                && s204.Len() == 2
                && s204[0 as goish::int] == "Content-Length"
                && s100.Len() == 2
                && s200.Len() == 0,
            fmt::Sprintf!(
                "304=%d 204=%d 100=%d 200=%d",
                s304.Len() as i64,
                s204.Len() as i64,
                s100.Len() as i64,
                s200.Len() as i64
            ),
        );
    }

    // ── parseContentLength ──
    {
        let cases: &[(&[&'static str], i64, bool)] = &[
            (&[], -1, false),
            (&["0"], 0, false),
            (&["5"], 5, false),
            (&[" 7 "], 7, false),      // trimmed
            (&[""], 0, true),          // "invalid empty Content-Length"
            (&["-1"], 0, true),        // ParseUint rejects the sign
            (&["abc"], 0, true),
            (&["9223372036854775807"], 9223372036854775807, false),
            (&["1", "2"], 1, false),   // only the first is consulted
        ];
        let mut bad = string("");
        for (input, want_n, want_err) in cases {
            let (n, err) = parseContentLength(&strs(input));
            if n != *want_n || err.IsNil() == *want_err {
                bad = fmt::Sprintf!("%v: n=%d err=%v", strs(input).Len() as i64, n, err);
            }
        }
        check("parseContentLength over 9 inputs", bad.Len() == 0, bad);
    }

    // ── shouldClose ── tokenised, not whole-value compare
    {
        let cases: &[(i64, i64, &[&'static str], bool)] = &[
            (0, 9, &[], true),                      // major < 1 always closes
            (1, 0, &[], true),                      // 1.0 defaults to close
            (1, 0, &["keep-alive"], false),
            (1, 0, &["close"], true),
            (1, 1, &[], false),                     // 1.1 defaults to keep-alive
            (1, 1, &["close"], true),
            (1, 1, &["Close"], true),               // case-insensitive
            (1, 1, &["keep-alive, close"], true),   // THE tokenising case
            (1, 1, &["keep-alive"], false),
        ];
        let mut bad = string("");
        for (maj, min, conn, want) in cases {
            let mut h = if conn.is_empty() {
                Header::new()
            } else {
                hdr("Connection", conn)
            };
            let got = shouldClose(*maj as goish::int, *min as goish::int, &mut h, false);
            if got != *want {
                bad = fmt::Sprintf!("%d.%d conn=%d -> %v want %v", *maj, *min, conn.len() as i64, got, *want);
            }
        }
        check("shouldClose over 9 cases (incl. \"keep-alive, close\")", bad.Len() == 0, bad);
    }
    // removeCloseHeader deletes Connection only when close is present
    {
        let mut h = hdr("Connection", &["close"]);
        let got = shouldClose(1, 1, &mut h, true);
        let gone = h.Values(string("Connection")).Len() == 0;
        let mut h2 = hdr("Connection", &["keep-alive"]);
        let _ = shouldClose(1, 1, &mut h2, true);
        let kept = h2.Values(string("Connection")).Len() == 1;
        check(
            "shouldClose(removeCloseHeader) deletes Connection only on close",
            got && gone && kept,
            string(""),
        );
    }

    // ── fixLength ── the smuggling-hardening surface
    {
        // (isResponse, status, method, contentLens, chunked) -> (n, isErr)
        let cases: &[(bool, i64, &'static str, &[&'static str], bool, i64, bool)] = &[
            (true, 200, "GET", &["5"], false, 5, false),
            (true, 200, "HEAD", &["5"], false, 0, false),
            (true, 204, "GET", &["5"], false, 0, false),
            (true, 304, "GET", &["5"], false, 0, false),
            (true, 101, "GET", &["5"], false, 0, false),
            (true, 200, "GET", &[], true, -1, false),
            (true, 200, "GET", &["5"], true, -1, false), // TE beats CL
            (true, 200, "GET", &[], false, -1, false),
            (false, 0, "POST", &["5"], false, 5, false),
            (false, 0, "POST", &[], false, 0, false), // requests default 0
            (false, 0, "POST", &[], true, -1, false),
            (true, 200, "GET", &["5", "5"], false, 5, false), // dup, agrees
            (true, 200, "GET", &["5", " 5 "], false, 5, false), // dup after trim
            (true, 200, "GET", &["5", "6"], false, 0, true), // DISAGREES -> error
            (true, 200, "GET", &["abc"], false, -1, true),
        ];
        let mut bad = string("");
        for (is_resp, st, m, cl, ch, want_n, want_err) in cases {
            let mut h = if cl.is_empty() {
                Header::new()
            } else {
                hdr("Content-Length", cl)
            };
            let (n, err) = fixLength(*is_resp, *st as goish::int, string(*m), &mut h, *ch);
            if n != *want_n || err.IsNil() == *want_err {
                bad = fmt::Sprintf!(
                    "resp=%v st=%d m=%s ch=%v -> n=%d err=%v (want n=%d err=%v)",
                    *is_resp, *st, string(*m), *ch, n, err, *want_n, *want_err
                );
            }
        }
        check("fixLength over 15 cases", bad.Len() == 0, bad);
    }
    // chunked must DELETE Content-Length so the two can't both be honoured
    {
        let mut h = hdr("Content-Length", &["5"]);
        let (n, _) = fixLength(true, 200, string("GET"), &mut h, true);
        check(
            "fixLength deletes Content-Length when chunked (RFC 9112)",
            n == -1 && h.Values(string("Content-Length")).Len() == 0,
            fmt::Sprintf!("n=%d cl_left=%d", n, h.Values(string("Content-Length")).Len() as i64),
        );
    }
    // agreeing duplicates are DEDUPLICATED down to one value
    {
        let mut h = hdr("Content-Length", &["5", " 5 "]);
        let (n, err) = fixLength(true, 200, string("GET"), &mut h, false);
        let vals = h.Values(string("Content-Length"));
        check(
            "fixLength deduplicates agreeing Content-Length headers",
            n == 5 && err.IsNil() && vals.Len() == 1 && vals[0 as goish::int] == "5",
            fmt::Sprintf!("n=%d len=%d", n, vals.Len() as i64),
        );
    }

    // ── fixTrailer ──
    {
        let mut h = hdr("Trailer", &["X-A, x-b"]);
        let (tr, err) = fixTrailer(&mut h, true);
        check(
            "fixTrailer splits and canonicalises a comma list",
            err.IsNil()
                && tr.Len() == 2
                && tr.has(string("X-A"))
                && tr.has(string("X-B"))
                && h.Values(string("Trailer")).Len() == 0,
            fmt::Sprintf!("len=%d err=%v", tr.Len() as i64, err),
        );
    }
    {
        // Trailer without chunking: NOT an error, and the header stays.
        let mut h = hdr("Trailer", &["X-A"]);
        let (tr, err) = fixTrailer(&mut h, false);
        check(
            "fixTrailer: Trailer without chunking is not an error (#27197)",
            err.IsNil() && tr.Len() == 0 && h.Values(string("Trailer")).Len() == 1,
            string(""),
        );
    }
    {
        let mut bad = string("");
        for k in ["Trailer", "Content-Length", "Transfer-Encoding"] {
            let mut h = hdr("Trailer", &[k]);
            let (_, err) = fixTrailer(&mut h, true);
            if err.IsNil() {
                bad = fmt::Sprintf!("%s accepted as a trailer key", string(k));
            }
        }
        check("fixTrailer rejects the three forbidden keys", bad.Len() == 0, bad);
    }

    // ── parseTransferEncoding ── strict and simple, by design
    {
        // (te, major, minor) -> (chunked, isErr, isUnsupportedTE)
        let cases: &[(&[&'static str], i64, i64, bool, bool)] = &[
            (&[], 1, 1, false, false),
            (&["chunked"], 1, 1, true, false),
            (&["Chunked"], 1, 1, true, false), // EqualFold
            (&["CHUNKED"], 1, 1, true, false),
            (&["identity"], 1, 1, false, true),
            (&["chunked", "gzip"], 1, 1, false, true), // too many
            (&["chunked"], 1, 0, false, false),        // ignored on HTTP/1.0
            (&["gzip"], 1, 1, false, true),
        ];
        let mut bad = string("");
        for (te, maj, min, want_chunked, want_err) in cases {
            let h = if te.is_empty() {
                Header::new()
            } else {
                hdr("Transfer-Encoding", te)
            };
            let mut tr = transferReader {
                Header: h,
                StatusCode: 0,
                RequestMethod: string("GET"),
                ProtoMajor: *maj as goish::int,
                ProtoMinor: *min as goish::int,
                Body: None,
                ContentLength: 0,
                Chunked: false,
                Close: false,
                Trailer: Header::new(),
            };
            let err = tr.parseTransferEncoding();
            let is_err = !err.IsNil();
            if tr.Chunked != *want_chunked || is_err != *want_err {
                bad = fmt::Sprintf!("chunked=%v err=%v", tr.Chunked, err);
            }
            // Every error from this function must be an unsupportedTEError.
            if is_err && !isUnsupportedTEError(err.clone()) {
                bad = fmt::Sprintf!("not an unsupportedTEError: %v", err);
            }
        }
        check("parseTransferEncoding over 8 cases", bad.Len() == 0, bad);
    }
    {
        // Go DELETES Transfer-Encoding from the header in every branch,
        // including the HTTP/1.0 ignore path.
        let mut tr = transferReader {
            Header: hdr("Transfer-Encoding", &["chunked"]),
            StatusCode: 0,
            RequestMethod: string("GET"),
            ProtoMajor: 1,
            ProtoMinor: 0,
            Body: None,
            ContentLength: 0,
            Chunked: false,
            Close: false,
            Trailer: Header::new(),
        };
        let _ = tr.parseTransferEncoding();
        check(
            "parseTransferEncoding removes Transfer-Encoding even on HTTP/1.0",
            !tr.Chunked && tr.Header.Values(string("Transfer-Encoding")).Len() == 0,
            string(""),
        );
    }

    // ── transferWriter.shouldSendContentLength ──
    {
        // (method, contentLength, transferEncoding, want)
        let cases: &[(&'static str, i64, &[&'static str], bool)] = &[
            ("GET", 5, &[], true),
            ("GET", 5, &["chunked"], false),   // chunked always wins
            ("GET", 0, &[], false),
            ("GET", 0, &["identity"], false),  // GET/HEAD excluded here
            ("HEAD", 0, &["identity"], false),
            ("POST", 0, &[], true),            // servers expect CL: 0
            ("PUT", 0, &[], true),
            ("PATCH", 0, &[], true),
            ("DELETE", 0, &[], false),         // ...but not DELETE
            ("DELETE", 0, &["identity"], true),// unless identity is set
            ("", 0, &["identity"], true),      // empty method too
            ("POST", -1, &[], false),          // unknown length
        ];
        let mut bad = string("");
        for (m, cl, te, want) in cases {
            let tw = transferWriter {
                Method: string(*m),
                ContentLength: *cl,
                TransferEncoding: strs(te),
            };
            if tw.shouldSendContentLength() != *want {
                bad = fmt::Sprintf!("%s cl=%d -> %v", string(*m), *cl, tw.shouldSendContentLength());
            }
        }
        check("shouldSendContentLength over 12 shapes", bad.Len() == 0, bad);
    }

    // ── body state flags ──
    {
        let b = body::__new();
        check("a fresh body has data remaining and was not closed early",
              b.bodyRemains() && !b.didEarlyClose(), string(""));
        b.__mark_early_close();
        check("didEarlyClose flips, and that is what refuses conn reuse",
              b.didEarlyClose(), string(""));

        let b2 = body::__new();
        static HIT: AtomicUsize = AtomicUsize::new(0);
        b2.registerOnHitEOF(alloc::boxed::Box::new(|| {
            HIT.fetch_add(1, Ordering::Relaxed);
        }));
        b2.__mark_eof();
        b2.__mark_eof();
        check("registerOnHitEOF fires exactly once, and bodyRemains goes false",
              !b2.bodyRemains() && HIT.load(Ordering::Relaxed) == 1,
              fmt::Sprintf!("hits=%d", HIT.load(Ordering::Relaxed) as i64));
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_TRANSFER_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_TRANSFER_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
