// http_dumpout_ref_smoke — httputil.DumpRequestOut against Go 1.25.5.
//
// DumpRequestOut's contract is that it shows what the TRANSPORT would
// put on the wire, not what the caller built: "It includes any headers
// that the standard http.Transport adds, such as User-Agent." Go gets
// that by round-tripping through a fake conn; goish serialises
// directly, so anything the transport adds has to be reproduced here
// or the dump misreports the wire.
//
// Two things this pins, both of which were wrong until measured:
//
//   * Accept-Encoding: gzip. goish's transport adds it (client.rs
//     roundTrip) and the dump did not show it, while a comment in
//     dump.rs asserted the transport "does not add Accept-Encoding".
//     It goes in LAST, after Content-Length and the caller's headers,
//     because Go carries it in extraHeaders — and a caller-set EMPTY
//     Accept-Encoding therefore yields TWO lines, since extraHeaders
//     appends rather than displaces.
//   * The dump must not CONSUME the request. Go drains and restores
//     (drainBody); goish did not, so a second dump failed with
//     "ContentLength=2 with nil Body" and a caller who dumped before
//     sending sent an empty body.
//
// GO[] below is Go's own output, transcribed from the bytes of a
// `go run` against /usr/local/go (1.25.5), not retyped.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http;
use goish::string;

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

/// Go 1.25.5  output, in case order.
static GO: [&str; 6] = [
    // plain
    "GET /p HTTP/1.1\r\nHost: e.com\r\nUser-Agent: Go-http-client/1.1\r\nAccept-Encoding: gzip\r\n\r\n",
    // ae-identity
    "GET /p HTTP/1.1\r\nHost: e.com\r\nUser-Agent: Go-http-client/1.1\r\nAccept-Encoding: identity\r\n\r\n",
    // ae-empty
    "GET /p HTTP/1.1\r\nHost: e.com\r\nUser-Agent: Go-http-client/1.1\r\nAccept-Encoding: \r\nAccept-Encoding: gzip\r\n\r\n",
    // head
    "HEAD /p HTTP/1.1\r\nHost: e.com\r\nUser-Agent: Go-http-client/1.1\r\n\r\n",
    // range
    "GET /p HTTP/1.1\r\nHost: e.com\r\nUser-Agent: Go-http-client/1.1\r\nRange: bytes=0-1\r\n\r\n",
    // post-xa
    "POST /x HTTP/1.1\r\nHost: e.com\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: 2\r\nX-A: 1\r\nAccept-Encoding: gzip\r\n\r\nhi",
];

static NAMES: [&str; 6] = [
    "plain", "ae-identity", "ae-empty", "head", "range", "post-xa",
];

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s
", string(name));
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s
", string(name), detail);
    }
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

fn mk(method: &'static str, url: &'static str, body: &'static str) -> http::Request {
    let (r, _) = http::NewRequest(
        string(method),
        string(url),
        if body.is_empty() {
            goish::goslice::slice::new()
        } else {
            goish::bytes(body)
        },
    );
    return r;
}

fn run() {
    let mut reqs: alloc::vec::Vec<(http::Request, bool)> = alloc::vec::Vec::new();

    reqs.push((mk("GET", "http://e.com/p", ""), false));

    let mut r2 = mk("GET", "http://e.com/p", "");
    r2.Header.Set(string("Accept-Encoding"), string("identity"));
    reqs.push((r2, false));

    let mut r3 = mk("GET", "http://e.com/p", "");
    r3.Header.Set(string("Accept-Encoding"), string(""));
    reqs.push((r3, false));

    reqs.push((mk("HEAD", "http://e.com/p", ""), false));

    let mut r5 = mk("GET", "http://e.com/p", "");
    r5.Header.Set(string("Range"), string("bytes=0-1"));
    reqs.push((r5, false));

    let mut r6 = mk("POST", "http://e.com/x", "hi");
    r6.Header.Set(string("X-A"), string("1"));
    reqs.push((r6, true));

    let mut i = 0usize;
    while i < reqs.len() {
        let (req, body) = &reqs[i];
        let (b, e) = http::httputil::DumpRequestOut(req, *body);
        let got = goish::string::from_bytes(&b);
        check(
            NAMES[i],
            e.IsNil() && got == string(GO[i]),
            fmt::Sprintf!("err=%v got=%q want=%q", e, got, string(GO[i])),
        );
        i += 1;
    }

    // The dump must leave the request usable: Go drains and restores,
    // so dumping twice gives the same bytes both times.
    let mut r7 = mk("POST", "http://e.com/x", "hi");
    r7.Header.Set(string("X-A"), string("1"));
    let (d1, _) = http::httputil::DumpRequestOut(&r7, true);
    let (d2, e2) = http::httputil::DumpRequestOut(&r7, true);
    check(
        "a dump does not consume the request body",
        e2.IsNil()
            && goish::string::from_bytes(&d1) == string(GO[5])
            && goish::string::from_bytes(&d2) == string(GO[5]),
        fmt::Sprintf!(
            "err=%v d1=%q d2=%q",
            e2,
            goish::string::from_bytes(&d1),
            goish::string::from_bytes(&d2)
        ),
    );

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("
%d passed, %d failed
", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_DUMPOUT_REF_SMOKE_OK
");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_DUMPOUT_REF_SMOKE_FAIL
");
    goish::os::Exit(1);
}
