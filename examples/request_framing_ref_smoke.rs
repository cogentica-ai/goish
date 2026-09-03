// request_framing_ref_smoke — what does the server accept, and what
// does it say when it refuses?
//
// Reference: Go 1.25.5 net/http, measured by tools/gen_request_framing_ref.go.
// Every GO[] line is Go's verbatim answer to the same byte stream.
//
// These are the request shapes that desync one HTTP hop from another:
// a Content-Length that contradicts itself or a Transfer-Encoding, a
// header name a proxy and a server disagree about, a chunk size that
// is not a number. What matters is not merely that a bad request is
// refused, but that two hops refuse — or accept — the SAME requests.
// A header this server ignores and a proxy in front of it honours is
// how the two come to disagree about where a request ends.
//
// It found one genuine hole and two divergences.
//
// THE HOLE: `Content-Length : 3` — one space before the colon. The
// parser split on the colon and canonicalised the name without ever
// checking that its bytes were token characters, so the name became
// something no lookup matches and the header was SILENTLY IGNORED.
// The request was served with no body and three unread bytes left on
// the connection. A front end that tolerates the space reads a
// 3-byte body; goish read none; the two then disagree about where
// this request ends and the next begins, and those three bytes are
// the start of an attacker-chosen request. Go answers 400 "invalid
// header name" and so does goish now — a request that is not served
// cannot desync.
//
// This mattered more than it would have a week ago. Until read-ahead
// was carried across requests, the leftover bytes were dropped and
// the connection stalled; now they are correctly kept for the next
// request, which is what turns a silently-ignored header from a lost
// request into a parsed one. Making pipelining work raised the price
// of a permissive parser, which is a good reason to have measured the
// two together.
//
// THE STATUS LINE LIED ABOUT THE VERSION. goish answered every
// request "HTTP/1.1", including HTTP/1.0 ones — a version the client
// never offered. Go answers in the version it was asked in.
//
// SILENT CLOSES. Five malformed-framing requests got no response at
// all: the connection just closed. Refusing them is right; refusing
// them without a word leaves the client with a reset and nothing to
// go on. Go answers a plain 400 and now so does goish.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{go, string};

// Go's verbatim output.
const GO: [&str; 14] = [
    "cl+te                n=2 status=HTTP/1.1 200 OK                  body=\"path=/ cl=-1 te=[chunked] body=\\\"\\\"\"",
    "dup-cl-same          n=1 status=HTTP/1.1 200 OK                  body=\"path=/ cl=3 te=[] body=\\\"abc\\\"\"",
    "dup-cl-diff          n=1 status=HTTP/1.1 400 Bad Request         body=\"400 Bad Request\"",
    "cl-list-same         n=1 status=HTTP/1.1 400 Bad Request         body=\"400 Bad Request\"",
    "te-chunked-twice     n=1 status=HTTP/1.1 501 Not Implemented     body=\"Unsupported transfer encoding\"",
    "te-identity          n=1 status=HTTP/1.1 501 Not Implemented     body=\"Unsupported transfer encoding\"",
    "cl-plus              n=1 status=HTTP/1.1 400 Bad Request         body=\"400 Bad Request\"",
    "cl-space             n=1 status=HTTP/1.1 200 OK                  body=\"path=/ cl=3 te=[] body=\\\"abc\\\"\"",
    "cl-hex               n=1 status=HTTP/1.1 400 Bad Request         body=\"400 Bad Request\"",
    "space-before-colon   n=1 status=HTTP/1.1 400 Bad Request: invalid header name body=\"400 Bad Request: invalid header name\"",
    "te-10                n=0 status=HTTP/1.0 200 OK                  body=\"path=/ cl=0 te=[] body=\\\"\\\"\"",
    "chunk-ext            n=1 status=HTTP/1.1 200 OK                  body=\"path=/ cl=-1 te=[chunked] body=\\\"hello\\\"\"",
    // KNOWN GAP, and a deliberate one. Go's line is:
    //   "bad-chunk-size       n=1 status=HTTP/1.1 200 OK                  body=\"\""
    // A chunk-size line of "5x" is not a number. Go runs the handler
    // anyway, hands it an empty body, and closes the connection after.
    // goish refuses the request and closes without answering.
    //
    // Matching Go here would mean serving a request whose body could
    // not be decoded — and if the body cannot be decoded, the server
    // does not know where this request ends and the next one begins.
    // That is precisely the state in which the read-ahead this port
    // now carries across requests (connReader.__pushback) must not be
    // trusted. Closing is the conservative answer to an undecodable
    // frame, so this divergence is left standing on purpose rather
    // than loosened to match.
    "bad-chunk-size       n=0 status=<none>                           body=\"\"",
    "neg-cl               n=1 status=HTTP/1.1 400 Bad Request         body=\"400 Bad Request\"",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            string(GO[i])
        );
    }
}

fn run_case(port: goish::int, label: &'static str, req: &str) {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        chk(fmt::Sprintf!("%-20s dial error: %v", string(label), e));
        return;
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(600 * 1_000_000)));
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
        req.as_bytes().to_vec(),
    ));
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    while out.len() < 4096 {
        let (n, re) = c.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if !re.IsNil() || n == 0 {
            break;
        }
    }
    let _ = c.Close();
    let raw = goish::string::from_bytes(&out);
    let rs: &str = raw.as_ref();
    let status = match rs.find("\r\n") {
        Some(i) if i > 0 => &rs[..i],
        _ => "<none>",
    };
    let nresp = rs.matches("HTTP/1.1 ").count();
    let mut body = "";
    if let Some(i) = rs.find("\r\n\r\n") {
        body = &rs[i + 4..];
        if let Some(j) = body.find("HTTP/1.1 ") {
            body = &body[..j];
        }
    }
    chk(fmt::Sprintf!(
        "%-20s n=%d status=%-32s body=%q",
        string(label),
        nresp as i64,
        goish::string::from_bytes(status.as_bytes()),
        goish::string::from_bytes(body.as_bytes())
    ));
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let mux = http::ServeMux::new();
    mux.HandleFunc("/", move |w, r| {
        let mut b = r.Body.clone();
        let (body, _) = goish::io::ReadAll(&mut b);
        let _ = w.Write(goish::convert::bytes(fmt::Sprintf!(
            "path=%s cl=%d te=%v body=%q",
            r.URL.Path,
            r.ContentLength,
            r.TransferEncoding,
            goish::string::from_bytes(&body)
        )));
    });
    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ..Default::default()
    });
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("listen: %v\n", le);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    {
        let s2 = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s2.Serve(ln);
        });
    }
    time::Sleep(time::Duration(150 * 1_000_000));

    run_case(port, "cl+te", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    run_case(port, "dup-cl-same", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc");
    run_case(port, "dup-cl-diff", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabc");
    run_case(
        port,
        "cl-list-same",
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3, 3\r\nConnection: close\r\n\r\nabc",
    );
    run_case(port, "te-chunked-twice", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n");
    run_case(port, "te-identity", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: identity\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc");
    run_case(
        port,
        "cl-plus",
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +3\r\nConnection: close\r\n\r\nabc",
    );
    run_case(
        port,
        "cl-space",
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3 \r\nConnection: close\r\n\r\nabc",
    );
    run_case(
        port,
        "cl-hex",
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0x3\r\nConnection: close\r\n\r\nabc",
    );
    run_case(
        port,
        "space-before-colon",
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 3\r\nConnection: close\r\n\r\nabc",
    );
    run_case(
        port,
        "te-10",
        "POST / HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    );
    run_case(port, "chunk-ext", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5;foo=bar\r\nhello\r\n0\r\n\r\n");
    run_case(port, "bad-chunk-size", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5x\r\nhello\r\n0\r\n\r\n");
    run_case(
        port,
        "neg-cl",
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\nConnection: close\r\n\r\n",
    );

    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
