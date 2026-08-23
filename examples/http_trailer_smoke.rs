// http_trailer_smoke — HTTP/1.1 response trailers on the server path.
//
// Reads the RAW bytes off a real socket, because the whole point is
// what lands after the terminating `0\r\n` chunk. Before this the
// server wrote a bare `0\r\n\r\n` and every trailer a handler set was
// silently dropped.
//
// Expected behaviour is Go 1.25.5's, taken from scripts/goref.sh
// against the real net/http. The subtle part: a key declared through
// the `Trailer` response header goes through ValidTrailerHeader and is
// DROPPED if RFC 7230 §4.1.2 forbids it, but a key set through the
// `Trailer:` magic prefix bypasses that check entirely. Go really does
// emit `Content-Length` as a trailer when you ask via the prefix.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{go, string};

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
    mux.HandleFunc("/t", |w, _r| {
        // Two valid names, two the RFC forbids in trailers.
        w.Header().Set(
            string("Trailer"),
            string("X-Sum, X-Bad, Content-Type, If-Match"),
        );
        w.WriteHeader(200);
        let _ = w.Write(goish::bytes("hello"));
        // Flush promotes to chunked and writes the head; trailers are
        // set AFTER, which is the whole point of a trailer.
        if let (f, true) = goish::cast!(w, http::Flusher) {
            f.Flush();
        }
        w.Header().Set(string("X-Sum"), string("42"));
        w.Header().Set(string("X-Bad"), string("nope"));
        w.Header()
            .Set(string("Content-Type"), string("should-not-appear"));
        w.Header()
            .Set(string("If-Match"), string("should-not-appear"));
        // The magic-prefix route, which does NOT go through
        // ValidTrailerHeader — Go emits these even when forbidden.
        w.Header().Set(
            fmt::Sprintf!("%sX-Late", string(goish::net::http::server::TrailerPrefix)),
            string("late-value"),
        );
        w.Header().Set(
            fmt::Sprintf!(
                "%sContent-Length",
                string(goish::net::http::server::TrailerPrefix)
            ),
            string("bad"),
        );
    });

    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
        ..Default::default()
    });
    let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !lerr.IsNil() {
        check("listen", false, fmt::Sprintf!("%v", lerr));
        finish();
    }
    let port = ln.Addr().Port;
    {
        let s = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s.Serve(ln);
        });
    }
    time::Sleep(time::Duration(150 * 1_000_000));

    // Raw request, raw response.
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        check("dial", false, fmt::Sprintf!("%v", e));
        finish();
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
        b"GET /t HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".to_vec(),
    ));
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    loop {
        let (n, re) = c.Read(&mut buf);
        for i in 0..n {
            raw.push(buf[i]);
        }
        if !re.IsNil() || n == 0 {
            break;
        }
    }
    let _ = c.Close();
    let wire = goish::string::from_bytes(&raw);
    let w: &str = wire.as_ref();

    check(
        "response is chunked and carries the body",
        w.contains("Transfer-Encoding: chunked") && w.contains("hello"),
        wire.clone(),
    );

    // Everything after the terminating zero-length chunk.
    let tail = match w.find("\r\n0\r\n") {
        None => "",
        Some(i) => &w[i + 5..],
    };
    check(
        "a terminating 0-chunk is present",
        !tail.is_empty() || w.contains("\r\n0\r\n"),
        wire.clone(),
    );

    check(
        "trailers declared via the Trailer header are emitted",
        tail.contains("X-Sum: 42") && tail.contains("X-Bad: nope"),
        goish::string::from_bytes(tail.as_bytes()),
    );

    check(
        "ValidTrailerHeader drops RFC-forbidden declared trailers",
        !tail.contains("should-not-appear"),
        goish::string::from_bytes(tail.as_bytes()),
    );

    check(
        "the Trailer: magic prefix bypasses the deny-list (Go's behaviour)",
        tail.contains("X-Late: late-value") && tail.contains("Content-Length: bad"),
        goish::string::from_bytes(tail.as_bytes()),
    );

    check(
        "the prefixed keys are not ALSO emitted in the head",
        !w[..w.find("\r\n\r\n").unwrap_or(0)].contains("Trailer:X-Late"),
        wire.clone(),
    );

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_TRAILER_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_TRAILER_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
