// http_transferwriter_smoke — the transfer.go write machinery:
// newTransferWriter's framing decisions, the 200ms body probe, chunked
// request encoding, trailers, the ContentLength-mismatch guard, and
// Response.Write's zero-or-unknown probe.
//
// What each assertion discriminates:
//
//   * a streaming request body with unknown length MUST go out
//     `Transfer-Encoding: chunked` and arrive intact — a client that
//     silently sends no body (the pre-port behavior for a non-eager
//     Body) passes nothing else in this file;
//   * a GET with a non-nil but EMPTY streaming body sends NO body and
//     NO Transfer-Encoding at all (Go issue 18257: zero-byte chunked
//     GETs confuse servers) — this is the probe's fast-EOF arm;
//   * a GET whose streaming body has bytes ready sends them chunked —
//     the probe's fast-byte arm, and the probed byte must not be lost
//     or reordered;
//   * a body that only becomes readable AFTER 200ms still arrives
//     complete — the probe's timeout arm hands the pending byte to
//     finishAsyncByteRead; losing it corrupts the first chunk;
//   * ContentLength=5 with a 3-byte body is a hard error naming both
//     numbers, not a silently short body;
//   * a chunked request carries its Trailer: announcement in the head
//     and the trailer values after the last chunk;
//   * Response.Write probes a ContentLength==0 body: empty stays
//     empty, non-empty flips to unknown length + Connection: close.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::fmt;
use goish::io::{self, Closer};
use goish::net::http;
use goish::sync::Mutex;
use goish::time;
use goish::{bytes, go, string};

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

fn wire_for(req: &http::Request) -> goish::string {
    let mut buf = goish::bytes::Buffer::new();
    let err = req.Write(&mut buf);
    if !err.IsNil() {
        return fmt::Sprintf!("WRITE-ERR:%v", err);
    }
    goish::string::from_bytes(&buf.Bytes())
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

fn run() -> ! {
    // ── 1. streaming POST body → chunked upload through a real server ──
    {
        let seen_body = Arc::new(Mutex::new(goish::string::new()));
        let seen_cl = Arc::new(AtomicI64::new(-999));
        let mux = http::ServeMux::new();
        {
            let b_h = seen_body.clone();
            let cl_h = seen_cl.clone();
            mux.HandleFunc(string("/up"), move |w, r| {
                let (body, _) = io::ReadAll(&mut r.Body.clone());
                *b_h.Lock() = goish::string::from_bytes(&body);
                cl_h.store(r.ContentLength, Ordering::SeqCst);
                let _ = w.Write(bytes("ok"));
            });
        }
        let ts = http::httptest::NewServer(Arc::new(mux));

        let (pr, mut pw) = io::Pipe();
        go!(stack(256 * 1024), move || {
            let _ = pw.Write(bytes("streamed "));
            time::Sleep(time::Duration(50 * 1_000_000));
            let _ = pw.Write(bytes("request body"));
            let _ = pw.Close();
        });
        let (mut req, _) = http::NewRequest(string("POST"), ts.URL() + string("/up"), goish::nil);
        req.Body = http::Body::from_reader(alloc::boxed::Box::new(pr));
        req.ContentLength = -1;
        let client = http::Client::default();
        let (mut resp, err) = client.Do(&req);
        check(
            "streaming POST body arrives intact",
            err.IsNil() && (*seen_body.Lock()).clone() == "streamed request body",
            fmt::Sprintf!("err=%v body=%q", err, (*seen_body.Lock()).clone()),
        );
        check(
            "server saw it as chunked (ContentLength -1)",
            seen_cl.load(Ordering::SeqCst) == -1,
            fmt::Sprintf!("cl=%d", seen_cl.load(Ordering::SeqCst)),
        );
        if err.IsNil() {
            let _ = resp.Body.Close();
        }
        ts.Close();
    }

    // ── 2. probe fast-EOF: GET with empty streaming body sends none ──
    {
        let (pr, pw) = io::Pipe();
        let _ = pw.Close(); // empty: first probe read answers EOF
        let (mut req, _) =
            http::NewRequest(string("GET"), string("http://x.test/probe"), goish::nil);
        req.Body = http::Body::from_reader(alloc::boxed::Box::new(pr));
        req.ContentLength = -1;
        let wire = wire_for(&req);
        let wv: &str = wire.as_ref();
        check(
            "empty probed GET body: no Transfer-Encoding on the wire",
            !wv.contains("Transfer-Encoding") && wv.ends_with("\r\n\r\n"),
            wire.clone(),
        );
    }

    // ── 3. probe fast-byte: GET with ready bytes goes chunked ──
    {
        let (pr, mut pw) = io::Pipe();
        go!(stack(256 * 1024), move || {
            let _ = pw.Write(bytes("hi"));
            let _ = pw.Close();
        });
        time::Sleep(time::Duration(50 * 1_000_000)); // let the byte land
        let (mut req, _) =
            http::NewRequest(string("GET"), string("http://x.test/probe"), goish::nil);
        req.Body = http::Body::from_reader(alloc::boxed::Box::new(pr));
        req.ContentLength = -1;
        let wire = wire_for(&req);
        let wv: &str = wire.as_ref();
        // The probed byte always travels as its own 1-byte chunk
        // (Go's CopyBuffer sees the MultiReader's first read return 1
        // byte); the pipe's remainder follows in its own chunk.
        check(
            "non-empty probed GET body: chunked, probed byte preserved",
            wv.contains("Transfer-Encoding: chunked")
                && wv.contains("1\r\nh\r\n")
                && wv.contains("1\r\ni\r\n")
                && wv.ends_with("0\r\n\r\n"),
            wire.clone(),
        );
    }

    // ── 4. probe timeout: late body still arrives complete ──
    {
        let (pr, mut pw) = io::Pipe();
        go!(stack(256 * 1024), move || {
            // Past the 200ms probe window.
            time::Sleep(time::Duration(400 * 1_000_000));
            let _ = pw.Write(bytes("late payload"));
            let _ = pw.Close();
        });
        let (mut req, _) =
            http::NewRequest(string("GET"), string("http://x.test/probe"), goish::nil);
        req.Body = http::Body::from_reader(alloc::boxed::Box::new(pr));
        req.ContentLength = -1;
        let wire = wire_for(&req);
        let wv: &str = wire.as_ref();
        // Same 1-byte-first-chunk shape: the async probe byte 'l'
        // arrives alone, then the pipe's remaining "ate payload".
        check(
            "probe-timeout body: chunked and complete (async byte not lost)",
            wv.contains("Transfer-Encoding: chunked")
                && wv.contains("1\r\nl\r\n")
                && wv.contains("ate payload\r\n")
                && wv.ends_with("0\r\n\r\n"),
            wire.clone(),
        );
    }

    // ── 5. ContentLength / body-length mismatch is a hard error ──
    {
        let (mut req, _) =
            http::NewRequest(string("POST"), string("http://x.test/short"), bytes("abc"));
        req.ContentLength = 5;
        let mut buf = goish::bytes::Buffer::new();
        let err = req.Write(&mut buf);
        check(
            "ContentLength=5 with 3-byte body is refused, naming both",
            !err.IsNil()
                && (err.Error().as_ref() as &str)
                    .contains("ContentLength=5 with Body length 3"),
            fmt::Sprintf!("err=%v", err),
        );
    }

    // ── 6. chunked request Trailer: announced in head, sent after body ──
    {
        let (mut req, _) =
            http::NewRequest(string("POST"), string("http://x.test/tr"), bytes("payload"));
        req.TransferEncoding = goish::slice::<goish::string>::__from_vec(alloc::vec![string(
            "chunked"
        )]);
        req.ContentLength = 0;
        req.Trailer = http::Header::new();
        req.Trailer.Set(string("X-Checksum"), string("abc123"));
        let wire = wire_for(&req);
        let wv: &str = wire.as_ref();
        let head_end = wv.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
        let (head, tail) = wv.split_at(head_end);
        check(
            "Trailer announced in head, value after the last chunk",
            head.contains("Trailer: X-Checksum")
                && !head.contains("abc123")
                && tail.contains("7\r\npayload\r\n0\r\n")
                && tail.contains("X-Checksum: abc123"),
            wire.clone(),
        );
    }

    // ── 7. Response.Write probes a zero-ContentLength body ──
    {
        // Empty body: stays empty, explicit Content-Length: 0.
        let mut resp = http::Response::default();
        resp.StatusCode = 200;
        resp.ProtoMajor = 1;
        resp.ProtoMinor = 1;
        let mut buf = goish::bytes::Buffer::new();
        let err = resp.Write(&mut buf);
        let wire = goish::string::from_bytes(&buf.Bytes());
        let wv: &str = wire.as_ref();
        check(
            "Response.Write: empty body → Content-Length: 0",
            err.IsNil() && wv.starts_with("HTTP/1.1 200 OK\r\n") && wv.contains("Content-Length: 0"),
            wire.clone(),
        );

        // Non-empty body with ContentLength unset: probed → unknown
        // length → close-delimited (Connection: close, no CL header).
        let mut resp = http::Response::default();
        resp.StatusCode = 200;
        resp.ProtoMajor = 1;
        resp.ProtoMinor = 1;
        resp.Body = http::Body::from_bytes(bytes("surprise body"));
        let mut buf = goish::bytes::Buffer::new();
        let err = resp.Write(&mut buf);
        let wire = goish::string::from_bytes(&buf.Bytes());
        let wv: &str = wire.as_ref();
        check(
            "Response.Write: unknown-length body → Connection: close + full body",
            err.IsNil()
                && wv.contains("Connection: close")
                && !wv.contains("Content-Length")
                && wv.ends_with("surprise body"),
            wire.clone(),
        );
    }

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("HTTP_TRANSFERWRITER_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_TRANSFERWRITER_FAIL (%d)\n", f as i64);
    goish::os::Exit(1);
}
