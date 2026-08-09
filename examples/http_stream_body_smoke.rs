// http_stream_body_smoke — Response.Body is a *streaming* reader
// (Go's `Body io.ReadCloser` shape), not a pre-drained slice.
//
// The QuCode motivation: an LLM client must render SSE tokens as they
// arrive. That requires `resp.Body.Read` to return data the moment a
// flushed chunk lands, while the server is still mid-response.
//
// Subtests (deterministic — a gate chan proves the ordering; no
// sleep-based races):
//
//   1. chunked streaming: handler writes "first|" + Flush, then parks
//      on a gate chan. The client's first Body.Read MUST return
//      "first|" while the handler is still parked (the pre-streaming
//      client drained the whole body inside RoundTrip — with the
//      handler parked on the gate that deadlocks, and the e2e timeout
//      flags it). Client then closes the gate, reads "second|" + EOF.
//   2. content-length body: ReadAll(Body) == full body, then EOF.
//   3. ctx cancel mid-body: handler writes "part1" + Flush and parks
//      on r.Context().Done(); client cancels, next Read errors.
//
// Pass criteria: all subtests print PASS; final "ok" line.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::io::{self, Closer, Reader};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{bytes, fmt, go, make, nil, string, syscall};

static SERVER_PAST_GATE: AtomicUsize = AtomicUsize::new(0);

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn slice_eq(got: &goish::goslice::slice<u8>, want: &[u8]) -> bool {
    if got.Len() != want.len() as i64 {
        return false;
    }
    for i in 0..want.len() {
        if got[i as i64] != want[i] {
            return false;
        }
    }
    true
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let gate = make!(chan (), 0);

    // ── routes ───────────────────────────────────────────────────
    let mux = http::ServeMux::new();
    {
        let gate_h = gate.clone();
        mux.HandleFunc(string("/stream"), move |w, _r| {
            let (f, ok) = goish::cast!(w, http::Flusher);
            let _ = w.Write(bytes("first|"));
            if ok {
                f.Flush();
            }
            // Park until the client has provably read chunk 1.
            let _ = (gate_h).Recv();
            SERVER_PAST_GATE.store(1, Ordering::Release);
            let _ = w.Write(bytes("second|"));
        });
    }
    mux.HandleFunc(string("/fixed"), |w, _r| {
        let _ = w.Write(bytes("hello, streaming world"));
    });
    mux.HandleFunc(string("/stall"), move |w, r| {
        let (f, ok) = goish::cast!(w, http::Flusher);
        let _ = w.Write(bytes("part1"));
        if ok {
            f.Flush();
        }
        // Park until the client goes away (disconnect cancels r.Context()).
        let ctx = r.Context();
        let _ = (ctx.Done()).Recv();
    });

    let mux_arc: Arc<dyn http::Handler> = Arc::new(mux);
    let mut srv = http::Server::default();
    srv.Handler = mux_arc;
    let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !err.IsNil() {
        die(b"http_stream_body: Listen failed\n");
    }
    let addr = ln.Addr().String();
    let srv_arc = Arc::new(srv);
    let srv_serve = srv_arc.clone();
    go!(move || {
        let _ = srv_serve.Serve(ln);
    });
    time::Sleep(time::Millisecond * 20);

    // ── 1. chunked streaming with happens-before proof ───────────
    {
        let url = fmt::Sprintf!("http://%s/stream", addr.clone());
        let (mut resp, err) = http::Get(url);
        if !err.IsNil() {
            fmt::Println!("[ 1] chunked streaming         FAIL Get err");
            failed += 1;
        } else {
            let mut ok = resp.StatusCode == 200 && resp.ContentLength == -1;

            // First read: must surface "first|" while the handler is
            // still parked on the gate.
            let mut dst = make!([]u8, 64);
            let (n, rerr) = resp.Body.Read(&mut dst);
            let first = dst.slice(0, n);
            if !(rerr.IsNil() && slice_eq(&first, b"first|")) {
                fmt::Println!("[ 1] chunked streaming         FAIL first read n={}", n);
                ok = false;
            }
            if SERVER_PAST_GATE.load(Ordering::Acquire) != 0 {
                fmt::Println!("[ 1] chunked streaming         FAIL server past gate before first read returned");
                ok = false;
            }

            // Release the handler; drain the rest.
            gate.Close();
            let (rest, aerr) = io::ReadAll(&mut resp.Body);
            if !(aerr.IsNil() && slice_eq(&rest, b"second|")) {
                fmt::Println!("[ 1] chunked streaming         FAIL rest read");
                ok = false;
            }
            // Post-EOF read: (0, EOF).
            let (n2, e2) = resp.Body.Read(&mut dst);
            if !(n2 == 0 && goish::errors::Is(e2, io::EOF)) {
                fmt::Println!("[ 1] chunked streaming         FAIL post-EOF read");
                ok = false;
            }
            let _ = resp.Body.Close();
            if ok {
                fmt::Println!("[ 1] chunked streaming         PASS");
            } else {
                failed += 1;
            }
        }
    }

    // ── 2. content-length body via ReadAll ───────────────────────
    {
        let url = fmt::Sprintf!("http://%s/fixed", addr.clone());
        let (mut resp, err) = http::Get(url);
        if !err.IsNil() {
            fmt::Println!("[ 2] content-length ReadAll    FAIL Get err");
            failed += 1;
        } else {
            let mut ok = resp.StatusCode == 200 && resp.ContentLength == 22;
            let (body, aerr) = io::ReadAll(&mut resp.Body);
            if !(aerr.IsNil() && slice_eq(&body, b"hello, streaming world")) {
                fmt::Println!("[ 2] content-length ReadAll    FAIL body");
                ok = false;
            }
            let _ = resp.Body.Close();
            if ok {
                fmt::Println!("[ 2] content-length ReadAll    PASS");
            } else {
                failed += 1;
            }
        }
    }

    // ── 3. ctx cancel interrupts a blocked Body.Read ─────────────
    {
        let url = fmt::Sprintf!("http://%s/stall", addr.clone());
        let (ctx, cancel) = goish::context::WithCancel(goish::context::Background());
        let (req, rerr) = http::NewRequestWithContext(ctx, string("GET"), url, nil);
        if !rerr.IsNil() {
            fmt::Println!("[ 3] ctx cancel mid-body       FAIL NewRequest err");
            failed += 1;
        } else {
            let client = http::Client::default();
            let (mut resp, err) = client.Do(&req);
            if !err.IsNil() {
                fmt::Println!("[ 3] ctx cancel mid-body       FAIL Do err");
                failed += 1;
            } else {
                let mut ok = true;
                let mut dst = make!([]u8, 64);
                let (n, e1) = resp.Body.Read(&mut dst);
                let part = dst.slice(0, n);
                if !(e1.IsNil() && slice_eq(&part, b"part1")) {
                    fmt::Println!("[ 3] ctx cancel mid-body       FAIL first read");
                    ok = false;
                }
                // Cancel from another goroutine after this read parks.
                // (Cancel is level-triggered: even if it fires before
                // the Read parks, the past-deadline slam is sticky.)
                go!(move || {
                    time::Sleep(time::Millisecond * 10);
                    cancel();
                });
                let (_n2, e2) = resp.Body.Read(&mut dst);
                if e2.IsNil() {
                    fmt::Println!("[ 3] ctx cancel mid-body       FAIL read after cancel returned nil err");
                    ok = false;
                }
                let _ = resp.Body.Close();
                if ok {
                    fmt::Println!("[ 3] ctx cancel mid-body       PASS");
                } else {
                    failed += 1;
                }
            }
        }
    }

    let _ = srv_arc.Shutdown(time::Second);

    if failed != 0 {
        die(b"http_stream_body_smoke: FAILED\n");
    }
    const OK: &[u8] = b"http_stream_body_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
