// http_readtimeout_body_smoke — Server.ReadTimeout must bound a slow
// BODY, not just the headers.
//
// Go documents ReadTimeout as "the maximum duration for reading the
// entire request, including the body". A client that sends its headers
// promptly and then dribbles the body is the slow-body form of
// slowloris: the headers arrive inside every header timeout, and only
// a bound on the whole request stops the connection being held open.
//
// goish bounds it. The deadline armed for the request is still in
// force when the body is read, because goish reads the body eagerly
// inside the request parse rather than handing the handler a stream.
//
// THE OUTCOME DIFFERS FROM GO, and that is the point of pinning both
// rows. Measured, ReadTimeout 500ms against a body dribbled over 1.5s:
//
//   Go     handler RUNS, its ReadAll returns read=2 and an i/o timeout
//   goish  handler NEVER RUNS, and nothing is written back
//
// Neither is a security hole — the connection is bounded either way,
// which is what this smoke exists to guard. The difference follows
// from the eager body: Go calls the handler as soon as the headers
// parse and lets it discover the truncation, while in goish the read
// fails before a handler exists to be told. Making goish match would
// mean a streaming request body, which is an architectural decision
// recorded in the ROADMAP rather than something to change here.
//
// The prompt-body row is the control, and it DOES match Go exactly: a
// body that arrives on time is read whole with no error. Without it,
// a "fix" that simply refused every request with a body would look
// green.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, Ordering};
use goish::goslice::slice;
use goish::gostring::string;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::types::{byte, int};
use goish::{fmt, go, time};

static HANDLER_RUNS: AtomicI64 = AtomicI64::new(0);
static BYTES_READ: AtomicI64 = AtomicI64::new(0);

#[goish::main]
fn main() {
    go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn probe(slow: bool) -> (i64, i64, usize) {
    HANDLER_RUNS.store(0, Ordering::Release);
    BYTES_READ.store(0, Ordering::Release);

    let mux = http::ServeMux::new();
    mux.HandleFunc(string::from("/"), move |w, r| {
        HANDLER_RUNS.fetch_add(1, Ordering::AcqRel);
        let mut body = r.Body.clone();
        let (b, _err) = goish::io::ReadAll(&mut body);
        BYTES_READ.store(goish::len(&b) as i64, Ordering::Release);
        let _ = w.Write(goish::convert::bytes(string::from("ok")));
    });
    let mut srv = http::Server::default();
    srv.Handler = Arc::new(mux) as Arc<dyn http::Handler>;
    srv.ReadTimeout = time::Millisecond * 500;
    let srv = Arc::new(srv);

    let (l, lerr) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
    if !lerr.IsNil() {
        fmt::Printf!("[!!] listen: %v\n", lerr);
        goish::os::Exit(1);
    }
    let addr = l.Addr().String();
    let s2 = srv.clone();
    go!(stack(512 * 1024), move || {
        let _ = s2.Serve(l);
    });
    time::Sleep(time::Millisecond * 50);

    let (mut c, derr) = net::Dial(string::from("tcp"), addr);
    if !derr.IsNil() {
        fmt::Printf!("[!!] dial: %v\n", derr);
        goish::os::Exit(1);
    }
    let _ = c.Write(goish::convert::bytes(string::from(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n",
    )));
    if slow {
        let _ = c.Write(goish::convert::bytes(string::from("01")));
        // Well past ReadTimeout.
        time::Sleep(time::Millisecond * 1500);
        let _ = c.Write(goish::convert::bytes(string::from("23456789")));
    } else {
        let _ = c.Write(goish::convert::bytes(string::from("0123456789")));
    }

    let _ = c.SetReadDeadline(time::Now().Add(time::Second * 2));
    let mut acc: Vec<u8> = Vec::new();
    let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 256]);
    loop {
        let (n, e) = c.Read(&mut buf);
        if n > 0 {
            acc.extend_from_slice(&buf.as_ref()[..n as usize]);
        }
        if n <= 0 || !e.IsNil() {
            break;
        }
    }
    let _ = c.Close();
    let _ = srv.Close();
    return (
        HANDLER_RUNS.load(Ordering::Acquire),
        BYTES_READ.load(Ordering::Acquire),
        acc.len(),
    );
}

fn run() {
    let mut bad = 0;

    // The security property: a dribbled body must not hold the
    // connection past ReadTimeout. goish refuses before the handler.
    let (runs, read, reply) = probe(true);
    if runs == 0 && reply == 0 {
        fmt::Printf!("ok   slow-body   bounded: handler never ran, nothing written back\n");
    } else {
        fmt::Printf!(
            "[!!] slow-body   handler_runs=%d read=%d reply_bytes=%d — the slow body was NOT bounded\n",
            runs, read, reply as int
        );
        bad += 1;
    }

    // The control, which matches Go exactly.
    let (runs, read, reply) = probe(false);
    if runs == 1 && read == 10 && reply > 0 {
        fmt::Printf!("ok   prompt-body handler ran, read=10, answered\n");
    } else {
        fmt::Printf!(
            "[!!] prompt-body handler_runs=%d read=%d reply_bytes=%d, want 1/10/>0\n",
            runs, read, reply as int
        );
        bad += 1;
    }

    if bad == 0 {
        fmt::Printf!("\nok 2/2\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d\n", bad as int);
    goish::os::Exit(1);
}
