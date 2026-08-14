// http_connreader_limit_smoke — Server.MaxHeaderBytes bounds the WHOLE
// header block through connReader's byte-limited Read.
//
// The discriminating shape: every header LINE is modest (well under
// any per-line cap), but the lines keep coming. Before the connReader
// wiring the per-line check was the only bound, so a client could
// stream unbounded header bytes forever; now the total budget
// (MaxHeaderBytes + 4096 bufio slop, Go's initialReadLimitSize) runs
// dry and the server answers Go's "431 Request Header Fields Too
// Large" and closes. The control case proves an ordinary request on
// the same server still works — the limit lifts for the body and
// resets per request.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::{Closer, Writer};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{bytes, string};

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
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

fn run() -> ! {
    let mux = http::ServeMux::new();
    mux.HandleFunc(string("/"), |w, _r| {
        let _ = w.Write(bytes("hello"));
    });
    let mut srv = http::Server::default();
    srv.Handler = Arc::new(mux);
    srv.MaxHeaderBytes = 8 << 10; // 8 KiB total header budget
    let srv = Arc::new(srv);
    let (ln, _) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let port = ln.Addr().Port;
    {
        let srv = srv.clone();
        goish::go!(stack(1024 * 1024), move || {
            let _ = srv.Serve(ln);
        });
    }
    time::Sleep(time::Duration(100 * 1_000_000));
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);

    // ── control: an ordinary request succeeds under the same cap ──
    {
        let (mut c, e) = net::Dial(string("tcp"), addr.clone());
        check("dial (control)", e.IsNil(), fmt::Sprintf!("%v", e));
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5_000_000_000)));
        let _ = c.Write(bytes("GET / HTTP/1.1\r\nHost: x\r\nX-Small: y\r\n\r\n"));
        let mut b = goish::make!([]goish::byte, 256);
        let (n, _) = goish::io::Reader::Read(&mut c, &mut b);
        let got = goish::string::from_bytes(&b.slice(0, n));
        check(
            "ordinary request under the cap gets 200",
            (got.as_ref() as &str).contains("200"),
            got,
        );
        let _ = c.Close();
    }

    // ── attack shape: modest lines, unbounded total ──
    {
        let (mut c, e) = net::Dial(string("tcp"), addr.clone());
        check("dial (flood)", e.IsNil(), fmt::Sprintf!("%v", e));
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(10_000_000_000)));
        let _ = c.Write(bytes("GET / HTTP/1.1\r\nHost: x\r\n"));
        // ~1 KiB per line, 40 lines = ~40 KiB of headers — every
        // line comfortably under the per-line cap, and few enough
        // lines that the header-COUNT limit can't fire first: the
        // 8 KiB + slop BYTE budget is the only thing that can stop
        // this, around line twelve.
        let line = fmt::Sprintf!(
            "X-Padding-Header-Name: %s\r\n",
            goish::strings::Repeat(string("v"), 1000)
        );
        let mut refused = false;
        let mut acc: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        // Write in batches and poll-read between them: once the
        // server has answered 431 it half-closes and then closes, and
        // a peer that keeps blasting bytes at a closed socket earns an
        // RST that DISCARDS the buffered response — so stop flooding
        // the moment the verdict (or the hangup) shows up.
        'flood: for _ in 0..40 {
            for _ in 0..1 {
                let (_, we) = c.Write(goish::convert::bytes(line.clone()));
                if !we.IsNil() {
                    refused = true;
                    break 'flood;
                }
            }
            let _ = c.SetReadDeadline(time::Now().Add(time::Duration(50 * 1_000_000)));
            let mut b = goish::make!([]goish::byte, 512);
            let (n, re) = goish::io::Reader::Read(&mut c, &mut b);
            for i in 0..n {
                acc.push(b[i]);
            }
            if n > 0 || (!re.IsNil() && !(re.Error().as_ref() as &str).contains("timeout")) {
                break 'flood;
            }
        }
        // Drain whatever else the server said before it closed.
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(2_000_000_000)));
        loop {
            let mut b = goish::make!([]goish::byte, 512);
            let (n, re) = goish::io::Reader::Read(&mut c, &mut b);
            for i in 0..n {
                acc.push(b[i]);
            }
            if !re.IsNil() || n == 0 {
                break;
            }
        }
        let reply = goish::string::from_bytes(&acc);
        let rv: &str = reply.as_ref();
        check(
            "header flood is refused with Go's 431",
            rv.contains("431 Request Header Fields Too Large") || refused,
            reply.clone(),
        );
        // The connection must be DEAD afterwards — Connection: close
        // semantics, not a desynced keep-alive.
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(1_000_000_000)));
        let _ = c.Write(bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        let mut b = goish::make!([]goish::byte, 64);
        let (n2, _) = goish::io::Reader::Read(&mut c, &mut b);
        check(
            "the flooded connection is closed, not reused",
            n2 == 0,
            fmt::Sprintf!("read %d bytes after 431", n2 as i64),
        );
        let _ = c.Close();
    }

    // ── and the server still serves AFTER surviving the flood ──
    {
        let (mut c, e) = net::Dial(string("tcp"), addr.clone());
        check("dial (after flood)", e.IsNil(), fmt::Sprintf!("%v", e));
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5_000_000_000)));
        let _ = c.Write(bytes("GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        let mut b = goish::make!([]goish::byte, 256);
        let (n, _) = goish::io::Reader::Read(&mut c, &mut b);
        let got = goish::string::from_bytes(&b.slice(0, n));
        check(
            "server still serves fresh conns after the flood",
            (got.as_ref() as &str).contains("200"),
            got,
        );
        let _ = c.Close();
    }

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("HTTP_CONNREADER_LIMIT_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_CONNREADER_LIMIT_FAIL (%d)\n", f as i64);
    goish::os::Exit(1);
}
