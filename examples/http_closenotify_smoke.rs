// http_closenotify_smoke — http.CloseNotifier over a real socket.
//
// CloseNotify is deprecated in Go in favour of the request context,
// but the two are driven by the SAME event here (Go's
// handleReadErrorLocked cancels the context and calls closeNotify
// together), so this also pins that they agree.
//
// What the test actually forces:
//
//   * the channel fires when the peer goes away MID-HANDLER. A
//     handler that finishes first would prove nothing — the whole
//     point is learning about the disconnect while still working.
//   * a handler that is never disconnected does NOT receive. A
//     CloseNotify that fires spuriously would have every long handler
//     abandoning work for a client that is still waiting.
//   * calling CloseNotify after ServeHTTP has returned PANICS, as Go
//     does: the channel could never fire, so handing one back would
//     be handing back a wait that never ends.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{go, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);
/// -1 = handler never ran, 0 = ran and saw no disconnect, 1 = notified.
static NOTIFIED: AtomicI64 = AtomicI64::new(-1);
static CTX_DONE: AtomicI64 = AtomicI64::new(-1);
static QUIET_NOTIFIED: AtomicI64 = AtomicI64::new(-1);

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

fn run() -> ! {
    let mux = http::ServeMux::new();

    // A handler that waits for the client to go away.
    mux.HandleFunc("/watch", |w, r| {
        let (cn, ok) = goish::cast!(w, http::CloseNotifier);
        if !ok {
            NOTIFIED.store(-2, Ordering::Relaxed);
            return;
        }
        let ch = cn.CloseNotify();
        let deadline = time::Now().Add(time::Duration(3 * 1_000_000_000));
        loop {
            match ch.__try_recv() {
                Some(_) => {
                    NOTIFIED.store(1, Ordering::Relaxed);
                    break;
                }
                None => {
                    if time::Now().After(deadline) {
                        NOTIFIED.store(0, Ordering::Relaxed);
                        break;
                    }
                    goish::runtime::sched::Gosched();
                }
            }
        }
        // The request context must agree — Go fires both from the same
        // read error.
        CTX_DONE.store(
            if r.Context().Err() != goish::nil { 1 } else { 0 },
            Ordering::Relaxed,
        );
        let _ = w.Write(goish::bytes("done"));
    });

    // A handler that is NOT disconnected: the channel must stay quiet.
    mux.HandleFunc("/quiet", |w, _r| {
        let (cn, ok) = goish::cast!(w, http::CloseNotifier);
        if !ok {
            QUIET_NOTIFIED.store(-2, Ordering::Relaxed);
            return;
        }
        let ch = cn.CloseNotify();
        let until = time::Now().Add(time::Duration(400 * 1_000_000));
        let mut fired = 0;
        while !time::Now().After(until) {
            if ch.__try_recv().is_some() {
                fired = 1;
                break;
            }
            goish::runtime::sched::Gosched();
        }
        QUIET_NOTIFIED.store(fired, Ordering::Relaxed);
        let _ = w.Write(goish::bytes("quiet"));
    });

    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ReadHeaderTimeout: time::Duration(5 * 1_000_000_000),
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

    // ── the peer hangs up while the handler is still running ──
    {
        let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
        let (mut c, e) = net::Dial(string("tcp"), addr);
        if !e.IsNil() {
            check("dial", false, fmt::Sprintf!("%v", e));
            finish();
        }
        let _ = c.Write(goish::bytes("GET /watch HTTP/1.1\r\nHost: x\r\n\r\n"));
        // Let the handler reach its CloseNotify wait, then vanish.
        time::Sleep(time::Duration(200 * 1_000_000));
        let _ = c.Close();

        let deadline = time::Now().Add(time::Duration(5 * 1_000_000_000));
        while NOTIFIED.load(Ordering::Relaxed) < 0 && !time::Now().After(deadline) {
            time::Sleep(time::Duration(20 * 1_000_000));
        }
        check(
            "CloseNotify fires when the client goes away mid-handler",
            NOTIFIED.load(Ordering::Relaxed) == 1,
            fmt::Sprintf!("state=%d (-2=no CloseNotifier, 0=timed out)", NOTIFIED.load(Ordering::Relaxed)),
        );
        check(
            "the request context is canceled by the same event",
            CTX_DONE.load(Ordering::Relaxed) == 1,
            fmt::Sprintf!("ctx=%d", CTX_DONE.load(Ordering::Relaxed)),
        );
    }

    // ── a client that stays put must not trigger it ──
    {
        let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
        let (mut c, e) = net::Dial(string("tcp"), addr);
        if !e.IsNil() {
            check("dial 2", false, fmt::Sprintf!("%v", e));
            finish();
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
        let _ = c.Write(goish::bytes(
            "GET /quiet HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ));
        let mut buf = goish::make!([]goish::byte, 1024);
        let (n, _) = c.Read(&mut buf);
        let reply = goish::string::from_bytes(&buf.slice(0, n));
        let _ = c.Close();
        check(
            "a connected client does not trigger CloseNotify",
            QUIET_NOTIFIED.load(Ordering::Relaxed) == 0
                && (reply.as_ref() as &str).contains("quiet"),
            fmt::Sprintf!("state=%d", QUIET_NOTIFIED.load(Ordering::Relaxed)),
        );
    }

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_CLOSENOTIFY_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_CLOSENOTIFY_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
