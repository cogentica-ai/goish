// http_hijack_smoke — http.Hijacker: a handler takes the connection
// away from the server and speaks its own protocol on it.
//
// This is what a websocket upgrade is made of, and the contract is
// entirely about OWNERSHIP:
//
//   * after Hijack, the server must not write to, close, or read from
//     the connection. If it closed it, the handler's socket would die
//     under it; if it kept reading, it would steal the peer's bytes.
//   * whatever the handler wrote BEFORE hijacking must already be on
//     the wire — Go flushes at Hijack for exactly this.
//   * deadlines are cleared. They were the server's policy for
//     serving one request; a long-lived hijacked conn never agreed to
//     them, and would die at the first idle moment.
//   * a second Hijack is ErrHijacked, not a second copy of the fd.
//
// The test speaks a tiny line protocol over the hijacked conn AFTER
// the handler returns, which is the part that cannot work unless the
// ownership transfer is real.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::errors;
use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{go, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);
static SECOND_HIJACK: AtomicI64 = AtomicI64::new(-1);
/// Set when the server reports StateHijacked for the connection.
static SAW_HIJACKED_STATE: AtomicI64 = AtomicI64::new(0);

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

    mux.HandleFunc("/upgrade", |w, _r| {
        // Written BEFORE the hijack: it has to reach the client.
        w.Header().Set(string("X-Before"), string("1"));
        let _ = w.Write(goish::bytes("switching\n"));

        let (cn, ok) = goish::cast!(w, http::Hijacker);
        if !ok {
            return;
        }
        let (mut conn, err) = cn.Hijack();
        if !err.IsNil() {
            return;
        }
        // A second Hijack must fail rather than hand out the fd twice.
        let (_, err2) = cn.Hijack();
        SECOND_HIJACK.store(
            if errors::Is(err2, http::ErrHijacked) { 1 } else { 0 },
            Ordering::Relaxed,
        );

        // Now speak a private protocol on the conn the server no
        // longer owns. Deliberately AFTER a pause, so a server that
        // closed the conn on handler return would have killed it.
        go!(stack(512 * 1024), move || {
            // Longer than the server's 1s WriteTimeout on purpose. Note
            // what this does and does not prove: the conn is still
            // alive well past the window the server would have given
            // it. It does NOT discriminate the deadline CLEAR — goish
            // consults a write deadline only when the write would
            // block, and five bytes into an empty socket buffer never
            // do. The clear is still right (Go does it, and a hijacked
            // conn never agreed to the server's policy), it is just
            // not what this assertion catches.
            time::Sleep(time::Duration(1300 * 1_000_000));
            let _ = conn.Write(goish::bytes("PING\n"));
            let mut buf = goish::make!([]goish::byte, 64);
            let (n, _) = conn.Read(&mut buf);
            let got = goish::string::from_bytes(&buf.slice(0, n));
            if (got.as_ref() as &str).contains("PONG") {
                let _ = conn.Write(goish::bytes("BYE\n"));
            }
            let _ = conn.Close();
        });
    });

    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
        // A short write timeout the hijacked conn must NOT inherit.
        WriteTimeout: time::Duration(1 * 1_000_000_000),
        ..Default::default()
    });
    // StateHijacked is reported ONLY by the serve loop's post-handler
    // hijack check. The ownership transfer alone would leave the loop
    // to discover a dead conn and report Idle — the states are how the
    // two are told apart.
    srv.SetConnState(Some(Arc::new(
        |_fd: goish::types::int, cs: http::server::ConnState| {
            if cs == http::server::StateHijacked {
                SAW_HIJACKED_STATE.store(1, Ordering::Relaxed);
            }
        },
    )));

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

    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        check("dial", false, fmt::Sprintf!("%v", e));
        finish();
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
    let _ = c.Write(goish::bytes("GET /upgrade HTTP/1.1\r\nHost: x\r\n\r\n"));

    // Read everything the connection produces: the pre-hijack response
    // AND the private protocol that follows on the same socket.
    let mut raw: Vec<u8> = Vec::new();
    let mut ponged = false;
    let deadline = time::Now().Add(time::Duration(5 * 1_000_000_000));
    loop {
        let mut buf = goish::make!([]goish::byte, 1024);
        let (n, re) = c.Read(&mut buf);
        for i in 0..n {
            raw.push(buf[i]);
        }
        let sofar = goish::string::from_bytes(&raw);
        let s: &str = sofar.as_ref();
        if !ponged && s.contains("PING") {
            let _ = c.Write(goish::bytes("PONG\n"));
            ponged = true;
        }
        if s.contains("BYE") || !re.IsNil() || n == 0 || time::Now().After(deadline) {
            break;
        }
    }
    let _ = c.Close();
    let wire = goish::string::from_bytes(&raw);
    let w: &str = wire.as_ref();

    check(
        "bytes written before the hijack still reach the client",
        w.contains("X-Before: 1") && w.contains("switching"),
        wire.clone(),
    );
    check(
        "the handler owns the conn after ServeHTTP returns",
        w.contains("PING") && ponged,
        wire.clone(),
    );
    check(
        "the hijacked conn outlives the server's WriteTimeout",
        w.contains("BYE"),
        wire,
    );
    check(
        "the server reports StateHijacked, not StateIdle",
        SAW_HIJACKED_STATE.load(Ordering::Relaxed) == 1,
        string(""),
    );
    check(
        "a second Hijack returns ErrHijacked",
        SECOND_HIJACK.load(Ordering::Relaxed) == 1,
        fmt::Sprintf!("state=%d", SECOND_HIJACK.load(Ordering::Relaxed)),
    );

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_HIJACK_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_HIJACK_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
