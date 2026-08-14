// http_proxy_upgrade_smoke — 101 Switching Protocols through the
// ReverseProxy (the shape of a websocket upgrade).
//
// Full chain under test: client → proxy (HTTP server + hijack) →
// backend (raw TCP speaking HTTP just long enough to say 101). What
// each assertion discriminates:
//
//   * the proxy must RE-ADD Connection/Upgrade after the hop-by-hop
//     strip — the backend refuses the request without them, so the
//     101 never happens if that re-add is missing.
//   * the client-side transport must hand the CONNECTION over as the
//     101 response's body (newReadWriteCloserBody); a client that
//     closes the conn on a bodyless 1xx kills the tunnel silently.
//   * bytes flow BOTH directions after the switch, through both the
//     proxy's hijacked user conn and the dup-split backend carrier —
//     the echo transform ("E:" prefix) proves the bytes crossed the
//     backend, not a short-circuit.
//   * a mismatched Upgrade type from the backend is refused (502),
//     never blindly tunnelled.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

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

/// Raw-TCP backend: HTTP just long enough to answer the upgrade, then
/// an "E:"-prefixing echo. `upgrade_reply` lets the mismatch test lie
/// about the protocol it switched to.
fn spawn_backend(upgrade_reply: &'static str) -> goish::int {
    let (ln, _) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let port = ln.Addr().Port;
    let ln = Arc::new(ln);
    go!(stack(512 * 1024), move || {
        loop {
            let (mut c, e) = ln.Accept();
            if !e.IsNil() {
                return;
            }
            go!(stack(512 * 1024), move || {
                // Read the request head.
                let mut head: Vec<u8> = Vec::new();
                let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5_000_000_000)));
                loop {
                    let mut b = goish::make!([]goish::byte, 512);
                    let (n, re) = c.Read(&mut b);
                    for i in 0..n {
                        head.push(b[i]);
                    }
                    let s = goish::string::from_bytes(&head);
                    if (s.as_ref() as &str).contains("\r\n\r\n") || !re.IsNil() || n == 0 {
                        break;
                    }
                }
                let s = goish::string::from_bytes(&head);
                let sv: &str = s.as_ref();
                if !(sv.to_ascii_lowercase().contains("upgrade: echo")
                    && sv.to_ascii_lowercase().contains("connection: upgrade"))
                {
                    let _ = c.Write(goish::bytes(
                        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
                    ));
                    let _ = c.Close();
                    return;
                }
                let reply = fmt::Sprintf!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: %s\r\nConnection: Upgrade\r\n\r\n",
                    string(upgrade_reply)
                );
                let _ = c.Write(goish::convert::bytes(reply));
                // Post-switch: prefix-echo until the peer goes away.
                loop {
                    let mut b = goish::make!([]goish::byte, 256);
                    let (n, re) = c.Read(&mut b);
                    if n > 0 {
                        let mut out: Vec<u8> = b"E:".to_vec();
                        for i in 0..n {
                            out.push(b[i]);
                        }
                        let _ = c.Write(goish::slice::<goish::byte>::__from_vec(out));
                    }
                    if !re.IsNil() || n == 0 {
                        let _ = c.Close();
                        return;
                    }
                }
            });
        }
    });
    port
}

fn spawn_proxy(backend_port: goish::int) -> goish::int {
    let target = fmt::Sprintf!("http://127.0.0.1:%d", backend_port as i64);
    let (turl, _) = http::url::Parse(target);
    let handler = http::httputil::NewSingleHostReverseProxy(turl);
    let srv = Arc::new(http::Server {
        Handler: handler,
        ReadHeaderTimeout: time::Duration(5_000_000_000),
        ..Default::default()
    });
    let (ln, _) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let port = ln.Addr().Port;
    go!(stack(1024 * 1024), move || {
        let _ = srv.Serve(ln);
    });
    port
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
    // ── the good backend: full upgrade + bidirectional bytes ──
    {
        let bp = spawn_backend("echo");
        let pp = spawn_proxy(bp);
        time::Sleep(time::Duration(200 * 1_000_000));

        let (mut c, e) = net::Dial(string("tcp"), fmt::Sprintf!("127.0.0.1:%d", pp as i64));
        if !e.IsNil() {
            check("dial proxy", false, fmt::Sprintf!("%v", e));
            finish();
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5_000_000_000)));
        let _ = c.Write(goish::bytes(
            "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n",
        ));
        // Read the 101 head.
        let mut head: Vec<u8> = Vec::new();
        loop {
            let mut b = goish::make!([]goish::byte, 512);
            let (n, re) = c.Read(&mut b);
            for i in 0..n {
                head.push(b[i]);
            }
            let s = goish::string::from_bytes(&head);
            if (s.as_ref() as &str).contains("\r\n\r\n") || !re.IsNil() || n == 0 {
                break;
            }
        }
        let hs = goish::string::from_bytes(&head);
        let hv: &str = hs.as_ref();
        check(
            "proxy relays the 101 with the Upgrade header",
            hv.starts_with("HTTP/1.1 101") && hv.to_ascii_lowercase().contains("upgrade: echo"),
            hs.clone(),
        );

        // Speak the switched protocol both ways, twice.
        for (i, msg) in [b"hello".as_ref(), b"again".as_ref()].iter().enumerate() {
            let _ = c.Write(goish::slice::<goish::byte>::__from_vec(msg.to_vec()));
            let mut b = goish::make!([]goish::byte, 64);
            let (n, _) = c.Read(&mut b);
            let got = goish::string::from_bytes(&b.slice(0, n));
            let want = fmt::Sprintf!("E:%s", goish::string::from_bytes(msg));
            check(
                if i == 0 {
                    "bytes cross the tunnel and come back transformed"
                } else {
                    "the tunnel stays up for a second exchange"
                },
                got == want,
                fmt::Sprintf!("got=%q want=%q", got, want),
            );
        }
        let _ = c.Close();
    }

    // ── a backend that switches to the WRONG protocol is refused ──
    {
        let bp = spawn_backend("totally-different");
        let pp = spawn_proxy(bp);
        time::Sleep(time::Duration(200 * 1_000_000));

        let (mut c, e) = net::Dial(string("tcp"), fmt::Sprintf!("127.0.0.1:%d", pp as i64));
        if !e.IsNil() {
            check("dial proxy 2", false, fmt::Sprintf!("%v", e));
            finish();
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5_000_000_000)));
        let _ = c.Write(goish::bytes(
            "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n",
        ));
        let mut b = goish::make!([]goish::byte, 1024);
        let (n, _) = c.Read(&mut b);
        let got = goish::string::from_bytes(&b.slice(0, n));
        check(
            "mismatched backend protocol is refused, not tunnelled",
            (got.as_ref() as &str).contains("502"),
            got,
        );
        let _ = c.Close();
    }

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_PROXY_UPGRADE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_PROXY_UPGRADE_FAIL\n");
    goish::os::Exit(1);
}
