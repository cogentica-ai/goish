// http_expect_continue_smoke — the client half of Expect: 100-continue
// (persistConn.waitForContinue + the sequential interim-peek feeder).
//
// What each case discriminates:
//
//   * against a goish server (which emits the interim 100 before the
//     eager body read): the body is HELD until the 100 arrives, then
//     sent — the handler sees the full body and the client the 200;
//   * a server that answers a FINAL response instead of 100 (417 on
//     the Expect) must get NO body bytes — the client skips the body
//     and surfaces the 417; a client that blasts the body anyway
//     desyncs the connection;
//   * a silent server (never answers the Expect) gets the body after
//     ExpectContinueTimeout — the request still completes, and the
//     elapsed time proves the wait actually happened.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{bytes, go, string};

static FAILED: AtomicUsize = AtomicUsize::new(0);
/// Bytes the raw backend saw AFTER the request head's blank line.
static BODY_BYTES_SEEN: AtomicUsize = AtomicUsize::new(0);
/// Backend mode: true → answer 417 immediately; false → stay silent
/// on the Expect, then serve whatever arrives.
static REFUSE: AtomicBool = AtomicBool::new(false);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

/// Raw backend: reads one request head; in REFUSE mode answers 417
/// without touching the body; otherwise NEVER sends a 100, waits for
/// the body (which must only arrive after the client's timeout),
/// echoes its length, and closes.
fn spawn_backend() -> goish::int {
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
                let mut acc: Vec<u8> = Vec::new();
                let _ = c.SetReadDeadline(time::Now().Add(time::Duration(10_000_000_000)));
                let head_end;
                loop {
                    let mut b = goish::make!([]goish::byte, 512);
                    let (n, re) = c.Read(&mut b);
                    for i in 0..n {
                        acc.push(b[i]);
                    }
                    let s = goish::string::from_bytes(&acc);
                    if let Some(i) = (s.as_ref() as &str).find("\r\n\r\n") {
                        head_end = i + 4;
                        break;
                    }
                    if !re.IsNil() || n == 0 {
                        let _ = c.Close();
                        return;
                    }
                }
                if REFUSE.load(Ordering::SeqCst) {
                    // A final response instead of the interim 100.
                    let _ = c.Write(bytes(
                        "HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n",
                    ));
                    // Watch briefly for body bytes that must not come.
                    let _ = c.SetReadDeadline(
                        time::Now().Add(time::Duration(400 * 1_000_000)),
                    );
                    let mut b = goish::make!([]goish::byte, 256);
                    let (n, _) = c.Read(&mut b);
                    BODY_BYTES_SEEN
                        .fetch_add((acc.len() - head_end) + n as usize, Ordering::SeqCst);
                    let _ = c.Close();
                    return;
                }
                // Silent on the Expect: read the Content-Length body
                // (it should only arrive after the client's wait).
                let hs = goish::string::from_bytes(&acc[..head_end]);
                let hv: &str = hs.as_ref();
                let cl: usize = hv
                    .to_ascii_lowercase()
                    .find("content-length:")
                    .map(|i| {
                        hv[i + 15..]
                            .trim_start()
                            .chars()
                            .take_while(|c| c.is_ascii_digit())
                            .collect::<alloc::string::String>()
                            .parse()
                            .unwrap_or(0)
                    })
                    .unwrap_or(0);
                let mut body: Vec<u8> = acc[head_end..].to_vec();
                while body.len() < cl {
                    let mut b = goish::make!([]goish::byte, 512);
                    let (n, re) = c.Read(&mut b);
                    for i in 0..n {
                        body.push(b[i]);
                    }
                    if !re.IsNil() || n == 0 {
                        break;
                    }
                }
                let reply = fmt::Sprintf!(
                    "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s",
                    body.len() as i64,
                    goish::string::from_bytes(&body)
                );
                let _ = c.Write(goish::convert::bytes(reply));
                let _ = c.Close();
            });
        }
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
    // ── 1. a goish server answers 100; the held body then flows ──
    {
        let seen = Arc::new(goish::sync::Mutex::new(goish::string::new()));
        let mux = http::ServeMux::new();
        {
            let seen = seen.clone();
            mux.HandleFunc(string("/up"), move |w, r| {
                let (b, _) = goish::io::ReadAll(&mut r.Body.clone());
                *seen.Lock() = goish::string::from_bytes(&b);
                let _ = w.Write(bytes("got it"));
            });
        }
        let ts = http::httptest::NewServer(Arc::new(mux));
        let mut client = http::Client::default();
        let mut tr = http::Transport::default();
        tr.ExpectContinueTimeout = time::Duration(2_000_000_000);
        client.Transport = Arc::new(tr);
        let (mut req, _) = http::NewRequest(
            string("POST"),
            ts.URL() + string("/up"),
            bytes("expect-me"),
        );
        req.Header.Set(string("Expect"), string("100-continue"));
        let (mut resp, err) = client.Do(&req);
        if err.IsNil() {
            let _ = resp.Body.Close();
        }
        check(
            "100 from a goish server releases the held body",
            err.IsNil() && (*seen.Lock()).clone() == "expect-me",
            fmt::Sprintf!("err=%v seen=%q", err, (*seen.Lock()).clone()),
        );
        ts.Close();
    }

    let port = spawn_backend();
    time::Sleep(time::Duration(100 * 1_000_000));
    let url = fmt::Sprintf!("http://127.0.0.1:%d/x", port as i64);
    // Fresh client (fresh pool) per case: the backend closes its conn
    // after each exchange, and a dead pooled conn under a
    // non-replayable POST surfaces the write error — in Go too.
    let mk_client = || {
        let mut c = http::Client::default();
        let mut tr = http::Transport::default();
        tr.ExpectContinueTimeout = time::Duration(300 * 1_000_000);
        c.Transport = Arc::new(tr);
        c
    };

    // ── 2. a final 417 instead of 100: the body is never sent ──
    {
        REFUSE.store(true, Ordering::SeqCst);
        let client = mk_client();
        let (mut req, _) =
            http::NewRequest(string("POST"), url.clone(), bytes("must-not-arrive"));
        req.Header.Set(string("Expect"), string("100-continue"));
        let (resp, err) = client.Do(&req);
        time::Sleep(time::Duration(600 * 1_000_000)); // let the backend's watch window close
        check(
            "417 instead of 100: status surfaces and NO body bytes were sent",
            err.IsNil()
                && resp.StatusCode == 417
                && BODY_BYTES_SEEN.load(Ordering::SeqCst) == 0,
            fmt::Sprintf!(
                "err=%v status=%d leaked=%d",
                err,
                resp.StatusCode,
                BODY_BYTES_SEEN.load(Ordering::SeqCst) as i64
            ),
        );
        REFUSE.store(false, Ordering::SeqCst);
    }

    // ── 3. a silent server: the body goes after ExpectContinueTimeout ──
    {
        let client = mk_client();
        let started = time::Now();
        let (mut req, _) =
            http::NewRequest(string("POST"), url.clone(), bytes("after-timeout"));
        req.Header.Set(string("Expect"), string("100-continue"));
        let (mut resp, err) = client.Do(&req);
        let elapsed = time::Now().Sub(started);
        let mut echoed = goish::string::new();
        if err.IsNil() {
            let (b, _) = goish::io::ReadAll(&mut resp.Body);
            echoed = goish::string::from_bytes(&b);
            let _ = resp.Body.Close();
        }
        check(
            "a silent server gets the body after the timeout, request completes",
            err.IsNil() && echoed == "after-timeout" && elapsed.0 >= 250 * 1_000_000,
            fmt::Sprintf!("err=%v echo=%q elapsed=%v", err, echoed, elapsed),
        );
    }

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("HTTP_EXPECT_CONTINUE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_EXPECT_CONTINUE_FAIL (%d)\n", f as i64);
    goish::os::Exit(1);
}
