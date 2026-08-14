// http_client_reuse_smoke — client-side keep-alive: the idle pool
// actually reuses connections.
//
// The server here is raw TCP so the ACCEPT COUNT is ground truth:
//
//   * three sequential GETs (body read + closed each time) must ride
//     ONE connection — a dial-per-request client shows 3 accepts;
//   * a body that is closed EARLY (unread remainder) must NOT be
//     pooled — reusing a desynced conn smuggles the stale bytes into
//     the next response — so the next request dials fresh;
//   * when the server closes the idle conn, the next request must
//     transparently retry on a fresh dial (Go shouldRetryRequest via
//     pc.isReused) — not surface an EOF to the caller;
//   * Transport.DisableKeepAlives = true restores dial-per-request.

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
static ACCEPTS: AtomicUsize = AtomicUsize::new(0);
/// When set, the per-conn loop hangs up after one response.
static CLOSE_AFTER_ONE: AtomicBool = AtomicBool::new(false);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

/// Raw keep-alive HTTP server: answers every request on a conn with a
/// fixed 22-byte body until the peer goes away (or CLOSE_AFTER_ONE).
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
            ACCEPTS.fetch_add(1, Ordering::SeqCst);
            go!(stack(512 * 1024), move || {
                loop {
                    // Read one request head.
                    let mut head: Vec<u8> = Vec::new();
                    let _ = c.SetReadDeadline(
                        time::Now().Add(time::Duration(10_000_000_000)),
                    );
                    loop {
                        let mut b = goish::make!([]goish::byte, 512);
                        let (n, re) = c.Read(&mut b);
                        for i in 0..n {
                            head.push(b[i]);
                        }
                        let s = goish::string::from_bytes(&head);
                        if (s.as_ref() as &str).contains("\r\n\r\n") || !re.IsNil() || n == 0
                        {
                            break;
                        }
                    }
                    if head.is_empty() {
                        let _ = c.Close();
                        return;
                    }
                    // A request body (Content-Length) is read and
                    // ECHOED — the rewind tripwire below asserts the
                    // replayed body arrived intact on the retry conn.
                    let hs = goish::string::from_bytes(&head);
                    let hv: &str = hs.as_ref();
                    let mut req_body: Vec<u8> = Vec::new();
                    if let Some(ci) = hv.to_ascii_lowercase().find("content-length:") {
                        let cl: usize = hv[ci + 15..]
                            .trim_start()
                            .chars()
                            .take_while(|c| c.is_ascii_digit())
                            .collect::<alloc::string::String>()
                            .parse()
                            .unwrap_or(0);
                        let delim = hv.find("\r\n\r\n").map(|i| i + 4).unwrap_or(head.len());
                        req_body.extend_from_slice(&head[delim..]);
                        while req_body.len() < cl {
                            let mut b = goish::make!([]goish::byte, 256);
                            let (n, re) = c.Read(&mut b);
                            for i in 0..n {
                                req_body.push(b[i]);
                            }
                            if !re.IsNil() || n == 0 {
                                break;
                            }
                        }
                    }
                    if req_body.is_empty() {
                        let _ = c.Write(bytes(
                            "HTTP/1.1 200 OK\r\nContent-Length: 22\r\n\r\nthis is the reply body",
                        ));
                    } else {
                        let reply = fmt::Sprintf!(
                            "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s",
                            req_body.len() as i64,
                            goish::string::from_bytes(&req_body)
                        );
                        let _ = c.Write(goish::convert::bytes(reply));
                    }
                    if CLOSE_AFTER_ONE.load(Ordering::SeqCst) {
                        let _ = c.Close();
                        return;
                    }
                }
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
    let port = spawn_backend();
    time::Sleep(time::Duration(100 * 1_000_000));
    let url = fmt::Sprintf!("http://127.0.0.1:%d/x", port as i64);

    // ── 1. three sequential GETs ride one connection ──
    {
        let client = http::Client::default();
        for i in 0..3 {
            let (mut resp, err) = client.Do(&{
                let (r, _) = http::NewRequest(string("GET"), url.clone(), goish::nil);
                r
            });
            if !err.IsNil() {
                check("sequential GET succeeds", false, fmt::Sprintf!("i=%d %v", i as i64, err));
                break;
            }
            let (body, _) = goish::io::ReadAll(&mut resp.Body);
            let _ = resp.Body.Close();
            if body.Len() != 22 {
                check("body intact", false, fmt::Sprintf!("len=%d", body.Len() as i64));
            }
        }
        check(
            "three sequential GETs ride ONE connection",
            ACCEPTS.load(Ordering::SeqCst) == 1,
            fmt::Sprintf!("accepts=%d", ACCEPTS.load(Ordering::SeqCst) as i64),
        );

        // ── 2. an early-closed body poisons the conn: next dials fresh ──
        let (mut resp, err) = client.Do(&{
            let (r, _) = http::NewRequest(string("GET"), url.clone(), goish::nil);
            r
        });
        check("request before early close", err.IsNil(), fmt::Sprintf!("%v", err));
        // Close WITHOUT reading: 22 unread bytes on the wire.
        let _ = resp.Body.Close();
        let before = ACCEPTS.load(Ordering::SeqCst);
        let (mut resp, err) = client.Do(&{
            let (r, _) = http::NewRequest(string("GET"), url.clone(), goish::nil);
            r
        });
        if err.IsNil() {
            let (body, _) = goish::io::ReadAll(&mut resp.Body);
            let _ = resp.Body.Close();
            check(
                "after an early close the next request dials FRESH and reads clean",
                ACCEPTS.load(Ordering::SeqCst) == before + 1 && body.Len() == 22,
                fmt::Sprintf!(
                    "accepts %d -> %d, body=%d",
                    before as i64,
                    ACCEPTS.load(Ordering::SeqCst) as i64,
                    body.Len() as i64
                ),
            );
        } else {
            check("after an early close the next request dials FRESH and reads clean",
                  false, fmt::Sprintf!("%v", err));
        }

        // ── 3. server closes the idle conn: retry is transparent ──
        CLOSE_AFTER_ONE.store(true, Ordering::SeqCst);
        // This response poisons nothing (fully read), but the server
        // hangs up right after it — the conn goes back to the pool
        // already dead.
        let (mut resp, err) = client.Do(&{
            let (r, _) = http::NewRequest(string("GET"), url.clone(), goish::nil);
            r
        });
        if err.IsNil() {
            let (_b, _) = goish::io::ReadAll(&mut resp.Body);
            let _ = resp.Body.Close();
        }
        CLOSE_AFTER_ONE.store(false, Ordering::SeqCst);
        time::Sleep(time::Duration(100 * 1_000_000));
        let (mut resp, err) = client.Do(&{
            let (r, _) = http::NewRequest(string("GET"), url.clone(), goish::nil);
            r
        });
        if err.IsNil() {
            let (body, _) = goish::io::ReadAll(&mut resp.Body);
            let _ = resp.Body.Close();
            check(
                "a server-closed idle conn is retried transparently",
                body.Len() == 22,
                fmt::Sprintf!("body=%d", body.Len() as i64),
            );
        } else {
            check(
                "a server-closed idle conn is retried transparently",
                false,
                fmt::Sprintf!("%v", err),
            );
        }
    }

    // ── 3b. a retried request REPLAYS its body (rewindBody/GetBody) ──
    {
        let client = http::Client::default();
        // Prime a pooled conn, then have the server kill it after the
        // next response: the POST-shaped follow-up lands on a dead
        // conn, retries, and must resend the FULL body — a client
        // that reuses the consumed body sends an empty one and the
        // echo comes back short (or the write errors on
        // ContentLength/body mismatch).
        CLOSE_AFTER_ONE.store(true, Ordering::SeqCst);
        let (mut resp, err) = client.Do(&{
            let (r, _) = http::NewRequest(string("GET"), url.clone(), goish::nil);
            r
        });
        if err.IsNil() {
            let (_b, _) = goish::io::ReadAll(&mut resp.Body);
            let _ = resp.Body.Close();
        }
        CLOSE_AFTER_ONE.store(false, Ordering::SeqCst);
        time::Sleep(time::Duration(100 * 1_000_000));
        // GET so shouldRetryRequest's isReplayable arm passes; the
        // body still exercises the rewind (GetBody replay).
        let (req, _) =
            http::NewRequest(string("GET"), url.clone(), bytes("replay-me-exactly"));
        let (mut resp, err) = client.Do(&req);
        if err.IsNil() {
            let (body, _) = goish::io::ReadAll(&mut resp.Body);
            let _ = resp.Body.Close();
            check(
                "a retried request replays its body via GetBody",
                goish::string::from_bytes(&body) == "replay-me-exactly",
                fmt::Sprintf!("echo=%q", goish::string::from_bytes(&body)),
            );
        } else {
            check(
                "a retried request replays its body via GetBody",
                false,
                fmt::Sprintf!("%v", err),
            );
        }
    }

    // ── 4. DisableKeepAlives restores dial-per-request ──
    {
        let before = ACCEPTS.load(Ordering::SeqCst);
        let mut client = http::Client::default();
        let mut tr = http::Transport::default();
        tr.DisableKeepAlives = true;
        client.Transport = Arc::new(tr);
        for _ in 0..2 {
            let (mut resp, err) = client.Do(&{
                let (r, _) = http::NewRequest(string("GET"), url.clone(), goish::nil);
                r
            });
            if err.IsNil() {
                let (_b, _) = goish::io::ReadAll(&mut resp.Body);
                let _ = resp.Body.Close();
            }
        }
        check(
            "DisableKeepAlives dials per request",
            ACCEPTS.load(Ordering::SeqCst) == before + 2,
            fmt::Sprintf!(
                "accepts %d -> %d",
                before as i64,
                ACCEPTS.load(Ordering::SeqCst) as i64
            ),
        );
    }

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("HTTP_CLIENT_REUSE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_CLIENT_REUSE_FAIL (%d)\n", f as i64);
    goish::os::Exit(1);
}
