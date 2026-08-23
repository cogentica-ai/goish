// http_transport_loops_smoke — persistConn's readLoop/writeLoop/
// wroteRequest driven over their real channel protocol (spawned by
// __spawn_loops on a dup-split TCP conn; roundTrip integration is
// staged, so this smoke IS the caller).
//
// What each case discriminates:
//
//   * a full round trip through the loops: writeRequest in on
//     writech, response out on the requestAndChan — the body read
//     concurrently with the WRITER goroutine still alive; after a
//     clean body close the hand-back BANKS the conn (the idle pool
//     must hold it), and wroteRequest reported the write ok;
//   * Expect: 100-continue THROUGH the loops: readLoop parses the
//     interim 100 and feeds writeLoop's continue channel — the body
//     is only written after the server's 100 (the raw backend
//     enforces ordering by refusing early bytes);
//   * a server that hangs up instead of answering: the error arrives
//     on the response channel, and the persistConn records a close
//     reason (readLoop's peek-fail classification).

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
use goish::net::http::transport::{
    connectMethodKey, persistConn, requestAndChan, responseAndError, wantConn, writeRequest,
};
use goish::time;
use goish::{bytes, go, string};

static FAILED: AtomicUsize = AtomicUsize::new(0);
/// Backend behavior knobs.
static SEND_100: AtomicBool = AtomicBool::new(false);
static HANG_UP: AtomicBool = AtomicBool::new(false);
/// Set when the backend saw body bytes BEFORE it sent its 100.
static EARLY_BODY: AtomicBool = AtomicBool::new(false);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

/// Raw backend: one exchange per conn. Reads the head; optionally
/// hangs up; optionally sends an interim 100 (checking no body bytes
/// arrived first); reads a Content-Length body; echoes it.
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
                if HANG_UP.load(Ordering::SeqCst) {
                    let _ = c.Close();
                    return;
                }
                if SEND_100.load(Ordering::SeqCst) {
                    if acc.len() > head_end {
                        EARLY_BODY.store(true, Ordering::SeqCst);
                    }
                    let _ = c.Write(bytes("HTTP/1.1 100 Continue\r\n\r\n"));
                }
                let hs = goish::string::from_bytes(&acc[..head_end]);
                let hv: &str = hs.as_ref();
                let cl: usize = hv
                    .to_ascii_lowercase()
                    .find("content-length:")
                    .map(|i| {
                        hv[i + 15..]
                            .trim_start()
                            .chars()
                            .take_while(|ch| ch.is_ascii_digit())
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
                // Keep the conn open so a banked reuse could read on;
                // the test tears it down.
                time::Sleep(time::Duration(2_000_000_000));
                let _ = c.Close();
            });
        }
    });
    port
}

/// Dial + build a persistConn + spawn its loops, banking into `t`'s
/// idle pool. Returns (pc, loops).
fn dial_pc(
    t: &Arc<http::Transport>,
    addr: goish::string,
) -> (Arc<persistConn>, goish::net::http::transport::pcLoops) {
    let (conn, e) = net::Dial(string("tcp"), addr.clone());
    if !e.IsNil() {
        fmt::Printf!("dial failed: %v\n", e);
        goish::os::Exit(1);
    }
    let key = connectMethodKey {
        proxy: string::new(),
        scheme: string("http"),
        addr,
        onlyH1: false,
    };
    let pc = Arc::new(persistConn::__new(key));
    pc.__put_src(goish::net::http::client::ConnSrc::Tcp(
        goish::bufio::NewReader(conn),
    ));
    let t2 = t.clone();
    let bank: Arc<
        dyn Fn(&Arc<persistConn>, goish::net::http::client::ConnSrc) -> bool + Send + Sync,
    > = Arc::new(move |pc, src| {
        pc.__put_src(src);
        return t2.tryPutIdleConn(pc).IsNil();
    });
    let (loops, le) = pc.__spawn_loops(time::Duration(2_000_000_000), bank);
    if !le.IsNil() {
        fmt::Printf!("spawn_loops failed: %v\n", le);
        goish::os::Exit(1);
    }
    (pc, loops.unwrap())
}

fn make_parts(
    url: goish::string,
    body: goish::slice<goish::byte>,
    expect: bool,
) -> (
    goish::slice<goish::byte>,
    goish::net::http::transfer::transferWriter,
    http::Request,
) {
    let (mut req, _) = http::NewRequest(string("POST"), url, body);
    if expect {
        req.Header.Set(string("Expect"), string("100-continue"));
    }
    let host = req.URL.Host.clone();
    let (head, tw, serr) = http::client::serialize_request_head(&req, &host, false);
    if !serr.IsNil() {
        fmt::Printf!("serialize failed: %v\n", serr);
        goish::os::Exit(1);
    }
    (head, tw, req)
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
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let url = fmt::Sprintf!("http://%s/x", addr);

    // ── 1. full round trip; clean body close banks the conn ──
    {
        let t = Arc::new(http::Transport::default());
        let (pc, loops) = dial_pc(&t, addr.clone());
        let (head, tw, req) = make_parts(url.clone(), bytes("loop-me"), false);

        let wr_ch: goish::gochan::chan<goish::error> = goish::make!(chan goish::error, 1);
        let _ = loops.writech.Send(writeRequest {
            head,
            tw,
            ch: wr_ch.clone(),
            continueCh: None,
        });
        let resc: goish::gochan::chan<responseAndError> = goish::make!(chan responseAndError, 1);
        let _ = loops.reqch.Send(requestAndChan {
            req: Some(req),
            ch: resc.clone(),
            continueCh: None,
        });

        let (rae, _) = resc.Recv();
        let (werr, _) = wr_ch.Recv();
        let mut ok = rae.err.IsNil() && werr.IsNil();
        let mut echoed = goish::string::new();
        if let Some(mut resp) = rae.res {
            let (b, _) = goish::io::ReadAll(&mut resp.Body);
            echoed = goish::string::from_bytes(&b);
            let _ = resp.Body.Close();
            ok = ok && resp.StatusCode == 200;
        } else {
            ok = false;
        }
        check(
            "a round trip flows through writeLoop + readLoop",
            ok && echoed == "loop-me",
            fmt::Sprintf!("err=%v write=%v echo=%q", rae.err, werr, echoed),
        );

        // The clean close must have BANKED the conn.
        time::Sleep(time::Duration(100 * 1_000_000));
        let w = Arc::new(wantConn::__new());
        w.__set_key(pc.cacheKey.clone());
        let delivered = t.queueForIdleConn(&w);
        check(
            "the clean body close banked the conn into the idle pool",
            delivered
                && w.__delivered()
                    .map(|d| Arc::ptr_eq(&d, &pc))
                    .unwrap_or(false),
            fmt::Sprintf!("delivered=%v", delivered),
        );
        if let Some(d) = w.__delivered() {
            d.close(goish::errors::New(string("test teardown")));
        }
    }

    // ── 2. Expect: 100-continue THROUGH the loops ──
    {
        SEND_100.store(true, Ordering::SeqCst);
        let t = Arc::new(http::Transport::default());
        let (_pc, loops) = dial_pc(&t, addr.clone());
        let (head, tw, req) = make_parts(url.clone(), bytes("after-100"), true);

        let continue_ch: goish::gochan::chan<bool> = goish::make!(chan bool, 1);
        let wr_ch: goish::gochan::chan<goish::error> = goish::make!(chan goish::error, 1);
        let _ = loops.writech.Send(writeRequest {
            head,
            tw,
            ch: wr_ch.clone(),
            continueCh: Some(continue_ch.clone()),
        });
        let resc: goish::gochan::chan<responseAndError> = goish::make!(chan responseAndError, 1);
        let _ = loops.reqch.Send(requestAndChan {
            req: Some(req),
            ch: resc.clone(),
            continueCh: Some(continue_ch),
        });

        let (rae, _) = resc.Recv();
        let mut echoed = goish::string::new();
        if let Some(mut resp) = rae.res {
            let (b, _) = goish::io::ReadAll(&mut resp.Body);
            echoed = goish::string::from_bytes(&b);
            let _ = resp.Body.Close();
        }
        check(
            "readLoop's interim 100 releases writeLoop's held body",
            rae.err.IsNil() && echoed == "after-100" && !EARLY_BODY.load(Ordering::SeqCst),
            fmt::Sprintf!(
                "err=%v echo=%q early=%v",
                rae.err,
                echoed,
                EARLY_BODY.load(Ordering::SeqCst)
            ),
        );
        SEND_100.store(false, Ordering::SeqCst);
    }

    // ── 3. a hang-up instead of a response surfaces on the channel ──
    {
        HANG_UP.store(true, Ordering::SeqCst);
        let t = Arc::new(http::Transport::default());
        let (pc, loops) = dial_pc(&t, addr.clone());
        let (head, tw, req) = make_parts(url.clone(), bytes("doomed"), false);
        let wr_ch: goish::gochan::chan<goish::error> = goish::make!(chan goish::error, 1);
        let _ = loops.writech.Send(writeRequest {
            head,
            tw,
            ch: wr_ch.clone(),
            continueCh: None,
        });
        let resc: goish::gochan::chan<responseAndError> = goish::make!(chan responseAndError, 1);
        let _ = loops.reqch.Send(requestAndChan {
            req: Some(req),
            ch: resc.clone(),
            continueCh: None,
        });
        let (rae, _) = resc.Recv();
        check(
            "a hang-up surfaces as an error and the pc records why",
            !rae.err.IsNil() && !pc.__closed_reason().IsNil(),
            fmt::Sprintf!("err=%v reason=%v", rae.err, pc.__closed_reason()),
        );
        HANG_UP.store(false, Ordering::SeqCst);
    }

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("HTTP_TRANSPORT_LOOPS_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_TRANSPORT_LOOPS_FAIL (%d)\n", f as i64);
    goish::os::Exit(1);
}
