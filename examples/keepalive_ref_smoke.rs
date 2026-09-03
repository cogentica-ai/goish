// keepalive_ref_smoke — connection lifecycle and response framing.
//
// Reference: Go 1.25.5 net/http, measured by tools/gen_keepalive_ref.go.
// Every GO[] line is Go's verbatim output for the same request.
//
// Three defects, all about what happens to a connection AFTER a
// response is written, and all invisible to a test that sends one
// request and reads one reply — which is what every other http smoke
// in this tree does.
//
//   1. READ-AHEAD WAS DROPPED BETWEEN REQUESTS. Go builds `c.bufr`
//      once per connection (server.go:2017), so bytes read past the
//      end of request N are still in the buffer for request N+1.
//      goish rebuilt its bufio.Reader per request and returned the
//      buffer to a pool, which resets it — so anything read ahead was
//      discarded. A client that sent two requests back to back got
//      one response, and then waited on a connection the server was
//      still holding open, until something timed out. Not just
//      pipelining: any two requests that land in the same read.
//      goish now hands the surplus to the connReader, which outlives
//      the loop (see connReader.__pushback).
//
//   2. THE CONNECTION HEADER IGNORED THE PROTOCOL VERSION. goish sent
//      `Connection: close` whenever it was not keeping the connection
//      and nothing otherwise. Go's rules are version-specific: `close`
//      is only ADDED on HTTP/1.1, and `keep-alive` only on HTTP/1.0
//      and only for a self-delimiting response. So goish told every
//      HTTP/1.0 client `close` where Go says nothing, and — worse —
//      never answered a 1.0 client that ASKED to keep the connection,
//      which meant HTTP/1.0 keep-alive did not work at all: the
//      connection was reusable and the client had no way to know.
//
//   3. A DECLARED CONTENT-LENGTH WAS NOT ENFORCED. A handler that set
//      Content-Length: 4 and wrote 9 bytes had all 9 put on the wire,
//      and its Write returned (5, nil) as if that were fine. Go
//      returns (0, ErrContentLength) and writes nothing past the
//      declared length. The handler-visible half is pinned below too,
//      because the wire and the handler have to agree.
//
// The pipelined case is the one worth keeping: it is the only line
// here that a single-request test cannot express, and it is what a
// keep-alive connection is FOR.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{go, string};

// Go's verbatim output.
const GO: [&str; 12] = [
    "11-default             conn=-          cl=4    te=-        body=\"body\"",
    "11-close               conn=close      cl=4    te=-        body=\"body\"",
    "11-handler-close       conn=close      cl=4    te=-        body=\"body\"",
    "10-default             conn=-          cl=4    te=-        body=\"body\"",
    "10-keepalive           conn=keep-alive cl=4    te=-        body=\"body\"",
    "11-204                 conn=-          cl=-    te=-        body=\"\"",
    "10-204                 conn=keep-alive cl=-    te=-        body=\"\"",
    "11-head                conn=-          cl=4    te=-        body=\"\"",
    "      overrun handler: n1=4 e1=<nil> n2=0 e2=http: wrote more than the declared Content-Length",
    "11-overrun             conn=-          cl=4    te=-        body=\"abcd\"",
    "11-under               conn=close      cl=10   te=-        body=\"abc\"",
    "pipelined-2            responses=2",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            string(GO[i])
        );
    }
}

fn hdr(raw: &str, name: &str) -> goish::string {
    for ln in raw.split("\r\n") {
        if ln.is_empty() {
            break;
        }
        let mut want = name.to_ascii_lowercase();
        want.push(':');
        if ln.to_ascii_lowercase().starts_with(&want) {
            return goish::string::from_bytes(ln[name.len() + 1..].trim().as_bytes());
        }
    }
    string("-")
}

fn body_of(raw: &str) -> goish::string {
    match raw.find("\r\n\r\n") {
        Some(i) => goish::string::from_bytes(&raw.as_bytes()[i + 4..]),
        None => string(""),
    }
}

fn probe(port: goish::int, label: &'static str, req: &str) -> goish::string {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        chk(fmt::Sprintf!("%-22s dial error: %v", string(label), e));
        return string("");
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(400 * 1_000_000)));
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
        req.as_bytes().to_vec(),
    ));
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    while out.len() < 4096 {
        let (n, re) = c.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if !re.IsNil() || n == 0 {
            break;
        }
    }
    let _ = c.Close();
    let raw = goish::string::from_bytes(&out);
    let rs: &str = raw.as_ref();
    chk(fmt::Sprintf!(
        "%-22s conn=%-10s cl=%-4s te=%-8s body=%q",
        string(label),
        hdr(rs, "Connection"),
        hdr(rs, "Content-Length"),
        hdr(rs, "Transfer-Encoding"),
        body_of(rs)
    ));
    raw
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

fn run() {
    let mux = http::ServeMux::new();
    mux.HandleFunc("/ok", move |w, _r| {
        let _ = w.Write(goish::convert::bytes(string("body")));
    });
    mux.HandleFunc("/hclose", move |w, _r| {
        w.Header().Set(string("Connection"), string("close"));
        let _ = w.Write(goish::convert::bytes(string("body")));
    });
    mux.HandleFunc("/overrun", move |w, _r| {
        w.Header().Set(string("Content-Length"), string("4"));
        let (n1, e1) = w.Write(goish::convert::bytes(string("abcd")));
        let (n2, e2) = w.Write(goish::convert::bytes(string("EXTRA")));
        chk(fmt::Sprintf!(
            "      overrun handler: n1=%d e1=%v n2=%d e2=%v",
            n1 as i64,
            e1,
            n2 as i64,
            e2
        ));
    });
    mux.HandleFunc("/under", move |w, _r| {
        w.Header().Set(string("Content-Length"), string("10"));
        let _ = w.Write(goish::convert::bytes(string("abc")));
    });
    mux.HandleFunc("/empty204", move |w, _r| {
        w.WriteHeader(204);
    });

    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ..Default::default()
    });
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("listen: %v\n", le);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    {
        let s2 = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s2.Serve(ln);
        });
    }
    time::Sleep(time::Duration(150 * 1_000_000));

    probe(port, "11-default", "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n");
    probe(
        port,
        "11-close",
        "GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    probe(
        port,
        "11-handler-close",
        "GET /hclose HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    probe(port, "10-default", "GET /ok HTTP/1.0\r\n\r\n");
    probe(
        port,
        "10-keepalive",
        "GET /ok HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    );
    probe(port, "11-204", "GET /empty204 HTTP/1.1\r\nHost: x\r\n\r\n");
    probe(
        port,
        "10-204",
        "GET /empty204 HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
    );
    probe(port, "11-head", "HEAD /ok HTTP/1.1\r\nHost: x\r\n\r\n");
    probe(
        port,
        "11-overrun",
        "GET /overrun HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    probe(
        port,
        "11-under",
        "GET /under HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );

    let raw = probe_raw(port, "GET /ok HTTP/1.1\r\nHost: x\r\n\r\nGET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let rs: &str = raw.as_ref();
    chk(fmt::Sprintf!(
        "%-22s responses=%d",
        string("pipelined-2"),
        rs.matches("HTTP/1.1 200").count() as i64
    ));

    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}

fn probe_raw(port: goish::int, req: &str) -> goish::string {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        return string("");
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(3_000 * 1_000_000)));
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
        req.as_bytes().to_vec(),
    ));
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    while out.len() < 4096 {
        let (n, re) = c.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if !re.IsNil() || n == 0 {
            break;
        }
    }
    let _ = c.Close();
    goish::string::from_bytes(&out)
}
