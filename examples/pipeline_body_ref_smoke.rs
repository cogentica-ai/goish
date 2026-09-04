// pipeline_body_ref_smoke — does a request BODY break the next
// request on the same connection?
//
// Reference: Go 1.25.5 net/http, measured by tools/gen_pipeline_body_ref.go.
// Every GO[] line is Go's verbatim output for the same byte stream.
//
// keepalive_ref_smoke established that goish answers two pipelined
// GETs. This asks the harder half of the same question: what happens
// when the first request carries a body, so the parser has to know
// exactly where that body ends before the next request begins. Get
// that boundary wrong in either direction and the failure is severe —
// body bytes parsed as a request line is the shape of request
// smuggling; a request line swallowed as body is a silently dropped
// request.
//
// It found one: a pipelined request following a CHUNKED body was
// LOST, while one following a Content-Length body was fine. The
// asymmetry is the tell. The Content-Length path reads the request's
// bufio directly, so read-ahead stays where the serve loop can find
// it. The chunked path hands that bufio to a ChunkedReader which
// wraps it in a bufio of its OWN, and the next request ended up in
// that inner buffer — dropped when the reader went out of scope.
//
// Both are now pushed back to the connReader, in stream order: the
// chunked reader's leftover first (it was pulled out of the outer
// buffer), then whatever remains in the outer buffer.
//
// The handlers are deliberately split: /read consumes the body,
// /noread ignores it. A parser that only finds the end of a body by
// watching a handler drain it would pass the first and fail the
// second.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{go, string};

// Go's verbatim output.
const GO: [&str; 8] = [
    "post-read+get          200=2 400=0 bodies=[read=5 OK]",
    "post-noread+get        200=2 400=0 bodies=[NOREAD OK]",
    "post-noread+2get       200=3 400=0 bodies=[NOREAD OK OK]",
    "2post-noread           200=3 400=0 bodies=[NOREAD NOREAD OK]",
    "chunked-read+get       200=2 400=0 bodies=[read=5 OK]",
    "chunked-noread+get     200=2 400=0 bodies=[NOREAD OK]",
    "bigbody-noread+get     200=2 400=0 bodies=[NOREAD OK]",
    "3get                   200=3 400=0 bodies=[OK OK OK]",
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

fn run_case(port: goish::int, label: &'static str, reqs: &str) {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        chk(fmt::Sprintf!("%-22s dial error: %v", string(label), e));
        return;
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(700 * 1_000_000)));
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
        reqs.as_bytes().to_vec(),
    ));
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 8192);
    while out.len() < 16384 {
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
    let n200 = rs.matches("HTTP/1.1 200").count();
    let n400 = rs.matches("HTTP/1.1 400").count();
    let mut bodies = String::from("[");
    let mut first = true;
    for part in rs.split("\r\n\r\n").skip(1) {
        let p = match part.find("HTTP/1.1 ") {
            Some(i) => &part[..i],
            None => part,
        };
        if !first {
            bodies.push(' ');
        }
        first = false;
        bodies.push_str(p);
    }
    bodies.push(']');
    chk(fmt::Sprintf!(
        "%-22s 200=%d 400=%d bodies=%s",
        string(label),
        n200 as i64,
        n400 as i64,
        goish::string::from_bytes(bodies.as_bytes())
    ));
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
        let _ = w.Write(goish::convert::bytes(string("OK")));
    });
    mux.HandleFunc("/read", move |w, r| {
        let mut body = r.Body.clone();
        let (b, _) = goish::io::ReadAll(&mut body);
        let _ = w.Write(goish::convert::bytes(fmt::Sprintf!(
            "read=%d",
            b.Len() as i64
        )));
    });
    mux.HandleFunc("/noread", move |w, _r| {
        let _ = w.Write(goish::convert::bytes(string("NOREAD")));
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

    let get = "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n";
    let last = "GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    let pread = "POST /read HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n12345";
    let pnoread = "POST /noread HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n12345";

    let mut s = String::new();
    s.push_str(pread);
    s.push_str(last);
    run_case(port, "post-read+get", &s);

    s = String::new();
    s.push_str(pnoread);
    s.push_str(last);
    run_case(port, "post-noread+get", &s);

    s = String::new();
    s.push_str(pnoread);
    s.push_str(get);
    s.push_str(last);
    run_case(port, "post-noread+2get", &s);

    s = String::new();
    s.push_str(pnoread);
    s.push_str(pnoread);
    s.push_str(last);
    run_case(port, "2post-noread", &s);

    s = String::new();
    s.push_str("POST /read HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n");
    s.push_str(last);
    run_case(port, "chunked-read+get", &s);

    s = String::new();
    s.push_str("POST /noread HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n");
    s.push_str(last);
    run_case(port, "chunked-noread+get", &s);

    s = String::new();
    s.push_str("POST /noread HTTP/1.1\r\nHost: x\r\nContent-Length: 70000\r\n\r\n");
    for _ in 0..70000 {
        s.push('A');
    }
    s.push_str(last);
    run_case(port, "bigbody-noread+get", &s);

    s = String::new();
    s.push_str(get);
    s.push_str(get);
    s.push_str(last);
    run_case(port, "3get", &s);

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
