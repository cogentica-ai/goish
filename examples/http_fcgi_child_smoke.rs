// http_fcgi_child_smoke — the FastCGI child serve loop, end to end
// over a real socket: fcgi.Serve accepts, reads records, runs a
// handler, and writes the response back as records.
//
// The wire format is the point. A FastCGI request is a sequence of
// records — BeginRequest, then Params (terminated by an EMPTY params
// record), then Stdin (terminated by an EMPTY stdin record) — and the
// reply is Stdout records carrying a CGI-style head, then an
// EndRequest. Getting the terminators wrong is the classic way to
// hang a FastCGI child forever, so each is exercised.
//
// Also checked: ProcessEnv surfaces the variables net/http does NOT
// put on the Request (REMOTE_USER is the example Go's own doc uses),
// while the ones it does put there (REQUEST_METHOD, QUERY_STRING, …)
// are filtered out — otherwise every handler would see them twice, in
// two different shapes.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::net::http::fcgi;
use goish::time;
use goish::{go, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);
static SAW_METHOD: goish::sync::Mutex<Vec<u8>> = goish::sync::Mutex::new(Vec::new());
static SAW_ENV: goish::sync::Mutex<Vec<u8>> = goish::sync::Mutex::new(Vec::new());
static SAW_BODY: goish::sync::Mutex<Vec<u8>> = goish::sync::Mutex::new(Vec::new());

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

fn remember(cell: &goish::sync::Mutex<Vec<u8>>, s: goish::string) {
    let mut g = cell.Lock();
    g.clear();
    for b in s.as_bytes() {
        g.push(*b);
    }
}

fn recall(cell: &goish::sync::Mutex<Vec<u8>>) -> goish::string {
    return goish::string::from_bytes(&cell.Lock().clone());
}

struct echoHandler;

impl http::Handler for echoHandler {
    fn ServeHTTP(&self, w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request) {
        remember(&SAW_METHOD, r.Method.clone());
        let (rbody, _) = goish::io::ReadAll(&mut r.Body.clone());
        remember(&SAW_BODY, goish::string::from_bytes(&rbody));
        // ProcessEnv is the whole reason the context is threaded
        // through: REMOTE_USER is nowhere on the Request.
        let env = fcgi::ProcessEnv(r);
        let (user, _) = env.Get(string("REMOTE_USER"));
        let (method, hasMethod) = env.Get(string("REQUEST_METHOD"));
        let _ = method;
        remember(
            &SAW_ENV,
            fmt::Sprintf!("user=%s method_present=%v", user, hasMethod),
        );
        w.Header().Set(string("X-Fcgi"), string("yes"));
        let _ = w.Write(goish::bytes("hello from fcgi"));
    }
}

// ── record framing helpers (the client side of the protocol) ─────────

fn record(typ: u8, reqId: u16, content: &[u8], out: &mut Vec<u8>) {
    let n = content.len();
    out.push(1); // version
    out.push(typ);
    out.push((reqId >> 8) as u8);
    out.push((reqId & 0xff) as u8);
    out.push((n >> 8) as u8);
    out.push((n & 0xff) as u8);
    out.push(0); // padding length
    out.push(0); // reserved
    for b in content {
        out.push(*b);
    }
}

/// One name/value pair in FastCGI's length-prefixed encoding. Both
/// lengths here are < 128, so both are single bytes.
fn pair(k: &str, v: &str, out: &mut Vec<u8>) {
    out.push(k.len() as u8);
    out.push(v.len() as u8);
    for b in k.as_bytes() {
        out.push(*b);
    }
    for b in v.as_bytes() {
        out.push(*b);
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
    goish::net::http::server::register_http_impls();
    goish::net::http::server::__goish_register_Handler_impl::<echoHandler>();

    let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !lerr.IsNil() {
        check("listen", false, fmt::Sprintf!("%v", lerr));
        finish();
    }
    let port = ln.Addr().Port;
    go!(stack(1024 * 1024), move || {
        let _ = fcgi::Serve(ln, Arc::new(echoHandler));
    });
    time::Sleep(time::Duration(150 * 1_000_000));

    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        check("dial", false, fmt::Sprintf!("%v", e));
        finish();
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));

    let mut req: Vec<u8> = Vec::new();
    // BeginRequest: role=1 (responder), flags=0 (do NOT keep the conn,
    // so the child closes and this test's read sees EOF).
    record(1, 1, &[0, 1, 0, 0, 0, 0, 0, 0], &mut req);
    // Params, then the empty record that ends them.
    let mut params: Vec<u8> = Vec::new();
    pair("REQUEST_METHOD", "POST", &mut params);
    pair("SERVER_PROTOCOL", "HTTP/1.1", &mut params);
    pair("HTTP_HOST", "example.com", &mut params);
    pair("REQUEST_URI", "/fcgi/path?q=1", &mut params);
    pair("QUERY_STRING", "q=1", &mut params);
    pair("CONTENT_LENGTH", "9", &mut params);
    pair("REMOTE_USER", "ada", &mut params);
    record(4, 1, &params, &mut req);
    record(4, 1, &[], &mut req);
    // Stdin, then the empty record that ends it — which is what makes
    // the child run the handler.
    record(5, 1, b"body-here", &mut req);
    record(5, 1, &[], &mut req);

    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(req));

    let mut raw: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    let readStart = time::Now();
    loop {
        let (n, re) = c.Read(&mut buf);
        for i in 0..n {
            raw.push(buf[i]);
        }
        if !re.IsNil() || n == 0 {
            break;
        }
    }
    let _ = c.Close();

    let wire = goish::string::from_bytes(&raw);
    let w: &str = wire.as_ref();

    check(
        "the handler ran, with the method and body from the records",
        recall(&SAW_METHOD) == "POST" && recall(&SAW_BODY) == "body-here",
        fmt::Sprintf!("method=%q body=%q", recall(&SAW_METHOD), recall(&SAW_BODY)),
    );
    check(
        "ProcessEnv surfaces REMOTE_USER and filters what the Request already carries",
        recall(&SAW_ENV) == "user=ada method_present=false",
        recall(&SAW_ENV),
    );
    check(
        "the reply carries the CGI head and the body",
        w.contains("Status: 200") && w.contains("X-Fcgi: yes") && w.contains("hello from fcgi"),
        wire.clone(),
    );
    // The last record must be EndRequest (type 3) for request 1.
    let ends = raw
        .windows(8)
        .filter(|r| r[0] == 1 && r[1] == 3 && r[2] == 0 && r[3] == 1)
        .count();
    // With flags=0 the child must hang up when the request is done.
    // If it did not, this read would have sat until its own 5s
    // deadline instead of ending on EOF.
    check(
        "flags=0 makes the child close the connection promptly",
        time::Since(readStart) < time::Duration(2 * 1_000_000_000),
        fmt::Sprintf!("read took %dms", time::Since(readStart).0 / 1_000_000),
    );
    check(
        "an EndRequest record closes the request out",
        ends >= 1,
        fmt::Sprintf!("end records=%d", ends as i64),
    );
    // ── keepConn: flags=1 keeps the connection for a second request ──
    //
    // This is the branch `errCloseConn` guards. With flags=0 (above)
    // the child must hang up after one request; with flags=1 it must
    // NOT, and a second exchange has to work on the same socket.
    {
        let addr2 = fmt::Sprintf!("127.0.0.1:%d", port as i64);
        let (mut c2, e2) = net::Dial(string("tcp"), addr2);
        if !e2.IsNil() {
            check("keepalive dial", false, fmt::Sprintf!("%v", e2));
            finish();
        }
        let _ = c2.SetReadDeadline(time::Now().Add(time::Duration(3 * 1_000_000_000)));
        // Both requests go out first: the replies arrive as a stream
        // of records and are not aligned to reads, so counting bodies
        // in the drained bytes is the only honest way to check.
        for i in 0..2u16 {
            let id = i + 1;
            let mut r2: Vec<u8> = Vec::new();
            // flags=1 → FCGI_KEEP_CONN.
            record(1, id, &[0, 1, 1, 0, 0, 0, 0, 0], &mut r2);
            let mut p2: Vec<u8> = Vec::new();
            pair("REQUEST_METHOD", "GET", &mut p2);
            pair("SERVER_PROTOCOL", "HTTP/1.1", &mut p2);
            pair("HTTP_HOST", "example.com", &mut p2);
            pair("REQUEST_URI", "/second", &mut p2);
            record(4, id, &p2, &mut r2);
            record(4, id, &[], &mut r2);
            record(5, id, &[], &mut r2);
            let _ = c2.Write(goish::slice::<goish::byte>::__from_vec(r2));
        }

        let mut all: Vec<u8> = Vec::new();
        let mut got;
        loop {
            let mut rbuf = goish::make!([]goish::byte, 4096);
            let (n, rerr) = c2.Read(&mut rbuf);
            for i in 0..n {
                all.push(rbuf[i]);
            }
            let sofar = goish::string::from_bytes(&all);
            got = (sofar.as_ref() as &str).matches("hello from fcgi").count();
            if got >= 2 || !rerr.IsNil() || n == 0 {
                break;
            }
        }
        let _ = c2.Close();
        check(
            "flags=FCGI_KEEP_CONN serves two requests on one connection",
            got == 2,
            fmt::Sprintf!("answered=%d of 2", got as i64),
        );
    }

    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_FCGI_CHILD_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_FCGI_CHILD_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
