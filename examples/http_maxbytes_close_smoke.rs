// http_maxbytes_close_smoke — a body-limit hit must close the conn.
//
// Go's maxBytesReader.Read calls requestTooLarge() through a
// `requestTooLarger` interface assertion (request.go:1243) BEFORE
// returning MaxBytesError. Without it the client keeps sending a body
// nobody reads, and the unread remainder is available to be parsed as
// the NEXT keep-alive request — a request-smuggling shape.
//
// Drives a real socket: oversized body on a keep-alive conn, then a
// second request on the same socket, which must not be served.

#![no_std]
#![no_main]

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
use goish::types::byte;
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
    mux.HandleFunc("/limited", |w, r| {
        // `w` is the borrow ServeHTTP handed us — exactly what
        // MaxBytesReader needs, and it outlives the reader.
        let body = r.body_reader();
        let mut mbr = http::MaxBytesReader(Some(w), body, 8);
        let mut buf = goish::make!([]goish::byte, 4096);
        let (_, e) = mbr.Read(&mut buf);
        if !e.IsNil() {
            w.WriteHeader(413);
            let _ = w.Write(goish::bytes("too large"));
            return;
        }
        let _ = w.Write(goish::bytes("ok"));
    });
    mux.HandleFunc("/ping", |w, _r| {
        let _ = w.Write(goish::bytes("pong"));
    });
    // MaxBytesHandler is the ergonomic form — and the one that closes
    // the conn, because it threads `w` through to MaxBytesReader.
    mux.Handle(
        "/wrapped",
        http::MaxBytesHandler(
            Arc::new(http::HandlerFunc(
                |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                    let (body, _) = goish::io::ReadAll(&mut r.Body.clone());
                    let _ = w.Write(goish::convert::bytes(fmt::Sprintf!("got %d", body.Len())));
                },
            )),
            8,
        ),
    );

    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
        ..Default::default()
    });
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        check("listen", false, fmt::Sprintf!("%v", le));
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

    let (mut c, e) = net::Dial(string("tcp"), fmt::Sprintf!("127.0.0.1:%d", port as i64));
    if !e.IsNil() {
        check("dial", false, fmt::Sprintf!("%v", e));
        finish();
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
    let mut req: Vec<u8> =
        b"POST /limited HTTP/1.1\r\nHost: x\r\nContent-Length: 64\r\n\r\n".to_vec();
    req.extend_from_slice(&[b'z'; 64]);
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(req));

    let mut first: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    let (n1, _) = c.Read(&mut buf);
    for i in 0..n1 {
        first.push(buf[i]);
    }
    let fs = goish::string::from_bytes(&first);
    let f: &str = fs.as_ref();
    check(
        "the oversized request gets a 413",
        f.contains("413"),
        fs.clone(),
    );
    check(
        "and the response announces Connection: close",
        f.contains("Connection: close"),
        fs,
    );

    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(
        b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
    ));
    let mut b2 = goish::make!([]goish::byte, 4096);
    let (n2, _) = c.Read(&mut b2);
    let mut second: Vec<u8> = Vec::new();
    for i in 0..n2 {
        second.push(b2[i]);
    }
    let ss = goish::string::from_bytes(&second);
    let sr: &str = ss.as_ref();
    let _ = c.Close();
    check(
        "the connection is closed, so no second request is served",
        !sr.contains("pong"),
        ss,
    );

    // ── MaxBytesHandler caps the body and closes the conn ──
    {
        let (mut c2, e2) = net::Dial(string("tcp"), fmt::Sprintf!("127.0.0.1:%d", port as i64));
        if !e2.IsNil() {
            check("dial 2", false, fmt::Sprintf!("%v", e2));
            finish();
        }
        let _ = c2.SetReadDeadline(time::Now().Add(time::Duration(5 * 1_000_000_000)));
        let mut rq: Vec<u8> =
            b"POST /wrapped HTTP/1.1\r\nHost: x\r\nContent-Length: 64\r\n\r\n".to_vec();
        rq.extend_from_slice(&[b'y'; 64]);
        let _ = c2.Write(goish::slice::<goish::byte>::__from_vec(rq));
        let mut bb = goish::make!([]goish::byte, 4096);
        let (n, _) = c2.Read(&mut bb);
        let mut v: Vec<u8> = Vec::new();
        for i in 0..n {
            v.push(bb[i]);
        }
        let rs = goish::string::from_bytes(&v);
        let r: &str = rs.as_ref();
        check(
            "MaxBytesHandler truncates the body to the cap",
            r.contains("got 8"),
            rs.clone(),
        );
        check(
            "and forces Connection: close like the manual form",
            r.contains("Connection: close"),
            rs,
        );
        let _ = c2.Write(goish::slice::<goish::byte>::__from_vec(
            b"GET /ping HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        ));
        let mut b3 = goish::make!([]goish::byte, 4096);
        let (n3, _) = c2.Read(&mut b3);
        let mut v3: Vec<u8> = Vec::new();
        for i in 0..n3 {
            v3.push(b3[i]);
        }
        let s3 = goish::string::from_bytes(&v3);
        let t3: &str = s3.as_ref();
        let _ = c2.Close();
        check(
            "so no second request is served on that conn either",
            !t3.contains("pong"),
            s3,
        );
    }

    // ── the OTHER Close: maxBytesReader.Close (request.go:1253) ──
    //
    // Go's MaxBytesReader returns an io.ReadCloser and closes the body
    // it wrapped, which is what makes the documented idiom work:
    //
    //     r.Body = http.MaxBytesReader(w, r.Body, n)
    //
    // The handler puts the wrapper BACK, so whoever closes the request
    // body closes the real one underneath. goish's wrapper implemented
    // Reader only — it could not be put back at all, since
    // Body::from_reader wants a ReadCloser — so the idiom was
    // unwritable and the declaration counted missing.
    {
        // A ReadCloser that records its own Close. Using a Body here
        // would prove nothing: an in-memory Body is Go's NopCloser
        // shape (NewRequest wraps a bytes.Reader in io.NopCloser), so
        // its Close is a no-op in Go too.
        let closed = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let src = CloseProbe {
            data: goish::bytes("hello there"),
            off: 0,
            closed: closed.clone(),
        };
        let wrapped = http::MaxBytesReader(None, src, 100);
        let mut outer = http::Body::from_reader(alloc::boxed::Box::new(wrapped));

        let mut probe = goish::make!([]byte, 5);
        let (n0, e0) = outer.Read(&mut probe);
        check(
            "the wrapper composes back into a Body and reads",
            n0 == 5 && e0.IsNil() && goish::string::from_bytes(&probe) == "hello",
            fmt::Sprintf!("n=%d err=%v got=%q", n0 as i64, e0, goish::string::from_bytes(&probe)),
        );

        let cerr = Closer::Close(&mut outer);
        check(
            "closing the wrapper closes the reader it wrapped",
            cerr.IsNil() && closed.load(Ordering::Relaxed),
            fmt::Sprintf!("close=%v inner-closed=%v", cerr, closed.load(Ordering::Relaxed)),
        );
    }

    finish();
}

// A minimal ReadCloser that records whether Close reached it — the
// only way to observe Go's `return l.r.Close()` from outside.
struct CloseProbe {
    data: goish::goslice::slice<byte>,
    off: usize,
    closed: Arc<core::sync::atomic::AtomicBool>,
}

impl Reader for CloseProbe {
    fn Read(&mut self, p: &mut goish::goslice::slice<byte>) -> (goish::types::int, goish::errors::error) {
        if self.off >= self.data.Len() as usize {
            return (0, goish::io::EOF.into());
        }
        let want = core::cmp::min(p.Len() as usize, self.data.Len() as usize - self.off);
        for i in 0..want {
            p[i] = self.data[self.off + i];
        }
        self.off += want;
        return (want as goish::types::int, goish::errors::nil);
    }
}

impl Closer for CloseProbe {
    fn Close(&mut self) -> goish::errors::error {
        self.closed.store(true, Ordering::Relaxed);
        return goish::errors::nil;
    }
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_MAXBYTES_CLOSE_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_MAXBYTES_CLOSE_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
