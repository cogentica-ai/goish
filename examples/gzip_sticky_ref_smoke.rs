// gzip_sticky_ref_smoke — the transport's gzip error is STICKY.
//
// Go's `gzipReader.zerr` (transport.go:3042) is commented "any error
// from gzip.NewReader; sticky", and the stickiness is load-bearing: a
// body that failed to gunzip must keep reporting that failure. goish
// returned the error once and then EOF, because the next Read re-ran
// gzip::NewReader over a reader that had already been consumed. A
// caller that reads again after an error — resilient code does — saw
// a corrupt response as a complete empty one.
//
// Go also checks zerr BEFORE the body's closed flag, so the error
// survives Close rather than becoming "read on closed response body".
//
// GO[] is the verbatim output of tools/gen_gzip_sticky_ref.go run by
// scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::Reader as _;
use goish::net;
use goish::net::http;
use goish::types::byte;
use goish::{go, string, time};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

/// Go 1.25.5, verbatim.
static GO: [&str; 4] = [
    "read1 n=0 err=gzip: invalid header",
    "read2 n=0 err=gzip: invalid header",
    "read3 n=0 err=gzip: invalid header",
    "after close n=0 err=gzip: invalid header",
];

fn check(name: goish::string, ok: bool, detail: goish::string) {
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
    mux.HandleFunc("/g", |w, _r| {
        w.Header().Set(string("Content-Encoding"), string("gzip"));
        let _ = w.Write(goish::bytes("not gzip at all, just bytes"));
    });
    let srv = alloc::sync::Arc::new(http::Server {
        Handler: alloc::sync::Arc::new(mux),
        ReadHeaderTimeout: time::Duration(3 * 1_000_000_000),
        ..Default::default()
    });
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        check(string("listen"), false, fmt::Sprintf!("%v", le));
        finish();
    }
    let port = ln.Addr().Port;
    {
        let s2 = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s2.Serve(ln);
        });
    }
    time::Sleep(time::Duration(200 * 1_000_000));

    let (mut resp, e) = http::Get(fmt::Sprintf!("http://127.0.0.1:%d/g", port as i64));
    if !e.IsNil() {
        check(string("get"), false, fmt::Sprintf!("%v", e));
        finish();
    }

    let mut buf = goish::make!([]byte, 8);
    let mut i = 0usize;
    while i < 3 {
        let (n, err) = resp.Body.Read(&mut buf);
        let line = fmt::Sprintf!("read%d n=%d err=%v", (i + 1) as i64, n as i64, err);
        check(
            fmt::Sprintf!("read %d repeats the gzip error", (i + 1) as i64),
            line == string(GO[i]),
            fmt::Sprintf!("got=%q want=%q", line, string(GO[i])),
        );
        i += 1;
    }

    let _ = goish::io::Closer::Close(&mut resp.Body.clone());
    let (n4, e4) = resp.Body.Read(&mut buf);
    let line = fmt::Sprintf!("after close n=%d err=%v", n4 as i64, e4);
    check(
        string("the error survives Close, as Go checks zerr first"),
        line == string(GO[3]),
        fmt::Sprintf!("got=%q want=%q", line, string(GO[3])),
    );

    let _ = srv.clone().Close();
    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("GZIP_STICKY_REF_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("GZIP_STICKY_REF_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
