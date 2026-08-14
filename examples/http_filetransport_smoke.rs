// http_filetransport_smoke — net/http/filetransport.go.
//
// `NewFileTransport` serves a FileSystem as a RoundTripper for the
// "file" protocol. The interesting property is that RoundTrip returns
// as soon as the response HEAD is known while the body is still being
// written down an io.Pipe by the serving goroutine — so a large file
// streams instead of buffering. The unbuffered channel send in
// sendResponse is what enforces that ordering.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::Reader;
use goish::net::http;
use goish::net::http::filetransport::{NewFileTransport, NewFileTransportFS};
use goish::os;
use goish::{slice, string};

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

fn drain(body: &mut http::client::Body) -> goish::string {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    loop {
        let (n, e) = body.Read(&mut buf);
        for i in 0..n {
            out.push(buf[i]);
        }
        if !e.IsNil() || n == 0 {
            break;
        }
    }
    return goish::string::from_bytes(&out);
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
    // A real directory with a real file — Dir() is the FileSystem Go's
    // own doc comment uses.
    let dir = string("/tmp/claude-1000/goish-filetransport-smoke");
    let _ = os::MkdirAll(dir.clone(), 0o755);
    let path = fmt::Sprintf!("%s/hello.txt", dir.clone());
    // 40 KiB, well past the pipe's buffer, so the body genuinely
    // streams rather than landing in one write.
    let mut big: Vec<u8> = Vec::new();
    for i in 0..40960u32 {
        big.push(b'a' + ((i % 26) as u8));
    }
    let werr = os::WriteFile(
        path.clone(),
        slice::<goish::byte>::__from_vec(big.clone()),
        0o644,
    );
    if !werr.IsNil() {
        check("setup", false, fmt::Sprintf!("WriteFile: %v", werr));
        finish();
    }

    let tr = NewFileTransport(Arc::new(goish::net::http::fs::NewDir(dir.clone())) as Arc<dyn goish::net::http::fs::FileSystem + Send + Sync>);

    // ── 1. a present file ──
    {
        let (req, e) = http::NewRequest(
            string("GET"),
            string("file:///hello.txt"),
            slice::new(),
        );
        if !e.IsNil() {
            check("NewRequest", false, fmt::Sprintf!("%v", e));
            finish();
        }
        let (mut resp, rerr) = tr.RoundTrip(&req);
        let body = drain(&mut resp.Body);
        check(
            "RoundTrip serves a file with 200 and the full body",
            rerr.IsNil()
                && resp.StatusCode == 200
                && resp.Status == "200 OK"
                && body.Len() == 40960
                && { let bs: &str = body.as_ref(); bs.starts_with("abcdefghij") },
            fmt::Sprintf!(
                "status=%d %q len=%d",
                resp.StatusCode,
                resp.Status.clone(),
                body.Len()
            ),
        );
        // Go sets ContentLength = -1 once anything was written, and
        // Proto/ProtoMajor/Close are fixed by newPopulateResponseWriter.
        check(
            "response carries HTTP/1.0, Close, ContentLength -1",
            resp.Proto == "HTTP/1.0" && resp.ProtoMajor == 1 && resp.Close
                && resp.ContentLength == -1,
            fmt::Sprintf!(
                "proto=%s major=%d close=%v cl=%d",
                resp.Proto.clone(),
                resp.ProtoMajor,
                resp.Close,
                resp.ContentLength
            ),
        );
        // fileHandler sets Content-Type by extension; that header must
        // survive the Header() handle onto the Response.
        let ct = resp.Header.Get(string("Content-Type"));
        check(
            "headers set by the handler reach the Response",
            ct.Len() > 0,
            fmt::Sprintf!("Content-Type=%q", ct),
        );
    }

    // ── 2. a missing file → 404, not a hang ──
    {
        let (req, _) = http::NewRequest(
            string("GET"),
            string("file:///nope.txt"),
            slice::new(),
        );
        let (mut resp, rerr) = tr.RoundTrip(&req);
        let _ = drain(&mut resp.Body);
        check(
            "a missing file yields 404",
            rerr.IsNil() && resp.StatusCode == 404,
            fmt::Sprintf!("status=%d err=%v", resp.StatusCode, rerr),
        );
    }

    // ── 3. NewFileTransportFS over an fs.FS ──
    {
        let fsys = os::DirFS(dir.clone());
        let tr2 = NewFileTransportFS(fsys);
        let (req, _) = http::NewRequest(
            string("GET"),
            string("file:///hello.txt"),
            slice::new(),
        );
        let (mut resp, rerr) = tr2.RoundTrip(&req);
        let body = drain(&mut resp.Body);
        check(
            "NewFileTransportFS serves the same bytes",
            rerr.IsNil() && resp.StatusCode == 200 && body.Len() == 40960,
            fmt::Sprintf!("status=%d len=%d err=%v", resp.StatusCode, body.Len(), rerr),
        );
    }

    // Go's test would also register it on a Transport
    // (`t.RegisterProtocol("file", …)`, filetransport.go's doc
    // comment). `Transport.RegisterProtocol` lives in transport.go,
    // which is not ported — see the transport.go worklist. Nothing to
    // assert here yet.

    let _ = os::RemoveAll(dir);
    finish();
}

fn finish() -> ! {
    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_FILETRANSPORT_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_FILETRANSPORT_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
