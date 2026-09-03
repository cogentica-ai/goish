// sniff_server_ref_smoke — what headers does a goish handler's
// response actually carry?
//
// Reference: Go 1.25.5 net/http, measured by tools/gen_sniff_server_ref.go.
// Every GO[] line is Go's verbatim output for the same handler.
//
// This measures the tail of Go's `chunkWriter.writeHeader`
// (server.go:1482-1550) — the block that runs after the status is
// known and decides what the response head says about itself. goish's
// two writers replace that function with their own head-building, and
// had skipped most of it. Four defects, all in the same few lines:
//
//   1. NO CONTENT-TYPE SNIFFING. Both writers seeded
//      "text/plain; charset=utf-8" in their constructor, which made
//      Go's `haveType` test permanently true, so nothing was ever
//      sniffed. Every handler-generated response went out as
//      text/plain: HTML rendered as source in a browser, images and
//      PDFs mislabelled, and — because Go sends no Content-Type at
//      all for an empty body — a header present where Go sends none.
//      15 of the first 18 cases below were wrong.
//
//   2. NO DATE HEADER, ever. Go stamps one on every response
//      including 204 and 304; RFC 9110 6.6.1 makes it a MUST for an
//      origin server with a clock. Caches that date a response by it
//      had nothing to work with.
//
//   3. NO SUPPRESSED-HEADER SCRUB. A 304 went out still carrying the
//      handler's Content-Type, Content-Length and Transfer-Encoding,
//      which RFC 7232 4.1 forbids. `suppressedHeaders` was already
//      ported in transfer.rs — it had simply never been called from
//      the response path.
//
//   4. CONTENT-LENGTH AND TRANSFER-ENCODING TOGETHER. A handler that
//      set "Transfer-Encoding: chunked" got a response advertising
//      BOTH that and a Content-Length, with an unframed body. That is
//      the response half of a smuggling desync — a proxy honouring
//      one header and a proxy honouring the other disagree about
//      where the body ends — and the body was unparseable to anything
//      that believed the Transfer-Encoding. Go logs the conflict,
//      drops the Content-Length, and chunk-frames.
//
// Two KNOWN GAPs remain, each recorded with Go's answer at the line.

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
use goish::net::http::responsewriter::Flusher;
use goish::time;
use goish::{go, string};

fn hdr(raw: &str, name: &str) -> goish::string {
    for ln in raw.split("\r\n") {
        if ln.is_empty() {
            break;
        }
        let lower = ln.to_ascii_lowercase();
        let mut want = name.to_ascii_lowercase();
        want.push(':');
        if lower.starts_with(&want) {
            return goish::string::from_bytes(ln[name.len() + 1..].trim().as_bytes());
        }
    }
    string("-")
}

fn req(port: goish::int, path: &str) -> goish::string {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        return string("");
    }
    let mut r = alloc::string::String::from("GET ");
    r.push_str(path);
    r.push_str(" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(r.into_bytes()));
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    while out.len() < 8192 {
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

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

// Go's verbatim output.
const GO: [&str; 27] = [
    "html-no-ct       ct=text/html; charset=utf-8        cl=28   te=-        date=<present>",
    "text-no-ct       ct=text/plain; charset=utf-8       cl=15   te=-        date=<present>",
    "empty-no-ct      ct=-                               cl=0    te=-        date=<present>",
    "png-no-ct        ct=image/png                       cl=12   te=-        date=<present>",
    "gif-no-ct        ct=image/gif                       cl=10   te=-        date=<present>",
    "pdf-no-ct        ct=application/pdf                 cl=14   te=-        date=<present>",
    "json-no-ct       ct=text/plain; charset=utf-8       cl=7    te=-        date=<present>",
    "xml-no-ct        ct=text/xml; charset=utf-8         cl=25   te=-        date=<present>",
    "explicit-ct      ct=application/vnd.custom          cl=20   te=-        date=<present>",
    "nosniff-no-ct    ct=text/html; charset=utf-8        cl=28   te=-        date=<present>",
    "two-writes       ct=text/html; charset=utf-8        cl=14   te=-        date=<present>",
    "lead-ws-html     ct=text/html; charset=utf-8        cl=18   te=-        date=<present>",
    "204-no-body      ct=-                               cl=-    te=-        date=<present>",
    "304-no-body      ct=-                               cl=-    te=-        date=<present>",
    "utf8-bom         ct=text/plain; charset=utf-8       cl=8    te=-        date=<present>",
    "binary-junk      ct=application/octet-stream        cl=5    te=-        date=<present>",
    "flush-then-html  ct=text/html; charset=utf-8        cl=-    te=chunked  date=<present>",
    "explicit-te      ct=-                               cl=-    te=chunked  date=<present>",
    "empty-ct         ct=                                cl=14   te=-        date=<present>",
    "big-body         ct=text/plain; charset=utf-8       cl=614  te=-        date=<present>",
    // KNOWN GAP. Go's line is:
    //   "ct-after-write   ct=text/html; charset=utf-8        cl=14   te=-        date=<present>"
    // Go snapshots the header map when the first Write reaches the
    // chunkWriter, so a Content-Type set AFTER the handler has already
    // written is too late and the sniffed type stands. goish buffers
    // the whole body and builds the head at flush time, so the late
    // Set is still visible and wins.
    //
    // This is the eager-vs-deferred difference behind the other
    // structural gaps in this port: goish's writer has no "headers are
    // now frozen" moment. Closing it means writing the head at the
    // first Write, which is the buffered design itself. A handler that
    // sets Content-Type after writing is doing something Go documents
    // as ineffective, so goish is the more forgiving of the two here
    // rather than the more wrong.
    "ct-after-write   ct=application/too-late            cl=14   te=-        date=<present>",
    "304-with-hdrs    ct=-                               cl=-    te=-        date=<present>",
    "cl-too-big       ct=text/plain; charset=utf-8       cl=100  te=-        date=<present>",
    // KNOWN GAP. Go's line is:
    //   "cl-too-small     ct=-                               cl=2    te=-        date=<present>"
    // A handler that declares Content-Length: 2 and then writes 16
    // bytes. Go's response.Write returns ErrContentLength and writes
    // NOTHING past the declared length, so the body is empty (and the
    // Content-Type unsniffed, because no bytes reached writeHeader).
    // goish sends all 16 bytes under the handler's Content-Length: 2.
    //
    // This is not a smuggling primitive in goish: shouldReuseConnection
    // already compares the declared length against the buffered body
    // and refuses to reuse the connection when they disagree, so the
    // surplus bytes cannot be read as the head of a following
    // response — the connection closes instead. What is missing is the
    // Write-side bound that would stop them being sent at all.
    "cl-too-small     ct=text/plain; charset=utf-8       cl=2    te=-        date=<present>",
    "own-date         ct=text/plain; charset=utf-8       cl=1    te=-        date=<present>",
    "gzip-ce          ct=-                               cl=14   te=-        date=<present>",
    "wh200-then-html  ct=text/html; charset=utf-8        cl=14   te=-        date=<present>",
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

const NAMES: [&str; 27] = [
    "html-no-ct",
    "text-no-ct",
    "empty-no-ct",
    "png-no-ct",
    "gif-no-ct",
    "pdf-no-ct",
    "json-no-ct",
    "xml-no-ct",
    "explicit-ct",
    "nosniff-no-ct",
    "two-writes",
    "lead-ws-html",
    "204-no-body",
    "304-no-body",
    "utf8-bom",
    "binary-junk",
    "flush-then-html",
    "explicit-te",
    "empty-ct",
    "big-body",
    "ct-after-write",
    "304-with-hdrs",
    "cl-too-big",
    "cl-too-small",
    "own-date",
    "gzip-ce",
    "wh200-then-html",
];

fn run() {
    let mux = http::ServeMux::new();
    fn w8(w: &(dyn http::ResponseWriter + Send + Sync), b: &[u8]) {
        let _ = w.Write(goish::slice::<goish::byte>::__from_vec(b.to_vec()));
    }
    mux.HandleFunc("/html-no-ct", move |w, _r| {
        w8(w, b"<html><body>hi</body></html>");
    });
    mux.HandleFunc("/text-no-ct", move |w, _r| {
        w8(w, b"just some words");
    });
    mux.HandleFunc("/empty-no-ct", move |_w, _r| {});
    mux.HandleFunc("/png-no-ct", move |w, _r| {
        w8(w, b"\x89PNG\r\n\x1a\ndata");
    });
    mux.HandleFunc("/gif-no-ct", move |w, _r| {
        w8(w, b"GIF89a....");
    });
    mux.HandleFunc("/pdf-no-ct", move |w, _r| {
        w8(w, b"%PDF-1.7\n%%EOF");
    });
    mux.HandleFunc("/json-no-ct", move |w, _r| {
        w8(w, b"{\"a\":1}");
    });
    mux.HandleFunc("/xml-no-ct", move |w, _r| {
        w8(w, b"<?xml version=\"1.0\"?><r/>");
    });
    mux.HandleFunc("/explicit-ct", move |w, _r| {
        w.Header()
            .Set(string("Content-Type"), string("application/vnd.custom"));
        w8(w, b"<html>ignored</html>");
    });
    mux.HandleFunc("/nosniff-no-ct", move |w, _r| {
        w.Header()
            .Set(string("X-Content-Type-Options"), string("nosniff"));
        w8(w, b"<html><body>hi</body></html>");
    });
    mux.HandleFunc("/two-writes", move |w, _r| {
        w8(w, b"<html>");
        w8(w, b"\x89PNG\r\n\x1a\n");
    });
    mux.HandleFunc("/lead-ws-html", move |w, _r| {
        w8(w, b"  \n\t<html>x</html>");
    });
    mux.HandleFunc("/204-no-body", move |w, _r| {
        w.WriteHeader(204);
    });
    mux.HandleFunc("/304-no-body", move |w, _r| {
        w.WriteHeader(304);
    });
    mux.HandleFunc("/utf8-bom", move |w, _r| {
        w8(w, b"\xef\xbb\xbfhello");
    });
    mux.HandleFunc("/binary-junk", move |w, _r| {
        w8(w, &[0x00u8, 0x01, 0x02, 0x03, 0xff]);
    });
    mux.HandleFunc("/flush-then-html", move |w, _r| {
        w8(w, b"<html>");
        if let (f, true) = goish::cast!(w, Flusher) {
            f.Flush();
        }
        w8(w, b"</html>");
    });
    mux.HandleFunc("/explicit-te", move |w, _r| {
        w.Header()
            .Set(string("Transfer-Encoding"), string("chunked"));
        w8(w, b"<html>x</html>");
    });
    mux.HandleFunc("/empty-ct", move |w, _r| {
        w.Header().Set(string("Content-Type"), string(""));
        w8(w, b"<html>x</html>");
    });
    mux.HandleFunc("/big-body", move |w, _r| {
        let mut v = alloc::vec![b' '; 600];
        v.extend_from_slice(b"<html>x</html>");
        w8(w, &v);
    });
    mux.HandleFunc("/ct-after-write", move |w, _r| {
        w8(w, b"<html>x</html>");
        w.Header()
            .Set(string("Content-Type"), string("application/too-late"));
    });
    mux.HandleFunc("/304-with-hdrs", move |w, _r| {
        w.Header().Set(string("Content-Type"), string("text/html"));
        w.Header().Set(string("Content-Length"), string("99"));
        w.Header()
            .Set(string("Transfer-Encoding"), string("chunked"));
        w.WriteHeader(304);
    });
    mux.HandleFunc("/cl-too-big", move |w, _r| {
        w.Header().Set(string("Content-Length"), string("100"));
        w8(w, b"short");
    });
    mux.HandleFunc("/cl-too-small", move |w, _r| {
        w.Header().Set(string("Content-Length"), string("2"));
        w8(w, b"much longer body");
    });
    mux.HandleFunc("/own-date", move |w, _r| {
        w.Header()
            .Set(string("Date"), string("Mon, 01 Jan 2001 00:00:00 GMT"));
        w8(w, b"x");
    });
    mux.HandleFunc("/gzip-ce", move |w, _r| {
        w.Header().Set(string("Content-Encoding"), string("gzip"));
        w8(w, b"<html>x</html>");
    });
    mux.HandleFunc("/wh200-then-html", move |w, _r| {
        w.WriteHeader(200);
        w8(w, b"<html>x</html>");
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
    time::Sleep(time::Duration(100 * 1_000_000));

    let mut i = 0;
    while i < NAMES.len() {
        let mut path = alloc::string::String::from("/");
        path.push_str(NAMES[i]);
        let raw = req(port, &path);
        let rs: &str = raw.as_ref();
        let d = hdr(rs, "Date");
        let dshown = if d.as_ref() as &str == "-" {
            string("-")
        } else {
            string("<present>")
        };
        chk(fmt::Sprintf!(
            "%-16s ct=%-31s cl=%-4s te=%-8s date=%s",
            string(NAMES[i]),
            hdr(rs, "Content-Type"),
            hdr(rs, "Content-Length"),
            hdr(rs, "Transfer-Encoding"),
            dshown
        ));
        i += 1;
    }
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
