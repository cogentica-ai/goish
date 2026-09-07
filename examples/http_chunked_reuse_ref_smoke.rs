// http_chunked_reuse_ref_smoke — a chunked response keeps its conn.
//
// Go banks a connection for reuse on `bodyEOFSignal.rerr == io.EOF`
// (transport.go:3019) — on the body having ENDED, never on the framing
// it used. goish reused Content-Length bodies and dropped chunked
// ones, so three chunked requests opened three connections where Go
// opens one, and every chunked response cost a fresh TCP connection
// (and a fresh TLS handshake over https).
//
// The reuse logic was not the cause. goish never read the TRAILER
// section of a chunked RESPONSE: readTrailer was ported and wired only
// to the server's request path, so the trailer bytes — at minimum a
// bare CRLF — stayed on the wire and the conn was desynced at the
// moment the body reported EOF. Banking it in that state would hand
// the next request a stream starting mid-trailer, which is a
// smuggling shape rather than an optimisation. The trailer read comes
// first; the reuse follows from it.
//
// GO[] is the verbatim output of tools/gen_chunked_reuse_ref.go under
// scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net;
use goish::net::http;
use goish::net::http::Flusher;
use goish::{go, string, time};

static CONNS: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 6] = [
    "body=\"part-one part-two\" te=chunked",
    "three chunked requests opened 1 connection(s)",
    "trailer req 0 body=\"with-trailer\" err=<nil>",
    "trailer req 1 body=\"with-trailer\" err=<nil>",
    "trailer req 2 body=\"with-trailer\" err=<nil>",
    "three trailered requests opened 1 connection(s)",
];

static TCONNS: AtomicUsize = AtomicUsize::new(0);

fn chk(got: goish::string) {
    let i = SEEN.fetch_add(1, Ordering::Relaxed);
    if i < GO.len() && got == string(GO[i]) {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            string(if i < GO.len() { GO[i] } else { "" })
        );
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
    // No Content-Length and a Flush: the response is chunked.
    mux.HandleFunc("/c", |w, _r| {
        let _ = w.Write(goish::bytes("part-one "));
        let (f, ok) = goish::cast!(w, Flusher);
        if ok {
            f.Flush();
        }
        let _ = w.Write(goish::bytes("part-two"));
    });
    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ReadHeaderTimeout: time::Duration(5 * 1_000_000_000),
        ..Default::default()
    });
    srv.SetConnState(Some(Arc::new(
        |_fd: goish::types::int, cs: http::server::ConnState| {
            if cs == http::server::StateNew {
                CONNS.fetch_add(1, Ordering::Relaxed);
            }
        },
    )));
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
    time::Sleep(time::Duration(200_000_000));

    let c = http::Client::default();
    let url = fmt::Sprintf!("http://127.0.0.1:%d/c", port as i64);
    let mut i = 0;
    while i < 3 {
        let (mut resp, e) = c.Get(url.clone());
        if !e.IsNil() {
            fmt::Printf!("get %d err=%v\n", i as i64, e);
            goish::os::Exit(1);
        }
        let (b, _) = goish::io::ReadAll(&mut resp.Body);
        let te = if resp.TransferEncoding.Len() > 0 {
            resp.TransferEncoding[0].clone()
        } else {
            string("none")
        };
        let _ = goish::io::Closer::Close(&mut resp.Body.clone());
        if i == 0 {
            chk(fmt::Sprintf!(
                "body=%q te=%s",
                goish::string::from_bytes(&b),
                te
            ));
        }
        i += 1;
    }
    time::Sleep(time::Duration(250_000_000));
    chk(fmt::Sprintf!(
        "three chunked requests opened %d connection(s)",
        CONNS.load(Ordering::Relaxed) as i64
    ));
    let _ = srv.clone().Close();

    // The case that decides whether the trailer consumption is right:
    // a REAL trailer section. Leave those lines on the wire and the
    // next response on that connection starts mid-trailer and parses
    // as garbage — which is why this reuses a conn three times rather
    // than checking one response in isolation.
    let tmux = http::ServeMux::new();
    tmux.HandleFunc("/t", |w, _r| {
        w.Header().Set(string("Trailer"), string("X-Checksum"));
        let _ = w.Write(goish::bytes("with-trailer"));
        let (f, ok) = goish::cast!(w, Flusher);
        if ok {
            f.Flush();
        }
        w.Header().Set(string("X-Checksum"), string("abc123"));
    });
    let tsrv = Arc::new(http::Server {
        Handler: Arc::new(tmux),
        ReadHeaderTimeout: time::Duration(5 * 1_000_000_000),
        ..Default::default()
    });
    tsrv.SetConnState(Some(Arc::new(
        |_fd: goish::types::int, cs: http::server::ConnState| {
            if cs == http::server::StateNew {
                TCONNS.fetch_add(1, Ordering::Relaxed);
            }
        },
    )));
    let (tln, tle) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !tle.IsNil() {
        fmt::Printf!("listen 2: %v\n", tle);
        goish::os::Exit(1);
    }
    let tport = tln.Addr().Port;
    {
        let s3 = tsrv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s3.Serve(tln);
        });
    }
    time::Sleep(time::Duration(200_000_000));

    let tclient = http::Client::default();
    let turl = fmt::Sprintf!("http://127.0.0.1:%d/t", tport as i64);
    let mut j = 0;
    while j < 3 {
        let (mut resp, e) = tclient.Get(turl.clone());
        if !e.IsNil() {
            fmt::Printf!("trailer get %d err=%v\n", j as i64, e);
            goish::os::Exit(1);
        }
        let (b, rerr) = goish::io::ReadAll(&mut resp.Body);
        let _ = goish::io::Closer::Close(&mut resp.Body.clone());
        chk(fmt::Sprintf!(
            "trailer req %d body=%q err=%v",
            j as i64,
            goish::string::from_bytes(&b),
            rerr
        ));
        j += 1;
    }
    time::Sleep(time::Duration(250_000_000));
    chk(fmt::Sprintf!(
        "three trailered requests opened %d connection(s)",
        TCONNS.load(Ordering::Relaxed) as i64
    ));
    let _ = tsrv.clone().Close();

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("\nok 6/6\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of 6\n", f as i64);
    goish::os::Exit(1);
}
