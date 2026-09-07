// http_reqbody_close_ref_smoke — closing a request body means it.
//
// Go's server request body is a `body` with a `closed` flag, and
// bodyLocked.Read (transfer.go:1038) answers ErrBodyReadAfterClose
// once it is set. goish let the handler keep reading: its request
// bodies are materialised, and an Eager body's Close is deliberately a
// NO-OP — Go wraps a client's outgoing body in io.NopCloser, and
// without that no-op a 307/308 redirect could not replay it.
//
// Both are true, of different bodies. The client's OUTGOING body is a
// NopCloser and must survive Close; the server's INCOMING body is not
// and must not. goish has one Body type for both, so the distinction
// is carried explicitly, set where the request parser builds the body.
//
// ErrBodyReadAfterClose was already ported and anchored here, and
// nothing had ever returned it — the "ported, anchored, and never
// called" shape ROADMAP §2e is about.
//
// GO[] is the verbatim output of tools/gen_reqbody_afterclose_ref.go
// under scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::io::Reader as _;
use goish::types::byte;
use goish::fmt;
use goish::net;
use goish::net::http;
use goish::{go, string, time};

static FAILED: AtomicUsize = AtomicUsize::new(0);
static GO: &str = "read1 n=5 err=<nil> close=<nil> read-after-close n=0 err=http: invalid Read on closed Body";

static LINE: goish::sync::Mutex<Option<goish::string>> = goish::sync::Mutex::new(None);

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn run() {
    let mux = http::ServeMux::new();
    mux.HandleFunc("/p", |_w, r| {
        let mut first = goish::make!([]byte, 5);
        let (n1, e1) = r.Body.clone().Read(&mut first);
        let cerr = goish::io::Closer::Close(&mut r.Body.clone());
        let mut second = goish::make!([]byte, 5);
        let (n2, e2) = r.Body.clone().Read(&mut second);
        *LINE.Lock() = Some(fmt::Sprintf!(
            "read1 n=%d err=%v close=%v read-after-close n=%d err=%v",
            n1 as i64, e1, cerr, n2 as i64, e2));
    });
    let srv = Arc::new(http::Server { Handler: Arc::new(mux),
        ReadHeaderTimeout: time::Duration(5*1_000_000_000), ..Default::default() });
    let (ln, _) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    let port = ln.Addr().Port;
    { let s2 = srv.clone(); go!(stack(1024*1024), move || { let _ = s2.Serve(ln); }); }
    time::Sleep(time::Duration(200_000_000));

    let (mut resp, e) = http::Post(fmt::Sprintf!("http://127.0.0.1:%d/p", port as i64),
        string("text/plain"), goish::bytes("hello world"));
    if !e.IsNil() { fmt::Printf!("post err=%v\n", e); goish::os::Exit(1); }
    let _ = goish::io::ReadAll(&mut resp.Body);
    time::Sleep(time::Duration(150_000_000));
    let l = LINE.Lock().clone();
    let got = match l {
        Some(l) => l,
        None => string("no line"),
    };
    if got == string(GO) {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!]\n  got:  %s\n  want: %s\n", got, string(GO));
    }
    let _ = srv.clone().Close();
    if FAILED.load(Ordering::Relaxed) == 0 {
        fmt::Printf!("\nok 1/1\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED\n");
    goish::os::Exit(1);
}
