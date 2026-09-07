// http_transport_clone_ref_smoke — Clone must carry the dial hooks.
//
// Go's Transport.Clone "returns a deep copy of t's exported fields" —
// all of them. goish copied fifteen and dropped four: Dial, DialTLS,
// DialTLSContext and ForceAttemptHTTP2. The three dial hooks are read
// at the dial site, so a Transport configured to reach the network a
// particular way handed its clone none of it and the clone dialled
// straight out, ignoring the configuration without a word.
//
// What kept it hidden was the doc: Clone's own comment listed those
// four among "Go fields goish's Transport does not have". It EXPLAINED
// the omission instead of describing it, so the gap read as intent.
//
// GO[] is the verbatim output of tools/gen_transport_clone_ref.go
// under scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net;
use goish::net::http;
use goish::{go, string, time};

static USED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 1] = ["clone-dial used=true status=200 err=<nil>"];

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
    mux.HandleFunc("/ok", |w, _r| {
        let _ = w.Write(goish::bytes("ok"));
    });
    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ReadHeaderTimeout: time::Duration(5 * 1_000_000_000),
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
    time::Sleep(time::Duration(200_000_000));

    // The deprecated ctx-less hook on purpose: DialContext was already
    // copied, so it would not have caught this.
    let mut tr = http::Transport::default();
    tr.Dial = Some(Arc::new(|network: string, addr: string| {
        USED.fetch_add(1, Ordering::Relaxed);
        let (c, e) = net::Dial(network, addr);
        if !e.IsNil() {
            return (None, e);
        }
        (
            Some(alloc::boxed::Box::new(c) as alloc::boxed::Box<dyn net::Conn>),
            goish::errors::nil,
        )
    }));

    let clone = tr.Clone();
    let mut c = http::Client::default();
    c.Transport = Arc::new(clone);
    let (resp, err) = c.Get(fmt::Sprintf!("http://127.0.0.1:%d/ok", port as i64));
    let code = if err.IsNil() { resp.StatusCode } else { 0 };

    let got = fmt::Sprintf!(
        "clone-dial used=%v status=%d err=%v",
        USED.load(Ordering::Relaxed) > 0,
        code as i64,
        err
    );
    if got == string(GO[0]) {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!]\n  got:  %s\n  want: %s\n", got, string(GO[0]));
    }
    let _ = srv.clone().Close();

    if FAILED.load(Ordering::Relaxed) == 0 {
        fmt::Printf!("\nok 1/1\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED\n");
    goish::os::Exit(1);
}
