// client_timeout_ref_smoke — what a Client.Timeout actually returns.
//
// Reference: Go 1.25.5 net/http, measured by
// tools/gen_client_timeout_ref.go. The GO[] line is Go's verbatim
// output.
//
// Two lines, and each exists because an API it checks was ported onto
// something the client never produced.
//
// The second line is the body half. Client.Timeout covers reading the
// response too, and there the error is not a url.Error at all — the
// response already arrived. Go's cancelTimerBody.Read wraps whatever
// the read returned, but only when the client's own timer fired, and
// marks it a timeout. goish HAD the predicate: setRequestCancel
// returns it, and the call site's comment even reads
// `&cancelTimerBody{stop, rc, reqDidTimeout}` — while passing only
// `stop`. So a body read killed by Client.Timeout came back as
// "read tcp 127.0.0.1:60460->…: i/o timeout", naming a port instead
// of the deadline. The same bug had already been found and fixed one
// call earlier, for the awaiting-headers annotation.
//
// Go wraps EVERY error out of Client.do in a `*url.Error`
// (client.go:617-634), which is what makes the standard idiom work:
//
//     if ue, ok := err.(*url.Error); ok && ue.Timeout() { retry }
//
// goish returned the bare inner error — "context deadline exceeded",
// with no Op, no URL, and nothing to assert on. url.Error.Timeout and
// Temporary had been ported earlier the same day and pinned against
// values BUILT BY HAND in a smoke; nothing checked whether a real
// client failure ever produced a url.Error. It did not.
//
// The netErr column is the second half: Go's `*url.Error` satisfies
// `net.Error` structurally, because it has Error, Timeout and
// Temporary. goish needed the impl spelled out and registered, or
// `errors.As(err, &netErr)` misses on a client error where Go's finds
// it.
//
// The request is made against a listener that ACCEPTS and never
// answers, so the client's own Timeout is what ends it — not a
// connection refusal, which would take a different path and prove
// nothing about the timeout wrapper.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::string::String;
use alloc::sync::Arc;
use goish::errors;
use goish::fmt;
use goish::net;
use goish::net::http;
use goish::net::url;
use goish::{go, string, time};

// Go's verbatim output.
const GO: [&str; 2] = [
    "client-timeout urlErr=true  Timeout=true  Temporary=true  netErr=true  op=\"Get\"",
    "body-timeout n=10 netErr=true  Timeout=true  err=\"context deadline exceeded (Client.Timeout or context cancellation while reading body)\"",
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
            goish::string(GO[i])
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
    // A listener that accepts and never answers, so the client's own
    // Timeout is what ends the request.
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("listen: %v\n", le);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    go!(stack(256 * 1024), move || {
        let (mut c, e) = ln.Accept();
        if e.IsNil() {
            time::Sleep(time::Duration(600_000_000));
            let _ = goish::io::Closer::Close(&mut c);
        }
    });
    time::Sleep(time::Duration(80_000_000));

    let mut u = String::from("http://127.0.0.1:");
    {
        let mut n = port as i64;
        let mut d: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        if n == 0 {
            d.push(b'0');
        }
        while n > 0 {
            d.push(b'0' + (n % 10) as u8);
            n /= 10;
        }
        d.reverse();
        for c in d.iter() {
            u.push(*c as char);
        }
    }
    u.push_str("/x");

    let mut client = http::Client::default();
    client.Timeout = time::Duration(150_000_000);
    client.Transport = Arc::new(http::Transport::default());
    let (r, _) = http::NewRequest(
        string("GET"),
        goish::string::from_bytes(u.as_bytes()),
        goish::nil,
    );
    let (_resp, rerr) = client.Do(&r);

    let ue = errors::As::<url::Error>(rerr.clone());
    let is_url_err = ue.is_some();
    let (to, tmp, op) = match ue.as_ref() {
        Some(e) => (e.Timeout(), e.Temporary(), e.Op.clone()),
        None => (false, false, string("")),
    };
    let (_ne, is_net_err) = errors::AsIface::<goish::d!(goish::net::net::Error)>(&rerr);
    // Deliberately NOT pinning the inner message. It races between
    // the socket's own deadline ("read: i/o timeout") and the client
    // context's ("context deadline exceeded") — both correct, both
    // Go-shaped, and which one wins depends on scheduling. What is
    // stable, and what a caller actually branches on, is the wrapper
    // and its three answers.
    chk(fmt::Sprintf!(
        "client-timeout urlErr=%-5v Timeout=%-5v Temporary=%-5v netErr=%-5v op=%q",
        is_url_err,
        to,
        tmp,
        is_net_err,
        op
    ));

    // ── the other half: Client.Timeout while reading the BODY ──
    //
    // The response came back fine, so there is no url.Error here at
    // all — Go's cancelTimerBody.Read wraps the read error instead,
    // and only when the client's own timer is what fired. goish had
    // the predicate (`setRequestCancel` returns it, and the call site
    // even cited `&cancelTimerBody{stop, rc, reqDidTimeout}`) but
    // handed the body only the stop function, so a body read killed
    // by Client.Timeout surfaced the raw socket error with a port
    // number in it, saying nothing about which deadline killed it.
    let mux = http::ServeMux::new();
    mux.HandleFunc("/s", |w, _r| {
        w.Header().Set(string("Content-Length"), string("100"));
        let _ = w.Write(goish::bytes("0123456789"));
        let (fl, ok) = goish::cast!(w, http::Flusher);
        if ok {
            fl.Flush();
        }
        time::Sleep(time::Duration(3 * 1_000_000_000));
    });
    let srv = Arc::new(http::Server {
        Handler: Arc::new(mux),
        ReadHeaderTimeout: time::Duration(5 * 1_000_000_000),
        ..Default::default()
    });
    let (bln, ble) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !ble.IsNil() {
        fmt::Printf!("listen 2: %v\n", ble);
        goish::os::Exit(1);
    }
    let bport = bln.Addr().Port;
    {
        let s2 = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s2.Serve(bln);
        });
    }
    time::Sleep(time::Duration(200_000_000));

    let mut bclient = http::Client::default();
    bclient.Timeout = time::Duration(400_000_000);
    bclient.Transport = Arc::new(http::Transport::default());
    let (breq, _) = http::NewRequest(
        string("GET"),
        fmt::Sprintf!("http://127.0.0.1:%d/s", bport as i64),
        goish::nil,
    );
    let (mut bresp, bgeterr) = bclient.Do(&breq);
    if !bgeterr.IsNil() {
        fmt::Printf!("body-timeout get failed: %v\n", bgeterr);
        goish::os::Exit(1);
    }
    let (bbytes, readerr) = goish::io::ReadAll(&mut bresp.Body);
    let (bne, is_body_net) = errors::AsIface::<goish::d!(goish::net::net::Error)>(&readerr);
    let btimeout = is_body_net && bne.Timeout();
    chk(fmt::Sprintf!(
        "body-timeout n=%d netErr=%-5v Timeout=%-5v err=%q",
        bbytes.Len() as i64,
        is_body_net,
        btimeout,
        readerr
    ));
    let _ = srv.clone().Close();

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
