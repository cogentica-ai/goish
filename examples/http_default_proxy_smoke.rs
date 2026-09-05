// http_default_proxy_smoke — the DEFAULT client must honour HTTP_PROXY.
//
// NOT a Go-reference smoke: Go dials the proxy and completes the
// request, which goish cannot do — CONNECT tunnelling is unported.
// What this pins is that goish CONSULTS the environment at all.
//
// goish had no `DefaultTransport`. `Client::default()` built a bare
// `Transport::default()`, which is all zeros — `Proxy: None` — so
// `http::Get(url)` ignored HTTP_PROXY, HTTPS_PROXY and NO_PROXY
// entirely and dialled the target directly. Go's DefaultTransport sets
// `Proxy: ProxyFromEnvironment`, and its doc comment says so in the
// first paragraph.
//
// `ProxyFromEnvironment` was ported and correct the whole time —
// http_proxyenv_smoke pins its NO_PROXY matching rule by rule — and
// nothing called it by default. proxy_dial_smoke already covered an
// EXPLICITLY configured `Transport.Proxy`, which is the case a user
// has thought about. This is the case nobody configures, because in Go
// it is configured for them.
//
// The target is 192.0.2.1 — TEST-NET-1, RFC 5737: never routed, and
// crucially NOT loopback. ProxyFromEnvironment deliberately never
// proxies loopback, so a local target cannot exercise this path at
// all; a test written against 127.0.0.1 would pass whether or not the
// environment was ever read.
//
// The discriminator is the error. Honouring the proxy produces the
// unsupported-CONNECT error immediately. Ignoring it produces a dial
// to 192.0.2.1 that goes nowhere.
//
// Note how it goes nowhere: with the fix reverted this example does
// not fail, it HANGS, and the harness kills it. `c.Timeout` is set to
// three seconds and does not stop it — a second defect, in a different
// place, recorded in ROADMAP 2g. So a regression here shows up as a
// timeout rather than a clean red line, which is still a signal but a
// worse one; when Client.Timeout bounds the dial, this becomes a
// three-second failure with the message above.
//
// HTTP_PROXY is set before the first request because the environment
// is read once and cached.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http;
use goish::string;

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
    let _ = goish::os::Setenv(string("HTTP_PROXY"), string("http://127.0.0.1:1"));
    let _ = goish::os::Unsetenv(string("NO_PROXY"));

    let mut c = http::Client::default();
    // Bounds the failure mode this guards against: with the proxy
    // ignored, the dial to a black-holed address never returns on its
    // own — goish has no dial timeout (see DefaultTransport's note).
    c.Timeout = goish::time::Duration(3_000_000_000);

    let (r, _) = http::NewRequest(string("GET"), string("http://192.0.2.1/x"), goish::nil);
    let start = goish::time::Now();
    let (_resp, err) = c.Do(&r);
    let took = goish::time::Since(start);

    let mut bad = 0;
    if err.IsNil() {
        fmt::Printf!("[!!] expected an error, got a response\n");
        bad += 1;
    } else {
        let msg = err.Error();
        let m: &str = msg.as_ref();
        if m.contains("proxy-CONNECT") {
            fmt::Printf!("ok   default client used HTTP_PROXY: %v\n", err);
        } else {
            fmt::Printf!("[!!] default client ignored HTTP_PROXY: %v\n", err);
            bad += 1;
        }
    }
    // A dial that was actually attempted takes the full timeout; a
    // refusal is immediate. Belt and braces on the error text.
    if took < goish::time::Duration(1_000_000_000) {
        fmt::Printf!("ok   refused without dialling the target\n");
    } else {
        fmt::Printf!("[!!] took %v — the target was dialled\n", took);
        bad += 1;
    }

    if bad == 0 {
        fmt::Printf!("\nok 2/2\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d\n", bad as i64);
    goish::os::Exit(1);
}
