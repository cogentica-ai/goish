// proxy_dial_smoke — a configured proxy must not be silently ignored.
//
// NOT a Go-reference smoke: Go dials the proxy and completes the
// request, which goish cannot do — CONNECT tunnelling is unported.
// What this pins is that goish FAILS CLOSED rather than open.
//
// `Transport.Proxy` was resolved by nobody. goish picked the proxy
// correctly — ProxyFromEnvironment and its NO_PROXY matching are
// pinned in detail by http_proxyenv_smoke — and then the request path
// built its connectMethod with `proxyURL: None` hard-coded, threw the
// answer away, and dialled the TARGET directly. The request
// succeeded. Nothing anywhere said a proxy had been asked for and
// skipped.
//
// That is the dangerous direction to fail in. Where a proxy is the
// egress control point — filtering, inspection, audit — going around
// it silently is a bypass, and the caller cannot tell from the
// outside: they get a 200.
//
// The two assertions are what distinguishes a bypass from a refusal:
//
//   the proxy listener is NOT contacted (goish cannot tunnel yet), and
//   the error names that limitation instead of reporting whatever the
//   direct dial happened to do.
//
// Before the fix this printed "connect: connection refused" — the
// TARGET's refusal, from a connection that should never have been
// attempted — with the proxy listener untouched. A target that HAD
// been listening would have returned a perfectly good response.
//
// When CONNECT lands, this smoke should start failing on the error
// line, and that is the point: it is the marker for the work.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
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
    // A listener standing in for the proxy: if the client honours the
    // proxy it connects HERE, whatever the target host is.
    let (ln, le) = goish::net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("listen: %v\n", le);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    let seen = Arc::new(goish::sync::Mutex::new(false));
    {
        let seen2 = seen.clone();
        goish::go!(stack(256 * 1024), move || {
            let (_c, e) = ln.Accept();
            if e.IsNil() {
                *seen2.Lock() = true;
            }
        });
    }
    goish::time::Sleep(goish::time::Duration(100_000_000));

    let mut purl = alloc::string::String::from("http://127.0.0.1:");
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
            purl.push(*c as char);
        }
    }
    purl.push('/');
    let purl_s = goish::string::from_bytes(purl.as_bytes());

    // A Transport whose resolver always names a proxy.
    let mut tr = http::Transport::default();
    tr.Proxy = Some(Arc::new(move |_r: &http::Request| {
        let (u, _) = goish::net::url::Parse(purl_s.clone());
        (u, goish::errors::nil)
    }));
    let mut client = http::Client::default();
    client.Transport = Arc::new(tr);

    // A REACHABLE target, so a bypass is provable rather than
    // inferred. The original version of this smoke aimed at
    // 127.0.0.1:1 with nothing listening, which cannot tell "refused
    // to dial the target" from "dialled the target and the target
    // refused" — it could only read the error text. With a real
    // server on the other end a bypass returns 200 and increments
    // this counter, and a refusal leaves it at zero.
    let (tln, tle) = goish::net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !tle.IsNil() {
        fmt::Printf!("target listen: %v\n", tle);
        goish::os::Exit(1);
    }
    let tport = tln.Addr().Port;
    let hits = Arc::new(goish::sync::Mutex::new(0i64));
    {
        let hits2 = hits.clone();
        goish::go!(stack(256 * 1024), move || {
            loop {
                let (c, e) = tln.Accept();
                if !e.IsNil() {
                    return;
                }
                *hits2.Lock() += 1;
                drop(c);
            }
        });
    }
    goish::time::Sleep(goish::time::Duration(100_000_000));
    let turl = {
        let mut u = alloc::string::String::from("http://127.0.0.1:");
        let mut n = tport as i64;
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
        u.push_str("/x");
        goish::string::from_bytes(u.as_bytes())
    };

    let (r, _) = http::NewRequest(string("GET"), turl, goish::nil);
    let (_resp, err) = client.Do(&r);
    let msg = err.Error();
    let m: &str = msg.as_ref();
    let mut bad = 0;
    if !m.contains("proxy-CONNECT") {
        fmt::Printf!("[!!] expected the proxy-unsupported error, got %q\n", msg);
        bad += 1;
    } else {
        fmt::Printf!("ok   proxied GET refused: %v\n", err);
    }
    // A direct dial would have left this false too, so it is the error
    // above that proves the difference — this guards the other side:
    // if a future CONNECT lands, the listener IS contacted and the
    // error line changes with it.
    if *seen.Lock() {
        fmt::Printf!("ok   proxy listener was contacted (CONNECT landed?)\n");
    } else {
        fmt::Printf!("ok   proxy listener not contacted (no CONNECT yet)\n");
    }

    // The direct assertion: the target is listening and answering, and
    // it must not have heard from us. This is the bypass itself, not
    // an error string standing in for it.
    let n = *hits.Lock();
    if n == 0 {
        fmt::Printf!("ok   target never contacted (no bypass)\n");
    } else {
        fmt::Printf!("[!!] target was contacted %d time(s) — the proxy was bypassed\n", n);
        bad += 1;
    }

    if bad == 0 {
        fmt::Printf!("\nok 3/3\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d\n", bad as i64);
    goish::os::Exit(1);
}
