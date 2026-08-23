// http_header_injection_smoke — a handler cannot inject a header by
// putting CRLF in a header VALUE or a space in a header NAME.
//
// This is the regression test for the third and worst of three
// independent header-injection sites goish had: `build_head`
// (response.rs), which is what writes onto a real socket. It was a
// hand-rolled `key: value\r\n` loop with neither the
// ValidHeaderFieldName guard nor the newline folding that
// Header::writeSubset applies, so
//
//     w.Header().Set("X-Thing", userControlledValue)
//
// with CRLF in that value put a real extra header on the wire — the
// classic response-splitting primitive. Go routes this path through
// writeSubset (chunkWriter.writeHeader ends with
// `cw.header.WriteSubset(w, excludeHeader)`); goish now does too.
//
// The test reads the RAW socket bytes rather than going through a
// client, because a client would parse the injected header back into
// a header map and hide the very thing under test.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};
use goish::convert::bytes;
use goish::io::{Reader, Writer};
use goish::net;
use goish::net::http;
use goish::{fmt, go, string, syscall, time};

#[goish::main]
fn main() {
    let mux = http::ServeMux::new();
    mux.HandleFunc(string("/"), |w, _r| {
        // Hostile values, as if echoed from user input.
        w.Header()
            .Set(string("X-Evil"), string("a\r\nX-Injected: yes"));
        w.Header().Set(string("Bad Name"), string("v"));
        w.Header().Set(string("X-Fine"), string("ok"));
        let _ = w.Write(bytes("body"));
    });
    let mux: Arc<dyn http::Handler> = Arc::new(mux);

    let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !err.IsNil() {
        fmt::Println!("setup: Listen failed");
        syscall::Exit(1);
    }
    let port = ln.Addr().Port;
    static PORT: AtomicI32 = AtomicI32::new(0);
    PORT.store(port as i32, Ordering::Release);

    let m2 = mux.clone();
    go!(stack(64 * 1024), move || {
        let _ = http::Serve(ln, m2);
    });

    go!(stack(64 * 1024), || {
        let p = PORT.load(Ordering::Acquire);
        let addr = string("127.0.0.1:") + goish::strconv::Itoa(p as i64);
        let (mut conn, err) = net::Dial(string("tcp"), addr);
        if !err.IsNil() {
            fmt::Println!("setup: Dial failed");
            syscall::Exit(1);
        }
        let _ = conn.SetReadDeadline(time::Now().Add(time::Second * 2));
        let req = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        let _ = conn.Write(bytes(req));

        let mut raw: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let mut buf: goish::goslice::slice<goish::types::byte> =
            goish::goslice::slice::__from_vec(alloc::vec![0u8; 1024]);
        loop {
            let (n, e) = conn.Read(&mut buf);
            if n > 0 {
                raw.extend_from_slice(&buf.as_ref()[..n as usize]);
            }
            if n <= 0 || !e.IsNil() {
                break;
            }
        }
        let got = string::from_bytes(&raw);

        let mut failed = 0;

        // 1. No injected header line. The value survives folded into
        //    X-Evil, so the check is that it never STARTS a line.
        if goish::strings::Contains(got.clone(), string("\r\nX-Injected:")) {
            fmt::Println!("[1] INJECTED header present  FAIL\n", got.clone());
            failed += 1;
        } else {
            fmt::Println!("[1] CRLF in a header value cannot inject  PASS");
        }

        // 2. The invalid header NAME is dropped entirely.
        if goish::strings::Contains(got.clone(), string("Bad Name")) {
            fmt::Println!("[2] invalid header name written  FAIL");
            failed += 1;
        } else {
            fmt::Println!("[2] invalid header name is dropped  PASS");
        }

        // 3. A legitimate header still gets through — the guard must
        //    not be so blunt that it eats valid headers.
        if goish::strings::Contains(got.clone(), string("X-Fine: ok\r\n")) {
            fmt::Println!("[3] valid header still written  PASS");
        } else {
            fmt::Println!("[3] valid header missing  FAIL\n", got.clone());
            failed += 1;
        }

        if failed == 0 {
            fmt::Println!("ok 3/3");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL ", failed, " of 3");
            syscall::Exit(1);
        }
    });

    // Park main until the client goroutine has exited(0)/exited(1).
    loop {
        goish::runtime::sched::Gosched();
    }
}
