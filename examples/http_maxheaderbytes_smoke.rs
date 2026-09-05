// http_maxheaderbytes_smoke — the server's bound on a request head.
//
// Reference: Go 1.25.5 net/http, tools/gen_maxheaderbytes_ref.go.
//
// `Server.MaxHeaderBytes` is the server's main header DoS bound, and
// Go answers 431 past it. Nothing here pinned it end to end: that the
// default is a megabyte, that setting the field moves the boundary,
// and that a request under the bound still succeeds.
//
// The last row is the one worth having. It is ONE header line of 100
// KiB, far past any bufio buffer but well under the 1 MiB default, and
// Go answers 200 because textproto accumulates a line longer than the
// buffer rather than refusing it. That is the server analogue of a
// defect fixed on the client this week, where a single response header
// over ~4 KiB failed the whole response with "bufio: buffer full".
// This row is what says the server does not have the same hole.
//
// The set-8k pair is the other half: with the field set to 8 KiB, 4000
// bytes of padding still passes and 20000 does not, so the boundary
// tracks the setting rather than being hard-coded.
//
// The count rows pin the other goish-only restriction this smoke
// found: request headers were capped at 100, where Go bounds only the
// byte total and serves 5000 of them. Real traffic exceeds 100 — many
// cookies, a CDN's forwarded and tracing headers — so that was a 400
// where Go answers 200.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::types::{byte, int};
use goish::{fmt, go, time};

const GO: [&str; 7] = [
    "default-small  limit=0        pad=100      count=0      \"HTTP/1.1 200 OK\\r\\n\"",
    "set-8k-under   limit=8192     pad=4000     count=0      \"HTTP/1.1 200 OK\\r\\n\"",
    "set-8k-over    limit=8192     pad=20000    count=0      \"HTTP/1.1 431 Request Header Fields Too Large\\r\\n\"",
    "default-over   limit=0        pad=2097152  count=0      \"HTTP/1.1 431 Request Header Fields Too Large\\r\\n\"",
    "long-line      limit=0        pad=102400   count=0      \"HTTP/1.1 200 OK\\r\\n\"",
    "count-200      limit=0        pad=0        count=200    \"HTTP/1.1 200 OK\\r\\n\"",
    "count-5000     limit=0        pad=0        count=5000   \"HTTP/1.1 200 OK\\r\\n\"",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let cases: [(&str, int, usize, usize); 7] = [
        ("default-small", 0, 100, 0),
        ("set-8k-under", 8 << 10, 4000, 0),
        ("set-8k-over", 8 << 10, 20000, 0),
        ("default-over", 0, 2 << 20, 0),
        ("long-line", 0, 100 << 10, 0),
        ("count-200", 0, 0, 200),
        ("count-5000", 0, 0, 5000),
    ];
    let mut ln_no: usize = 0;
    for (name, limit, pad, count) in cases.iter() {
        let mux = http::ServeMux::new();
        mux.HandleFunc(string::from("/"), |w, _r| {
            let _ = w.Write(goish::convert::bytes(string::from("ok")));
        });
        let mut srv = http::Server::default();
        srv.Handler = Arc::new(mux) as Arc<dyn http::Handler>;
        srv.MaxHeaderBytes = *limit;
        let srv = Arc::new(srv);

        let (l, lerr) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
        if !lerr.IsNil() {
            fmt::Printf!("[!!] listen: %v\n", lerr);
            goish::os::Exit(1);
        }
        let addr = l.Addr().String();
        let s2 = srv.clone();
        go!(stack(512 * 1024), move || {
            let _ = s2.Serve(l);
        });
        time::Sleep(time::Millisecond * 50);

        let (mut c, derr) = net::Dial(string::from("tcp"), addr);
        if !derr.IsNil() {
            fmt::Printf!("[!!] dial: %v\n", derr);
            goish::os::Exit(1);
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Second * 3));
        let mut req: Vec<u8> = Vec::new();
        req.extend_from_slice(b"GET / HTTP/1.1\r\nHost: x\r\n");
        if *count > 0 {
            for i in 0..*count {
                req.extend_from_slice(b"X-H");
                let n = goish::strconv::Itoa(i as i64);
                req.extend_from_slice(goish::convert::bytes(n).as_ref());
                req.extend_from_slice(b": v\r\n");
            }
        } else {
            req.extend_from_slice(b"X-Pad: ");
            for _ in 0..*pad {
                req.push(b'a');
            }
            req.extend_from_slice(b"\r\n");
        }
        req.extend_from_slice(b"Connection: close\r\n\r\n");
        let _ = c.Write(slice::__from_vec(req));

        let mut acc: Vec<u8> = Vec::new();
        let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 256]);
        loop {
            let (n, e) = c.Read(&mut buf);
            if n > 0 {
                acc.extend_from_slice(&buf.as_ref()[..n as usize]);
            }
            let done = acc.windows(2).any(|w| w == b"\r\n");
            if n <= 0 || !e.IsNil() || done {
                break;
            }
        }
        let status = match acc.windows(2).position(|w| w == b"\r\n") {
            Some(i) => string::from_bytes(&acc[..i + 2]),
            None => string::new(),
        };
        chk(&mut ln_no, &fmt::Sprintf!("%-14s limit=%-8d pad=%-8d count=%-6d %q",
            string::from(*name), *limit, *pad as int, *count as int, status));

        let _ = c.Close();
        let _ = srv.Close();
    }
    if ln_no != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln_no as int, GO.len() as int);
    }
    goish::os::Exit(0);
}
