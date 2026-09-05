// http_leading_crlf_smoke — stray CRLF before a request line, after a
// POST, must be tolerated.
//
// Reference: Go 1.25.5 net/http, tools/gen_leadingcrlf_ref.go.
//
// Go peeks four bytes and discards `numLeadingCRorLF(peek)` before
// reading the next request — but ONLY when the previous request on the
// connection was a POST: "RFC 7230 section 3 tolerance for old buggy
// clients" (server.go:1036). goish had numLeadingCRorLF ported and
// anchored and called from nowhere, and tracked no last method, so the
// stray bytes reached the request-line parser and the connection got a
// 400.
//
// The shape is a real one: an old client sends a POST whose body is
// followed by a CRLF that is not part of it, and the next request on
// the keep-alive connection starts with those bytes.
//
// Go's two answers, and the pair is the whole test:
//
//   after=POST  HTTP/1.1 200 OK
//   after=GET   HTTP/1.1 400 Bad Request
//
// The GET row is why this cannot be fixed by skipping leading CRLF
// unconditionally. Go is deliberately strict everywhere else, because
// leading blank lines before a request line are otherwise a request
// smuggling primitive: a proxy that skips them and an origin that does
// not disagree about where one request ends and the next begins.
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

const GO: [&str; 2] = [
    "after=POST  second-request: \"HTTP/1.1 200 OK\\r\\n\"",
    "after=GET   second-request: \"HTTP/1.1 400 Bad Request\\r\\n\"",
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

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    for i in 0..=(hay.len() - needle.len()) {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    return None;
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
    let mut ln_no: usize = 0;
    for first in ["POST", "GET"].iter() {
        let mux = http::ServeMux::new();
        mux.HandleFunc(string::from("/"), |w, r| {
            let body = string::from("ok:") + r.Method.clone();
            let _ = w.Write(goish::convert::bytes(body));
        });
        let mut srv = http::Server::default();
        srv.Handler = Arc::new(mux) as Arc<dyn http::Handler>;
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
        let _ = c.SetReadDeadline(time::Now().Add(time::Second * 2));

        let req1: &[u8] = if *first == "POST" {
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi"
        } else {
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
        };
        let _ = c.Write(slice::__from_vec(req1.to_vec()));

        // Drain the first response exactly: head plus its declared
        // body, so none of it leaks into the line read below.
        let mut raw: Vec<u8> = Vec::new();
        let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 512]);
        loop {
            let (n, e) = c.Read(&mut buf);
            if n > 0 {
                raw.extend_from_slice(&buf.as_ref()[..n as usize]);
            }
            if n <= 0 || !e.IsNil() {
                break;
            }
            if let Some(i) = find(&raw, b"\r\n\r\n") {
                // "ok:POST" is 7, "ok:GET" is 6.
                let want = if *first == "POST" { 7 } else { 6 };
                if raw.len() >= i + 4 + want {
                    break;
                }
            }
        }

        // The second request, preceded by the stray bytes.
        let _ = c.Write(slice::__from_vec(
            b"\r\n\r\nGET /second HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        ));
        let mut resp2: Vec<u8> = Vec::new();
        loop {
            let (n, e) = c.Read(&mut buf);
            if n > 0 {
                resp2.extend_from_slice(&buf.as_ref()[..n as usize]);
            }
            if n <= 0 || !e.IsNil() || find(&resp2, b"\r\n").is_some() {
                break;
            }
        }
        let status = match find(&resp2, b"\r\n") {
            Some(i) => string::from_bytes(&resp2[..i + 2]),
            None => string::new(),
        };
        chk(&mut ln_no, &fmt::Sprintf!("after=%-5s second-request: %q",
            string::from(*first), status));

        let _ = c.Close();
        let _ = srv.Close();
    }
    if ln_no != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln_no as int, GO.len() as int);
    }
    goish::os::Exit(0);
}
