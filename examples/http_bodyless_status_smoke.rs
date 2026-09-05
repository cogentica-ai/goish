// http_bodyless_status_smoke — statuses that allow no body.
//
// Reference: Go 1.25.5 net/http, tools/gen_bodyless_ref.go.
//
// 204, 304 and 1xx must carry neither a body nor a Content-Length. The
// framing matters more than the pedantry: a 304 that announces a
// length the response does not contain leaves the next request on a
// keep-alive connection reading the wrong bytes, which is a desync a
// handler should not be able to cause by accident.
//
// Go's guarantees, and each row is one of them:
//
//   204-clean            no Content-Length, no body
//   204-handler-writes   a handler that writes anyway is IGNORED
//   304-clean            same as 204
//   304-handler-writes   same — the write does not reach the wire
//   304-explicit-cl      a handler-set Content-Length is STRIPPED.
//                        Go does not let the handler announce a length
//                        on a status that cannot carry one.
//   205-reset            205 is NOT bodyless: it gets Content-Length: 0
//   200-empty            the ordinary case, Content-Length: 0
//
// The last two rows are what stop a fix that simply suppressed
// Content-Length everywhere from looking correct: the line between
// "bodyless" and "allowed but empty" runs between 304 and 205.
//
// Date is normalised and the header block sorted on both sides; goish
// orders Connection differently (ROADMAP 2i).
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
    "204-clean            \"HTTP/1.1 204 No Content\\\\r\\\\nConnection: close\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\n\"",
    "204-handler-writes   \"HTTP/1.1 204 No Content\\\\r\\\\nConnection: close\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\n\"",
    "304-clean            \"HTTP/1.1 304 Not Modified\\\\r\\\\nConnection: close\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\n\"",
    "304-handler-writes   \"HTTP/1.1 304 Not Modified\\\\r\\\\nConnection: close\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\n\"",
    "304-explicit-cl      \"HTTP/1.1 304 Not Modified\\\\r\\\\nConnection: close\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\n\"",
    "205-reset            \"HTTP/1.1 205 Reset Content\\\\r\\\\nConnection: close\\\\r\\\\nContent-Length: 0\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\n\"",
    "200-empty            \"HTTP/1.1 200 OK\\\\r\\\\nConnection: close\\\\r\\\\nContent-Length: 0\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\n\"",
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
    let cases: [(&str, int, &str, &str); 7] = [
        ("204-clean", 204, "", ""),
        ("204-handler-writes", 204, "oops", ""),
        ("304-clean", 304, "", ""),
        ("304-handler-writes", 304, "oops", ""),
        ("304-explicit-cl", 304, "", "42"),
        ("205-reset", 205, "", ""),
        ("200-empty", 200, "", ""),
    ];
    let mut ln_no: usize = 0;
    for (name, status, body, set_cl) in cases.iter() {
        let mux = http::ServeMux::new();
        let b = string::from(*body);
        let cl = string::from(*set_cl);
        let st = *status;
        mux.HandleFunc(string::from("/"), move |w, _r| {
            if cl.Len() > 0 {
                w.Header().Set(string::from("Content-Length"), cl.clone());
            }
            w.WriteHeader(st);
            if b.Len() > 0 {
                let _ = w.Write(goish::convert::bytes(b.clone()));
            }
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
        let _ = c.Write(goish::convert::bytes(string::from(
            "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )));
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
        }
        let _ = c.Close();
        let _ = srv.Close();

        let text = string::from_bytes(&raw);
        let parts = goish::strings::Split(text, string::from("\r\n"));
        let mut v: Vec<string> = Vec::new();
        for p in parts.iter() {
            if goish::strings::HasPrefix(p.clone(), string::from("Date: ")) {
                v.push(string::from("Date: DATE"));
            } else {
                v.push(p.clone());
            }
        }
        let mut head_end = v.len();
        for (i, p) in v.iter().enumerate() {
            if p.Len() == 0 {
                head_end = i;
                break;
            }
        }
        if head_end > 1 {
            let mut hdrs: Vec<string> = v[1..head_end].to_vec();
            hdrs.sort_by(|a, b| goish::strings::Compare(a.clone(), b.clone()).cmp(&0));
            for (i, h) in hdrs.iter().enumerate() {
                v[1 + i] = h.clone();
            }
        }
        let mut joined = string::new();
        for (i, p) in v.iter().enumerate() {
            if i > 0 {
                joined = joined + string::from("\\r\\n");
            }
            joined = joined + p.clone();
        }
        chk(&mut ln_no, &fmt::Sprintf!("%-20s %q", string::from(*name), joined));
    }
    if ln_no != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln_no as int, GO.len() as int);
    }
    goish::os::Exit(0);
}
