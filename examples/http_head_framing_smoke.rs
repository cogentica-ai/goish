// http_head_framing_smoke — what a HEAD response looks like on the
// wire.
//
// Reference: Go 1.25.5 net/http, tools/gen_head_ref.go.
//
// A HEAD reply must carry the headers a GET would, including
// Content-Length, and NO body. This is framing, not cosmetics: a body
// on a HEAD leaves bytes in the stream that the next request on a
// keep-alive connection reads as its own, which is a response-splitting
// desync.
//
// Five rows, five different decisions, and three of them are easy to
// get wrong in ways that still look plausible:
//
//   head-writes-body   the handler wrote 11 bytes: Content-Length is 11
//                      and the body is suppressed. Counting what was
//                      NOT sent is the whole trick.
//   get-writes-body    the control — identical headers, body present.
//                      Without it, a server that dropped every body
//                      would pass the rest.
//   head-empty         the handler wrote nothing: Go sends NO
//                      Content-Length at all, not "Content-Length: 0".
//   head-explicit-cl   a handler-set Content-Length survives.
//   head-wrong-cl      a handler-set Content-Length survives EVEN WHEN
//                      it contradicts what the handler wrote — 999
//                      against two bytes. Go does not correct it,
//                      because on a HEAD the handler is declaring what
//                      a GET would return, and only the handler knows.
//
// Date is normalised and the header block sorted on both sides.
// Since ROADMAP 2i goish's wire order matches Go's — pinned by
// http_header_order_ref_smoke — that sort is now redundant rather
// than load-bearing. It is kept only because this smoke's
// reference was transcribed sorted, and order is not what it
// measures.
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

const GO: [&str; 5] = [
    "head-writes-body   \"HTTP/1.1 200 OK\\\\r\\\\nConnection: close\\\\r\\\\nContent-Length: 11\\\\r\\\\nContent-Type: text/plain; charset=utf-8\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\n\"",
    "get-writes-body    \"HTTP/1.1 200 OK\\\\r\\\\nConnection: close\\\\r\\\\nContent-Length: 11\\\\r\\\\nContent-Type: text/plain; charset=utf-8\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\nhello world\"",
    "head-empty         \"HTTP/1.1 200 OK\\\\r\\\\nConnection: close\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\n\"",
    "head-explicit-cl   \"HTTP/1.1 200 OK\\\\r\\\\nConnection: close\\\\r\\\\nContent-Length: 11\\\\r\\\\nContent-Type: text/plain; charset=utf-8\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\n\"",
    "head-wrong-cl      \"HTTP/1.1 200 OK\\\\r\\\\nConnection: close\\\\r\\\\nContent-Length: 999\\\\r\\\\nContent-Type: text/plain; charset=utf-8\\\\r\\\\nDate: DATE\\\\r\\\\n\\\\r\\\\n\"",
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
    let cases: [(&str, &str, &str, &str); 5] = [
        ("head-writes-body", "HEAD", "hello world", ""),
        ("get-writes-body", "GET", "hello world", ""),
        ("head-empty", "HEAD", "", ""),
        ("head-explicit-cl", "HEAD", "hello world", "11"),
        ("head-wrong-cl", "HEAD", "hi", "999"),
    ];
    let mut ln_no: usize = 0;
    for (name, method, body, set_cl) in cases.iter() {
        let mux = http::ServeMux::new();
        let b = string::from(*body);
        let cl = string::from(*set_cl);
        mux.HandleFunc(string::from("/"), move |w, _r| {
            if cl.Len() > 0 {
                w.Header().Set(string::from("Content-Length"), cl.clone());
            }
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
        let req = string::from(*method)
            + string::from(" / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        let _ = c.Write(goish::convert::bytes(req));

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

        // Normalise Date, then sort the header block. See the note above.
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
        chk(&mut ln_no, &fmt::Sprintf!("%-18s %q", string::from(*name), joined));
    }
    if ln_no != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln_no as int, GO.len() as int);
    }
    goish::os::Exit(0);
}
