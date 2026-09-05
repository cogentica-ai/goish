// http_keepalives_enabled_smoke — SetKeepAlivesEnabled(false) must
// actually stop connection reuse.
//
// Reference: Go 1.25.5 net/http, measured by
// tools/gen_keepalives_ref.go.
//
// `Server.SetKeepAlivesEnabled` stored a flag that nothing read.
// `doKeepAlives` — the only reader of it, anchored to
// server.go:3650 — was called from nowhere, while Go consults it twice
// per request: once in chunkWriter.writeHeader (server.go:1301) to
// decide the Connection header, and once in conn.serve
// (server.go:2127) to decide whether to go round the loop again. So an
// operator draining a server, or one that simply does not want
// keep-alives, got connections reused anyway and no indication that the
// setting had been ignored.
//
// Two things are observable here and they are NOT the same: the
// Connection header the server sends, and whether a second request on
// the same socket is answered. The reference measures both because
// Go's answers diverge on one row.
//
// That row is `enabled=false proto=1.0`, which still says
// `Connection: keep-alive` and still refuses to reuse. It is not a
// mistake in the capture. Go's writeHeader adds the 1.0 keep-alive
// header off `wants10KeepAlive` alone, ungated by keepAlivesEnabled,
// while closeAfterReply is gated — so the header is a leftover courtesy
// and the connection closes under it. A fix that gated the header on
// doKeepAlives too would look more principled and would diverge from Go
// on exactly this line.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::goslice::slice;
use goish::io::{Closer, Reader, Writer};
use goish::gostring::string;
use goish::net;
use goish::net::http;
use goish::types::{byte, int};
use goish::{fmt, go, time};

const GO: [&str; 4] = [
    "enabled=true  proto=1.1 connection=\"\"         reused=true",
    "enabled=true  proto=1.0 connection=\"keep-alive\" reused=true",
    "enabled=false proto=1.1 connection=\"close\"    reused=false",
    "enabled=false proto=1.0 connection=\"keep-alive\" reused=false",
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

/// Read until `raw` holds a complete response head plus `body` bytes,
/// or the deadline kills the read.
fn read_response(conn: &mut net::TCPConn, body: usize) -> alloc::vec::Vec<u8> {
    let mut raw: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 1024]);
    loop {
        let (n, e) = conn.Read(&mut buf);
        if n > 0 {
            raw.extend_from_slice(&buf.as_ref()[..n as usize]);
        }
        if n <= 0 || !e.IsNil() {
            return raw;
        }
        if let Some(i) = find(&raw, b"\r\n\r\n") {
            if raw.len() >= i + 4 + body {
                return raw;
            }
        }
    }
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

/// The `Connection:` header value, or "" when the server sent none.
fn connection_header(raw: &[u8]) -> string {
    let head = match find(raw, b"\r\n\r\n") {
        Some(i) => &raw[..i + 2],
        None => raw,
    };
    let text = string::from_bytes(head);
    for line in goish::strings::Split(text, string::from("\r\n")).iter() {
        if goish::strings::HasPrefix(line.clone(), string::from("Connection:")) {
            return goish::strings::TrimSpace(
                goish::strings::TrimPrefix(line.clone(), string::from("Connection:")));
        }
    }
    return string::new();
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
    for enabled in [true, false].iter() {
        for proto in ["1.1", "1.0"].iter() {
            let mux = http::ServeMux::new();
            mux.HandleFunc(string::from("/"), |w, _r| {
                let _ = w.Write(goish::convert::bytes(string::from("hi")));
            });
            let mut srv = http::Server::default();
            srv.Handler = Arc::new(mux) as Arc<dyn http::Handler>;
            let srv = Arc::new(srv);
            srv.SetKeepAlivesEnabled(*enabled);

            let (ln, err) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
            if !err.IsNil() {
                fmt::Printf!("[!!] listen: %v\n", err);
                goish::os::Exit(1);
            }
            let addr = ln.Addr().String();
            let s2 = srv.clone();
            go!(stack(256 * 1024), move || {
                let _ = s2.Serve(ln);
            });
            time::Sleep(time::Millisecond * 50);

            let (mut conn, derr) = net::Dial(string::from("tcp"), addr);
            if !derr.IsNil() {
                fmt::Printf!("[!!] dial: %v\n", derr);
                goish::os::Exit(1);
            }
            let _ = conn.SetReadDeadline(time::Now().Add(time::Second * 2));

            let mut req = string::from("GET / HTTP/") + string::from(*proto)
                + string::from("\r\nHost: x\r\n");
            if *proto == "1.0" {
                req = req + string::from("Connection: keep-alive\r\n");
            }
            req = req + string::from("\r\n");

            let _ = conn.Write(goish::convert::bytes(req.clone()));
            let raw = read_response(&mut conn, 2);
            let connv = connection_header(&raw);

            // The property that matters: is a second request on the
            // same socket answered?
            let _ = conn.SetReadDeadline(time::Now().Add(time::Second * 1));
            let _ = conn.Write(goish::convert::bytes(req));
            let second = read_response(&mut conn, 2);
            let reused = second.len() >= 4 && &second[..4] == b"HTTP";

            chk(&mut ln_no, &fmt::Sprintf!("enabled=%-5v proto=%s connection=%-10q reused=%v",
                *enabled, string::from(*proto), connv, reused));

            let _ = conn.Close();
            let _ = srv.Close();
        }
    }
    if ln_no != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln_no as int, GO.len() as int);
    }
    goish::os::Exit(0);
}
