// http_multirange_smoke — a multi-range request over the wire.
//
// Reference: Go 1.25.5 net/http, tools/gen_multirange_ref.go — the
// whole response, byte for byte, with the random boundary and the Date
// normalised.
//
// `rangesMIMESize` is on the never-called list and is NOT a defect:
// Go must precompute the encoded length because it streams the
// multipart body through an io.Pipe, while goish builds it into a
// buffer and takes its length, which is exact by construction.
// http_range_smoke already checks the function itself against Go
// (521 bytes for its case).
//
// What nothing checked is the part this replaces: whether goish's
// multipart/byteranges response is the same as Go's. Content-Length is
// self-consistent either way — goish measures what it built — so a
// difference in the part headers, their order, or the boundary
// delimiters would produce a perfectly coherent response that is not
// Go's, and no existing test looks at it.
//
// The single-range row is here as the control: it takes the other
// branch entirely (Content-Range on the response, no multipart), so a
// change that broke the multipart encoder alone would still show one
// green line.
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

const GO: [&str; 3] = [
    "range=bytes=0-9,20-29      HTTP/1.1 206 Partial Content\\r\\nAccept-Ranges: bytes\\r\\nConnection: close\\r\\nContent-Length: 364\\r\\nContent-Type: multipart/byteranges; boundary=BOUNDARY\\r\\nDate: DATE\\r\\n\\r\\n--BOUNDARY\\r\\nContent-Range: bytes 0-9/36\\r\\nContent-Type: text/plain; charset=utf-8\\r\\n\\r\\n0123456789\\r\\n--BOUNDARY\\r\\nContent-Range: bytes 20-29/36\\r\\nContent-Type: text/plain; charset=utf-8\\r\\n\\r\\nklmnopqrst\\r\\n--BOUNDARY--\\r\\n",
    "range=bytes=0-0,5-5,10-10  HTTP/1.1 206 Partial Content\\r\\nAccept-Ranges: bytes\\r\\nConnection: close\\r\\nContent-Length: 485\\r\\nContent-Type: multipart/byteranges; boundary=BOUNDARY\\r\\nDate: DATE\\r\\n\\r\\n--BOUNDARY\\r\\nContent-Range: bytes 0-0/36\\r\\nContent-Type: text/plain; charset=utf-8\\r\\n\\r\\n0\\r\\n--BOUNDARY\\r\\nContent-Range: bytes 5-5/36\\r\\nContent-Type: text/plain; charset=utf-8\\r\\n\\r\\n5\\r\\n--BOUNDARY\\r\\nContent-Range: bytes 10-10/36\\r\\nContent-Type: text/plain; charset=utf-8\\r\\n\\r\\na\\r\\n--BOUNDARY--\\r\\n",
    "range=bytes=0-9            HTTP/1.1 206 Partial Content\\r\\nAccept-Ranges: bytes\\r\\nConnection: close\\r\\nContent-Length: 10\\r\\nContent-Range: bytes 0-9/36\\r\\nContent-Type: text/plain; charset=utf-8\\r\\nDate: DATE\\r\\n\\r\\n0123456789",
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

fn crate_cmp(a: &string, b: &string) -> core::cmp::Ordering {
    return goish::strings::Compare(a.clone(), b.clone()).cmp(&0);
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
    // The same 36 bytes Go's generator served. A strings.Reader is a
    // Reader+Seeker, which is all ServeContent asks for, and keeps the
    // test off the filesystem.
    const BODY: &str = "0123456789abcdefghijklmnopqrstuvwxyz";

    let mux = http::ServeMux::new();
    mux.HandleFunc(string::from("/f.txt"), move |w, r| {
        let mut content = goish::strings::NewReader(string::from(BODY));
        http::ServeContent(
            w,
            goish::gonilable_ref::nilable_ref::new(r),
            string::from("f.txt"),
            time::Time::default(),
            &mut content,
        );
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
    go!(stack(1024 * 1024), move || {
        let _ = s2.Serve(l);
    });
    time::Sleep(time::Millisecond * 50);

    let mut ln_no: usize = 0;
    for rng in ["bytes=0-9,20-29", "bytes=0-0,5-5,10-10", "bytes=0-9"].iter() {
        let (mut c, derr) = net::Dial(string::from("tcp"), addr.clone());
        if !derr.IsNil() {
            fmt::Printf!("[!!] dial: %v\n", derr);
            goish::os::Exit(1);
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Second * 2));
        let req = string::from("GET /f.txt HTTP/1.1\r\nHost: x\r\nRange: ")
            + string::from(*rng)
            + string::from("\r\nConnection: close\r\n\r\n");
        let _ = c.Write(goish::convert::bytes(req));

        let mut raw: Vec<u8> = Vec::new();
        let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 1024]);
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

        // Normalise: the boundary is random and the Date moves. Take
        // the boundary from the Content-Type rather than guessing its
        // shape, so this does not depend on how long goish's is.
        let mut text = string::from_bytes(&raw);
        if let Some(i) = find(&raw, b"boundary=") {
            let rest = &raw[i + 9..];
            let end = find(rest, b"\r\n").unwrap_or(rest.len());
            let b = string::from_bytes(&rest[..end]);
            text = goish::strings::ReplaceAll(text, b, string::from("BOUNDARY"));
        }
        // Date: one line, replaced wholesale. Then the header block
        // is SORTED, on both sides — goish emits Connection inside its
        // sorted header map while Go appends it last through
        // extraHeader. Header order is not significant in HTTP and the
        // subject here is the multipart body, so the order is
        // normalised rather than compared. The divergence is real and
        // recorded in the ROADMAP; it is not hidden by this.
        let parts = goish::strings::Split(text.clone(), string::from("\r\n"));
        let mut outv: Vec<string> = Vec::new();
        for p in parts.iter() {
            if goish::strings::HasPrefix(p.clone(), string::from("Date: ")) {
                outv.push(string::from("Date: DATE"));
            } else {
                outv.push(p.clone());
            }
        }
        // The head ends at the first empty element (the blank line).
        let mut head_end = outv.len();
        for (i, p) in outv.iter().enumerate() {
            if p.Len() == 0 {
                head_end = i;
                break;
            }
        }
        if head_end > 1 {
            let mut hdrs: Vec<string> = outv[1..head_end].to_vec();
            hdrs.sort_by(|a, b| crate_cmp(a, b));
            for (i, h) in hdrs.iter().enumerate() {
                outv[1 + i] = h.clone();
            }
        }
        let mut joined = string::new();
        for (i, p) in outv.iter().enumerate() {
            if i > 0 {
                joined = joined + string::from("\\r\\n");
            }
            joined = joined + p.clone();
        }
        chk(&mut ln_no, &fmt::Sprintf!("range=%-20s %s", string::from(*rng), joined));
    }

    let _ = srv.Close();
    if ln_no != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln_no as int, GO.len() as int);
    }
    goish::os::Exit(0);
}
