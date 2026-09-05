// http_trailer_ref_smoke — response trailers on the wire.
//
// Reference: Go 1.25.5 net/http, tools/gen_trailer_ref.go.
//
// A trailer must be ANNOUNCED in the Trailer header before the body
// and emitted after the last chunk, which only works under chunked
// encoding. The rows are the four decisions that follow, plus a
// control:
//
//   announced-and-set    announced, set, emitted after the 0 chunk
//   announced-not-set    announced but never set: nothing is emitted,
//                        and the response still terminates cleanly
//   set-not-announced    set but NOT announced: NOT emitted. This is
//                        the row that matters — a value a handler put
//                        in the header map after the head went out
//                        must not appear on the wire unless it was
//                        declared, or a handler could smuggle a header
//                        past anything that read the announced set.
//   no-trailers          plain chunked, the control
//   announced-no-flush   the same as the first: an explicit Flush is
//                        not what makes trailers work
//
// The header block is sorted on both sides (goish orders it
// differently, ROADMAP 2i) and the Date normalised, but the BODY —
// chunk sizes, the terminating 0, and the trailer lines after it — is
// compared verbatim, because that is the framing under test.
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
    "announced-and-set    \"HTTP/1.1 200 OK\\\\r\\\\nConnection: close\\\\r\\\\nContent-Type: text/plain; charset=utf-8\\\\r\\\\nDate: DATE\\\\r\\\\nTrailer: X-Sum\\\\r\\\\nTransfer-Encoding: chunked\\\\r\\\\n\\\\r\\\\n4\\\\r\\\\nbody\\\\r\\\\n0\\\\r\\\\nX-Sum: 42\\\\r\\\\n\\\\r\\\\n\"",
    "announced-not-set    \"HTTP/1.1 200 OK\\\\r\\\\nConnection: close\\\\r\\\\nContent-Type: text/plain; charset=utf-8\\\\r\\\\nDate: DATE\\\\r\\\\nTrailer: X-Sum\\\\r\\\\nTransfer-Encoding: chunked\\\\r\\\\n\\\\r\\\\n4\\\\r\\\\nbody\\\\r\\\\n0\\\\r\\\\n\\\\r\\\\n\"",
    "set-not-announced    \"HTTP/1.1 200 OK\\\\r\\\\nConnection: close\\\\r\\\\nContent-Type: text/plain; charset=utf-8\\\\r\\\\nDate: DATE\\\\r\\\\nTransfer-Encoding: chunked\\\\r\\\\n\\\\r\\\\n4\\\\r\\\\nbody\\\\r\\\\n0\\\\r\\\\n\\\\r\\\\n\"",
    "no-trailers          \"HTTP/1.1 200 OK\\\\r\\\\nConnection: close\\\\r\\\\nContent-Type: text/plain; charset=utf-8\\\\r\\\\nDate: DATE\\\\r\\\\nTransfer-Encoding: chunked\\\\r\\\\n\\\\r\\\\n4\\\\r\\\\nbody\\\\r\\\\n0\\\\r\\\\n\\\\r\\\\n\"",
    "announced-no-flush   \"HTTP/1.1 200 OK\\\\r\\\\nConnection: close\\\\r\\\\nContent-Type: text/plain; charset=utf-8\\\\r\\\\nDate: DATE\\\\r\\\\nTrailer: X-Sum\\\\r\\\\nTransfer-Encoding: chunked\\\\r\\\\n\\\\r\\\\n4\\\\r\\\\nbody\\\\r\\\\n0\\\\r\\\\nX-Sum: 42\\\\r\\\\n\\\\r\\\\n\"",
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
    // (name, announce, set_value, flush)
    let cases: [(&str, &str, &str, bool); 5] = [
        ("announced-and-set", "X-Sum", "42", true),
        ("announced-not-set", "X-Sum", "", true),
        ("set-not-announced", "", "42", true),
        ("no-trailers", "", "", true),
        ("announced-no-flush", "X-Sum", "42", false),
    ];
    let mut ln_no: usize = 0;
    for (name, announce, setv, flush) in cases.iter() {
        let mux = http::ServeMux::new();
        let ann = string::from(*announce);
        let sv = string::from(*setv);
        let fl = *flush;
        mux.HandleFunc(string::from("/"), move |w, _r| {
            if ann.Len() > 0 {
                w.Header().Set(string::from("Trailer"), ann.clone());
            }
            let _ = w.Write(goish::convert::bytes(string::from("body")));
            if fl {
                let (f, ok) = goish::cast!(w, http::Flusher);
                if ok {
                    f.Flush();
                }
            }
            if sv.Len() > 0 {
                w.Header().Set(string::from("X-Sum"), sv.clone());
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
