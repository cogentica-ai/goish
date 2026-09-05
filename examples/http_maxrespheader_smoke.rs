// http_maxrespheader_smoke — Transport.MaxResponseHeaderBytes must
// bound the response head.
//
// Reference: Go 1.25.5 net/http, tools/gen_maxrespheader_ref.go, same
// four limits against the same hostile server.
//
// `MaxResponseHeaderBytes` was a public field that only `Clone` and
// `maxHeaderResponseSize` ever read, and nothing called
// `maxHeaderResponseSize`. So the setting did nothing — and Go's
// default when the field is UNSET is 10 MiB, "conservative default;
// same as http2", so goish was not merely ignoring a user's setting,
// it had no bound at all where Go always has one.
//
// The server here sends 20000 SHORT headers. That shape is the point:
// a single header line was already bounded, by bufio's buffer through
// ReadSlice, and no line here comes close to it. The TOTAL was
// unbounded, so a hostile or broken server could grow a goish client's
// Header map until the process died — with the client having asked for
// a limit and been given none.
//
// limit=0 and limit=1MiB must SUCCEED: about 340 KiB of headers fits
// under both the explicit megabyte and the 10 MiB default. A fix that
// bounded everything at some fixed size would pass the two error cases
// and fail these.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::types::{byte, int};
use goish::{fmt, go, time};

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
    let (ln, lerr) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
    if !lerr.IsNil() {
        fmt::Printf!("[!!] listen: %v\n", lerr);
        goish::os::Exit(1);
    }
    let addr = ln.Addr().String();

    go!(stack(512 * 1024), move || {
        loop {
            let (mut c, e) = ln.Accept();
            if !e.IsNil() {
                return;
            }
            // Read the request line and headers, then answer with a
            // head far larger than any single line.
            let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4096]);
            let _ = c.Read(&mut buf);
            let mut head: Vec<u8> = Vec::new();
            head.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
            for i in 0..20000 {
                head.extend_from_slice(b"X-Pad-");
                let n = goish::strconv::Itoa(i as i64);
                head.extend_from_slice(goish::convert::bytes(n).as_ref());
                head.extend_from_slice(b": 0123456789\r\n");
            }
            head.extend_from_slice(b"Content-Length: 2\r\n\r\nhi");
            let _ = c.Write(slice::__from_vec(head));
            let _ = c.Close();
        }
    });
    time::Sleep(time::Millisecond * 50);

    let url = string::from("http://") + addr + string::from("/");
    let mut bad = 0;
    let cases: [(i64, bool); 4] = [
        (0, true),
        (1 << 10, false),
        (1 << 16, false),
        (1 << 20, true),
    ];
    for (limit, want_ok) in cases.iter() {
        let mut tr = http::Transport::default();
        tr.MaxResponseHeaderBytes = *limit;
        let mut c = http::Client::default();
        c.Transport = alloc::sync::Arc::new(tr);
        c.Timeout = time::Second * 10;

        let (req, _) = http::NewRequest("GET", url.clone(), goish::nil);
        let (mut resp, err) = c.Do(&req);
        if *want_ok {
            if err.IsNil() && resp.StatusCode == 200 {
                fmt::Printf!("ok   limit=%-8d status=200\n", *limit);
                let _ = goish::io::Closer::Close(&mut resp.Body);
            } else {
                fmt::Printf!("[!!] limit=%d: wanted success, got %v\n", *limit, err);
                bad += 1;
            }
            continue;
        }
        if err.IsNil() {
            fmt::Printf!("[!!] limit=%d: wanted the limit to fire, got status %d\n",
                *limit, resp.StatusCode);
            bad += 1;
            continue;
        }
        let msg = err.Error();
        let m: &str = msg.as_ref();
        let want = string::from("server response headers exceeded ")
            + goish::strconv::Itoa(*limit)
            + string::from(" bytes; aborted");
        let w: &str = want.as_ref();
        if m.contains(w) {
            fmt::Printf!("ok   limit=%-8d refused: %v\n", *limit, err);
        } else {
            fmt::Printf!("[!!] limit=%d: wrong error: %v\n", *limit, err);
            bad += 1;
        }
    }

    if bad == 0 {
        fmt::Printf!("\nok 4/4\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d\n", bad as int);
    goish::os::Exit(1);
}
