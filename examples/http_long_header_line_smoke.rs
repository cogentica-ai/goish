// http_long_header_line_smoke — one response header line longer than
// the read buffer must still arrive.
//
// Reference: Go 1.25.5 net/http, tools/gen_bufsize_ref.go.
//
// goish read response header lines with a single `bufio.ReadSlice`
// and surfaced its ErrBufferFull, so a response carrying one header
// line over ~4 KiB failed the WHOLE request with "bufio: buffer full".
// Go reads them through textproto, whose readLineSlice loops on
// `bufio.ReadLine`'s `more` flag and accumulates.
//
// Not an edge case: a large Set-Cookie, a CSP policy or a
// Server-Timing list all pass 4 KiB routinely. And the failure was not
// "the header is truncated" — the response was lost entirely.
//
// Go's answers, all three measured:
//
//   readbuf=0      hdr=8000   status=200 longlen=8000
//   readbuf=16384  hdr=8000   status=200 longlen=8000
//   readbuf=0      hdr=64000  status=200 longlen=64000
//
// That pair is why the fix is in the line reader and not in the
// buffer. `Transport.ReadBufferSize` sizes the reader for efficiency;
// it does not decide whether a long line is legal, and Go accepts the
// same 8000-byte line at either setting. goish's ReadBufferSize is
// still inert — recorded in the ROADMAP — and this smoke pins that
// the answer does not depend on it.
//
// The 64 KiB case is here because the fix must keep accumulating past
// one extra buffer's worth, not just handle a single overflow.
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

fn serve(n: usize) -> string {
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
            let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4096]);
            let _ = c.Read(&mut buf);
            let mut head: Vec<u8> = Vec::new();
            head.extend_from_slice(b"HTTP/1.1 200 OK\r\nX-Long: ");
            for _ in 0..n {
                head.push(b'a');
            }
            head.extend_from_slice(b"\r\nContent-Length: 2\r\n\r\nhi");
            let _ = c.Write(slice::__from_vec(head));
            let _ = c.Close();
        }
    });
    time::Sleep(time::Millisecond * 50);
    return string::from("http://") + addr + string::from("/");
}

fn probe(url: string, readbuf: int, want: usize) -> bool {
    let mut tr = http::Transport::default();
    tr.ReadBufferSize = readbuf;
    let mut c = http::Client::default();
    c.Transport = alloc::sync::Arc::new(tr);
    c.Timeout = time::Second * 10;
    let (req, _) = http::NewRequest("GET", url, goish::nil);
    let (mut resp, err) = c.Do(&req);
    if !err.IsNil() {
        fmt::Printf!("[!!] readbuf=%-6d err=%v\n", readbuf, err);
        return false;
    }
    let got = resp.Header.Get(string::from("X-Long")).Len() as usize;
    let _ = goish::io::Closer::Close(&mut resp.Body);
    if resp.StatusCode != 200 || got != want {
        fmt::Printf!("[!!] readbuf=%-6d status=%d longlen=%d, want 200/%d\n",
            readbuf, resp.StatusCode, got as int, want as int);
        return false;
    }
    fmt::Printf!("ok   readbuf=%-6d status=200 longlen=%d\n", readbuf, got as int);
    return true;
}

fn run() {
    let mut bad = 0;
    // Go's two pinned rows: the same 8000-byte line at the default and
    // at a raised buffer.
    let url = serve(8000);
    if !probe(url.clone(), 0, 8000) {
        bad += 1;
    }
    if !probe(url, 16384, 8000) {
        bad += 1;
    }
    // Well past a second buffer, so the accumulation loop has to run
    // more than once. Go accepts this one too — measured, not assumed.
    let url2 = serve(64000);
    if !probe(url2, 0, 64000) {
        bad += 1;
    }

    if bad == 0 {
        fmt::Printf!("\nok 3/3\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d\n", bad as int);
    goish::os::Exit(1);
}
