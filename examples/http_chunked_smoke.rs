// http_chunked_smoke — exercise HTTP/1.1 chunked Transfer-Encoding
// in both directions:
//
//   1. Request body uploaded with `Transfer-Encoding: chunked` is
//      assembled correctly from the wire by ReadRequest.
//
//   2. ResponseWriter::Flush() switches the response into chunked
//      mode; the client (a goish goroutine using net::Dial) sees a
//      `Transfer-Encoding: chunked` head and decodes individual
//      chunks back into the expected body.
//
// Pass criteria: every named subtest prints "PASS"; final "ok" line.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::time;
use goish::{bytes, go, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Direct ChunkedReader/Writer round-trip via an in-memory
    //    bytes::Buffer. Sanity-check the decoder matches the encoder.
    {
        let mut buf = goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(Vec::new()));
        {
            let mut cw = http::internal::chunked::NewChunkedWriter(&mut buf);
            let _ = cw.Write(bytes("hello "));
            let _ = cw.Write(bytes("world"));
            let _ = cw.Close();
        }
        // Wire dump so we can assert chunk sizes.
        let wire = buf.Bytes();
        let mut got = Vec::new();
        for i in 0..wire.Len() {
            got.push(wire[i]);
        }
        // Expected: "6\r\nhello \r\n5\r\nworld\r\n0\r\n"
        let expected = b"6\r\nhello \r\n5\r\nworld\r\n0\r\n";
        if got.as_slice() == expected {
            fmt::Println!("[ 1] writer wire format        PASS");
        } else {
            fmt::Println!(
                "[ 1] writer wire format        FAIL got len={} expected len={}",
                got.len(),
                expected.len()
            );
            failed += 1;
        }
    }

    // 2. ChunkedReader decodes what ChunkedWriter wrote. Append the
    //    final CRLF after the "0\r\n" to complete the stream.
    {
        let wire_vec: Vec<u8> = b"6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n".to_vec();
        let buf = goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(wire_vec));
        let mut cr = http::internal::chunked::NewChunkedReader(buf);
        let mut out: Vec<u8> = Vec::new();
        loop {
            let mut dst = goish::goslice::slice::<u8>::__from_vec(alloc::vec![0u8; 32]);
            let (n, err) = cr.Read(&mut dst);
            for i in 0..n {
                out.push(dst[i as i64]);
            }
            if !err.IsNil() {
                break;
            }
            if n == 0 {
                break;
            }
        }
        if out.as_slice() == b"hello world" {
            fmt::Println!("[ 2] reader decode             PASS");
        } else {
            fmt::Println!(
                "[ 2] reader decode             FAIL got {} bytes",
                out.len()
            );
            failed += 1;
        }
    }

    // 3. Live HTTP server: handler calls w.Flush() then writes 3
    //    chunks; client decodes them off the wire. Pass: total body
    //    after chunk-decode equals the concatenation.
    {
        let mux = http::ServeMux::new();
        mux.HandleFunc(string("/stream"), |w, _r| {
            // Go: f, ok := w.(http.Flusher)
            let (f, ok) = goish::cast!(w, http::Flusher);
            if ok {
                f.Flush();
            }
            let _ = w.Write(bytes("AAA"));
            if ok {
                f.Flush();
            }
            let _ = w.Write(bytes("BBB"));
            if ok {
                f.Flush();
            }
            let _ = w.Write(bytes("CCC"));
        });
        let mux_arc: Arc<dyn http::Handler> = Arc::new(mux);
        let mut srv = http::Server::default();
        srv.Handler = mux_arc;
        let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if !err.IsNil() {
            fmt::Println!("[ 3] Listen FAIL");
            failed += 1;
        } else {
            let addr = ln.Addr().String();
            let srv_arc = Arc::new(srv);
            let srv_for_serve = srv_arc.clone();
            go!(move || {
                let _ = srv_for_serve.Serve(ln);
            });
            time::Sleep(time::Millisecond * 20);

            let (mut conn, derr) = net::Dial(string("tcp"), addr);
            if !derr.IsNil() {
                fmt::Println!("[ 3] Dial FAIL");
                failed += 1;
            } else {
                let _ = conn.Write(bytes(
                    "GET /stream HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
                ));
                let mut whole: Vec<u8> = Vec::new();
                loop {
                    let mut dst = goish::goslice::slice::<u8>::__from_vec(alloc::vec![0u8; 1024]);
                    let (n, e) = conn.Read(&mut dst);
                    for i in 0..(n as usize) {
                        whole.push(dst[i as i64]);
                    }
                    if n == 0 || !e.IsNil() {
                        break;
                    }
                }
                let _ = conn.Close();

                // Find header/body split.
                let split = find_marker(&whole, b"\r\n\r\n");
                match split {
                    None => {
                        fmt::Println!("[ 3] streaming response        FAIL no head/body split");
                        failed += 1;
                    }
                    Some(i) => {
                        let head = &whole[..i];
                        let body_wire = &whole[i + 4..];
                        let has_te = find_marker_ci(head, b"transfer-encoding: chunked").is_some();
                        // Decode the chunked body off the wire.
                        let decoded = decode_chunked(body_wire);
                        if has_te && decoded.as_slice() == b"AAABBBCCC" {
                            fmt::Println!("[ 3] streaming response        PASS");
                        } else {
                            fmt::Println!(
                                "[ 3] streaming response        FAIL has_te={} decoded.len={}",
                                has_te,
                                decoded.len()
                            );
                            failed += 1;
                        }
                    }
                }
            }
            let srv_for_shut = srv_arc.clone();
            let _ = srv_for_shut.Shutdown(time::Second);
        }
    }

    // 4. Chunked request body upload: client sends a chunked body,
    //    handler reports req.Body and ContentLength=-1.
    {
        let result_len = Arc::new(AtomicUsize::new(0));
        let result_cl = Arc::new(core::sync::atomic::AtomicI64::new(99999));
        let result_match = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let len_h = result_len.clone();
        let cl_h = result_cl.clone();
        let match_h = result_match.clone();

        let mux = http::ServeMux::new();
        mux.HandleFunc(string("/upload"), move |w, r| {
            let (rbody, _) = goish::io::ReadAll(&mut r.Body.clone());
            len_h.store(rbody.Len() as usize, Ordering::SeqCst);
            cl_h.store(r.ContentLength as i64, Ordering::SeqCst);
            let body = &rbody;
            let expected = b"hello world!";
            let mut ok = body.Len() as usize == expected.len();
            if ok {
                for i in 0..expected.len() {
                    if body[i as i64] != expected[i] {
                        ok = false;
                        break;
                    }
                }
            }
            match_h.store(if ok { 1 } else { 0 }, Ordering::SeqCst);
            let _ = w.Write(bytes("ack\n"));
        });
        let mux_arc: Arc<dyn http::Handler> = Arc::new(mux);
        let mut srv = http::Server::default();
        srv.Handler = mux_arc;
        let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if !err.IsNil() {
            fmt::Println!("[ 4] Listen FAIL");
            failed += 1;
        } else {
            let addr = ln.Addr().String();
            let srv_arc = Arc::new(srv);
            let srv_for_serve = srv_arc.clone();
            go!(move || {
                let _ = srv_for_serve.Serve(ln);
            });
            time::Sleep(time::Millisecond * 20);

            let (mut conn, derr) = net::Dial(string("tcp"), addr);
            if !derr.IsNil() {
                fmt::Println!("[ 4] Dial FAIL");
                failed += 1;
            } else {
                // POST with chunked body: "hello " then "world!".
                let req = b"POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nhello \r\n6\r\nworld!\r\n0\r\n\r\n";
                let _ = conn.Write(goish::goslice::slice::<u8>::__from_vec(req.to_vec()));
                // Drain response so server can complete the request cycle.
                let mut whole: Vec<u8> = Vec::new();
                loop {
                    let mut dst = goish::goslice::slice::<u8>::__from_vec(alloc::vec![0u8; 256]);
                    let (n, e) = conn.Read(&mut dst);
                    for i in 0..(n as usize) {
                        whole.push(dst[i as i64]);
                    }
                    if n == 0 || !e.IsNil() {
                        break;
                    }
                }
                let _ = conn.Close();
                // Wait for handler to record the result.
                time::Sleep(time::Millisecond * 30);

                let body_len = result_len.load(Ordering::SeqCst);
                let cl = result_cl.load(Ordering::SeqCst);
                let m = result_match.load(Ordering::SeqCst);
                if body_len == 12 && cl == -1 && m == 1 {
                    fmt::Println!("[ 4] chunked request upload    PASS");
                } else {
                    fmt::Println!(
                        "[ 4] chunked request upload    FAIL body_len={} cl={} match={}",
                        body_len,
                        cl,
                        m
                    );
                    failed += 1;
                }
            }
            let srv_for_shut = srv_arc.clone();
            let _ = srv_for_shut.Shutdown(time::Second);
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 4", failed);
        syscall::Exit(1);
    }
}

fn find_marker(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    for i in 0..=hay.len() - needle.len() {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

fn find_marker_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    for i in 0..=hay.len() - needle.len() {
        let mut ok = true;
        for j in 0..needle.len() {
            if (hay[i + j] | 0x20) != (needle[j] | 0x20) {
                ok = false;
                break;
            }
        }
        if ok {
            return Some(i);
        }
    }
    None
}

/// Tiny in-test chunked decoder for what the server emits — we want
/// to verify the wire bytes independently of our own ChunkedReader.
fn decode_chunked(wire: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < wire.len() {
        let crlf = match find_marker(&wire[i..], b"\r\n") {
            Some(off) => i + off,
            None => return out,
        };
        let size_str = &wire[i..crlf];
        let mut size: usize = 0;
        for &b in size_str {
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return out,
            };
            size = (size << 4) | (d as usize);
        }
        i = crlf + 2;
        if size == 0 {
            return out;
        }
        if i + size > wire.len() {
            return out;
        }
        out.extend_from_slice(&wire[i..i + size]);
        i += size + 2; // consume CRLF after data
    }
    out
}
