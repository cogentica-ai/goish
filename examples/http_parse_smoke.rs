// http_parse_smoke — exercise the M27c http::ReadRequest parser
// over a real TCP loopback connection.
//
// Server side: bufio.NewReader(conn) → http::ReadRequest → assert
// fields. Client side: synthesize a raw HTTP/1.1 request and write
// it onto the wire.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use goish::bufio;
use goish::io::{Closer, Writer};
use goish::net;
use goish::net::http;
use goish::runtime::sched::schedule;
use goish::{bytes, go, string, syscall, KB};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    check(err.IsNil(), b"net.Listen failed\n");
    let port = ln.Addr().Port;

    static CLIENT_PORT: AtomicI32 = AtomicI32::new(0);
    static CLIENT_DONE: AtomicUsize = AtomicUsize::new(0);
    CLIENT_PORT.store(port as i32, Ordering::Release);

    go!(stack(16 * KB), || {
        // Build the dial address.
        let p = CLIENT_PORT.load(Ordering::Acquire) as u32;
        let mut addr_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(24);
        addr_buf.extend_from_slice(b"127.0.0.1:");
        let mut tmp = [0u8; 6];
        let mut i = tmp.len();
        let mut n = p;
        if n == 0 {
            i -= 1;
            tmp[i] = b'0';
        } else {
            while n > 0 {
                i -= 1;
                tmp[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        addr_buf.extend_from_slice(&tmp[i..]);
        let addr = string::from_bytes(&addr_buf);

        let (mut conn, err) = net::Dial(string("tcp"), addr);
        if !err.IsNil() {
            die(b"Dial failed\n");
        }

        // POST request with body. Build via concat so leading
        // whitespace doesn't sneak into the wire bytes.
        let mut req_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(256);
        req_buf.extend_from_slice(b"POST /api/echo?q=1 HTTP/1.1\r\n");
        req_buf.extend_from_slice(b"Host: example.com\r\n");
        req_buf.extend_from_slice(b"User-Agent: goish-test\r\n");
        req_buf.extend_from_slice(b"Content-Type: application/json\r\n");
        req_buf.extend_from_slice(b"Content-Length: 13\r\n");
        req_buf.extend_from_slice(b"\r\n");
        req_buf.extend_from_slice(b"{\"hello\":1}\r\n");
        let req_str = string::from_bytes(&req_buf);
        let req_len = req_str.Len() as usize;
        let (n, err) = conn.Write(bytes(req_str));
        if !err.IsNil() || n as usize != req_len {
            die(b"client Write failed\n");
        }
        // Half-close write so the server's body Read sees EOF cleanly.
        let _ = conn.CloseWrite();
        let _ = conn.Close();
        CLIENT_DONE.store(1, Ordering::Release);
    });

    let (conn, err) = ln.Accept();
    check(err.IsNil(), b"Accept failed\n");

    let mut br = bufio::NewReader(conn);
    let (req, err) = http::ReadRequest(&mut br);
    check(err.IsNil(), b"ReadRequest failed\n");

    check(req.Method == "POST", b"Method != POST\n");
    check(req.URL.Path == "/api/echo", b"URL.Path != /api/echo\n");
    check(req.URL.RawQuery == "q=1", b"URL.RawQuery != q=1\n");
    check(req.Proto == "HTTP/1.1", b"Proto != HTTP/1.1\n");
    check(req.ProtoMajor == 1 && req.ProtoMinor == 1, b"version != 1.1\n");
    check(req.Host == "example.com", b"Host != example.com\n");

    let ua = req.Header.Get(string("User-Agent"));
    check(ua == "goish-test", b"User-Agent missing\n");

    let ct = req.Header.Get(string("content-type")); // case-insensitive
    check(ct == "application/json", b"Content-Type lookup failed\n");

    check(req.ContentLength == 13, b"ContentLength != 13\n");

    let body: &[u8] = &*req.Body;
    if body != b"{\"hello\":1}\r\n" {
        // Diagnostic dump.
        let pre: &[u8] = b"got body (len=";
        syscall::Write(syscall::STDERR, pre.as_ptr(), pre.len());
        let mut tmp = [0u8; 8];
        let mut n = body.len();
        let mut i = tmp.len();
        if n == 0 {
            i -= 1;
            tmp[i] = b'0';
        } else {
            while n > 0 {
                i -= 1;
                tmp[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        syscall::Write(syscall::STDERR, tmp[i..].as_ptr(), tmp.len() - i);
        let mid: &[u8] = b"): [";
        syscall::Write(syscall::STDERR, mid.as_ptr(), mid.len());
        syscall::Write(syscall::STDERR, body.as_ptr(), body.len());
        let suf: &[u8] = b"]\n";
        syscall::Write(syscall::STDERR, suf.as_ptr(), suf.len());
        die(b"Body bytes wrong\n");
    }

    while CLIENT_DONE.load(Ordering::Acquire) == 0 {
        goish::runtime::sched::Gosched();
    }
    let _ = ln.Close();

    let ok: &[u8] = b"http_parse_smoke: ok\n";
    syscall::Write(syscall::STDOUT, ok.as_ptr(), ok.len());

    schedule();
}
