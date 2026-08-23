// net_smoke — exercise the public goish::net API end-to-end.
//
// Mirrors socket_smoke but goes through the public Go-shaped API
// (`net.Listen`, `Accept`, `Dial`, `Conn.Read/Write`) so we
// validate the M27b boundary discipline (no Vec/&str/&[u8] in
// public signatures) at the call site.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::runtime::sched::schedule;
use goish::{bytes, go, make, string, syscall};

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
    // 1. Listen on 127.0.0.1:0 — kernel picks a port.
    let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    check(err.IsNil(), b"net.Listen failed\n");
    let port = ln.Addr().Port;
    check(port != 0, b"got port == 0\n");

    // 2. Spawn a client goroutine that dials, writes, reads.
    static CLIENT_PORT: AtomicI32 = AtomicI32::new(0);
    static CLIENT_DONE: AtomicUsize = AtomicUsize::new(0);
    CLIENT_PORT.store(port as i32, Ordering::Release);

    go!(|| {
        // Build "127.0.0.1:<port>" and dial.
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
            die(b"net.Dial failed\n");
        }
        // Send a request.
        let (n, err) = conn.Write(bytes("hi\n"));
        if !err.IsNil() || n != 3 {
            die(b"client Write failed\n");
        }
        // Read the reply.
        let mut buf = make!([]u8, 16);
        let (n, err) = conn.Read(&mut buf);
        if !err.IsNil() || n != 4 {
            die(b"client Read failed\n");
        }
        if &(*buf)[..4] != b"pong" {
            die(b"client got wrong bytes\n");
        }
        let _ = conn.Close();
        CLIENT_DONE.store(1, Ordering::Release);
    });

    // 3. Server accepts, reads, writes, closes.
    let (mut conn, err) = ln.Accept();
    check(err.IsNil(), b"Accept failed\n");
    let mut buf = make!([]u8, 32);
    let (n, err) = conn.Read(&mut buf);
    check(err.IsNil() && n == 3, b"server Read short\n");
    check(&(*buf)[..3] == b"hi\n", b"server got wrong bytes\n");
    let (_n, err) = conn.Write(bytes("pong"));
    check(err.IsNil(), b"server Write failed\n");
    let _ = conn.Close();

    // 4. Wait for client + close listener.
    while CLIENT_DONE.load(Ordering::Acquire) == 0 {
        goish::runtime::sched::Gosched();
    }
    let _ = ln.Close();

    let ok: &[u8] = b"net_smoke: ok\n";
    syscall::Write(syscall::STDOUT, ok.as_ptr(), ok.len());

    schedule();
}
