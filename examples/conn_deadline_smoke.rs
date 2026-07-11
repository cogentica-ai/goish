// conn_deadline_smoke — exercise Conn::SetReadDeadline.
//
// Spawns one server goroutine that accepts and idles. The main
// goroutine dials, SetReadDeadlines 100 ms in the future, and tries
// to Read. Expects "read: i/o timeout" within ~100-1000 ms.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use goish::io::{Closer, Reader};
use goish::net;
use goish::runtime::sched::schedule;
use goish::time;
use goish::{go, make, string, syscall};

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
    check(err.IsNil(), b"Listen failed\n");
    let port = ln.Addr().Port;

    static SERVER_HAS_PEER: AtomicUsize = AtomicUsize::new(0);
    static CLIENT_PORT: AtomicI32 = AtomicI32::new(0);
    static CLIENT_DONE: AtomicUsize = AtomicUsize::new(0);
    CLIENT_PORT.store(port as i32, Ordering::Release);

    // Client side runs in a goroutine so main can hold `ln`.
    go!(|| {
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
        while SERVER_HAS_PEER.load(Ordering::Acquire) == 0 {
            goish::runtime::sched::Gosched();
        }
        let dl = time::Now().Add(time::Millisecond * 100);
        if !conn.SetReadDeadline(dl).IsNil() {
            die(b"SetReadDeadline failed\n");
        }
        let t0 = time::Now();
        let mut buf = make!([]u8, 16);
        let (n, err) = conn.Read(&mut buf);
        let elapsed = time::Since(t0);
        if n != 0 {
            die(b"Read returned non-zero on timeout\n");
        }
        if err.IsNil() {
            die(b"Read returned no error on timeout\n");
        }
        if !(err.Error() == "read: i/o timeout") {
            die(b"Error message is not 'read: i/o timeout'\n");
        }
        if elapsed.Nanoseconds() < 50_000_000 || elapsed.Nanoseconds() > 1_000_000_000 {
            die(b"Read returned at the wrong time (50ms..1s window)\n");
        }
        let _ = conn.Close();
        CLIENT_DONE.store(1, Ordering::Release);
    });

    // Server: accept, mark, and idle reading. The peer never writes.
    let (mut conn, err) = ln.Accept();
    check(err.IsNil(), b"Accept failed\n");
    SERVER_HAS_PEER.store(1, Ordering::Release);

    // Wait for client to time out, then drop the conn.
    while CLIENT_DONE.load(Ordering::Acquire) == 0 {
        goish::runtime::sched::Gosched();
    }
    let _ = conn.Close();
    let _ = ln.Close();

    let ok: &[u8] = b"conn_deadline_smoke: ok\n";
    syscall::Write(syscall::STDOUT, ok.as_ptr(), ok.len());
    schedule();
}
