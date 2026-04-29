// socket_smoke — exercise the M27a Linux socket syscalls end-to-end.
//
// Test plan:
//   1. socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) → server fd.
//   2. setsockopt(SO_REUSEADDR).
//   3. bind(127.0.0.1:0)  — port 0 = kernel picks free port.
//   4. listen(backlog=8).
//   5. spawn a goroutine that opens a client socket and connects to
//      the server's loopback address.
//   6. accept(server) → conn fd.
//   7. server writes "hello", client reads and verifies.
//   8. close everything.
//
// Uses raw goish::syscall directly (M27a only — net package lands in
// M27b). Each step asserts via die() so a non-zero exit means failure.

#![no_std]
#![no_main]

extern crate goish;

use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use goish::runtime::sched::schedule;
use goish::syscall;
use goish::{go, KB};

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
    // Step 1-4: server side.
    let srv = syscall::Socket(
        syscall::AF_INET,
        syscall::SOCK_STREAM | syscall::SOCK_CLOEXEC,
        syscall::IPPROTO_TCP,
    );
    check(srv >= 0, b"socket(server) failed\n");

    // SO_REUSEADDR — let us re-bind the same port quickly.
    let one: i32 = 1;
    let r = syscall::Setsockopt(
        srv,
        syscall::SOL_SOCKET,
        syscall::SO_REUSEADDR,
        &one as *const i32 as *const u8,
        core::mem::size_of::<i32>() as u32,
    );
    check(r == 0, b"setsockopt(SO_REUSEADDR) failed\n");

    // Bind to 127.0.0.1:0 — kernel picks the port.
    let bind_addr = syscall::SockaddrIn::loopback(0);
    let r = syscall::Bind(
        srv,
        &bind_addr,
        core::mem::size_of::<syscall::SockaddrIn>() as u32,
    );
    check(r == 0, b"bind failed\n");

    // Recover the assigned port via getsockname.
    let mut got = syscall::SockaddrIn::loopback(0);
    let mut got_len: u32 = core::mem::size_of::<syscall::SockaddrIn>() as u32;
    // No getsockname helper yet — call via the syscall module's
    // syscall3 using SYS_GETSOCKNAME=51.
    let r = unsafe {
        syscall::syscall3(
            syscall::SYS_GETSOCKNAME,
            srv as usize,
            &mut got as *mut _ as usize,
            &mut got_len as *mut _ as usize,
        )
    };
    check(r == 0, b"getsockname failed\n");
    let port = got.port_host();
    check(port != 0, b"got port == 0\n");

    let r = syscall::Listen(srv, 8);
    check(r == 0, b"listen failed\n");

    // Step 5: client goroutine.
    static CLIENT_FD: AtomicI32 = AtomicI32::new(-1);
    static CLIENT_DONE: AtomicUsize = AtomicUsize::new(0);
    go!(stack(8 * KB), move || {
        let cli = syscall::Socket(
            syscall::AF_INET,
            syscall::SOCK_STREAM | syscall::SOCK_CLOEXEC,
            syscall::IPPROTO_TCP,
        );
        if cli < 0 {
            die(b"socket(client) failed\n");
        }
        let dst = syscall::SockaddrIn::loopback(port);
        let r = syscall::Connect(
            cli,
            &dst,
            core::mem::size_of::<syscall::SockaddrIn>() as u32,
        );
        if r != 0 {
            die(b"connect failed\n");
        }
        // Read the server's greeting.
        let mut buf = [0u8; 16];
        let n = syscall::Read(cli, buf.as_mut_ptr(), buf.len());
        if n < 5 {
            die(b"client read short\n");
        }
        if &buf[..5] != b"hello" {
            die(b"client read wrong bytes\n");
        }
        CLIENT_FD.store(cli, Ordering::Release);
        CLIENT_DONE.store(1, Ordering::Release);
    });

    // Step 6-7: server accepts and writes.
    let mut peer = syscall::SockaddrIn::loopback(0);
    let mut peer_len: u32 = core::mem::size_of::<syscall::SockaddrIn>() as u32;
    let conn = syscall::Accept4(
        srv,
        &mut peer,
        &mut peer_len,
        syscall::SOCK_CLOEXEC,
    );
    check(conn >= 0, b"accept4 failed\n");

    let greeting: &[u8] = b"hello";
    let n = syscall::Write(conn, greeting.as_ptr(), greeting.len());
    check(n == 5, b"server write short\n");

    // Step 8: shutdown + close.
    let _ = syscall::Shutdown(conn, syscall::SHUT_RDWR);
    let _ = syscall::Close(conn);

    // Wait for client to finish.
    while CLIENT_DONE.load(Ordering::Acquire) == 0 {
        goish::runtime::sched::Gosched();
    }
    let cli = CLIENT_FD.load(Ordering::Acquire);
    let _ = syscall::Shutdown(cli, syscall::SHUT_RDWR);
    let _ = syscall::Close(cli);
    let _ = syscall::Close(srv);

    let ok: &[u8] = b"socket_smoke: ok\n";
    syscall::Write(syscall::STDOUT, ok.as_ptr(), ok.len());

    schedule();
}
