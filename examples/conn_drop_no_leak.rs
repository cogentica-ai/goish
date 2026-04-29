// conn_drop_no_leak — verify Drop on Conn / Listener releases the
// kernel fd. We open and drop 1000 client+server pairs without
// calling Close explicitly; afterwards we check our own fd table
// in /proc/self/fd and assert the count hasn't grown unboundedly.
//
// Pre-M27h, every dropped Conn/Listener leaked one fd permanently.
// 1000 cycles would leave 2000+ fds open and eventually hit
// EMFILE. With Drop, we expect a stable fd count (≤ ~30 — the
// open-on-startup baseline plus any in-flight kept-alive conns).

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI32, Ordering};
use goish::net;
use goish::runtime::sched::schedule;
use goish::{go, string, syscall, KB};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

/// Count how many entries are in /proc/self/fd. Uses getdents64 to
/// avoid pulling in std::fs.
fn count_fds() -> usize {
    // SYS_OPENAT (= 257) on x86_64.
    const SYS_OPENAT: usize = 257;
    const SYS_GETDENTS64: usize = 217;
    const SYS_CLOSE: usize = 3;
    const AT_FDCWD: i32 = -100;
    const O_RDONLY: i32 = 0;
    const O_DIRECTORY: i32 = 0o200000;
    let path = b"/proc/self/fd\0";
    let dfd = unsafe {
        syscall::syscall3(
            SYS_OPENAT,
            AT_FDCWD as usize,
            path.as_ptr() as usize,
            (O_RDONLY | O_DIRECTORY) as usize,
        )
    } as i32;
    if dfd < 0 {
        return 0;
    }
    let mut buf = [0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = unsafe {
            syscall::syscall3(
                SYS_GETDENTS64,
                dfd as usize,
                buf.as_mut_ptr() as usize,
                buf.len(),
            )
        };
        if n <= 0 {
            break;
        }
        // Walk linux_dirent64 entries: u64 d_ino, i64 d_off, u16 d_reclen, u8 d_type, char d_name[].
        let mut off = 0usize;
        while off < n as usize {
            let d_reclen =
                u16::from_le_bytes([buf[off + 16], buf[off + 17]]) as usize;
            // Filter "." and ".." which getdents always returns.
            let name_start = off + 19;
            let name0 = buf[name_start];
            let name1 = if d_reclen > 20 { buf[name_start + 1] } else { 0 };
            if !(name0 == b'.' && (name1 == 0 || name1 == b'.')) {
                total += 1;
            }
            off += d_reclen;
        }
    }
    let _ = unsafe { syscall::syscall1(SYS_CLOSE, dfd as usize) };
    total
}

#[goish::main]
fn main() {
    let baseline = count_fds();

    // Spin up a long-lived listener to dial against. We wrap it in
    // an Arc so main can call Close() to break the accept loop on
    // shutdown — a clean exit lets bpftrace observability scripts
    // (scripts/bpftrace/netpoll_leak.bt) report a balanced delta.
    let (server_ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    check(err.IsNil(), b"server Listen failed\n");
    let port = server_ln.Addr().Port;
    static SERVER_PORT: AtomicI32 = AtomicI32::new(0);
    SERVER_PORT.store(port as i32, Ordering::Release);

    let server_ln = alloc::sync::Arc::new(server_ln);
    let server_ln_for_accept = server_ln.clone();

    // Server accept loop in a goroutine — accept and immediately drop.
    go!(stack(64 * KB), move || {
        loop {
            let (conn, err) = server_ln_for_accept.Accept();
            if !err.IsNil() {
                return;
            }
            // Drop the conn immediately. With Drop, this should
            // release the fd back to the kernel.
            drop(conn);
        }
    });

    // Yield once so the server enters its accept loop.
    for _ in 0..10 {
        goish::runtime::sched::Gosched();
    }

    // Client side: 200 dial+drop cycles. Each cycle the kernel
    // assigns a new fd; without Drop, fds would accumulate.
    const ITERATIONS: usize = 200;
    for _ in 0..ITERATIONS {
        let p = SERVER_PORT.load(Ordering::Acquire) as u32;
        let mut addr_buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(24);
        addr_buf.extend_from_slice(b"127.0.0.1:");
        let mut tmp = [0u8; 6];
        let mut i = tmp.len();
        let mut n = p;
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        addr_buf.extend_from_slice(&tmp[i..]);
        let addr = string::from_bytes(&addr_buf);

        let (conn, err) = net::Dial(string("tcp"), addr);
        if err.IsNil() {
            // Drop the conn without explicit Close.
            drop(conn);
        }
    }

    // Give the server time to drain the accepts (it's also dropping).
    for _ in 0..50 {
        goish::runtime::sched::Gosched();
    }

    let after = count_fds();

    // After 200 dial+drop cycles, fd count should be roughly
    // baseline + a small constant (server fd + epoll fd + eventfd
    // + a few in-flight). Threshold of baseline+30 is generous.
    if after > baseline + 30 {
        let msg = b"FD LEAK: count grew far beyond baseline\n";
        syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
        // Print numbers for diagnosis.
        let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        buf.extend_from_slice(b"baseline=");
        push_dec(&mut buf, baseline as u64);
        buf.extend_from_slice(b" after=");
        push_dec(&mut buf, after as u64);
        buf.extend_from_slice(b"\n");
        syscall::Write(syscall::STDERR, buf.as_ptr(), buf.len());
        syscall::Exit(1);
    }

    // Cleanly close the listener so the netpoll registration is
    // unregistered before exit — gives bpftrace a balanced report.
    let _ = server_ln.Close();
    // Yield so the accept goroutine notices the closed fd and exits,
    // dropping its Arc<Listener> clone (Drop is now idempotent so
    // this is harmless even though Close already ran).
    for _ in 0..20 {
        goish::runtime::sched::Gosched();
    }

    let ok: &[u8] = b"conn_drop_no_leak: fd count stable across 200 dial+drop cycles\n";
    syscall::Write(syscall::STDOUT, ok.as_ptr(), ok.len());
    syscall::Exit(0);
}

fn push_dec(buf: &mut alloc::vec::Vec<u8>, mut n: u64) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        buf.push(tmp[i]);
    }
}
