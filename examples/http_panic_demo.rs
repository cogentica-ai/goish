// http_panic_demo — self-contained proof that goish HTTP server
// survives panicking handlers. Server + drivers in one binary, no
// curl/bash/inter-process noise.
//
// Layout:
//   - Server goroutine: HTTP/1.1 mux with /healthz + /panic.
//     /panic does `panic!()` mid-handler. Phase B.1 recovery catches
//     it; Phase B.2.0 (defer!) ensures any deferred cleanups still
//     fire.
//   - Drivers: 4 goroutines, each performs N round-trips of /panic
//     followed by N round-trips of /healthz (verify alive).
//   - Final assertion: server still answers /healthz, all drivers
//     completed, panic count matches expected.
//
// Memory check: report VmRSS via /proc/self/status before and after
// the load. Should be flat (Phase B.1 + B.2.0 don't leak).

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use goish::gochan::chan;
use goish::io::Writer;
use goish::net;
use goish::net::http;
use goish::runtime::sched;
use goish::sync::WaitGroup;
use goish::{bytes, defer, go, make, slice, string, syscall, KB};

const N_DRIVERS: i64 = 4;
const PANICS_PER_DRIVER: i64 = 25;
const HEALTHZ_PER_DRIVER: i64 = 5;

static REQ_PANIC_HANDLED: AtomicU64 = AtomicU64::new(0);
static REQ_HEALTHZ_OK: AtomicU64 = AtomicU64::new(0);
static REQ_DRIVE_PANIC_DONE: AtomicU64 = AtomicU64::new(0);
static REQ_DRIVE_HEALTHZ_DONE: AtomicU64 = AtomicU64::new(0);
// Sentinel that increments on `defer!` body running inside the panic
// handler — proves panic-time defer cleanups fire even on the HTTP
// server's per-request goroutine.
static DEFER_RAN_ON_PANIC: AtomicU64 = AtomicU64::new(0);

fn print(s: &[u8]) {
    syscall::Write(syscall::STDOUT, s.as_ptr(), s.len());
}

fn print_dec(mut n: u64) {
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    syscall::Write(syscall::STDOUT, buf[i..].as_ptr(), buf.len() - i);
}

/// Read /proc/self/status and parse VmRSS in KB.
fn vmrss_kb() -> u64 {
    let fd = syscall::Open(b"/proc/self/status\0".as_ptr(), 0, 0);
    if fd < 0 { return 0; }
    let mut buf = [0u8; 2048];
    let mut total = 0usize;
    loop {
        let n = syscall::Read(fd, unsafe { buf.as_mut_ptr().add(total) }, buf.len() - total);
        if n <= 0 { break; }
        total += n as usize;
        if total >= buf.len() { break; }
    }
    syscall::Close(fd);
    let s = &buf[..total];
    let key = b"VmRSS:";
    if let Some(pos) = (0..s.len()).find(|&i| s[i..].starts_with(key)) {
        let mut p = pos + key.len();
        while p < s.len() && (s[p] == b' ' || s[p] == b'\t') { p += 1; }
        let mut v = 0u64;
        while p < s.len() && s[p].is_ascii_digit() {
            v = v * 10 + (s[p] - b'0') as u64;
            p += 1;
        }
        return v;
    }
    0
}

/// In-process driver: open one TCP conn, write HTTP/1.1 request,
/// drain response. Returns true on a 2xx-line response, false on
/// connection failure / non-2xx.
fn http_request(addr: &goish::gostring::string, path: &[u8]) -> bool {
    let (mut conn, err) = net::Dial(string("tcp"), addr.clone());
    if !err.IsNil() {
        return false;
    }
    // Conn's Drop closes the fd; no explicit defer needed.

    // Build minimal HTTP/1.1 request. Connection: close so server
    // closes after one response — keeps the driver simple (no
    // pipelining, no parsing Content-Length).
    let mut req = [0u8; 256];
    let mut len = 0usize;
    let prefix = b"GET ";
    req[..prefix.len()].copy_from_slice(prefix);
    len += prefix.len();
    req[len..len + path.len()].copy_from_slice(path);
    len += path.len();
    let suffix = b" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    req[len..len + suffix.len()].copy_from_slice(suffix);
    len += suffix.len();

    let req_slice = slice::__from_vec(req[..len].to_vec());
    let (n_w, err) = conn.Write(req_slice);
    if !err.IsNil() || n_w as usize != len {
        return false;
    }

    // Drain response — first chunk is enough to check status line.
    let resp_slice = slice::__from_vec(alloc::vec![0u8; 256]);
    let mut resp_slice = resp_slice;
    let (n_r, _err) = goish::io::Reader::Read(&mut conn, &mut resp_slice);
    if n_r <= 0 {
        return false;
    }
    let bytes_read = unsafe {
        core::slice::from_raw_parts(resp_slice.as_ptr(), n_r as usize)
    };
    bytes_read.starts_with(b"HTTP/1.1 2")
}

#[goish::main]
fn main() {
    go!(|| {
        run_demo();
    });
    sched::schedule();
}

fn run_demo() {
    // Server publishes its port on this chan once Listen succeeds.
    let port_chan: chan<u16> = make!(chan u16, 1);

    // ── Server goroutine ──────────────────────────────────────────
    let port_chan_srv = port_chan.clone();
    go!(move || {
        let mux = http::ServeMux::new();

        mux.HandleFunc(string("/healthz"), |w, _r| {
            REQ_HEALTHZ_OK.fetch_add(1, Ordering::Relaxed);
            let _ = w.Write(bytes("ok\n"));
        });

        // The panicking handler. defer! before the panic should still
        // fire via cleanup registry → DEFER_RAN_ON_PANIC increments.
        mux.HandleFunc(string("/panic"), |_w, _r| {
            defer!{ DEFER_RAN_ON_PANIC.fetch_add(1, Ordering::Relaxed); }
            REQ_PANIC_HANDLED.fetch_add(1, Ordering::Relaxed);
            panic!("intentional panic from /panic route");
        });

        let mux: Arc<dyn http::Handler> = Arc::new(mux);

        let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if !err.IsNil() {
            print(b"listen failed\n");
            syscall::Exit(1);
        }
        port_chan_srv.Send(ln.Addr().Port as u16);

        let _ = http::Serve(ln, mux);
    });

    // ── Wait for server's port ────────────────────────────────────
    let (port, ok) = port_chan.Recv();
    if !ok {
        print(b"server didn't publish a port\n");
        syscall::Exit(1);
    }

    // Build the address string ONCE; drivers clone refs to it.
    let mut addr_buf = [0u8; 32];
    let prefix = b"127.0.0.1:";
    addr_buf[..prefix.len()].copy_from_slice(prefix);
    let mut alen = prefix.len();
    let mut p = port as u32;
    let mut tmp = [0u8; 8];
    let mut ti = tmp.len();
    if p == 0 { ti -= 1; tmp[ti] = b'0'; }
    while p > 0 { ti -= 1; tmp[ti] = b'0' + (p % 10) as u8; p /= 10; }
    let pn = tmp.len() - ti;
    addr_buf[alen..alen + pn].copy_from_slice(&tmp[ti..]);
    alen += pn;
    let addr = string::from_bytes(&addr_buf[..alen]);

    print(b"server pid=");
    print_dec(syscall::Getpid() as u64);
    print(b" port=");
    print_dec(port as u64);
    print(b"\n");

    let rss_before = vmrss_kb();
    print(b"VmRSS before drive: ");
    print_dec(rss_before);
    print(b" KB\n");

    // ── Drivers ──────────────────────────────────────────────────
    let wg = WaitGroup::new();
    for _did in 0..N_DRIVERS {
        let addr_c = addr.clone();
        wg.GoStack(64 * KB, move || {
            for _ in 0..PANICS_PER_DRIVER {
                let _ = http_request(&addr_c, b"/panic");
                REQ_DRIVE_PANIC_DONE.fetch_add(1, Ordering::Relaxed);
            }
            for _ in 0..HEALTHZ_PER_DRIVER {
                let ok = http_request(&addr_c, b"/healthz");
                if ok {
                    REQ_DRIVE_HEALTHZ_DONE.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }
    wg.Wait();

    // ── Wait for the panic-recovery path to complete on stragglers ──
    let expected_panics = (N_DRIVERS * PANICS_PER_DRIVER) as u64;
    for _ in 0..50_000 {
        if sched::G_PANIC_COUNT.load(Ordering::Acquire) >= expected_panics {
            break;
        }
        sched::Gosched();
    }

    let rss_after = vmrss_kb();

    // ── Final alive check ────────────────────────────────────────
    let final_alive = http_request(&addr, b"/healthz");

    // ── Report ───────────────────────────────────────────────────
    let drive_panic = REQ_DRIVE_PANIC_DONE.load(Ordering::Relaxed);
    let drive_healthz = REQ_DRIVE_HEALTHZ_DONE.load(Ordering::Relaxed);
    let server_panics = REQ_PANIC_HANDLED.load(Ordering::Relaxed);
    let server_healthz = REQ_HEALTHZ_OK.load(Ordering::Relaxed);
    let g_panic_count = sched::G_PANIC_COUNT.load(Ordering::Relaxed);
    let defer_ran = DEFER_RAN_ON_PANIC.load(Ordering::Relaxed);

    print(b"\n=== report ===\n");
    print(b"drivers OK    : "); print_dec(drive_panic); print(b" panic + ");
    print_dec(drive_healthz); print(b" healthz\n");
    print(b"server OK     : "); print_dec(server_panics); print(b" panic-handled + ");
    print_dec(server_healthz); print(b" healthz-served\n");
    print(b"G_PANIC_COUNT : "); print_dec(g_panic_count); print(b"\n");
    print(b"DEFER_RAN_ON_PANIC: "); print_dec(defer_ran); print(b"\n");
    print(b"final alive   : "); print(if final_alive { b"yes\n" } else { b"NO\n" });
    print(b"VmRSS after   : "); print_dec(rss_after);
    print(b" KB (delta from before: ");
    print_dec(rss_after.saturating_sub(rss_before));
    print(b" KB)\n");

    let expected_drive_panic = (N_DRIVERS * PANICS_PER_DRIVER) as u64;
    let expected_drive_healthz = (N_DRIVERS * HEALTHZ_PER_DRIVER) as u64;

    let pass = drive_panic == expected_drive_panic
        && drive_healthz == expected_drive_healthz
        && server_panics == expected_drive_panic
        && g_panic_count >= expected_drive_panic
        && defer_ran == expected_drive_panic
        && final_alive
        && rss_after.saturating_sub(rss_before) < 1024; // <1 MB growth

    if pass {
        print(b"\nPASS\n");
        syscall::Exit(0);
    } else {
        print(b"\nFAIL\n");
        syscall::Exit(1);
    }
}
