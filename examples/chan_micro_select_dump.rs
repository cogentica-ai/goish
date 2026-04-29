// SIGUSR1-dumpable diagnostic for the 3-chan select deadlock.
//
// Same workload as `chan_micro_select_3unbuf` but each side
// records its current iteration index to atomics. On SIGUSR1
// (sent by an external watchdog when the test hangs), the
// handler dumps:
//   - SS_ITER, SR_ITER (current loop iter number)
//   - SS_PASS, SR_PASS (which pass: 0=pre-pass-1, 1=in pass-1,
//     2=in pass-2, 3=in pass-3 cancel, 4=in body, 5=loop tail)
//   - per-chan SS_N, SR_N counters
//   - SEND_TOTAL, RECV_TOTAL
//
// The handler uses raw `syscall::Write` so it bypasses goish's
// goroutine-based signal forwarding, which would deadlock since
// the user goroutines are themselves stuck. Mirrors how Go's
// runtime SIGQUIT handler dumps state without relying on the
// scheduler.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI32, AtomicI64, AtomicUsize, Ordering};

use goish::gochan::chan;
use goish::runtime::sched::schedule;
use goish::syscall::{self, Sigaction, RtSigaction, SigreturnTrampoline, SIGUSR1};
use goish::{go, make, select};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

const N: i64 = 100_000;

static SEND_TOTAL: AtomicI64 = AtomicI64::new(0);
static RECV_TOTAL: AtomicI64 = AtomicI64::new(0);
static GS_DONE: AtomicUsize = AtomicUsize::new(0);

static SS_ITER: AtomicI64 = AtomicI64::new(-1);
static SR_ITER: AtomicI64 = AtomicI64::new(-1);
static SS_LAST_HIT: AtomicI32 = AtomicI32::new(-1);
static SR_LAST_HIT: AtomicI32 = AtomicI32::new(-1);
static SS_N: [AtomicI64; 3] = [AtomicI64::new(0), AtomicI64::new(0), AtomicI64::new(0)];
static SR_N: [AtomicI64; 3] = [AtomicI64::new(0), AtomicI64::new(0), AtomicI64::new(0)];

fn write_decimal(label: &[u8], n: i64) {
    syscall::Write(syscall::STDERR, label.as_ptr(), label.len());
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    let neg = n < 0;
    let mut x = if neg { -(n as i128) as u128 } else { n as u128 };
    if x == 0 { i -= 1; buf[i] = b'0'; }
    else { while x > 0 { i -= 1; buf[i] = b'0' + (x % 10) as u8; x /= 10; } }
    if neg { i -= 1; buf[i] = b'-'; }
    syscall::Write(syscall::STDERR, buf[i..].as_ptr(), buf.len() - i);
}

extern "C" fn sigusr1_handler(_sig: i32) {
    const TAG: &[u8] = b"\n=== SIGUSR1: state dump ===\n";
    syscall::Write(syscall::STDERR, TAG.as_ptr(), TAG.len());
    write_decimal(b"send_total=", SEND_TOTAL.load(Ordering::Relaxed));
    write_decimal(b" recv_total=", RECV_TOTAL.load(Ordering::Relaxed));
    write_decimal(b"\nss_iter=", SS_ITER.load(Ordering::Relaxed));
    write_decimal(b" sr_iter=", SR_ITER.load(Ordering::Relaxed));
    write_decimal(b" ss_last_hit=", SS_LAST_HIT.load(Ordering::Relaxed) as i64);
    write_decimal(b" sr_last_hit=", SR_LAST_HIT.load(Ordering::Relaxed) as i64);
    syscall::Write(syscall::STDERR, b"\nss_n=[".as_ptr(), 7);
    for k in 0..3 {
        if k > 0 { syscall::Write(syscall::STDERR, b",".as_ptr(), 1); }
        write_decimal(b"", SS_N[k].load(Ordering::Relaxed));
    }
    syscall::Write(syscall::STDERR, b"] sr_n=[".as_ptr(), 8);
    for k in 0..3 {
        if k > 0 { syscall::Write(syscall::STDERR, b",".as_ptr(), 1); }
        write_decimal(b"", SR_N[k].load(Ordering::Relaxed));
    }
    syscall::Write(syscall::STDERR, b"]\n=== end dump ===\n".as_ptr(), 18);
    syscall::Exit(7);
}

#[goish::main]
fn main() {
    let sa = Sigaction {
        sa_handler: sigusr1_handler as usize,
        sa_flags: 0x04000000, // SA_RESTORER
        sa_restorer: SigreturnTrampoline as usize,
        sa_mask: 0,
    };
    unsafe {
        RtSigaction(SIGUSR1, &sa, core::ptr::null_mut());
    }

    let c: [chan<i64>; 3] = [
        make!(chan i64),
        make!(chan i64),
        make!(chan i64),
    ];

    {
        let c1_init: [chan<i64>; 3] = [c[0].clone(), c[1].clone(), c[2].clone()];
        go!(move || {
            let mut c1 = c1_init;
            let mut n = [0i64; 3];
            for it in 0..(3 * N) {
                SS_ITER.store(it, Ordering::Relaxed);
                select! {
                    (c1[0]).Send(0) => {
                        SS_LAST_HIT.store(0, Ordering::Relaxed);
                        n[0] += 1; SS_N[0].store(n[0], Ordering::Relaxed);
                        if n[0] == N { c1[0] = chan::nil(); }
                    },
                    (c1[1]).Send(0) => {
                        SS_LAST_HIT.store(1, Ordering::Relaxed);
                        n[1] += 1; SS_N[1].store(n[1], Ordering::Relaxed);
                        if n[1] == N { c1[1] = chan::nil(); }
                    },
                    (c1[2]).Send(0) => {
                        SS_LAST_HIT.store(2, Ordering::Relaxed);
                        n[2] += 1; SS_N[2].store(n[2], Ordering::Relaxed);
                        if n[2] == N { c1[2] = chan::nil(); }
                    },
                }
                SEND_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    {
        let c1_init: [chan<i64>; 3] = [c[0].clone(), c[1].clone(), c[2].clone()];
        go!(move || {
            let mut c1 = c1_init;
            let mut n = [0i64; 3];
            for it in 0..(3 * N) {
                SR_ITER.store(it, Ordering::Relaxed);
                select! {
                    let _ = (c1[0]).Recv() => {
                        SR_LAST_HIT.store(0, Ordering::Relaxed);
                        n[0] += 1; SR_N[0].store(n[0], Ordering::Relaxed);
                        if n[0] == N { c1[0] = chan::nil(); }
                    },
                    let _ = (c1[1]).Recv() => {
                        SR_LAST_HIT.store(1, Ordering::Relaxed);
                        n[1] += 1; SR_N[1].store(n[1], Ordering::Relaxed);
                        if n[1] == N { c1[1] = chan::nil(); }
                    },
                    let _ = (c1[2]).Recv() => {
                        SR_LAST_HIT.store(2, Ordering::Relaxed);
                        n[2] += 1; SR_N[2].store(n[2], Ordering::Relaxed);
                        if n[2] == N { c1[2] = chan::nil(); }
                    },
                }
                RECV_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    check(GS_DONE.load(Ordering::Relaxed) == 2, b"chan_micro_select_dump: not all done\n");
    check(SEND_TOTAL.load(Ordering::Relaxed) == 3 * N, b"send total wrong\n");
    check(RECV_TOTAL.load(Ordering::Relaxed) == 3 * N, b"recv total wrong\n");

    const OK: &[u8] = b"chan_micro_select_dump: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
