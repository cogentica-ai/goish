// Diagnostic version of chan_micro_select_3unbuf.
//
// Adds a watchdog goroutine that, after a 2-second wait, dumps:
//   - SEND_TOTAL / RECV_TOTAL
//   - per-chan n[] arrays (via shared atomics)
//   - chan queue lengths
//   - LIVE_G_COUNT
//
// If we deadlock, the watchdog dumps state showing exactly
// which side is stuck and on which chan.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gochan::chan;
use goish::runtime::sched::{live_g_count, schedule};
use goish::time::{Sleep, Second};
use goish::{go, make, select, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

const N: i64 = 1_000;

static SEND_TOTAL: AtomicI64 = AtomicI64::new(0);
static RECV_TOTAL: AtomicI64 = AtomicI64::new(0);
static GS_DONE: AtomicUsize = AtomicUsize::new(0);

// Per-side, per-chan counters visible to watchdog.
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

fn dump_state(c: &[chan<i64>; 3], tag: &[u8]) {
    syscall::Write(syscall::STDERR, tag.as_ptr(), tag.len());
    write_decimal(b"\n  send_total=", SEND_TOTAL.load(Ordering::Relaxed));
    write_decimal(b" recv_total=", RECV_TOTAL.load(Ordering::Relaxed));
    write_decimal(b" gs_done=", GS_DONE.load(Ordering::Relaxed) as i64);
    write_decimal(b" live_g=", live_g_count() as i64);
    syscall::Write(syscall::STDERR, b"\n  ss_n=[".as_ptr(), 8);
    for k in 0..3 {
        if k > 0 { syscall::Write(syscall::STDERR, b",".as_ptr(), 1); }
        write_decimal(b"", SS_N[k].load(Ordering::Relaxed));
    }
    syscall::Write(syscall::STDERR, b"] sr_n=[".as_ptr(), 8);
    for k in 0..3 {
        if k > 0 { syscall::Write(syscall::STDERR, b",".as_ptr(), 1); }
        write_decimal(b"", SR_N[k].load(Ordering::Relaxed));
    }
    syscall::Write(syscall::STDERR, b"]\n  c_len=[".as_ptr(), 10);
    for k in 0..3 {
        if k > 0 { syscall::Write(syscall::STDERR, b",".as_ptr(), 1); }
        write_decimal(b"", c[k].Len() as i64);
    }
    syscall::Write(syscall::STDERR, b"]\n".as_ptr(), 2);
}

#[goish::main]
fn main() {
    let c: [chan<i64>; 3] = [
        make!(chan i64),
        make!(chan i64),
        make!(chan i64),
    ];

    // Watchdog: after 2 s, if not all 2 worker Gs are done, dump state.
    {
        let cw: [chan<i64>; 3] = [c[0].clone(), c[1].clone(), c[2].clone()];
        go!(move || {
            Sleep(goish::time::Duration(2 * 1_000_000_000));
            let _ = Second;
            if GS_DONE.load(Ordering::Relaxed) < 2 {
                dump_state(&cw, b"WATCHDOG: deadlock detected (2s no progress)");
                syscall::Exit(7);
            }
        });
    }

    // Sender select goroutine.
    {
        let c1_init: [chan<i64>; 3] = [c[0].clone(), c[1].clone(), c[2].clone()];
        go!(move || {
            let mut c1 = c1_init;
            let mut n = [0i64; 3];
            for _ in 0..(3 * N) {
                select! {
                    (c1[0]).Send(0) => { n[0] += 1; SS_N[0].store(n[0], Ordering::Relaxed); if n[0] == N { c1[0] = chan::nil(); } },
                    (c1[1]).Send(0) => { n[1] += 1; SS_N[1].store(n[1], Ordering::Relaxed); if n[1] == N { c1[1] = chan::nil(); } },
                    (c1[2]).Send(0) => { n[2] += 1; SS_N[2].store(n[2], Ordering::Relaxed); if n[2] == N { c1[2] = chan::nil(); } },
                }
                SEND_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    // Receiver select goroutine.
    {
        let c1_init: [chan<i64>; 3] = [c[0].clone(), c[1].clone(), c[2].clone()];
        go!(move || {
            let mut c1 = c1_init;
            let mut n = [0i64; 3];
            for _ in 0..(3 * N) {
                select! {
                    let _ = (c1[0]).Recv() => { n[0] += 1; SR_N[0].store(n[0], Ordering::Relaxed); if n[0] == N { c1[0] = chan::nil(); } },
                    let _ = (c1[1]).Recv() => { n[1] += 1; SR_N[1].store(n[1], Ordering::Relaxed); if n[1] == N { c1[1] = chan::nil(); } },
                    let _ = (c1[2]).Recv() => { n[2] += 1; SR_N[2].store(n[2], Ordering::Relaxed); if n[2] == N { c1[2] = chan::nil(); } },
                }
                RECV_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    if SEND_TOTAL.load(Ordering::Relaxed) != 3 * N
        || RECV_TOTAL.load(Ordering::Relaxed) != 3 * N
    {
        dump_state(&c, b"FINAL: counters wrong");
        syscall::Exit(8);
    }

    // Drop unused
    let _ = Vec::<u8>::new();

    const OK: &[u8] = b"chan_micro_select_diag: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
