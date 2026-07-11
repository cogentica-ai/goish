// Asymmetric: only the sender uses select! (3 chans).
// Receivers are 3 plain-Recv goroutines, one per chan.
// If this reproduces, sender-side select! is sufficient to trigger the bug.
// If clean, both sides must use select!.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gochan::chan;
use goish::runtime::sched::schedule;
use goish::{go, make, select, syscall};

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

#[goish::main]
fn main() {
    let c: [chan<i64>; 3] = [
        make!(chan i64),
        make!(chan i64),
        make!(chan i64),
    ];

    static SEND_TOTAL: AtomicI64 = AtomicI64::new(0);
    static RECV_TOTAL: AtomicI64 = AtomicI64::new(0);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);

    {
        let c1_init: [chan<i64>; 3] = [c[0].clone(), c[1].clone(), c[2].clone()];
        // Explicit 64 KiB stack: the select! body in debug mode plus
        // chan-runtime overhead exceeds the M26 default (2 KiB).
        go!(move || {
            let mut c1 = c1_init;
            let mut n = [0i64; 3];
            for _ in 0..(3 * N) {
                select! {
                    (c1[0]).Send(0) => { n[0] += 1; if n[0] == N { c1[0] = chan::nil(); } },
                    (c1[1]).Send(0) => { n[1] += 1; if n[1] == N { c1[1] = chan::nil(); } },
                    (c1[2]).Send(0) => { n[2] += 1; if n[2] == N { c1[2] = chan::nil(); } },
                }
                SEND_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    for k in 0..3 {
        let ck = c[k].clone();
        go!(move || {
            for _ in 0..N {
                let _ = ck.Recv();
                RECV_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    check(GS_DONE.load(Ordering::Relaxed) == 4, b"chan_micro_select_send_only: not all done\n");
    check(SEND_TOTAL.load(Ordering::Relaxed) == 3 * N, b"chan_micro_select_send_only: send total wrong\n");
    check(RECV_TOTAL.load(Ordering::Relaxed) == 3 * N, b"chan_micro_select_send_only: recv total wrong\n");

    const OK: &[u8] = b"chan_micro_select_send_only: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
