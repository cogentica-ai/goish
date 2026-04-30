// Smaller-N variant of chan_micro_select_send_only to characterize
// minimum scale at which the bug fires. N=10000 vs original 100000.
// Sender uses select! across 3 chans; 3 plain receivers.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gochan::chan;
use goish::runtime::sched::schedule;
use goish::{go, make, select, syscall, KB};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

const N: i64 = 10_000;

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
        go!(stack(64 * KB), move || {
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
        go!(stack(64 * KB), move || {
            for _ in 0..N {
                let _ = ck.Recv();
                RECV_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    check(GS_DONE.load(Ordering::Relaxed) == 4, b"chan_micro_select_send_small: not all done\n");
    check(SEND_TOTAL.load(Ordering::Relaxed) == 3 * N, b"chan_micro_select_send_small: send total wrong\n");
    check(RECV_TOTAL.load(Ordering::Relaxed) == 3 * N, b"chan_micro_select_send_small: recv total wrong\n");

    const OK: &[u8] = b"chan_micro_select_send_small: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
