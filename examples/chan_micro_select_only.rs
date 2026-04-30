// Step 3 in the M17b-δ bug-hunting ladder.
//
// 2 goroutines, both using `select!` with a single send and a
// single recv case (so there's a real lock-order on >1 chan
// per select pass). 4 chans (matching `chan_select_stress`'s
// shape) but no plain Send/Recv goroutines — every chan op
// goes through select.
//
// If the failure rate matches `chan_select_stress`, the bug
// is in select. If this passes 0/200, the bug needs the
// plain-Send/Recv + select interaction.

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

const N: i64 = 100_000;

#[goish::main]
fn main() {
    let c: [chan<i64>; 4] = [
        make!(chan i64),
        make!(chan i64),
        make!(chan i64, 2),
        make!(chan i64, 3),
    ];

    static SEND_TOTAL: AtomicI64 = AtomicI64::new(0);
    static RECV_TOTAL: AtomicI64 = AtomicI64::new(0);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);

    // Select sender: 4N iterations, sends to one of c[0..3].
    {
        let c1_init: [chan<i64>; 4] = [c[0].clone(), c[1].clone(), c[2].clone(), c[3].clone()];
        go!(stack(64 * KB), move || {
            let mut c1 = c1_init;
            let mut n = [0i64; 4];
            for _ in 0..(4 * N) {
                select! {
                    (c1[3]).Send(0) => {
                        n[3] += 1;
                        if n[3] == N { c1[3] = chan::nil(); }
                    },
                    (c1[2]).Send(0) => {
                        n[2] += 1;
                        if n[2] == N { c1[2] = chan::nil(); }
                    },
                    (c1[0]).Send(0) => {
                        n[0] += 1;
                        if n[0] == N { c1[0] = chan::nil(); }
                    },
                    (c1[1]).Send(0) => {
                        n[1] += 1;
                        if n[1] == N { c1[1] = chan::nil(); }
                    },
                }
                SEND_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    // Select receiver: 4N iterations, receives from one of c[0..3].
    {
        let c1_init: [chan<i64>; 4] = [c[0].clone(), c[1].clone(), c[2].clone(), c[3].clone()];
        go!(stack(64 * KB), move || {
            let mut c1 = c1_init;
            let mut n = [0i64; 4];
            for _ in 0..(4 * N) {
                select! {
                    let _ = (c1[0]).Recv() => {
                        n[0] += 1;
                        if n[0] == N { c1[0] = chan::nil(); }
                    },
                    let _ = (c1[1]).Recv() => {
                        n[1] += 1;
                        if n[1] == N { c1[1] = chan::nil(); }
                    },
                    let _ = (c1[2]).Recv() => {
                        n[2] += 1;
                        if n[2] == N { c1[2] = chan::nil(); }
                    },
                    let _ = (c1[3]).Recv() => {
                        n[3] += 1;
                        if n[3] == N { c1[3] = chan::nil(); }
                    },
                }
                RECV_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    check(
        GS_DONE.load(Ordering::Relaxed) == 2,
        b"chan_micro_select_only: not all 2 Gs done\n",
    );
    check(
        SEND_TOTAL.load(Ordering::Relaxed) == 4 * N,
        b"chan_micro_select_only: send total wrong\n",
    );
    check(
        RECV_TOTAL.load(Ordering::Relaxed) == 4 * N,
        b"chan_micro_select_only: recv total wrong\n",
    );

    const OK: &[u8] = b"chan_micro_select_only: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
