// Smoke test: M17a-ε — multi-M chan + select stress (port of
// Go runtime/chan_test.go:342 TestSelectStress).
//
// Hammers 4 channels (2 unbuffered, 1 cap-2, 1 cap-3) with 10
// concurrent goroutines:
//   - 4 dedicated senders (one per chan, send N each)
//   - 4 dedicated receivers (one per chan, recv N each)
//   - 1 select-sender that sends 4N times across all 4 chans;
//     when a chan's count reaches N, the local handle is replaced
//     with `chan::nil()` so subsequent select picks skip that case
//     (Go's `c1[k] = nil` pattern at chan_test.go:382-401).
//   - 1 select-receiver mirror.
//
// Total per chan: 2N sends and 2N recvs (deterministic, balanced).
// Successful completion under multi-M proves the chan + select +
// nil-chan machinery is race-free under heavy contention.

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

const N: i64 = 1_000;

#[goish::main]
fn main() {
    let c0 = make!(chan i64);       // unbuffered
    let c1 = make!(chan i64);       // unbuffered
    let c2 = make!(chan i64, 2);    // buffered cap=2
    let c3 = make!(chan i64, 3);    // buffered cap=3

    static SEND_TOTAL: AtomicI64 = AtomicI64::new(0);
    static RECV_TOTAL: AtomicI64 = AtomicI64::new(0);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);

    // ── 4 dedicated senders + 4 dedicated receivers ────────────────
    {
        let c = c0.clone();
        go!(move || {
            for _ in 0..N { c.Send(0); SEND_TOTAL.fetch_add(1, Ordering::Relaxed); }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    {
        let c = c1.clone();
        go!(move || {
            for _ in 0..N { c.Send(0); SEND_TOTAL.fetch_add(1, Ordering::Relaxed); }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    {
        let c = c2.clone();
        go!(move || {
            for _ in 0..N { c.Send(0); SEND_TOTAL.fetch_add(1, Ordering::Relaxed); }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    {
        let c = c3.clone();
        go!(move || {
            for _ in 0..N { c.Send(0); SEND_TOTAL.fetch_add(1, Ordering::Relaxed); }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    {
        let c = c0.clone();
        go!(move || {
            for _ in 0..N { let _ = c.Recv(); RECV_TOTAL.fetch_add(1, Ordering::Relaxed); }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    {
        let c = c1.clone();
        go!(move || {
            for _ in 0..N { let _ = c.Recv(); RECV_TOTAL.fetch_add(1, Ordering::Relaxed); }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    {
        let c = c2.clone();
        go!(move || {
            for _ in 0..N { let _ = c.Recv(); RECV_TOTAL.fetch_add(1, Ordering::Relaxed); }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    {
        let c = c3.clone();
        go!(move || {
            for _ in 0..N { let _ = c.Recv(); RECV_TOTAL.fetch_add(1, Ordering::Relaxed); }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    // ── Select-sender: 4N sends, balanced via nil-replacement ──────
    {
        let mut s0 = c0.clone();
        let mut s1 = c1.clone();
        let mut s2 = c2.clone();
        let mut s3 = c3.clone();
        go!(move || {
            let mut n = [0i64; 4];
            for _ in 0..(4 * N) {
                select! {
                    s3.Send(0) => {
                        n[3] += 1;
                        if n[3] == N { s3 = chan::nil(); }
                    },
                    s2.Send(0) => {
                        n[2] += 1;
                        if n[2] == N { s2 = chan::nil(); }
                    },
                    s0.Send(0) => {
                        n[0] += 1;
                        if n[0] == N { s0 = chan::nil(); }
                    },
                    s1.Send(0) => {
                        n[1] += 1;
                        if n[1] == N { s1 = chan::nil(); }
                    },
                }
                SEND_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    // ── Select-receiver: 4N recvs, balanced via nil-replacement ────
    {
        let mut r0 = c0.clone();
        let mut r1 = c1.clone();
        let mut r2 = c2.clone();
        let mut r3 = c3.clone();
        go!(move || {
            let mut n = [0i64; 4];
            for _ in 0..(4 * N) {
                select! {
                    let _ = r0.Recv() => {
                        n[0] += 1;
                        if n[0] == N { r0 = chan::nil(); }
                    },
                    let _ = r1.Recv() => {
                        n[1] += 1;
                        if n[1] == N { r1 = chan::nil(); }
                    },
                    let _ = r2.Recv() => {
                        n[2] += 1;
                        if n[2] == N { r2 = chan::nil(); }
                    },
                    let _ = r3.Recv() => {
                        n[3] += 1;
                        if n[3] == N { r3 = chan::nil(); }
                    },
                }
                RECV_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    check(GS_DONE.load(Ordering::Relaxed) == 10, b"select_stress: not all 10 Gs done\n");
    check(SEND_TOTAL.load(Ordering::Relaxed) == 8 * N, b"select_stress: send total wrong\n");
    check(RECV_TOTAL.load(Ordering::Relaxed) == 8 * N, b"select_stress: recv total wrong\n");

    const OK: &[u8] = b"chan_select_stress: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
