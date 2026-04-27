// Smoke test: M17a-ε — self-select (port of Go runtime/chan_test.go:303
// TestSelfSelect).
//
// Two goroutines hammer the same chan with selects that contain
// BOTH a send case and a recv case for the same chan. Verifies
// no crash, no deadlock, and (on unbuffered chans) that no goroutine
// ever receives a value it sent itself — pass-1 try_send/try_recv
// only matches against OTHER goroutines' parked sudogs.
//
// Run twice: once with cap=0 (unbuffered) and once with cap=10
// (buffered). Buffered case can self-receive (G sends, G's next
// iteration recvs from buf), which is fine — only the cap=0 case
// asserts no-self-receive.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicUsize, Ordering};

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

const ITERS: i64 = 500;

#[goish::main]
fn main() {
    test_self_select(0); // unbuffered — no self-receive allowed
    test_self_select(10); // buffered — self-receive allowed (via buf)

    const OK: &[u8] = b"chan_self_select: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

fn test_self_select(chan_cap: i64) {
    let c = if chan_cap == 0 {
        make!(chan i64)
    } else {
        make!(chan i64, chan_cap)
    };

    static SELF_RECV_VIOLATIONS: AtomicUsize = AtomicUsize::new(0);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);
    SELF_RECV_VIOLATIONS.store(0, Ordering::Relaxed);
    GS_DONE.store(0, Ordering::Relaxed);

    for p in 0..2i64 {
        let c = c.clone();
        go!(move || {
            for i in 0..ITERS {
                if p == 0 || i % 2 == 0 {
                    select! {
                        c.Send(p) => {},
                        let v = c.Recv() => {
                            if chan_cap == 0 && v == p {
                                SELF_RECV_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
                            }
                        },
                    }
                } else {
                    select! {
                        let v = c.Recv() => {
                            if chan_cap == 0 && v == p {
                                SELF_RECV_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
                            }
                        },
                        c.Send(p) => {},
                    }
                }
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    check(GS_DONE.load(Ordering::Relaxed) == 2, b"self_select: not all Gs done\n");
    if chan_cap == 0 {
        check(
            SELF_RECV_VIOLATIONS.load(Ordering::Relaxed) == 0,
            b"self_select: unbuffered self-receive observed\n",
        );
    }
}
