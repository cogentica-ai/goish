// Minimal repro for the M17b-δ rc=2 spurious-wake hypothesis.
//
// Exactly 2 goroutines on one unbuffered chan; no `select!`,
// no `Close`, no buffered chans, no timers. The sender's
// `success` bit must always be `true` when it resumes from
// `gopark` — the math model in `doc/M17b-delta-wake-protocol-
// model.md` proves this. Any rc=2 panic from this program
// localizes the bug to the scheduler/preempt path (Candidate 1
// in §7 of the model doc), not the chan protocol.
//
// Counters:
//   SEND_TOTAL  := number of Send calls completed.
//   RECV_TOTAL  := number of Recv calls that returned `(_, true)`.
//
// Assertions on `schedule()` return:
//   SEND_TOTAL == N
//   RECV_TOTAL == N
//
// If the program panics with `goish: chan: send on closed
// channel ...` despite the test never calling `Close`, the bug
// is in the wake protocol (per §6 Candidate 1).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gochan::chan;
use goish::runtime::sched::schedule;
use goish::{go, make, syscall, KB};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

const N: i64 = 1_000_000;

#[goish::main]
fn main() {
    let c: chan<i64> = make!(chan i64);
    static SEND_TOTAL: AtomicI64 = AtomicI64::new(0);
    static RECV_TOTAL: AtomicI64 = AtomicI64::new(0);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);

    {
        let cs = c.clone();
        go!(stack(64 * KB), move || {
            for _ in 0..N {
                cs.Send(0);
                SEND_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    {
        let cr = c.clone();
        go!(stack(64 * KB), move || {
            for _ in 0..N {
                let _ = cr.Recv();
                RECV_TOTAL.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    check(
        GS_DONE.load(Ordering::Relaxed) == 2,
        b"chan_micro: not all 2 Gs done\n",
    );
    check(
        SEND_TOTAL.load(Ordering::Relaxed) == N,
        b"chan_micro: send total wrong\n",
    );
    check(
        RECV_TOTAL.load(Ordering::Relaxed) == N,
        b"chan_micro: recv total wrong\n",
    );

    const OK: &[u8] = b"chan_micro_send_recv: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
