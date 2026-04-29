// spawn_density — smoke test for M26 per-G stack size.
//
// Spawns a small batch of goroutines using the new
// `go!(stack(N * KB), …)` macro form, exercising mixed sizes:
// the receiver uses the default 2 KiB stack (after page-rounding,
// 4 KiB), the sender uses an explicit 64 KiB.
//
// Demonstrates the API; doesn't (yet) measure RSS. A real density
// benchmark needs a chunked stack pool (Phase 2) to deliver
// sub-page allocation, plus a workload that genuinely sits idle on
// chans without growing frames in debug mode.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use goish::gochan::chan;
use goish::runtime::sched::schedule;
use goish::{go, make, syscall, KB};

const N: i64 = 16;

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1)
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    let c: chan<i64> = make!(chan i64);

    static SEND: AtomicI64 = AtomicI64::new(0);
    static RECV: AtomicI64 = AtomicI64::new(0);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);

    {
        let cs = c.clone();
        // Sender: use 64 KiB explicitly (chan runtime overhead).
        go!(stack(64 * KB), move || {
            for _ in 0..N {
                cs.Send(1);
                SEND.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    {
        let cr = c.clone();
        // Receiver: also 64 KiB. The point of this example is the
        // *macro form*; tighter stacks need either chunked allocation
        // or release-mode frames to be safe.
        go!(stack(64 * KB), move || {
            for _ in 0..N {
                let _ = cr.Recv();
                RECV.fetch_add(1, Ordering::Relaxed);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    schedule();

    check(SEND.load(Ordering::Relaxed) == N, b"spawn_density: SEND wrong\n");
    check(RECV.load(Ordering::Relaxed) == N, b"spawn_density: RECV wrong\n");
    check(GS_DONE.load(Ordering::Relaxed) == 2, b"spawn_density: GS_DONE wrong\n");
}
