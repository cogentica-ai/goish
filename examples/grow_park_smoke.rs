// grow_park_smoke — exercise chan-park INSIDE a grown stack region.
//
// Validation that M28-α (free-on-scope-exit) is safe across goroutine
// parks under the post-residual scheduler (956153a / 84edfb5 / 9028a07).
// 100/100 clean at 4+ KiB home stack confirms that the prior "chan-
// park inside grow is unsafe" diagnosis was actually a 2-KiB home
// overflow during `grow_and_call` setup, not a park-resume corruption.
//
// **Home-stack note:** uses bare `go!()` (default 2 KiB). Earlier
// regression with 2 KiB was the Box::new allocator path inside
// `grow_and_call`'s pre-pivot frame; eliminated by switching to a
// stack-resident `MaybeUninit<F>` slot. The 2 KiB sub-page density
// goal (preserved against bumping the default) stays intact.
//
// Topology:
//   producer ──c──> consumer
//                     ↑
//                  inside maybe_grow
//   - producer goroutine sends NITER values into c, closes.
//   - consumer goroutine runs maybe_grow(64 KiB), then inside the
//     grown region drains c via Recv-loop until close.
//
// Each Recv() parks (when c is empty), is awakened by producer Send,
// resumes ON THE GROWN REGION. If anything in the park/resume path
// assumes home-stack bounds, this will break.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use goish::runtime::sched;
use goish::{go, make, syscall, KB};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond { die(msg); }
}

const NITER: i64 = 1_000;
static GOT_N: AtomicI64 = AtomicI64::new(0);
static GOT_SUM: AtomicI64 = AtomicI64::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);

#[goish::main]
fn main() {
    let c = make!(chan i64, 4);

    // Producer.
    {
        let c = c.clone();
        go!(move || {
            for i in 1..=NITER {
                c.Send(i);
            }
            c.Close();
        });
    }

    // Consumer — runs Recv-loop INSIDE maybe_grow on a grown region.
    {
        let c = c.clone();
        go!(move || {
            let (n, s) = sched::maybe_grow(8 * KB, 64 * KB, || {
                let mut n: i64 = 0;
                let mut s: i64 = 0;
                loop {
                    let (v, ok) = c.Recv();
                    if !ok { break; }
                    n += 1;
                    s += v;
                }
                (n, s)
            });
            GOT_N.store(n, Ordering::Release);
            GOT_SUM.store(s, Ordering::Release);
            DONE.store(1, Ordering::Release);
        });
    }

    while DONE.load(Ordering::Acquire) == 0 {
        sched::Gosched();
    }

    let n = GOT_N.load(Ordering::Acquire);
    let s = GOT_SUM.load(Ordering::Acquire);
    let expected_sum = NITER * (NITER + 1) / 2;
    check(n == NITER, b"grow_park_smoke: count wrong\n");
    check(s == expected_sum, b"grow_park_smoke: sum wrong\n");
    check(sched::grow_hits() >= 1, b"grow_park_smoke: did not grow\n");

    syscall::Write(syscall::STDOUT, b"grow_park_smoke: ok\n".as_ptr(), 20);
}
