// stack_grow_ladder_smoke — force real stack pivots and check that
// every region is given back.
//
// examples/grow_smoke.rs covers one `maybe_grow` pivot. This covers
// what it does not (#33, "force actual ARM stack pivots and assert
// grow_hits() increases and cleanup balances"):
//
//   1. the `maybe_grow_step` ladder: home → tier-2 (64 KiB) → tier-3
//      (1 MiB), observed from the deepest frame as two live regions;
//   2. a goroutine that parks on a channel INSIDE a grown region and
//      resumes there, on whichever M picks it up;
//   3. balance: after both, `grow_live()` and `grow_bytes_live()` are
//      back to 0 and `grow_hits()` rose by at least one per pivot.
//
// Every goroutine under test is spawned with an explicit small
// `stack(N)`. A bare `go!()` gets a 1 MiB reservation
// (`Stack::new_reserved`), so these workloads would never reach a red
// zone there — which is why the
// undeclared grow_3tier / grow_macro / grow_park / grow_auto harnesses,
// written for a bare-`go!()` auto-grow that does not exist, report
// "did not grow" on every target.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use goish::runtime::sched;
use goish::{go, make, syscall, KB};

fn print(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn print_dec(mut n: u64) {
    if n == 0 {
        print(b"0");
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    print(&buf[i..]);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
        syscall::Exit(1);
    }
}

fn wait(done: &AtomicUsize) {
    while done.load(Ordering::Acquire) == 0 {
        sched::Gosched();
    }
}

// ─── 1. the ladder ───────────────────────────────────────────────────

static DEEPEST_LIVE: AtomicUsize = AtomicUsize::new(0);
static LADDER_SUM: AtomicI64 = AtomicI64::new(0);
static LADDER_DONE: AtomicUsize = AtomicUsize::new(0);

// Keep each level SMALL. `maybe_grow_step` checks the red zone once per
// level, and on a home stack that zone is a fixed 1 KiB which must also
// hold the pivot path (~600-800 B in debug). A level bigger than the
// slack between the two — measured: 1264 B in debug with a 256 B
// scratch array — steps past the bottom of the home slot between two
// checks, and stackpool slots have no guard page, so it corrupts a
// neighbour instead of faulting. This body is ~192 B per level in
// debug and ~128 B in release; `black_box(&sum)` pins a stack slot so
// release cannot fold the frame away. 1000 levels then outgrow tier-2
// (64 KiB) in both profiles and stay far inside tier-3 (1 MiB).
const DEPTH: i64 = 1000;

#[inline(never)]
fn ladder(n: i64, sum: i64) -> i64 {
    sched::maybe_grow_step(|| {
        core::hint::black_box(&sum);
        if n == 0 {
            DEEPEST_LIVE.store(sched::grow_live(), Ordering::Release);
            return sum;
        }
        ladder(n - 1, sum + n)
    })
}

// ─── 2. park inside a grown region ───────────────────────────────────

const NITER: i64 = 1_000;
static PARK_N: AtomicI64 = AtomicI64::new(0);
static PARK_SUM: AtomicI64 = AtomicI64::new(0);
static PARK_DONE: AtomicUsize = AtomicUsize::new(0);

#[goish::main]
fn main() {
    // 1. DEPTH levels from a 2 KiB home stack outgrow tier-2 too, so
    //    the deepest frame runs two pivots down.
    let hits0 = sched::grow_hits();
    go!(stack(2 * KB), move || {
        LADDER_SUM.store(ladder(DEPTH, 0), Ordering::Release);
        LADDER_DONE.store(1, Ordering::Release);
    });
    wait(&LADDER_DONE);
    let ladder_hits = sched::grow_hits() - hits0;

    check(LADDER_SUM.load(Ordering::Acquire) == DEPTH * (DEPTH + 1) / 2, b"FAIL: ladder sum wrong\n");
    check(ladder_hits >= 2, b"FAIL: ladder did not pivot twice\n");
    check(DEEPEST_LIVE.load(Ordering::Acquire) >= 2, b"FAIL: deepest frame not two regions down\n");
    check(sched::grow_live() == 0, b"FAIL: ladder regions not returned\n");
    check(sched::grow_bytes_live() == 0, b"FAIL: ladder bytes not returned\n");

    // 2. A 4 KiB stack always sits inside maybe_grow's 8 KiB red zone,
    //    so the consumer pivots before its first Recv, then parks there
    //    on every empty channel.
    let hits1 = sched::grow_hits();
    let c = make!(chan i64, 4);
    {
        // The producer is not under test: a bare go!, off the stackpool.
        let c = c.clone();
        go!(move || {
            for i in 1..=NITER {
                c.Send(i);
            }
            c.Close();
        });
    }
    {
        let c = c.clone();
        go!(stack(4 * KB), move || {
            let (n, s) = sched::maybe_grow(8 * KB, 64 * KB, || {
                let mut n: i64 = 0;
                let mut s: i64 = 0;
                loop {
                    let (v, ok) = c.Recv();
                    if !ok {
                        break;
                    }
                    n += 1;
                    s += v;
                }
                (n, s)
            });
            PARK_N.store(n, Ordering::Release);
            PARK_SUM.store(s, Ordering::Release);
            PARK_DONE.store(1, Ordering::Release);
        });
    }
    wait(&PARK_DONE);
    let park_hits = sched::grow_hits() - hits1;

    check(PARK_N.load(Ordering::Acquire) == NITER, b"FAIL: park count wrong\n");
    check(PARK_SUM.load(Ordering::Acquire) == NITER * (NITER + 1) / 2, b"FAIL: park sum wrong\n");
    check(park_hits >= 1, b"FAIL: consumer did not pivot\n");

    // 3. Balance across both.
    check(sched::grow_live() == 0, b"FAIL: grow_live not 0\n");
    check(sched::grow_bytes_live() == 0, b"FAIL: grow_bytes_live not 0\n");
    check(sched::grow_peak_live() >= 2, b"FAIL: grow_peak_live < 2\n");

    print(b"stack_grow_ladder_smoke: ladder_hits=");
    print_dec(ladder_hits as u64);
    print(b" deepest_live=");
    print_dec(DEEPEST_LIVE.load(Ordering::Acquire) as u64);
    print(b" park_hits=");
    print_dec(park_hits as u64);
    print(b"\nstack_grow_ladder_smoke: OK\n");
}
