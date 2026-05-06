// grow_3tier_smoke — exercise the 3-tier auto-grow ladder via
// `runtime::sched::maybe_grow_step`.
//
// Three goroutines, all spawned bare (default 2 KiB home stack):
//
//   shallow: depth 3   → 1 pivot   (home → tier-2; home is too small
//                                    to host any maybe_grow_step call
//                                    so it pivots unconditionally)
//   medium:  depth 50  → 1 pivot   (home → tier-2; stays in 64 KiB)
//   deep:    depth 500 → 2 pivots  (home → tier-2 → tier-3; tier-2
//                                    runs out and pivots to 1 MiB)
//
// `deep_recurse` wraps each level in `maybe_grow_step`, so the runtime
// pivots when remaining-room drops below the per-tier red zone. Home
// tier always pivots (the fast-path check itself wouldn't fit safely);
// tier-2 → tier-3 uses the standard 8 KiB red-zone fast path.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use goish::runtime::sched;
use goish::{go, syscall};

fn print(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

#[inline(never)]
fn deep_recurse(n: i64, sum: i64) -> i64 {
    sched::maybe_grow_step(|| {
        if n == 0 {
            return sum;
        }
        deep_recurse(n - 1, sum + n)
    })
}

static SHALLOW_RESULT: AtomicI64 = AtomicI64::new(0);
static MEDIUM_RESULT: AtomicI64 = AtomicI64::new(0);
static DEEP_RESULT: AtomicI64 = AtomicI64::new(0);
static DONE: AtomicUsize = AtomicUsize::new(0);

#[goish::main]
fn main() {
    let hits_before = sched::grow_hits();

    // Shallow — should never pivot.
    go!(move || {
        let r = deep_recurse(3, 0);
        SHALLOW_RESULT.store(r, Ordering::Release);
        DONE.fetch_add(1, Ordering::AcqRel);
    });

    // Medium — overflows 2 KiB, fits in 64 KiB tier-2.
    go!(move || {
        let r = deep_recurse(50, 0);
        MEDIUM_RESULT.store(r, Ordering::Release);
        DONE.fetch_add(1, Ordering::AcqRel);
    });

    // Deep — overflows tier-2, needs tier-3 (1 MiB) headroom.
    go!(move || {
        let r = deep_recurse(500, 0);
        DEEP_RESULT.store(r, Ordering::Release);
        DONE.fetch_add(1, Ordering::AcqRel);
    });

    while DONE.load(Ordering::Acquire) < 3 {
        sched::Gosched();
    }

    let hits = sched::grow_hits() - hits_before;

    print(b"grow_3tier_smoke: hits=");
    print_dec(hits as u64);
    print(b" peak_live=");
    print_dec(sched::grow_peak_live() as u64);
    print(b"\n");

    // Expected pivots: shallow=1, medium=1, deep=2 → total ≥ 4.
    if hits < 4 {
        die(b"FAIL: expected at least 4 pivots across the 3 goroutines\n");
    }
    let s = SHALLOW_RESULT.load(Ordering::Acquire);
    let m = MEDIUM_RESULT.load(Ordering::Acquire);
    let d = DEEP_RESULT.load(Ordering::Acquire);
    if s != 3 * 4 / 2 {
        die(b"FAIL: shallow result wrong\n");
    }
    if m != 50 * 51 / 2 {
        die(b"FAIL: medium result wrong\n");
    }
    if d != 500 * 501 / 2 {
        die(b"FAIL: deep result wrong\n");
    }

    print(b"grow_3tier_smoke: ok\n");
    syscall::Exit(0);
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
