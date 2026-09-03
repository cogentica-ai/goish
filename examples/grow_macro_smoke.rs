// NOT DECLARED IN Cargo.toml, SO e2e NEVER RUNS THIS.
//
// This harness specifies AUTOMATIC stack growth for the bare `go!()`
// form. That feature does not exist: the bare arm of the `go!` macro
// calls `newproc_at` with no growth wrap, and has since M28
// (f49842f) — the commit that added this file, the growth machinery,
// and a macro comment claiming the two were connected. They were not.
//
// It fails today, on purpose left visible rather than deleted: it is
// the specification the feature would have to satisfy. Declaring it
// would simply turn CI red.
//
// What DOES work: `go!(stack(N), …)` to size a stack up front, and
// `runtime::sched::maybe_grow` / `maybe_grow_step` called explicitly
// at a recursion site — see examples/grow_smoke.rs, which is declared
// and passes.
//
// grow_macro_smoke — exercise the bare `go!()` (default auto-grow)
// vs. `go!(stack(N), …)` (fixed-size opt-out) macro arms.
//
// Two spawn forms compared on the same recursive workload:
//
//   bare:      go!(|| body)              — default: 2 KiB home,
//                                          AUTO-GROWABLE via the
//                                          maybe_grow_step wrap added
//                                          by the macro. Body pivots
//                                          lazily to tier-2 (64 KiB)
//                                          when home runs low, then
//                                          to tier-3 (1 MiB) on deeper
//                                          maybe_grow_step calls.
//   stack(N):  go!(stack(64*KB), …)      — explicit 64 KiB, FIXED.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use goish::runtime::sched;
use goish::{go, syscall, KB};

fn print(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

#[inline(never)]
fn recurse_step(n: i64, sum: i64) -> i64 {
    sched::maybe_grow_step(move || {
        if n == 0 {
            return sum;
        }
        recurse_step(n - 1, sum + n)
    })
}

#[inline(never)]
fn recurse_plain(n: i64, sum: i64) -> i64 {
    if n == 0 {
        return sum;
    }
    recurse_plain(n - 1, sum + n)
}

static GROW_DONE: AtomicUsize = AtomicUsize::new(0);
static STACK_DONE: AtomicUsize = AtomicUsize::new(0);
static GROW_R: AtomicI64 = AtomicI64::new(0);
static STACK_R: AtomicI64 = AtomicI64::new(0);

#[goish::main]
fn main() {
    let hits_before = sched::grow_hits();

    // Bare form (auto-grow default) — body pivots lazily as recursion
    // descends; can climb to tier-3 via internal maybe_grow_step calls.
    go!(move || {
        let r = recurse_step(500, 0);
        GROW_R.store(r, Ordering::Release);
        GROW_DONE.store(1, Ordering::Release);
    });

    // Explicit stack(N) form — fixed 64 KiB, no grow. Sufficient for
    // mid-range recursion known at spawn time.
    go!(stack(64 * KB), move || {
        let r = recurse_plain(50, 0);
        STACK_R.store(r, Ordering::Release);
        STACK_DONE.store(1, Ordering::Release);
    });

    while GROW_DONE.load(Ordering::Acquire) == 0 || STACK_DONE.load(Ordering::Acquire) == 0 {
        sched::Gosched();
    }

    let hits = sched::grow_hits() - hits_before;

    print(b"grow_macro_smoke: hits=");
    print_dec(hits as u64);
    print(b" peak_live=");
    print_dec(sched::grow_peak_live() as u64);
    print(b"\n");

    // Bare goroutine: body has macro-inserted maybe_grow_step + the
    // user's recurse_step's per-level maybe_grow_step. Recursion to
    // depth 500 forces tier-2 → tier-3, so >=2 pivots fire.
    // Stack(N) goroutine: 0 pivots (recurse_plain has no maybe_grow_step).
    if hits < 2 {
        die(b"FAIL: expected >=2 pivots from the bare-grow goroutine\n");
    }

    let grow_r = GROW_R.load(Ordering::Acquire);
    let stack_r = STACK_R.load(Ordering::Acquire);
    if grow_r != 500 * 501 / 2 {
        die(b"FAIL: bare-grow result wrong\n");
    }
    if stack_r != 50 * 51 / 2 {
        die(b"FAIL: stack(N) result wrong\n");
    }

    print(b"grow_macro_smoke: ok\n");
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
