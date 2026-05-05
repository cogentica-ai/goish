// grow_macro_smoke — exercise the `go!(grow, || body)` macro arm.
//
// Three spawn forms compared on the same recursive workload:
//
//   bare     go!(|| body)               — default 2 KiB, no grow.
//                                         deep recursion would SEGV;
//                                         we use a shallow body.
//   grow     go!(grow, || body)         — spawns on 2 KiB, body
//                                         auto-pivots to tier-2 at
//                                         entry. deep recursion
//                                         climbs to tier-3 if the
//                                         body calls maybe_grow_step
//                                         internally.
//   stack(N) go!(stack(64*KB), || body) — explicit 64 KiB, no grow.
//                                         deep recursion fits in
//                                         tier-2 but cannot climb.

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
        if n == 0 { return sum; }
        recurse_step(n - 1, sum + n)
    })
}

#[inline(never)]
fn recurse_plain(n: i64, sum: i64) -> i64 {
    if n == 0 { return sum; }
    recurse_plain(n - 1, sum + n)
}

static BARE_DONE: AtomicUsize = AtomicUsize::new(0);
static GROW_DONE: AtomicUsize = AtomicUsize::new(0);
static STACK_DONE: AtomicUsize = AtomicUsize::new(0);
static BARE_R: AtomicI64 = AtomicI64::new(0);
static GROW_R: AtomicI64 = AtomicI64::new(0);
static STACK_R: AtomicI64 = AtomicI64::new(0);

#[goish::main]
fn main() {
    let hits_before = sched::grow_hits();

    // Bare form — small workload that fits in 2 KiB.
    go!(move || {
        let r = recurse_plain(2, 0);
        BARE_R.store(r, Ordering::Release);
        BARE_DONE.store(1, Ordering::Release);
    });

    // Auto-grow form — body pivots at entry, then climbs to tier-3
    // via internal maybe_grow_step calls when tier-2 runs low.
    go!(grow, move || {
        let r = recurse_step(500, 0);
        GROW_R.store(r, Ordering::Release);
        GROW_DONE.store(1, Ordering::Release);
    });

    // Explicit stack(N) form — fixed 64 KiB, sufficient for
    // mid-range recursion.
    go!(stack(64 * KB), move || {
        let r = recurse_plain(50, 0);
        STACK_R.store(r, Ordering::Release);
        STACK_DONE.store(1, Ordering::Release);
    });

    while BARE_DONE.load(Ordering::Acquire) == 0
        || GROW_DONE.load(Ordering::Acquire) == 0
        || STACK_DONE.load(Ordering::Acquire) == 0
    {
        sched::Gosched();
    }

    let hits = sched::grow_hits() - hits_before;

    print(b"grow_macro_smoke: hits=");
    print_dec(hits as u64);
    print(b" peak_live=");
    print_dec(sched::grow_peak_live() as u64);
    print(b"\n");

    // bare form: 0 pivots (no maybe_grow_step calls)
    // grow form: 2 pivots (entry → tier-2; tier-2 → tier-3 from internal recursion)
    // stack(N) form: 0 pivots
    if hits < 2 {
        die(b"FAIL: expected >=2 pivots from the grow goroutine\n");
    }

    let bare = BARE_R.load(Ordering::Acquire);
    let grow_r = GROW_R.load(Ordering::Acquire);
    let stack_r = STACK_R.load(Ordering::Acquire);
    if bare != 2 * 3 / 2 { die(b"FAIL: bare result wrong\n"); }
    if grow_r != 500 * 501 / 2 { die(b"FAIL: grow result wrong\n"); }
    if stack_r != 50 * 51 / 2 { die(b"FAIL: stack(N) result wrong\n"); }

    print(b"grow_macro_smoke: ok\n");
    syscall::Exit(0);
}

fn print_dec(mut n: u64) {
    if n == 0 { print(b"0"); return; }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    print(&buf[i..]);
}
