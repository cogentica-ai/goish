// defer! smoke test.
//
// Covers:
//   1. LIFO order at scope exit.
//   2. Snapshot capture (defer body sees the value at defer-time).
//   3. Cleanup runs even on early return.
//   4. Multiple defers within a function — all run in reverse order.

#![no_std]
#![no_main]

use core::cell::Cell;
use goish::{defer, int, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// Helper: pushes a tag onto a shared trace and returns. Used to assert
// the *order* in which defers fire.
fn trace_push(trace: &Cell<int>, tag: int) {
    // shift left 4 bits per push so we can pack a sequence of small tags
    // into one int. Final value reads MSB→LSB as the order they were
    // pushed.
    trace.set((trace.get() << 4) | (tag & 0xF));
}

// (1) Two defers, LIFO drop order.
fn lifo_two(trace: &Cell<int>) {
    defer! { trace_push(trace, 1); }
    defer! { trace_push(trace, 2); }
    // end-of-fn: 2 drops first (newer binding), then 1.
    // trace ends up: 0 << 4 | 2  → 2; then 2 << 4 | 1 → 0x21
}

// (2) Snapshot capture: body sees value at defer-time, not exit-time.
fn snapshot(out: &Cell<int>) {
    let n: int = 7;
    defer! { out.set(n); } // captures n=7 by move
                           // Even if we shadow n later, the closure already owns the original.
    let _n: int = 99;
}

// (3) Defer fires on early return.
fn early_return(trace: &Cell<int>, take_branch: bool) -> int {
    defer! { trace_push(trace, 9); }
    if take_branch {
        return 1;
    }
    0
}

// (4) Three defers stacked.
fn lifo_three(trace: &Cell<int>) {
    defer! { trace_push(trace, 1); }
    defer! { trace_push(trace, 2); }
    defer! { trace_push(trace, 3); }
    // expected at exit: 3 first, then 2, then 1
    // trace: 0→3, →0x32, →0x321
}

#[goish::main]
fn main() {
    // (1) Two defers, LIFO.
    let trace = Cell::new(0i64);
    lifo_two(&trace);
    check(trace.get() == 0x21, b"defer: LIFO of 2 wrong\n");

    // (2) Snapshot capture.
    let out = Cell::new(0i64);
    snapshot(&out);
    check(out.get() == 7, b"defer: snapshot wrong\n");

    // (3) Fires on early return — branch taken.
    let trace = Cell::new(0i64);
    let r = early_return(&trace, true);
    check(r == 1, b"defer: early-return value wrong\n");
    check(trace.get() == 9, b"defer: must fire on early return\n");

    // (3b) Fires on natural return — branch not taken.
    let trace = Cell::new(0i64);
    let r = early_return(&trace, false);
    check(r == 0, b"defer: natural-return value wrong\n");
    check(trace.get() == 9, b"defer: must fire on natural return\n");

    // (4) Three-defer LIFO stack.
    let trace = Cell::new(0i64);
    lifo_three(&trace);
    check(trace.get() == 0x321, b"defer: LIFO of 3 wrong\n");

    // (5) Single-expression form: defer!(expr) without braces. Wrapped
    // in a function so the inner scope ends and the defer fires.
    fn touch(target: &Cell<bool>) {
        defer!(target.set(true));
    }
    let touched = Cell::new(false);
    touch(&touched);
    check(touched.get(), b"defer: single-expr form wrong\n");

    const OK: &[u8] = b"defer: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
