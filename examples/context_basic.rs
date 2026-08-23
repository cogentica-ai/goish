// Smoke test: M19 — context.Context.
//
// Tests the user-facing API:
//   1. Background returns a never-cancelled context with nil Done.
//   2. WithCancel: explicit cancel closes Done and sets Err.
//   3. WithTimeout: deadline expiry cancels Done with DeadlineExceeded.
//   4. select! { recv ctx.Done() | recv work() } — the canonical
//      timeout idiom now works end-to-end.
//   5. Parent cancellation propagates to children.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::context;
use goish::runtime::sched::schedule;
use goish::time::Milliseconds;
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

#[goish::main]
fn main() {
    test_background_never_cancels();
    test_with_cancel();
    test_with_timeout_fires();
    test_select_done_as_timeout();
    test_parent_cancel_propagates();

    const OK: &[u8] = b"context_basic: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ── Test 1: Background's Done is nil; Err is nil ─────────────────

fn test_background_never_cancels() {
    let ctx = context::Background();
    check(ctx.Done().is_nil(), b"bg: Done not nil\n");
    check(ctx.Err().IsNil(), b"bg: Err not nil\n");
    check(ctx.Deadline().is_none(), b"bg: Deadline not None\n");
}

// ── Test 2: WithCancel: cancel closes Done, sets Err ─────────────

fn test_with_cancel() {
    static FIRED: AtomicUsize = AtomicUsize::new(0);
    static ERR_NIL_BEFORE: AtomicUsize = AtomicUsize::new(99);
    static ERR_NIL_AFTER: AtomicUsize = AtomicUsize::new(99);

    let (ctx, cancel) = context::WithCancel(context::Background());
    ERR_NIL_BEFORE.store(if ctx.Err().IsNil() { 1 } else { 0 }, Ordering::Release);

    let ctx_for_g = ctx.clone();
    go!(move || {
        let _ = ctx_for_g.Done().Recv();
        FIRED.store(1, Ordering::Release);
    });

    // Cancel from the outer scope.
    cancel();

    // Eventually the goroutine fires.
    schedule();

    ERR_NIL_AFTER.store(if ctx.Err().IsNil() { 1 } else { 0 }, Ordering::Release);
    check(
        ERR_NIL_BEFORE.load(Ordering::Acquire) == 1,
        b"cancel: pre-Err not nil\n",
    );
    check(
        FIRED.load(Ordering::Acquire) == 1,
        b"cancel: Done didn't fire\n",
    );
    check(
        ERR_NIL_AFTER.load(Ordering::Acquire) == 0,
        b"cancel: post-Err nil\n",
    );
}

// ── Test 3: WithTimeout fires after the deadline ─────────────────

fn test_with_timeout_fires() {
    static FIRED: AtomicUsize = AtomicUsize::new(0);

    let (ctx, _cancel) = context::WithTimeout(context::Background(), Milliseconds(15));
    let ctx_for_g = ctx.clone();
    go!(move || {
        let _ = ctx_for_g.Done().Recv();
        FIRED.store(1, Ordering::Release);
    });
    schedule();

    check(
        FIRED.load(Ordering::Acquire) == 1,
        b"timeout: Done didn't fire\n",
    );
    check(!ctx.Err().IsNil(), b"timeout: Err nil\n");
}

// ── Test 4: select! with ctx.Done() as a timeout source ──────────

fn test_select_done_as_timeout() {
    static TIMED_OUT: AtomicUsize = AtomicUsize::new(0);

    let (ctx, _cancel) = context::WithTimeout(context::Background(), Milliseconds(10));
    let never = make!(chan i64);
    let ctx_for_g = ctx.clone();
    go!(move || {
        select! {
            let _v = never.Recv() => die(b"select-done: never fired\n"),
            let _t = (ctx_for_g.Done()).Recv() => {
                TIMED_OUT.store(1, Ordering::Release);
            },
        }
    });
    schedule();

    check(
        TIMED_OUT.load(Ordering::Acquire) == 1,
        b"select-done: timeout case missed\n",
    );
}

// ── Test 5: parent cancel propagates to derived contexts ────────

fn test_parent_cancel_propagates() {
    static CHILD_FIRED: AtomicUsize = AtomicUsize::new(0);

    let (parent, p_cancel) = context::WithCancel(context::Background());
    let (child, _c_cancel) = context::WithCancel(parent.clone());

    let child_for_g = child.clone();
    go!(move || {
        let _ = child_for_g.Done().Recv();
        CHILD_FIRED.store(1, Ordering::Release);
    });

    // Cancel parent — child must see it.
    p_cancel();

    schedule();

    check(
        CHILD_FIRED.load(Ordering::Acquire) == 1,
        b"propagate: child didn't see\n",
    );
    check(!parent.Err().IsNil(), b"propagate: parent.Err nil\n");
    check(!child.Err().IsNil(), b"propagate: child.Err nil\n");
}
