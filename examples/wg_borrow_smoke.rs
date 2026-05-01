// Smoke test: WaitGroup Form 3 — stack-local WG that lets spawned
// goroutines borrow stack data. The compiler enforces:
//
//   - the WaitGroup outlives every captured borrow;
//   - the WaitGroup's Drop calls Wait() before borrowed data drops;
//   - leaking goroutines past the WG's scope is impossible
//     (except via the explicit `mem::forget` escape hatch).
//
// This is the goish equivalent of Go 1.25's `wg.Go(f)` plus
// std::thread::scope's lifetime safety, with the flat surface of
// `let wg = WaitGroup::new();`.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, Ordering};

use goish::runtime::sched::schedule;
use goish::sync::WaitGroup;
use goish::{go, syscall, KB};

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
    // Wrap the body in a goroutine so Wait() / blocking Drop can
    // park-resume rather than block the bootstrap thread (which has
    // no `current_g`).
    go!(stack(64 * KB), || {
        test_borrow_atomic();
        test_explicit_wait_then_drop();
        test_reuse_after_wait();
    });
    schedule();

    const OK: &[u8] = b"wg_borrow_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ── Test 1: borrow a stack-local AtomicI64 from spawned goroutines ──
//
// The closure captures `&total` from the outer scope. Today (without
// Form 3) this would be a compile error: closures spawned via go!()
// must be `'static`. With Form 3, the WG's lifetime bounds the
// closure, the borrow checker accepts it, and the WG's Drop guarantees
// every spawned task finishes before `total` falls out of scope.
fn test_borrow_atomic() {
    let total: AtomicI64 = AtomicI64::new(0);
    let total_ref = &total;
    {
        let wg = WaitGroup::new();
        for n in 1..=10i64 {
            // `move` makes each closure capture its own `n`. The
            // captured `total_ref` is &AtomicI64 — a shared
            // reference, which is `Copy`, so `move` doesn't consume
            // `total_ref` itself. Each closure ends up with its own
            // (n, &total) pair, all sharing the stack-local atomic.
            wg.Go(move || {
                total_ref.fetch_add(n, Ordering::Relaxed);
            });
        }
        // wg drops here → Wait() runs → all 10 goroutines joined.
    }
    let got = total.load(Ordering::Acquire);
    check(got == 55, b"borrow: total != 55\n");
}

// ── Test 2: explicit Wait() before Drop ─────────────────────────────
//
// Mirrors Go 1.25 idiom: `wg.Go(...); wg.Wait();`. The trailing
// Drop sees counter == 0 and is a no-op (fast path).
fn test_explicit_wait_then_drop() {
    let counter: AtomicI64 = AtomicI64::new(0);
    let wg = WaitGroup::new();
    for _ in 0..8 {
        wg.Go(|| {
            counter.fetch_add(1, Ordering::Relaxed);
        });
    }
    wg.Wait();
    check(
        counter.load(Ordering::Acquire) == 8,
        b"explicit-wait: counter != 8\n",
    );
    // wg drops here — Wait already ran, fast path, no second wait.
}

// ── Test 3: reuse — second batch after first Wait() returned ───────
//
// Same WG, two staged batches. Drop catches the second batch even
// though the user didn't write a second Wait().
fn test_reuse_after_wait() {
    let stage1: AtomicI64 = AtomicI64::new(0);
    let stage2: AtomicI64 = AtomicI64::new(0);
    {
        let wg = WaitGroup::new();
        for _ in 0..4 {
            wg.Go(|| {
                stage1.fetch_add(1, Ordering::Relaxed);
            });
        }
        wg.Wait(); // explicit barrier: stage1 fully done before stage2 starts.
        check(
            stage1.load(Ordering::Acquire) == 4,
            b"reuse: stage1 not fully drained at barrier\n",
        );
        for _ in 0..6 {
            wg.Go(|| {
                stage2.fetch_add(1, Ordering::Relaxed);
            });
        }
        // No second Wait — Drop catches stage2.
    }
    check(
        stage2.load(Ordering::Acquire) == 6,
        b"reuse: stage2 didn't finish before drop\n",
    );
}
