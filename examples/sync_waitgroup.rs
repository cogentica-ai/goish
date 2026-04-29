// Smoke test: M16g-β — sync.WaitGroup.
//
// Tests:
//   1. Add/Done/Wait basic flow.
//   2. Many waiters: multiple Gs Wait, all unblock when counter→0.
//   3. WaitGroup.Go — Go 1.25 sugar that bundles Add + spawn + Done.
//   4. Reuse: WaitGroup is reusable after Wait returns (Add a new
//      batch, wait again).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

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
    test_add_done_wait();
    test_many_waiters();
    test_go_method();
    test_reuse();

    const OK: &[u8] = b"sync_waitgroup: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ── Test 1: 32 workers, each Done()s; main waits then verifies ────

fn test_add_done_wait() {
    static WG: WaitGroup = WaitGroup::new();
    static SUM: AtomicI64 = AtomicI64::new(0);

    const N: i64 = 32;
    WG.Add(N);

    for i in 0..N {
        go!(stack(8 * KB), move || {
            SUM.fetch_add(i + 1, Ordering::Relaxed);
            WG.Done();
        });
    }

    // Spawn one waiter goroutine; the schedule() drain coordinates it.
    static WAIT_DONE: AtomicUsize = AtomicUsize::new(0);
    go!(stack(8 * KB), || {
        WG.Wait();
        WAIT_DONE.store(1, Ordering::Release);
    });
    schedule();

    check(WAIT_DONE.load(Ordering::Acquire) == 1, b"add-done-wait: waiter didn't return\n");
    let expected: i64 = (1..=N).sum();
    check(SUM.load(Ordering::Relaxed) == expected, b"add-done-wait: sum wrong\n");
}

// ── Test 2: many concurrent waiters all unblock at count→0 ────────

fn test_many_waiters() {
    static WG: WaitGroup = WaitGroup::new();
    static WAITERS_DONE: AtomicUsize = AtomicUsize::new(0);

    WAITERS_DONE.store(0, Ordering::Relaxed);
    WG.Add(1);

    const N_WAITERS: usize = 16;
    for _ in 0..N_WAITERS {
        go!(stack(8 * KB), || {
            WG.Wait();
            WAITERS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }

    // Single Done() should release all 16 waiters.
    go!(stack(8 * KB), || {
        WG.Done();
    });
    schedule();

    check(
        WAITERS_DONE.load(Ordering::Relaxed) == N_WAITERS,
        b"many-waiters: not all unblocked\n",
    );
}

// ── Test 3: WaitGroup.Go convenience method ───────────────────────

fn test_go_method() {
    static WG: WaitGroup = WaitGroup::new();
    static GO_RAN: AtomicI64 = AtomicI64::new(0);

    GO_RAN.store(0, Ordering::Relaxed);

    const N: i64 = 24;
    for _ in 0..N {
        WG.Go(|| {
            GO_RAN.fetch_add(1, Ordering::Relaxed);
        });
    }

    static W2: AtomicUsize = AtomicUsize::new(0);
    go!(stack(8 * KB), || {
        WG.Wait();
        W2.store(1, Ordering::Release);
    });
    schedule();

    check(W2.load(Ordering::Acquire) == 1, b"go-method: Wait didn't return\n");
    check(GO_RAN.load(Ordering::Relaxed) == N, b"go-method: not all tasks ran\n");
}

// ── Test 4: reuse — second batch after first Wait() returned ──────

fn test_reuse() {
    static WG: WaitGroup = WaitGroup::new();
    static C1: AtomicI64 = AtomicI64::new(0);
    static C2: AtomicI64 = AtomicI64::new(0);

    C1.store(0, Ordering::Relaxed);
    C2.store(0, Ordering::Relaxed);

    // First batch.
    WG.Add(8);
    for _ in 0..8 {
        go!(stack(8 * KB), || {
            C1.fetch_add(1, Ordering::Relaxed);
            WG.Done();
        });
    }
    static W1: AtomicUsize = AtomicUsize::new(0);
    go!(stack(8 * KB), || {
        WG.Wait();
        W1.store(1, Ordering::Release);

        // Second batch — only after first Wait returned.
        WG.Add(5);
        for _ in 0..5 {
            go!(stack(8 * KB), || {
                C2.fetch_add(1, Ordering::Relaxed);
                WG.Done();
            });
        }
        WG.Wait();
    });
    schedule();

    check(W1.load(Ordering::Acquire) == 1, b"reuse: first Wait didn't return\n");
    check(C1.load(Ordering::Relaxed) == 8, b"reuse: first batch count wrong\n");
    check(C2.load(Ordering::Relaxed) == 5, b"reuse: second batch count wrong\n");
}
