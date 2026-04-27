// Smoke test: M16g-γ — sync.Once.
//
// Tests:
//   1. Single Do call invokes f exactly once.
//   2. N concurrent goroutines racing on Do — exactly one runs f.
//   3. After f returns, all Do callers see f's effects (memory
//      ordering via Release/Acquire on the `done` atomic).
//   4. Subsequent Do calls (post-completion) return without
//      invoking f.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::runtime::sched::schedule;
use goish::sync::Once;
use goish::{go, syscall};

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
    test_single_do();
    test_concurrent_race();
    test_idempotent_after_complete();

    const OK: &[u8] = b"sync_once: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ── Test 1: single Do invokes f exactly once ─────────────────────

fn test_single_do() {
    static O: Once = Once::new();
    static N: AtomicUsize = AtomicUsize::new(0);

    O.Do(|| { N.fetch_add(1, Ordering::Relaxed); });
    O.Do(|| { N.fetch_add(1, Ordering::Relaxed); });
    O.Do(|| { N.fetch_add(1, Ordering::Relaxed); });

    check(N.load(Ordering::Relaxed) == 1, b"single-do: ran f more than once\n");
}

// ── Test 2: N concurrent goroutines all racing on Do ─────────────

fn test_concurrent_race() {
    static O: Once = Once::new();
    static F_RAN: AtomicUsize = AtomicUsize::new(0);
    static SHARED: AtomicI64 = AtomicI64::new(0);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);

    F_RAN.store(0, Ordering::Relaxed);
    SHARED.store(0, Ordering::Relaxed);
    GS_DONE.store(0, Ordering::Relaxed);

    const N: usize = 64;
    for _ in 0..N {
        go!(|| {
            O.Do(|| {
                F_RAN.fetch_add(1, Ordering::Relaxed);
                // Touch SHARED inside f to verify all Do-callers
                // observe f's effects after Do returns.
                SHARED.store(42, Ordering::Release);
            });
            // Each Do-caller must observe SHARED == 42 (f's effect).
            check(
                SHARED.load(Ordering::Acquire) == 42,
                b"concurrent: caller didn't see f's effects\n",
            );
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    schedule();

    check(GS_DONE.load(Ordering::Relaxed) == N, b"concurrent: not all Gs done\n");
    check(F_RAN.load(Ordering::Relaxed) == 1, b"concurrent: f ran more than once\n");
}

// ── Test 3: post-completion calls fast-path through, no f ────────

fn test_idempotent_after_complete() {
    static O: Once = Once::new();
    static F_RAN: AtomicUsize = AtomicUsize::new(0);

    F_RAN.store(0, Ordering::Relaxed);

    O.Do(|| { F_RAN.fetch_add(1, Ordering::Relaxed); });
    // f has run; subsequent Do() calls take the fast path.
    for _ in 0..1000 {
        O.Do(|| { F_RAN.fetch_add(1, Ordering::Relaxed); });
    }

    check(F_RAN.load(Ordering::Relaxed) == 1, b"idempotent: f ran > once\n");
}
