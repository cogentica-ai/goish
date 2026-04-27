// Smoke test: M16g-α — sync.Mutex.
//
// Tests:
//   1. Uncontended Lock/Unlock works.
//   2. TryLock fast paths.
//   3. Multi-goroutine contention: shared counter under Mutex
//      protection always reaches the expected total (no lost updates).
//   4. Cross-goroutine handoff: one G locks, another G unlocks (Go
//      allows this — Mutex isn't owned by a goroutine).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::runtime::sched::schedule;
use goish::sync::Mutex;
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
    test_lock_unlock_uncontended();
    test_trylock();
    test_contended_counter();
    test_cross_g_handoff();

    const OK: &[u8] = b"sync_mutex: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ── Test 1: uncontended Lock/Unlock from a single goroutine.
// Demonstrates the Go-shape `LockManual` + `Unlock` pair (matches
// `m.Lock(); ...; m.Unlock()` verbatim from Go code).

fn test_lock_unlock_uncontended() {
    static MU: Mutex = Mutex::new(());
    static RAN: AtomicUsize = AtomicUsize::new(0);

    go!(|| {
        MU.LockManual();
        RAN.fetch_add(1, Ordering::Relaxed);
        MU.Unlock();

        // Re-lock to confirm Unlock fully released.
        MU.LockManual();
        RAN.fetch_add(1, Ordering::Relaxed);
        MU.Unlock();
    });
    schedule();

    check(RAN.load(Ordering::Relaxed) == 2, b"uncontended: didn't run twice\n");
    check(MU.TryLockManual(), b"uncontended: TryLock failed after Unlock\n");
    MU.Unlock();
}

// ── Test 2: TryLock fast paths (both Manual and RAII forms) ───────

fn test_trylock() {
    static MU: Mutex = Mutex::new(());

    // Manual (Go-shape, returns bool):
    check(MU.TryLockManual(), b"trylock: fresh mutex, TryLockManual failed\n");
    check(!MU.TryLockManual(), b"trylock: locked mutex, TryLockManual succeeded\n");
    MU.Unlock();

    // RAII (returns Option<MutexGuard>):
    {
        let g = MU.TryLock();
        check(g.is_some(), b"trylock: fresh mutex, TryLock returned None\n");
        check(MU.TryLock().is_none(), b"trylock: TryLock should fail under guard\n");
        // g drops at end of block -> unlocks.
    }

    // After the guard scope, the lock is free again.
    {
        let g = MU.TryLock();
        check(g.is_some(), b"trylock: after guard drop, TryLock failed\n");
        // g drops at end of block.
    }
}

// ── Test 3: contended counter — N goroutines each do K increments
// ── under the mutex; final count must equal N*K exactly.

fn test_contended_counter() {
    const N_GS: i64 = 32;
    const N_INCREMENTS: i64 = 1_000;

    static MU: Mutex = Mutex::new(());
    static SHARED: AtomicI64 = AtomicI64::new(0);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);

    // Reset (test runs after others may have touched MU).
    SHARED.store(0, Ordering::Relaxed);
    GS_DONE.store(0, Ordering::Relaxed);

    for _ in 0..N_GS {
        go!(move || {
            for _ in 0..N_INCREMENTS {
                let _g = MU.Lock();
                // Read-modify-write under lock; if Mutex were broken,
                // updates would be lost under multi-M contention.
                let v = SHARED.load(Ordering::Relaxed);
                SHARED.store(v + 1, Ordering::Relaxed);
                // _g drops -> unlocks at end of iteration.
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    schedule();

    check(GS_DONE.load(Ordering::Relaxed) as i64 == N_GS, b"contended: not all Gs done\n");
    let got = SHARED.load(Ordering::Relaxed);
    check(got == N_GS * N_INCREMENTS, b"contended: counter wrong (lost updates)\n");
}

// ── Test 4: cross-goroutine handoff — one G locks, another unlocks.

fn test_cross_g_handoff() {
    static MU: Mutex = Mutex::new(());
    static A_LOCKED: AtomicUsize = AtomicUsize::new(0);
    static B_UNLOCKED: AtomicUsize = AtomicUsize::new(0);
    static C_GOT_LOCK: AtomicUsize = AtomicUsize::new(0);

    // Reset.
    A_LOCKED.store(0, Ordering::Relaxed);
    B_UNLOCKED.store(0, Ordering::Relaxed);
    C_GOT_LOCK.store(0, Ordering::Relaxed);

    // G A: take the lock, signal, then exit (without unlocking).
    // Use the manual API since Lock+Unlock cross goroutine boundaries.
    go!(|| {
        MU.LockManual();
        A_LOCKED.store(1, Ordering::Release);
    });

    // G B: wait until A signals, then unlock on behalf of A.
    go!(|| {
        while A_LOCKED.load(Ordering::Acquire) == 0 {
            goish::runtime::sched::Gosched();
        }
        MU.Unlock();
        B_UNLOCKED.store(1, Ordering::Release);
    });

    // G C: wait until B unlocks, then take the lock and release it.
    go!(|| {
        while B_UNLOCKED.load(Ordering::Acquire) == 0 {
            goish::runtime::sched::Gosched();
        }
        MU.LockManual();
        C_GOT_LOCK.store(1, Ordering::Release);
        MU.Unlock();
    });

    schedule();

    check(A_LOCKED.load(Ordering::Acquire) == 1, b"handoff: A didn't lock\n");
    check(B_UNLOCKED.load(Ordering::Acquire) == 1, b"handoff: B didn't unlock\n");
    check(C_GOT_LOCK.load(Ordering::Acquire) == 1, b"handoff: C didn't acquire\n");
}
