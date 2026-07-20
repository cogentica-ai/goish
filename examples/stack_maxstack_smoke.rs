// Smoke test: runtime/debug::SetMaxStack drives the bare-go!() stack
// reservation — the blessed pattern for deep-recursion workloads
// (compilers, tree walkers; typescript-go calls SetMaxStack from an
// env var before spawning its checkers).
//
// What this exercises:
//
//   1. SetMaxStack(64 MiB) → a *bare* go!() goroutine spawned after
//      the call can recurse far past the 1 MiB default reservation.
//      Without the knob this recursion would hit the guard page.
//   2. WaitGroup.Go inherits the raised reservation — it spawns via
//      the same bare path, so the typescript-go WorkGroup pattern
//      (SetMaxStack at startup, wg.Go(checkTask) later) needs no
//      call-site changes.
//   3. go!(stack(N)) with a huge N (256 MiB, MAP_NORESERVE) works
//      independently of SetMaxStack for one-off deep goroutines.
//   4. Restoring the default flushes mismatched reserve-pool entries
//      and later shallow spawns still run — pool-transition safety.

#![no_std]
#![no_main]

extern crate alloc;

use core::sync::atomic::{AtomicI64, Ordering};

use goish::runtime::debug;
use goish::runtime::sched::schedule;
use goish::sync::WaitGroup;
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

/// Recursive frame eater (same shape as stack_reserve_smoke): each
/// level pins a 1 KiB buffer, so depth D consumes > D KiB of stack.
/// `black_box` keeps the buffer alive in release builds; reading it
/// after the recursive call keeps every frame live across the chain.
fn burn(depth: usize) -> i64 {
    let mut buf = [0u8; 1024];
    buf[0] = (depth & 0xff) as u8;
    buf[1023] = 1;
    let buf = core::hint::black_box(&mut buf);
    if depth == 0 {
        return (buf[0] as i64) + (buf[1023] as i64);
    }
    (buf[1023] as i64) + burn(depth - 1)
}

#[goish::main]
fn main() {
    const MB: usize = 1024 * 1024;

    // ─── Test 1: SetMaxStack raises the bare-go!() reservation ─────
    //
    // 8192 levels × ~1 KiB+ per frame ≈ 8+ MiB of stack — an 8×
    // overflow of the 1 MiB default, comfortably inside 64 MiB even
    // with debug-build frame overhead.
    let prev = debug::SetMaxStack((64 * MB) as i64);
    check(prev == (1 * MB) as i64, b"t1: initial SetMaxStack value\n");

    static T1: AtomicI64 = AtomicI64::new(0);
    go!(|| {
        T1.store(burn(8192), Ordering::Release);
    });
    schedule();
    check(T1.load(Ordering::Acquire) == 8193, b"t1: deep bare-go recursion\n");

    // ─── Test 2: WaitGroup.Go inherits the raised reservation ──────
    //
    // The typescript-go shape: SetMaxStack at startup, worker tasks
    // spawned through WaitGroup.Go later. Same bare spawn path, so
    // the 64 MiB reservation applies with no call-site changes.
    static T2: AtomicI64 = AtomicI64::new(0);
    let wg = WaitGroup::new();
    wg.Go(|| {
        T2.store(burn(8192), Ordering::Release);
    });
    wg.Wait();
    check(T2.load(Ordering::Acquire) == 8193, b"t2: WaitGroup.Go deep recursion\n");

    // ─── Test 3: go!(stack(N)) huge one-off reservation ────────────
    //
    // 48k levels ≈ 48+ MiB of frames on an explicit 256 MiB
    // MAP_NORESERVE reservation — virtual space is free until
    // touched, so the reservation itself costs nothing up front.
    static T3: AtomicI64 = AtomicI64::new(0);
    go!(stack(256 * MB), || {
        T3.store(burn(49_152), Ordering::Release);
    });
    schedule();
    check(T3.load(Ordering::Acquire) == 49_153, b"t3: stack(256MB) deep recursion\n");

    // ─── Test 4: restore default; pool transition + shallow spawns ─
    //
    // Dropping back to 1 MiB flushes the 64 MiB entries parked in the
    // reserve pool (size-tagged, so no mislabeled reuse). Subsequent
    // shallow bare goroutines spawn and recycle normally.
    let prev = debug::SetMaxStack((1 * MB) as i64);
    check(prev == (64 * MB) as i64, b"t4: raised value read back\n");

    static T4: AtomicI64 = AtomicI64::new(0);
    for _ in 0..8 {
        go!(|| {
            T4.fetch_add(burn(100), Ordering::AcqRel);
        });
    }
    schedule();
    check(T4.load(Ordering::Acquire) == 8 * 101, b"t4: shallow spawns after restore\n");

    let msg = b"MAXSTACK_OK all 4 tests passed\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
