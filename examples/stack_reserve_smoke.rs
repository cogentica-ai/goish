// Smoke test: M29 — reserve-big, commit-lazy bare-go!() stacks.
//
// Bare `go!(|| body)` goroutines run on a 1 MiB lazily-committed
// virtual reservation with a bottom guard page — no stack sizing, no
// pivot annotations. This exercises the properties the design
// promises:
//
//   1. Deep recursion in a bare goroutine (~600 KiB of frames) just
//      works — no `stack(N)`, no `maybe_grow_step`.
//   2. Parking (chan send) from *inside* deep frames works — the
//      reservation is one contiguous region owned by the G, so
//      resuming on another M is safe. (The old pivot ladder
//      explicitly could NOT do this: its grown regions were freed at
//      scope exit.)
//   3. Spawn churn recycles reservations through the reserve pool
//      instead of mmap/munmap per goroutine.
//   4. The main goroutine (8 MiB reservation) hosts deep inline
//      recursion too.

#![no_std]
#![no_main]

extern crate alloc;

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gochan::chan;
use goish::runtime::sched::{reserve_pool_len, schedule};
use goish::{go, make, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

/// Recursive frame eater: each level pins a 1 KiB buffer, so depth D
/// consumes > D KiB of stack. `black_box` keeps the buffer from being
/// optimized out in release builds. Returns a value derived from the
/// buffer so the whole chain is data-dependent.
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
    // ─── Test 1: deep recursion in a bare goroutine ────────────────
    //
    // 600 levels × ~1 KiB+ per frame ≈ 600+ KiB — would overflow any
    // fixed 2/64 KiB stack, fits the 1 MiB reservation.
    static T1: AtomicI64 = AtomicI64::new(0);
    go!(|| {
        T1.store(burn(600), Ordering::Release);
    });
    schedule();
    check(T1.load(Ordering::Acquire) == 601, b"t1: deep recursion result\n");

    // ─── Test 2: park on a chan from inside deep frames ────────────
    //
    // Sender recurses ~300 KiB down, then sends on an unbuffered chan
    // from that depth (blocking until the receiver arrives). The G
    // parks and resumes with 300 KiB of live frames on its reserved
    // stack.
    static T2: AtomicI64 = AtomicI64::new(0);
    let ch: chan<i64> = make!(chan i64);
    let tx = ch.clone();
    go!(move || {
        fn deep_send(depth: usize, tx: &chan<i64>) -> i64 {
            let mut buf = [0u8; 1024];
            buf[0] = 7;
            let buf = core::hint::black_box(&mut buf);
            if depth == 0 {
                tx.Send(42); // park HERE, deep in the stack
                return buf[0] as i64;
            }
            deep_send(depth - 1, tx)
        }
        deep_send(300, &tx);
    });
    go!(move || {
        let (v, ok) = ch.Recv();
        check(ok, b"t2: recv ok\n");
        T2.store(v, Ordering::Release);
    });
    schedule();
    check(T2.load(Ordering::Acquire) == 42, b"t2: value through deep send\n");

    // ─── Test 3: spawn churn recycles reservations ─────────────────
    //
    // 300 bare goroutines run and die; their 1 MiB reservations must
    // land in the reserve pool (capped at 256) rather than being
    // munmap'd, and subsequent spawns must drain the pool.
    static RAN: AtomicUsize = AtomicUsize::new(0);
    for _ in 0..300 {
        go!(|| {
            RAN.fetch_add(1, Ordering::Relaxed);
        });
    }
    schedule();
    check(RAN.load(Ordering::Relaxed) == 300, b"t3: churn count\n");
    check(reserve_pool_len() > 0, b"t3: reserve pool empty after churn\n");

    // ─── Test 4: deep recursion on the main goroutine ──────────────
    //
    // Main gets an 8 MiB reservation; 2000 levels ≈ 2+ MiB of frames.
    check(burn(2000) == 2001, b"t4: main-G deep recursion\n");

    const OK: &[u8] = b"stack_reserve_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
