// defer_panic_smoke — verify that `defer!` bodies run when the
// enclosing scope panics, not just on normal return.
//
// Background: on stable Rust + no_std, panic = "abort" means Drops
// are skipped on panic. `defer!` registers itself with the per-G
// cleanup list (B.1+); the panic_handler walks the list and runs
// each registered body before `gogo`-ing to the recovery point.
//
// This test:
//   1. Goroutine A: panics inside a scope with three `defer!`s.
//      Verifies all three deferred bodies ran (LIFO order).
//   2. Goroutine B: returns normally with a `defer!`. Verifies the
//      body ran on Drop (existing behavior — regression check).
//   3. Process exits 0; G_PANIC_COUNT == 1.

#![no_std]
#![no_main]

extern crate goish;

use core::sync::atomic::{AtomicI64, Ordering};

use goish::runtime::sched;
use goish::sync::WaitGroup;
use goish::{defer, go, syscall, KB};

fn print(s: &[u8]) {
    syscall::Write(syscall::STDOUT, s.as_ptr(), s.len());
}

fn print_dec(n: i64) {
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    let neg = n < 0;
    let mut x = if neg { (-(n as i128)) as u128 } else { n as u128 };
    if x == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while x > 0 {
            i -= 1;
            buf[i] = b'0' + (x % 10) as u8;
            x /= 10;
        }
    }
    if neg { i -= 1; buf[i] = b'-'; }
    let _ = n;
    syscall::Write(syscall::STDOUT, buf[i..].as_ptr(), buf.len() - i);
}

// Trace which defer bodies ran, in invocation order.
static TRACE: [AtomicI64; 8] = [
    AtomicI64::new(0), AtomicI64::new(0), AtomicI64::new(0), AtomicI64::new(0),
    AtomicI64::new(0), AtomicI64::new(0), AtomicI64::new(0), AtomicI64::new(0),
];
static TRACE_LEN: AtomicI64 = AtomicI64::new(0);

fn record(tag: i64) {
    let i = TRACE_LEN.fetch_add(1, Ordering::AcqRel);
    if (i as usize) < TRACE.len() {
        TRACE[i as usize].store(tag, Ordering::Release);
    }
}

#[goish::main]
fn main() {
    go!(|| {
        let wg = WaitGroup::new();

        // ── Goroutine A: panics with 3 defers. Should record 3, 2, 1
        // (LIFO) before recovery + Done().
        wg.GoStack(32 * KB, || {
            defer!{ record(1); }
            defer!{ record(2); }
            defer!{ record(3); }
            record(100);
            panic!("intentional panic in goroutine A");
        });

        // ── Goroutine B: returns normally with one defer. Records
        // 200 first then 4 on scope-exit Drop.
        wg.GoStack(8 * KB, || {
            defer!{ record(4); }
            record(200);
        });

        // Manual Done() to compensate for goroutine A's missing Done()
        // (its closure was abandoned by panic recovery before Done()
        // ran).
        wg.Done();
        wg.Wait();

        // Spin for the panic-recovery path to complete.
        for _ in 0..10_000 {
            if sched::G_PANIC_COUNT.load(Ordering::Acquire) >= 1 {
                break;
            }
            sched::Gosched();
        }

        let n = TRACE_LEN.load(Ordering::Acquire);
        print(b"trace: ");
        for i in 0..n.min(TRACE.len() as i64) {
            print_dec(TRACE[i as usize].load(Ordering::Acquire));
            print(b" ");
        }
        print(b"(len=");
        print_dec(n);
        print(b")\n");
        print(b"panics=");
        print_dec(sched::G_PANIC_COUNT.load(Ordering::Acquire) as i64);
        print(b"\n");

        // Expected order:
        //   100  (A's body before panic)
        //   3    (A's defer!{record(3)})
        //   2    (A's defer!{record(2)})
        //   1    (A's defer!{record(1)})
        //   200  (B's body)
        //   4    (B's defer!{record(4)})
        //
        // (A and B run on different Ms; the relative order between
        // 100/200 and the defers is undefined, but within each
        // goroutine the LIFO order is fixed. Check membership +
        // intra-goroutine LIFO.)
        let trace_vals: [i64; 6] = [
            TRACE[0].load(Ordering::Acquire),
            TRACE[1].load(Ordering::Acquire),
            TRACE[2].load(Ordering::Acquire),
            TRACE[3].load(Ordering::Acquire),
            TRACE[4].load(Ordering::Acquire),
            TRACE[5].load(Ordering::Acquire),
        ];

        let has = |x: i64| trace_vals.iter().any(|&v| v == x);
        let all_present = has(100) && has(3) && has(2) && has(1) && has(200) && has(4);

        // Check LIFO within A: position of 3 < position of 2 < position of 1
        let pos = |x: i64| trace_vals.iter().position(|&v| v == x).unwrap_or(99);
        let lifo_a = pos(3) < pos(2) && pos(2) < pos(1);

        let panics = sched::G_PANIC_COUNT.load(Ordering::Acquire);

        if all_present && lifo_a && n == 6 && panics == 1 {
            print(b"PASS\n");
        } else {
            print(b"FAIL all_present=");
            print_dec(all_present as i64);
            print(b" lifo_a=");
            print_dec(lifo_a as i64);
            print(b" panics=");
            print_dec(panics as i64);
            print(b"\n");
            syscall::Exit(1);
        }
    });

    sched::schedule();
}
