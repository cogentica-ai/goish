// Smoke test: M17a-ε — nil-chan semantics.
//
// Goish supports Go's `var c chan T` zero-value chan via
// `chan::<T>::nil()`:
//   - Send/Recv on nil block forever (runtime/chan.go:177-183).
//   - Close on nil panics (closechan).
//   - In `select!`, nil cases are filtered out of the lock order
//     and pass-1/2/3 (runtime/select.go:173-177).
//
// Tests here cover only the deadlock-free paths — we can't exercise
// "block forever" without a hung goroutine. Verifies nil + non-nil
// mixed select converges deterministically.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gochan::chan;
use goish::runtime::sched::schedule;
use goish::{go, make, select, syscall, KB};

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
    test_select_with_nil_recv_chooses_other();
    test_select_with_nil_send_chooses_other();
    test_select_with_default_and_all_nil();
    test_select_progresses_after_replace();

    const OK: &[u8] = b"chan_nil: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// Nil recv case must be skipped; the ready non-nil send case fires.
fn test_select_with_nil_recv_chooses_other() {
    static GOT: AtomicI64 = AtomicI64::new(-1);

    let nil_ch: chan<i64> = chan::nil();
    let real = make!(chan i64, 1);

    {
        let real = real.clone();
        let nil_ch = nil_ch.clone();
        go!(stack(64 * KB), move || {
            select! {
                let _v = nil_ch.Recv() => die(b"nil-recv: nil case fired\n"),
                real.Send(42) => { GOT.store(42, Ordering::Relaxed); },
            }
        });
    }

    {
        let real = real.clone();
        go!(stack(64 * KB), move || {
            let (v, _) = real.Recv();
            // ensure consumer sees what we sent
            if v != 42 {
                die(b"nil-recv: consumer got wrong value\n");
            }
        });
    }
    schedule();

    check(GOT.load(Ordering::Relaxed) == 42, b"nil-recv: select didn't fire send case\n");
}

// Nil send case must be skipped; the non-nil recv case fires.
fn test_select_with_nil_send_chooses_other() {
    static GOT_V: AtomicI64 = AtomicI64::new(-1);

    let nil_ch: chan<i64> = chan::nil();
    let real = make!(chan i64, 1);

    // Pre-fill so the recv case is immediately ready.
    real.Send(7);

    {
        let real = real.clone();
        let nil_ch = nil_ch.clone();
        go!(stack(64 * KB), move || {
            select! {
                nil_ch.Send(99) => die(b"nil-send: nil case fired\n"),
                let v = real.Recv() => { GOT_V.store(v, Ordering::Relaxed); },
            }
        });
    }
    schedule();

    check(GOT_V.load(Ordering::Relaxed) == 7, b"nil-send: didn't recv from real\n");
}

// All cases nil, default present: default fires.
fn test_select_with_default_and_all_nil() {
    static DEFAULT_FIRED: AtomicUsize = AtomicUsize::new(0);

    let n1: chan<i64> = chan::nil();
    let n2: chan<i64> = chan::nil();

    {
        let n1 = n1.clone();
        let n2 = n2.clone();
        go!(stack(64 * KB), move || {
            select! {
                let _ = n1.Recv() => die(b"all-nil-default: n1 fired\n"),
                n2.Send(5) => die(b"all-nil-default: n2 fired\n"),
                default => { DEFAULT_FIRED.fetch_add(1, Ordering::Relaxed); },
            }
        });
    }
    schedule();

    check(DEFAULT_FIRED.load(Ordering::Relaxed) == 1, b"all-nil-default: default didn't fire\n");
}

// Replace a chan with nil mid-loop to bound case counts. After the
// real chan is replaced, only the other path can fire. Mirrors the
// `c1[k] = nil` pattern from Go's TestSelectStress.
fn test_select_progresses_after_replace() {
    static A_COUNT: AtomicI64 = AtomicI64::new(0);
    static B_COUNT: AtomicI64 = AtomicI64::new(0);

    let a = make!(chan i64, 16);
    let b = make!(chan i64, 16);

    // Pre-fill both with 8 values each.
    for _ in 0..8 {
        a.Send(1);
        b.Send(2);
    }

    // Selector: drain 8 from a, then nil-out a so subsequent picks
    // come only from b. After draining 16 total iterations both are
    // accounted for.
    {
        let mut a_h = a.clone();
        let b_h = b.clone();
        go!(stack(64 * KB), move || {
            for _ in 0..16 {
                select! {
                    let v = a_h.Recv() => {
                        A_COUNT.fetch_add(v, Ordering::Relaxed);
                        if A_COUNT.load(Ordering::Relaxed) >= 8 {
                            // a drained — replace handle with nil so
                            // remaining iterations only see b.
                            a_h = chan::nil();
                        }
                    },
                    let v = b_h.Recv() => {
                        B_COUNT.fetch_add(v, Ordering::Relaxed);
                    },
                }
            }
        });
    }
    schedule();

    check(A_COUNT.load(Ordering::Relaxed) == 8, b"replace: a count wrong\n");
    check(B_COUNT.load(Ordering::Relaxed) == 16, b"replace: b count wrong\n");
}
