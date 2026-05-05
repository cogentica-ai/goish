// Smoke test: M16f-α step 4b — the `select!` macro.
//
// Mirrors examples/select_handcoded.rs scenarios but exercises the
// macro instead of hand-rolled equivalents. Tests:
//
//   1. Pass-1 hit on recv (bare ident binding).
//   2. Pass-1 hit on send.
//   3. Pass-1 hit with tuple `(v, ok)` binding.
//   4. Pass-1 hit with `_` binding.
//   5. Default arm fires (no case ready).
//   6. Park then send case fires.
//   7. Park then recv case fires.
//   8. Many-iter mixed: 100 selectors, 50 sends + 50 recvs counterparts.
//   9. Paren-expr fallback for chan handle.
//  10. Multi-recv on same chan (auto-clone semantics).

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

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
    test_pass1_recv_bare();
    test_pass1_send();
    test_pass1_recv_tuple();
    test_pass1_recv_underscore();
    test_default_fires();
    test_park_then_send();
    test_park_then_recv();
    test_many_iterations();
    test_paren_chan_recv();
    test_multi_recv_same_chan();

    const OK: &[u8] = b"select_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ─── Test 1: pass-1 recv with bare-ident binding ──────────────────

fn test_pass1_recv_bare() {
    let ch_recv = make!(chan i64, 1);
    let ch_send = make!(chan i64, 0);

    static GOT: AtomicI64 = AtomicI64::new(-1);

    {
        let ch = ch_recv.clone();
        go!(stack(64 * KB), move || ch.Send(0xCAFE));
    }
    {
        let cr = ch_recv.clone();
        let cs = ch_send.clone();
        go!(stack(64 * KB), move || {
            let outcome: u8 = select! {
                let v = cr.Recv() => {
                    GOT.store(v, Ordering::Relaxed);
                    1u8
                },
                cs.Send(99) => 2u8,
            };
            check(outcome == 1, b"t1: wrong arm fired\n");
        });
    }
    schedule();
    check(GOT.load(Ordering::Relaxed) == 0xCAFE, b"t1: wrong recv value\n");
}

// ─── Test 2: pass-1 send (buffered slot available) ────────────────

fn test_pass1_send() {
    let ch_recv = make!(chan i64, 0);
    let ch_send = make!(chan i64, 1); // has slot — send fires

    {
        let cr = ch_recv.clone();
        let cs = ch_send.clone();
        go!(stack(64 * KB), move || {
            let arm: u8 = select! {
                let _ = cr.Recv() => 1u8,
                cs.Send(7) => 2u8,
            };
            check(arm == 2, b"t2: wrong arm fired\n");
        });
    }
    schedule();
    check(ch_send.Len() == 1, b"t2: send didn't deposit\n");
}

// ─── Test 3: pass-1 recv with tuple `(v, ok)` binding ─────────────

fn test_pass1_recv_tuple() {
    let ch = make!(chan i64, 1);
    static GOT_V: AtomicI64 = AtomicI64::new(-1);
    static GOT_OK: AtomicUsize = AtomicUsize::new(99);

    // Pre-fill the buffered slot synchronously. Spawning a sender
    // goroutine here is racy under M17b-γ work-stealing: a worker
    // M can steal the selector and run its `select!` *before* the
    // sender goroutine executes, causing the `default` arm to fire
    // spuriously. Go's runtime documents this class of test bug at
    // proc.go:7042-7050 — assertions that rely on goroutine spawn
    // order are "poorly-written tests". Since `Send` on an empty
    // 1-buffer is non-blocking, deposit the value directly from
    // main M; the test's intent (pass-1 hit on tuple-binding recv)
    // is preserved without the order assumption.
    ch.Send(123);

    {
        let c = ch.clone();
        go!(stack(64 * KB), move || {
            select! {
                let (v, ok) = c.Recv() => {
                    GOT_V.store(v, Ordering::Relaxed);
                    GOT_OK.store(if ok { 1 } else { 0 }, Ordering::Relaxed);
                },
                default => die(b"t3: default fired unexpectedly\n"),
            }
        });
    }
    schedule();
    check(GOT_V.load(Ordering::Relaxed) == 123, b"t3: wrong v\n");
    check(GOT_OK.load(Ordering::Relaxed) == 1, b"t3: wrong ok\n");
}

// ─── Test 4: pass-1 recv with `_` binding ─────────────────────────

fn test_pass1_recv_underscore() {
    let ch = make!(chan i64, 1);
    static FIRED: AtomicUsize = AtomicUsize::new(0);

    {
        let c = ch.clone();
        go!(stack(64 * KB), move || c.Send(42));
    }
    {
        let c = ch.clone();
        go!(stack(64 * KB), move || {
            select! {
                let _ = c.Recv() => FIRED.store(1, Ordering::Relaxed),
            }
        });
    }
    schedule();
    check(FIRED.load(Ordering::Relaxed) == 1, b"t4: didn't fire\n");
    // Buffer should be drained.
    check(ch.Len() == 0, b"t4: chan still has values\n");
}

// ─── Test 5: default fires when no case ready ─────────────────────

fn test_default_fires() {
    let cr = make!(chan i64, 0);
    let cs = make!(chan i64, 0);
    static FIRED: AtomicUsize = AtomicUsize::new(0);

    {
        let cr = cr.clone();
        let cs = cs.clone();
        go!(stack(64 * KB), move || {
            let arm: u8 = select! {
                let _ = cr.Recv() => 1u8,
                cs.Send(0) => 2u8,
                default => 9u8,
            };
            FIRED.store(arm as usize, Ordering::Relaxed);
        });
    }
    schedule();
    check(FIRED.load(Ordering::Relaxed) == 9, b"t5: default didn't fire\n");
}

// ─── Test 6: park then send fires ─────────────────────────────────

fn test_park_then_send() {
    let cr = make!(chan i64, 0);
    let cs = make!(chan i64, 0);
    static FIRED: AtomicUsize = AtomicUsize::new(0);
    static SEND_GOT: AtomicI64 = AtomicI64::new(0);

    {
        let cr = cr.clone();
        let cs = cs.clone();
        go!(stack(64 * KB), move || {
            let arm: u8 = select! {
                let _ = cr.Recv() => 1u8,
                cs.Send(11) => 2u8,
            };
            FIRED.store(arm as usize, Ordering::Relaxed);
        });
    }
    // Counterpart: receiver on cs (matches the send case).
    {
        let cs = cs.clone();
        go!(stack(64 * KB), move || {
            let (v, _) = cs.Recv();
            SEND_GOT.store(v, Ordering::Relaxed);
        });
    }
    schedule();
    check(FIRED.load(Ordering::Relaxed) == 2, b"t6: send arm didn't fire\n");
    check(SEND_GOT.load(Ordering::Relaxed) == 11, b"t6: recv missed value\n");
}

// ─── Test 7: park then recv fires ─────────────────────────────────

fn test_park_then_recv() {
    let cr = make!(chan i64, 0);
    let cs = make!(chan i64, 0);
    static FIRED: AtomicUsize = AtomicUsize::new(0);
    static GOT: AtomicI64 = AtomicI64::new(0);

    {
        let cr = cr.clone();
        let cs = cs.clone();
        go!(stack(64 * KB), move || {
            select! {
                let v = cr.Recv() => {
                    GOT.store(v, Ordering::Relaxed);
                    FIRED.store(1, Ordering::Relaxed);
                },
                cs.Send(22) => FIRED.store(2, Ordering::Relaxed),
            }
        });
    }
    {
        let cr = cr.clone();
        go!(stack(64 * KB), move || cr.Send(0xBEEF));
    }
    schedule();
    check(FIRED.load(Ordering::Relaxed) == 1, b"t7: recv arm didn't fire\n");
    check(GOT.load(Ordering::Relaxed) == 0xBEEF, b"t7: wrong recv value\n");
}

// ─── Test 8: many iterations, mixed counterparts ──────────────────

fn test_many_iterations() {
    const N: usize = 100;
    let cr = make!(chan i64, 0);
    let cs = make!(chan i64, 0);

    static RECV_FIRES: AtomicUsize = AtomicUsize::new(0);
    static SEND_FIRES: AtomicUsize = AtomicUsize::new(0);
    static SEND_SUM: AtomicI64 = AtomicI64::new(0);
    static RECV_SUM: AtomicI64 = AtomicI64::new(0);

    for i in 0..N {
        // Clone for selector closure.
        let cr_sel = cr.clone();
        let cs_sel = cs.clone();
        go!(stack(64 * KB), move || {
            select! {
                let v = cr_sel.Recv() => {
                    RECV_FIRES.fetch_add(1, Ordering::Relaxed);
                    RECV_SUM.fetch_add(v, Ordering::Relaxed);
                },
                cs_sel.Send(i as i64) => {
                    SEND_FIRES.fetch_add(1, Ordering::Relaxed);
                },
            }
        });
        // Counterpart goroutines borrow fresh clones from the
        // outer `cr` / `cs` (still owned by the loop body).
        if i % 2 == 0 {
            let cs_cp = cs.clone();
            go!(stack(64 * KB), move || {
                let (v, _) = cs_cp.Recv();
                SEND_SUM.fetch_add(v, Ordering::Relaxed);
            });
        } else {
            let cr_cp = cr.clone();
            let val = i as i64 + 1000;
            go!(stack(64 * KB), move || cr_cp.Send(val));
        }
    }
    schedule();
    let recv_fires = RECV_FIRES.load(Ordering::Relaxed);
    let send_fires = SEND_FIRES.load(Ordering::Relaxed);
    check(recv_fires + send_fires == N, b"t8: total fires mismatch\n");
    check(send_fires == 50, b"t8: send_fires != 50\n");
    check(recv_fires == 50, b"t8: recv_fires != 50\n");

    // RECV_SUM is deterministic: the 50 cr-senders deliver 50
    // distinct odd-i values (1001, 1003, …, 1099), and exactly 50
    // selectors fire their recv branch — the sum of all values
    // pulled from `cr` is therefore fixed, regardless of which
    // selectors won the race.
    let expected_recv: i64 = (0..N as i64).filter(|i| i % 2 == 1).map(|i| i + 1000).sum();
    check(RECV_SUM.load(Ordering::Relaxed) == expected_recv, b"t8: recv sum\n");

    // SEND_SUM is NOT deterministic. With M17b-γ work-stealing the
    // 100 selectors run in parallel across worker Ms; *which* 50
    // selectors fire their send branch depends on race timing —
    // any 50 of the 100 can win. The original assertion
    // `SEND_SUM == 0+2+4+…+98 = 2450` silently assumed selectors
    // i=0,2,…,98 fire send, which only held under the single-M
    // pre-γ scheduler. proc.go:7042-7050 documents this class of
    // test bug:
    //
    //   "we introduce some randomness into scheduling decisions
    //    when running with the race detector. … breaking many
    //    poorly-written tests."
    //
    // The invariant we *can* assert is the bound:
    // SEND_SUM ∈ [0, sum(0..N)] = [0, 4950].
    let send_sum = SEND_SUM.load(Ordering::Relaxed);
    let upper: i64 = (0..N as i64).sum();
    check(
        send_sum >= 0 && send_sum <= upper,
        b"t8: send sum out of range\n",
    );
}

// ─── Test 9: paren-expr fallback for chan ─────────────────────────

fn test_paren_chan_recv() {
    // Simulate a "complex" chan expression via a 1-element slice.
    let ch = make!(chan i64, 1);
    let chans = [ch.clone()];
    static GOT: AtomicI64 = AtomicI64::new(-1);

    {
        let c = ch.clone();
        go!(stack(64 * KB), move || c.Send(0xF00D));
    }
    {
        let c = chans[0].clone();
        go!(stack(64 * KB), move || {
            select! {
                let v = (c).Recv() => GOT.store(v, Ordering::Relaxed),
            }
        });
    }
    schedule();
    check(GOT.load(Ordering::Relaxed) == 0xF00D, b"t9: paren-chan recv missed\n");
}

// ─── Test 10: multi-recv on same chan (auto-clone) ────────────────

fn test_multi_recv_same_chan() {
    let ch = make!(chan i64, 4);
    {
        let c = ch.clone();
        go!(stack(64 * KB), move || {
            c.Send(1);
            c.Send(2);
            c.Send(3);
            c.Send(4);
        });
    }
    static SUM: AtomicI64 = AtomicI64::new(0);
    {
        let c = ch.clone();
        go!(stack(64 * KB), move || {
            // Multi-recv arm — auto-clone semantic should let both
            // arms reference the same `c` without consuming it.
            for _ in 0..4 {
                select! {
                    let v = c.Recv() => SUM.fetch_add(v, Ordering::Relaxed),
                    let v2 = c.Recv() => SUM.fetch_add(v2 * 10, Ordering::Relaxed),
                };
            }
        });
    }
    schedule();
    let sum = SUM.load(Ordering::Relaxed);
    // Each Recv yields 1, 2, 3, 4. Each iteration fires exactly one arm
    // (the same chan satisfies both). Some go to v (×1), some to v2 (×10).
    // Total values are 1+2+3+4=10, contributed as either v or v2. So SUM
    // is in [10, 100] depending on which arm fires each time. Let's just
    // verify it's in that range and total values were drained.
    check(sum >= 10 && sum <= 100, b"t10: sum out of range\n");
    check(ch.Len() == 0, b"t10: chan still has values\n");
}
