// Smoke test: M16f-β — lock-order sort + selparkcommit stress.
//
// Exercises the β-specific paths added on top of α:
//
//   1. Same-chan dedup — N cases on the same chan must not deadlock
//      when pass-1 acquires a single lock for all of them.
//   2. Many-distinct-chan select — pass-1 sorts and acquires N
//      distinct locks in address order; gopark+selparkcommit
//      releases them in the same order.
//   3. Pass-1 hit on a multi-chan select releases all N held locks
//      before breaking with the body.
//   4. Default-arm release — default fires under held locks; release
//      then break must not leave any chan locked.
//   5. Park + multi-counterpart — a select on M chans wakes when any
//      one fires; remaining M-1 sudogs are cancelled cleanly.
//
// In single-M cooperative goish these scenarios are correct under α
// too; β's value is multi-M correctness (not exercised here yet —
// M17a-ε will add multi-M tests). What β must not regress is the
// single-M path, and these tests verify that.

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
    test_same_chan_dedup_4_cases();
    test_eight_distinct_chans_default();
    test_eight_distinct_chans_park_then_recv();
    test_eight_distinct_chans_park_then_send();
    test_default_releases_all_locks();
    test_repeated_selects_no_deadlock();

    const OK: &[u8] = b"select_lockorder: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ─── Test 1: 4 cases on the same chan must dedup the lock ─────────

fn test_same_chan_dedup_4_cases() {
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
            for _ in 0..4 {
                select! {
                    let v = c.Recv() => SUM.fetch_add(v, Ordering::Relaxed),
                    let v = c.Recv() => SUM.fetch_add(v * 2, Ordering::Relaxed),
                    let v = c.Recv() => SUM.fetch_add(v * 4, Ordering::Relaxed),
                    let v = c.Recv() => SUM.fetch_add(v * 8, Ordering::Relaxed),
                };
            }
        });
    }
    schedule();
    let sum = SUM.load(Ordering::Relaxed);
    // Exactly 1+2+3+4=10 distinct values consumed; each multiplied by
    // 1/2/4/8 depending on which arm fires. Min coefficient sum = 10×1 = 10
    // (all arms hit ×1). Max = 10×8 = 80. Verify in range, drained.
    check(sum >= 10 && sum <= 80, b"t1: sum out of bounds\n");
    check(ch.Len() == 0, b"t1: chan not drained\n");
}

// ─── Test 2: 8 distinct chans + default — must release all 8 ──────

fn test_eight_distinct_chans_default() {
    let chs: [_; 8] = [
        make!(chan i64, 0), make!(chan i64, 0),
        make!(chan i64, 0), make!(chan i64, 0),
        make!(chan i64, 0), make!(chan i64, 0),
        make!(chan i64, 0), make!(chan i64, 0),
    ];
    static FIRED: AtomicUsize = AtomicUsize::new(0);
    let cs: [_; 8] = [
        chs[0].clone(), chs[1].clone(), chs[2].clone(), chs[3].clone(),
        chs[4].clone(), chs[5].clone(), chs[6].clone(), chs[7].clone(),
    ];
    go!(stack(64 * KB), move || {
        let arm: u8 = select! {
            let _ = (cs[0]).Recv() => 0u8,
            let _ = (cs[1]).Recv() => 1u8,
            let _ = (cs[2]).Recv() => 2u8,
            let _ = (cs[3]).Recv() => 3u8,
            let _ = (cs[4]).Recv() => 4u8,
            let _ = (cs[5]).Recv() => 5u8,
            let _ = (cs[6]).Recv() => 6u8,
            let _ = (cs[7]).Recv() => 7u8,
            default => 99u8,
        };
        FIRED.store(arm as usize, Ordering::Relaxed);
    });
    schedule();
    check(FIRED.load(Ordering::Relaxed) == 99, b"t2: default not fired\n");
    // Critical β check: the chans must not still be locked. A
    // subsequent independent op on each should succeed.
    for ch in &chs {
        check(ch.Len() == 0, b"t2: chan inaccessible after default\n");
    }
}

// ─── Test 3: 8 distinct chans, park, then a counterpart fires ─────

fn test_eight_distinct_chans_park_then_recv() {
    let chs: [_; 8] = [
        make!(chan i64, 0), make!(chan i64, 0),
        make!(chan i64, 0), make!(chan i64, 0),
        make!(chan i64, 0), make!(chan i64, 0),
        make!(chan i64, 0), make!(chan i64, 0),
    ];
    static FIRED: AtomicI64 = AtomicI64::new(-1);
    static GOT: AtomicI64 = AtomicI64::new(0);

    let cs: [_; 8] = [
        chs[0].clone(), chs[1].clone(), chs[2].clone(), chs[3].clone(),
        chs[4].clone(), chs[5].clone(), chs[6].clone(), chs[7].clone(),
    ];
    go!(stack(64 * KB), move || {
        let arm = select! {
            let v = (cs[0]).Recv() => { GOT.store(v, Ordering::Relaxed); 0i64 },
            let v = (cs[1]).Recv() => { GOT.store(v, Ordering::Relaxed); 1i64 },
            let v = (cs[2]).Recv() => { GOT.store(v, Ordering::Relaxed); 2i64 },
            let v = (cs[3]).Recv() => { GOT.store(v, Ordering::Relaxed); 3i64 },
            let v = (cs[4]).Recv() => { GOT.store(v, Ordering::Relaxed); 4i64 },
            let v = (cs[5]).Recv() => { GOT.store(v, Ordering::Relaxed); 5i64 },
            let v = (cs[6]).Recv() => { GOT.store(v, Ordering::Relaxed); 6i64 },
            let v = (cs[7]).Recv() => { GOT.store(v, Ordering::Relaxed); 7i64 },
        };
        FIRED.store(arm, Ordering::Relaxed);
    });
    // Counterpart: send on chan 5.
    {
        let c = chs[5].clone();
        go!(stack(64 * KB), move || c.Send(0xABCD));
    }
    schedule();
    check(FIRED.load(Ordering::Relaxed) == 5, b"t3: wrong arm fired\n");
    check(GOT.load(Ordering::Relaxed) == 0xABCD, b"t3: wrong recv value\n");
    // β invariant: all 8 chan locks must be released by selparkcommit.
    // Verify by independent ops.
    for ch in &chs {
        check(ch.Len() == 0, b"t3: chan locked after wake\n");
    }
}

// ─── Test 4: 8-chan select parked, send-arm wins via counterpart ──

fn test_eight_distinct_chans_park_then_send() {
    let chs: [_; 8] = [
        make!(chan i64, 0), make!(chan i64, 0),
        make!(chan i64, 0), make!(chan i64, 0),
        make!(chan i64, 0), make!(chan i64, 0),
        make!(chan i64, 0), make!(chan i64, 0),
    ];
    static FIRED: AtomicI64 = AtomicI64::new(-1);
    static SENT: AtomicI64 = AtomicI64::new(0);

    let cs: [_; 8] = [
        chs[0].clone(), chs[1].clone(), chs[2].clone(), chs[3].clone(),
        chs[4].clone(), chs[5].clone(), chs[6].clone(), chs[7].clone(),
    ];
    go!(stack(64 * KB), move || {
        let arm = select! {
            (cs[0]).Send(100) => 0i64,
            (cs[1]).Send(101) => 1i64,
            (cs[2]).Send(102) => 2i64,
            (cs[3]).Send(103) => 3i64,
            (cs[4]).Send(104) => 4i64,
            (cs[5]).Send(105) => 5i64,
            (cs[6]).Send(106) => 6i64,
            (cs[7]).Send(107) => 7i64,
        };
        FIRED.store(arm, Ordering::Relaxed);
    });
    {
        let c = chs[3].clone();
        go!(stack(64 * KB), move || {
            let (v, _) = c.Recv();
            SENT.store(v, Ordering::Relaxed);
        });
    }
    schedule();
    check(FIRED.load(Ordering::Relaxed) == 3, b"t4: wrong arm fired\n");
    check(SENT.load(Ordering::Relaxed) == 103, b"t4: counterpart got wrong value\n");
}

// ─── Test 5: default fires; verify locks released ─────────────────

fn test_default_releases_all_locks() {
    let a = make!(chan i64, 0);
    let b = make!(chan i64, 0);
    let c = make!(chan i64, 0);
    {
        let a = a.clone();
        let b = b.clone();
        let c = c.clone();
        go!(stack(64 * KB), move || {
            select! {
                let _ = a.Recv() => die(b"t5: a fired\n"),
                let _ = b.Recv() => die(b"t5: b fired\n"),
                let _ = c.Recv() => die(b"t5: c fired\n"),
                default => {},
            }
        });
    }
    schedule();
    // After the goroutine exits with default fired, the chans must
    // be fully usable again (locks released). Spawn three more
    // goroutines that each send + recv on each chan; all must
    // complete.
    static DONE: AtomicUsize = AtomicUsize::new(0);
    for ch in [a, b, c] {
        let s = ch.clone();
        let r = ch.clone();
        go!(stack(64 * KB), move || s.Send(1));
        go!(stack(64 * KB), move || {
            let _ = r.Recv();
            DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    schedule();
    check(DONE.load(Ordering::Relaxed) == 3, b"t5: chan unusable after default\n");
}

// ─── Test 6: 50 selects in a row on shared chans, no deadlock ─────

fn test_repeated_selects_no_deadlock() {
    let a = make!(chan i64, 8);
    let b = make!(chan i64, 8);
    static OK_COUNT: AtomicUsize = AtomicUsize::new(0);

    // Producer pre-fills.
    {
        let a = a.clone();
        let b = b.clone();
        go!(stack(64 * KB), move || {
            for i in 0..50i64 {
                if i % 2 == 0 {
                    a.Send(i);
                } else {
                    b.Send(i);
                }
            }
        });
    }
    {
        let a = a.clone();
        let b = b.clone();
        go!(stack(64 * KB), move || {
            for _ in 0..50 {
                select! {
                    let _ = a.Recv() => OK_COUNT.fetch_add(1, Ordering::Relaxed),
                    let _ = b.Recv() => OK_COUNT.fetch_add(1, Ordering::Relaxed),
                };
            }
        });
    }
    schedule();
    check(OK_COUNT.load(Ordering::Relaxed) == 50, b"t6: not all 50 selects fired\n");
}
