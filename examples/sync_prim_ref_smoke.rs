// sync_prim_ref_smoke — Mutex, RWMutex and WaitGroup against Go.
// (sync/mutex.go, sync/rwmutex.go, sync/waitgroup.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_syncprim_ref.go` run in `package
// sync_test` by `scripts/goref.sh`.
//
// Every file under src/sync/ carried no provenance anchors and matched
// Go by NAME ONLY. This pins the half of these primitives that is
// DETERMINISTIC single-threaded — the TryLock family's answers,
// RWMutex's reader/writer exclusion, and WaitGroup's counter reaching
// zero. The blocking half needs real contention and is not what this
// checks; it is exercised by the concurrency smokes elsewhere.
//
// The rows worth having are the exclusion ones. `TryLock` while a
// SECOND reader still holds the lock must be false — a port that
// decrements a reader count and then lets a writer in as soon as one
// reader leaves would pass every single-reader test and corrupt data
// under two.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::gostring::string;
use goish::sync::{Mutex, RWMutex, WaitGroup};
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn eqb(failed: &mut int, got: bool, want: bool, what: &str) {
    if got == want {
        return;
    }
    fmt::Printf!("[!!] %s FAIL got %v want %v\n", s(what), got, want);
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Mutex.TryLock. goish's Mutex guards a value and hands back a
    //    guard, where Go's is bare — so `TryLock` returns an Option and
    //    "did it succeed" is `is_some()`. The ANSWERS are Go's.
    {
        let mu: Mutex<int> = Mutex::new(0);
        let g1 = mu.TryLock();
        eqb(&mut failed, g1.is_some(), true, "mutex trylock-free");
        // Held: a second TryLock must fail while the guard is alive.
        eqb(
            &mut failed,
            mu.TryLock().is_some(),
            false,
            "mutex trylock-held",
        );
        drop(g1);
        let g2 = mu.TryLock();
        eqb(
            &mut failed,
            g2.is_some(),
            true,
            "mutex trylock-after-unlock",
        );
        drop(g2);
    }

    // 2. RWMutex. goish's is Go's shape — bare RLock/RUnlock/Lock —
    //    because it guards nothing.
    {
        let rw = RWMutex::new();
        eqb(&mut failed, rw.TryRLock(), true, "rw tryrlock-free");
        eqb(&mut failed, rw.TryRLock(), true, "rw tryrlock-second");
        // A writer must be refused while ANY reader holds it.
        eqb(
            &mut failed,
            rw.TryLock(),
            false,
            "rw trylock-while-read-held",
        );
        rw.RUnlock();
        // Still one reader left — still refused. This is the row that
        // catches a port letting a writer in as soon as one reader
        // leaves.
        eqb(
            &mut failed,
            rw.TryLock(),
            false,
            "rw trylock-one-reader-left",
        );
        rw.RUnlock();
        eqb(&mut failed, rw.TryLock(), true, "rw trylock-no-readers");
        // While a writer holds it, neither a reader nor another writer
        // may enter.
        eqb(
            &mut failed,
            rw.TryRLock(),
            false,
            "rw tryrlock-while-write-held",
        );
        eqb(
            &mut failed,
            rw.TryLock(),
            false,
            "rw trylock-while-write-held",
        );
        rw.Unlock();
        eqb(&mut failed, rw.TryRLock(), true, "rw tryrlock-after-unlock");
        rw.RUnlock();

        // A fresh RWMutex admits a writer straight away.
        let rw2 = RWMutex::new();
        eqb(&mut failed, rw2.TryLock(), true, "rw2 trylock-fresh");
        rw2.Unlock();
    }

    // 3. WaitGroup's counter. Wait on a ZERO counter returns
    //    immediately rather than blocking forever, which is what makes
    //    a WaitGroup safe to Wait on before anything has been added.
    {
        let wg = WaitGroup::new();
        wg.Wait();
        fmt::Println!("[ok] wg wait-on-zero returned");

        wg.Add(2);
        wg.Done();
        wg.Done();
        wg.Wait();
        fmt::Println!("[ok] wg add2-done2 returned");

        // Add takes a negative delta directly, as long as the counter
        // does not go below zero.
        wg.Add(3);
        wg.Add(-3);
        wg.Wait();
        fmt::Println!("[ok] wg add-negative returned");
    }

    // 4. WaitGroup::Go (Go 1.25) increments the counter and runs f in a
    //    new goroutine; Wait blocks until all three have finished. Go:
    //    wg go-count=3.
    {
        let wg2 = Arc::new(WaitGroup::new());
        let ran = Arc::new(Mutex::new(0 as int));
        for _ in 0..3 {
            let r = ran.clone();
            wg2.Go(move || {
                *r.Lock() += 1;
            });
        }
        wg2.Wait();
        let n = *ran.Lock();
        if n != 3 {
            fmt::Printf!("[!!] wg go-count FAIL got %d want 3\n", n);
            failed += 1;
        }

        // Reuse after Wait is allowed.
        wg2.Add(1);
        wg2.Done();
        wg2.Wait();
        fmt::Println!("[ok] wg reuse returned");
    }

    if failed == 0 {
        fmt::Println!("ok - sync primitives match Go");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed);
        syscall::Exit(1);
    }
}
