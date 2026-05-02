// sync_map_smoke — exercise sync.Map (slim port).
// (sync/map.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI64, Ordering};
use goish::gostring::string;
use goish::runtime::sched::schedule;
use goish::sync::{Map, WaitGroup};
use goish::{go, syscall, Println, KB};

#[goish::main]
fn main() {
    go!(stack(64 * KB), || run_tests());
    schedule();
}

fn run_tests() {
    let mut failed = 0;

    // 1. Empty Map: Load returns zero + false.
    {
        let m: Map<string, i64> = Map::new();
        let (v, ok) = m.Load(string::from_static("missing"));
        if v == 0 && !ok {
            Println!("[ 1] Load on empty           PASS");
        } else {
            Println!("[ 1] Load on empty           FAIL");
            failed += 1;
        }
    }

    // 2. Store then Load.
    {
        let m: Map<string, i64> = Map::new();
        m.Store(string::from_static("k"), 42);
        let (v, ok) = m.Load(string::from_static("k"));
        if v == 42 && ok {
            Println!("[ 2] Store/Load              PASS");
        } else {
            Println!("[ 2] Store/Load              FAIL v={} ok={}", v, ok);
            failed += 1;
        }
    }

    // 3. Delete removes the entry.
    {
        let m: Map<string, i64> = Map::new();
        m.Store(string::from_static("k"), 1);
        m.Delete(string::from_static("k"));
        let (_v, ok) = m.Load(string::from_static("k"));
        if !ok {
            Println!("[ 3] Delete                  PASS");
        } else {
            Println!("[ 3] Delete                  FAIL");
            failed += 1;
        }
    }

    // 4. LoadOrStore on absent key inserts and returns the new value.
    {
        let m: Map<string, i64> = Map::new();
        let (actual, loaded) = m.LoadOrStore(string::from_static("k"), 7);
        if actual == 7 && !loaded {
            Println!("[ 4] LoadOrStore absent      PASS");
        } else {
            Println!("[ 4] LoadOrStore absent      FAIL");
            failed += 1;
        }
    }

    // 5. LoadOrStore on present key returns existing value, ignores new.
    {
        let m: Map<string, i64> = Map::new();
        m.Store(string::from_static("k"), 100);
        let (actual, loaded) = m.LoadOrStore(string::from_static("k"), 999);
        let (after, _) = m.Load(string::from_static("k"));
        if actual == 100 && loaded && after == 100 {
            Println!("[ 5] LoadOrStore present     PASS");
        } else {
            Println!("[ 5] LoadOrStore present     FAIL actual={} after={}", actual, after);
            failed += 1;
        }
    }

    // 6. LoadAndDelete on present key returns value + removes it.
    {
        let m: Map<string, i64> = Map::new();
        m.Store(string::from_static("k"), 5);
        let (v, ok) = m.LoadAndDelete(string::from_static("k"));
        let (_, after_ok) = m.Load(string::from_static("k"));
        if v == 5 && ok && !after_ok {
            Println!("[ 6] LoadAndDelete present   PASS");
        } else {
            Println!("[ 6] LoadAndDelete present   FAIL");
            failed += 1;
        }
    }

    // 7. LoadAndDelete on absent key returns zero + false.
    {
        let m: Map<string, i64> = Map::new();
        let (v, ok) = m.LoadAndDelete(string::from_static("missing"));
        if v == 0 && !ok {
            Println!("[ 7] LoadAndDelete absent    PASS");
        } else {
            Println!("[ 7] LoadAndDelete absent    FAIL");
            failed += 1;
        }
    }

    // 8. Swap returns previous, then new value is in place.
    {
        let m: Map<string, i64> = Map::new();
        m.Store(string::from_static("k"), 10);
        let (prev, loaded) = m.Swap(string::from_static("k"), 20);
        let (after, _) = m.Load(string::from_static("k"));
        if prev == 10 && loaded && after == 20 {
            Println!("[ 8] Swap present            PASS");
        } else {
            Println!("[ 8] Swap present            FAIL");
            failed += 1;
        }
    }

    // 9. Swap on absent: prev=0, loaded=false, value present after.
    {
        let m: Map<string, i64> = Map::new();
        let (prev, loaded) = m.Swap(string::from_static("k"), 5);
        let (after, _) = m.Load(string::from_static("k"));
        if prev == 0 && !loaded && after == 5 {
            Println!("[ 9] Swap absent             PASS");
        } else {
            Println!("[ 9] Swap absent             FAIL");
            failed += 1;
        }
    }

    // 10. Range visits all entries.
    {
        let m: Map<string, i64> = Map::new();
        m.Store(string::from_static("a"), 1);
        m.Store(string::from_static("b"), 2);
        m.Store(string::from_static("c"), 3);
        let counter = alloc::sync::Arc::new(AtomicI64::new(0));
        let counter_clone = counter.clone();
        m.Range(move |_k, v| {
            counter_clone.fetch_add(v, Ordering::Relaxed);
            true
        });
        if counter.load(Ordering::Relaxed) == 6 {
            Println!("[10] Range visits all        PASS");
        } else {
            Println!("[10] Range visits all        FAIL sum={}", counter.load(Ordering::Relaxed));
            failed += 1;
        }
    }

    // 11. Range stops on false.
    {
        let m: Map<string, i64> = Map::new();
        m.Store(string::from_static("a"), 1);
        m.Store(string::from_static("b"), 2);
        m.Store(string::from_static("c"), 3);
        let counter = alloc::sync::Arc::new(AtomicI64::new(0));
        let counter_clone = counter.clone();
        m.Range(move |_k, _v| {
            counter_clone.fetch_add(1, Ordering::Relaxed);
            // Stop after first.
            false
        });
        if counter.load(Ordering::Relaxed) == 1 {
            Println!("[11] Range short-circuit     PASS");
        } else {
            Println!("[11] Range short-circuit     FAIL count={}", counter.load(Ordering::Relaxed));
            failed += 1;
        }
    }

    // 12. Clear removes all entries.
    {
        let m: Map<string, i64> = Map::new();
        m.Store(string::from_static("a"), 1);
        m.Store(string::from_static("b"), 2);
        m.Clear();
        let (_, ok_a) = m.Load(string::from_static("a"));
        let (_, ok_b) = m.Load(string::from_static("b"));
        if !ok_a && !ok_b {
            Println!("[12] Clear                   PASS");
        } else {
            Println!("[12] Clear                   FAIL");
            failed += 1;
        }
    }

    // 13. Concurrent Store from many goroutines: every write must persist.
    {
        let m: Map<i64, i64> = Map::new();
        let wg = WaitGroup::new();
        for tid in 0..4i64 {
            let mref = &m;
            wg.GoStack(64 * KB, move || {
                for i in 0..50i64 {
                    mref.Store(tid * 100 + i, i);
                }
            });
        }
        wg.Wait();
        // Count entries via Range.
        let counter = alloc::sync::Arc::new(AtomicI64::new(0));
        let counter_clone = counter.clone();
        m.Range(move |_k, _v| {
            counter_clone.fetch_add(1, Ordering::Relaxed);
            true
        });
        if counter.load(Ordering::Relaxed) == 200 {
            Println!("[13] Concurrent Store        PASS");
        } else {
            Println!("[13] Concurrent Store        FAIL n={}", counter.load(Ordering::Relaxed));
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 13/13");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 13");
        syscall::Exit(1);
    }
}
