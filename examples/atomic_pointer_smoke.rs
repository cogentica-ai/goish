// atomic_pointer_smoke — exercise sync/atomic::Pointer<T>.
//
// Coverage:
//   1. Empty Pointer → Load returns None.
//   2. Store(Some) + Load round-trip — Arc::ptr_eq with original.
//   3. Store(None) clears — Load returns None.
//   4. Store overwrite — second Load reflects most recent Store.
//   5. Swap returns previous Some, stores new.
//   6. Swap on empty Pointer returns None, stores new.
//   7. CompareAndSwap success when current is Arc::ptr_eq with old.
//   8. CompareAndSwap failure when current is a different Arc.
//   9. CompareAndSwap None→Some on empty Pointer succeeds.
//  10. Concurrent Store + Load from multiple goroutines maintains
//      ref-count integrity (no double-free, no missed clones).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::runtime::sched::schedule;
use goish::sync::atomic::Pointer;
use goish::sync::WaitGroup;
use goish::{go, syscall, Println};

const KB: usize = 1024;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn ok_line(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

#[goish::main]
fn main() {
    go!(stack(128 * KB), || {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    schedule();
}

fn run_tests() {
    test_1_empty_load();
    test_2_store_load();
    test_3_store_none_clears();
    test_4_store_overwrite();
    test_5_swap_existing();
    test_6_swap_empty();
    test_7_cas_success();
    test_8_cas_failure();
    test_9_cas_on_empty();
    test_10_concurrent();
}

// 1. Empty Pointer → Load returns None.
fn test_1_empty_load() {
    let p: Pointer<i64> = Pointer::new();
    if p.Load().is_none() {
        ok_line(b"[ 1] empty Load is None          PASS\n");
    } else {
        ok_line(b"[ 1] empty Load is None          FAIL\n");
        fail();
    }
}

// 2. Store + Load round-trip; Arc::ptr_eq with original.
fn test_2_store_load() {
    let p: Pointer<i64> = Pointer::new();
    let a = Arc::new(42i64);
    p.Store(Some(a.clone()));
    let got = p.Load();
    if got.is_some() && Arc::ptr_eq(&got.unwrap(), &a) {
        ok_line(b"[ 2] Store + Load round-trip     PASS\n");
    } else {
        ok_line(b"[ 2] Store + Load round-trip     FAIL\n");
        fail();
    }
}

// 3. Store(None) clears.
fn test_3_store_none_clears() {
    let p: Pointer<i64> = Pointer::new();
    p.Store(Some(Arc::new(7)));
    p.Store(None);
    if p.Load().is_none() {
        ok_line(b"[ 3] Store(None) clears          PASS\n");
    } else {
        ok_line(b"[ 3] Store(None) clears          FAIL\n");
        fail();
    }
}

// 4. Store overwrite — Load reflects most recent.
fn test_4_store_overwrite() {
    let p: Pointer<i64> = Pointer::new();
    p.Store(Some(Arc::new(1)));
    p.Store(Some(Arc::new(2)));
    let last = Arc::new(3i64);
    p.Store(Some(last.clone()));
    let got = p.Load().unwrap();
    if Arc::ptr_eq(&got, &last) && *got == 3 {
        ok_line(b"[ 4] Store overwrite             PASS\n");
    } else {
        ok_line(b"[ 4] Store overwrite             FAIL\n");
        fail();
    }
}

// 5. Swap returns previous Some.
fn test_5_swap_existing() {
    let p: Pointer<i64> = Pointer::new();
    let a = Arc::new(7i64);
    let b = Arc::new(99i64);
    p.Store(Some(a.clone()));
    let old = p.Swap(Some(b.clone()));
    let now = p.Load().unwrap();
    let old_arc = old.unwrap();
    if Arc::ptr_eq(&old_arc, &a) && Arc::ptr_eq(&now, &b) {
        ok_line(b"[ 5] Swap returns previous       PASS\n");
    } else {
        ok_line(b"[ 5] Swap returns previous       FAIL\n");
        fail();
    }
}

// 6. Swap on empty Pointer.
fn test_6_swap_empty() {
    let p: Pointer<i64> = Pointer::new();
    let new = Arc::new(50i64);
    let old = p.Swap(Some(new.clone()));
    let now = p.Load().unwrap();
    if old.is_none() && Arc::ptr_eq(&now, &new) {
        ok_line(b"[ 6] Swap on empty               PASS\n");
    } else {
        ok_line(b"[ 6] Swap on empty               FAIL\n");
        fail();
    }
}

// 7. CAS success when current is ptr_eq with old.
fn test_7_cas_success() {
    let p: Pointer<i64> = Pointer::new();
    let a = Arc::new(10i64);
    let b = Arc::new(20i64);
    p.Store(Some(a.clone()));
    let swapped = p.CompareAndSwap(Some(a.clone()), Some(b.clone()));
    let now = p.Load().unwrap();
    if swapped && Arc::ptr_eq(&now, &b) {
        ok_line(b"[ 7] CAS success                 PASS\n");
    } else {
        ok_line(b"[ 7] CAS success                 FAIL\n");
        fail();
    }
}

// 8. CAS failure when current is a different Arc (even if pointee equal).
fn test_8_cas_failure() {
    let p: Pointer<i64> = Pointer::new();
    let a = Arc::new(10i64);
    let other = Arc::new(10i64); // pointee-equal but different Arc
    let b = Arc::new(20i64);
    p.Store(Some(a.clone()));
    let swapped = p.CompareAndSwap(Some(other), Some(b));
    let now = p.Load().unwrap();
    if !swapped && Arc::ptr_eq(&now, &a) {
        ok_line(b"[ 8] CAS failure (ptr identity)  PASS\n");
    } else {
        ok_line(b"[ 8] CAS failure (ptr identity)  FAIL\n");
        fail();
    }
}

// 9. CAS None→Some on empty.
fn test_9_cas_on_empty() {
    let p: Pointer<i64> = Pointer::new();
    let new = Arc::new(100i64);
    let swapped = p.CompareAndSwap(None, Some(new.clone()));
    let now = p.Load().unwrap();
    if swapped && Arc::ptr_eq(&now, &new) {
        ok_line(b"[ 9] CAS None->Some              PASS\n");
    } else {
        ok_line(b"[ 9] CAS None->Some              FAIL\n");
        fail();
    }
}

// 10. Concurrent Store + Load — race-free, no double-free.
fn test_10_concurrent() {
    let p: Arc<Pointer<i64>> = Arc::new(Pointer::new());
    let wg = Arc::new(WaitGroup::new());
    let writers = 4i64;
    let iters = 1000;

    wg.Add(writers);
    for w in 0..writers {
        let p = p.clone();
        let wg2 = wg.clone();
        go!(stack(64 * KB), move || {
            for i in 0..iters {
                p.Store(Some(Arc::new(w * 1_000_000 + i)));
            }
            wg2.Done();
        });
    }

    let observed = Arc::new(AtomicI64::new(0));
    let stop = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let p2 = p.clone();
    let observed2 = observed.clone();
    let stop2 = stop.clone();
    let reader_wg = Arc::new(WaitGroup::new());
    reader_wg.Add(1);
    let reader_wg2 = reader_wg.clone();
    go!(stack(64 * KB), move || {
        while !stop2.load(Ordering::Acquire) {
            let _ = p2.Load();
            observed2.fetch_add(1, Ordering::AcqRel);
        }
        reader_wg2.Done();
    });

    wg.Wait();
    stop.store(true, Ordering::Release);
    reader_wg.Wait();

    let n = observed.load(Ordering::Acquire);
    if n > 0 {
        ok_line(b"[10] concurrent Store + Load     PASS\n");
    } else {
        ok_line(b"[10] concurrent Store + Load     FAIL\n");
        fail();
    }
}
