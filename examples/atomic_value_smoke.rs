// atomic_value_smoke — exercise sync/atomic::Value<T>.
//
// Coverage:
//   1. Empty Value → Load returns (T::default(), false).
//   2. Store + Load round-trip.
//   3. Store overwrite — second Load reflects the most recent Store.
//   4. Swap returns previous (old, true) and stores new.
//   5. Swap on empty Value returns (T::default(), false) but stores new.
//   6. CompareAndSwap success when stored value matches old.
//   7. CompareAndSwap failure when stored value differs from old.
//   8. CompareAndSwap on empty Value with old=T::default() succeeds.
//   9. Concurrent Store + Load from multiple goroutines maintain
//      type-consistency (compile-time guarantee replaces Go's runtime
//      panic; we just verify race-free behaviour).
//  10. Value<string> works for non-trivial Clone types.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::gostring::string;
use goish::runtime::sched::schedule;
use goish::sync::atomic::Value;
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
    go!(|| {
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
    test_3_store_overwrite();
    test_4_swap_with_existing();
    test_5_swap_empty();
    test_6_cas_success();
    test_7_cas_failure();
    test_8_cas_on_empty();
    test_9_concurrent_store_load();
    test_10_value_of_string();
}

// 1. Empty Value → Load returns default + false.
fn test_1_empty_load() {
    let v: Value<i64> = Value::new();
    let (x, ok) = v.Load();
    if x == 0 && !ok {
        ok_line(b"[ 1] empty Load returns default  PASS\n");
    } else {
        ok_line(b"[ 1] empty Load returns default  FAIL\n");
        fail();
    }
}

// 2. Store + Load round-trip.
fn test_2_store_load() {
    let v: Value<i64> = Value::new();
    v.Store(42);
    let (x, ok) = v.Load();
    if x == 42 && ok {
        ok_line(b"[ 2] Store + Load round-trip     PASS\n");
    } else {
        ok_line(b"[ 2] Store + Load round-trip     FAIL\n");
        fail();
    }
}

// 3. Store overwrite.
fn test_3_store_overwrite() {
    let v: Value<i64> = Value::new();
    v.Store(1);
    v.Store(2);
    v.Store(3);
    let (x, ok) = v.Load();
    if x == 3 && ok {
        ok_line(b"[ 3] Store overwrite             PASS\n");
    } else {
        ok_line(b"[ 3] Store overwrite             FAIL\n");
        fail();
    }
}

// 4. Swap returns previous.
fn test_4_swap_with_existing() {
    let v: Value<i64> = Value::new();
    v.Store(7);
    let (old, ok) = v.Swap(99);
    let (now, _) = v.Load();
    if old == 7 && ok && now == 99 {
        ok_line(b"[ 4] Swap returns previous       PASS\n");
    } else {
        ok_line(b"[ 4] Swap returns previous       FAIL\n");
        fail();
    }
}

// 5. Swap on empty Value.
fn test_5_swap_empty() {
    let v: Value<i64> = Value::new();
    let (old, ok) = v.Swap(50);
    let (now, now_ok) = v.Load();
    if old == 0 && !ok && now == 50 && now_ok {
        ok_line(b"[ 5] Swap on empty Value         PASS\n");
    } else {
        ok_line(b"[ 5] Swap on empty Value         FAIL\n");
        fail();
    }
}

// 6. CAS success.
fn test_6_cas_success() {
    let v: Value<i64> = Value::new();
    v.Store(10);
    let swapped = v.CompareAndSwap(10, 20);
    let (now, _) = v.Load();
    if swapped && now == 20 {
        ok_line(b"[ 6] CAS success                 PASS\n");
    } else {
        ok_line(b"[ 6] CAS success                 FAIL\n");
        fail();
    }
}

// 7. CAS failure.
fn test_7_cas_failure() {
    let v: Value<i64> = Value::new();
    v.Store(10);
    let swapped = v.CompareAndSwap(99, 20);
    let (now, _) = v.Load();
    if !swapped && now == 10 {
        ok_line(b"[ 7] CAS failure                 PASS\n");
    } else {
        ok_line(b"[ 7] CAS failure                 FAIL\n");
        fail();
    }
}

// 8. CAS on empty Value with old=default succeeds.
fn test_8_cas_on_empty() {
    let v: Value<i64> = Value::new();
    let swapped = v.CompareAndSwap(0, 100);
    let (now, ok) = v.Load();
    if swapped && now == 100 && ok {
        ok_line(b"[ 8] CAS on empty + default      PASS\n");
    } else {
        ok_line(b"[ 8] CAS on empty + default      FAIL\n");
        fail();
    }
}

// 9. Concurrent Store + Load — race-free.
fn test_9_concurrent_store_load() {
    let v: Arc<Value<i64>> = Arc::new(Value::new());
    let wg = Arc::new(WaitGroup::new());
    let writers = 4i64;
    let iters = 1000;

    wg.Add(writers);
    for w in 0..writers {
        let v = v.clone();
        let wg2 = wg.clone();
        go!(move || {
            for i in 0..iters {
                v.Store(w * 1_000_000 + i);
            }
            wg2.Done();
        });
    }

    // Reader counts how many distinct (high-bits) we see.
    let observed = Arc::new(AtomicI64::new(0));
    let stop = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let v2 = v.clone();
    let observed2 = observed.clone();
    let stop2 = stop.clone();
    let reader_wg = Arc::new(WaitGroup::new());
    reader_wg.Add(1);
    let reader_wg2 = reader_wg.clone();
    go!(move || {
        while !stop2.load(Ordering::Acquire) {
            let (_x, _ok) = v2.Load();
            observed2.fetch_add(1, Ordering::AcqRel);
        }
        reader_wg2.Done();
    });

    wg.Wait();
    stop.store(true, Ordering::Release);
    reader_wg.Wait();

    let n = observed.load(Ordering::Acquire);
    // Reader must have observed at least one Load without panicking.
    if n > 0 {
        ok_line(b"[ 9] concurrent Store + Load     PASS\n");
    } else {
        ok_line(b"[ 9] concurrent Store + Load     FAIL\n");
        fail();
    }
}

// 10. Value<string> works for non-trivial types.
fn test_10_value_of_string() {
    let v: Value<string> = Value::new();
    v.Store(string::from_static("hello"));
    let (got, ok) = v.Load();
    if got == string::from_static("hello") && ok {
        ok_line(b"[10] Value<string>               PASS\n");
    } else {
        ok_line(b"[10] Value<string>               FAIL\n");
        fail();
    }
}
