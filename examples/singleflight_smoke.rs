// singleflight_smoke — exercise sync::singleflight::Group.
//
// Coverage:
//   1. Single-flight de-dup: 5 goroutines call Do(same key, same fn);
//      fn runs exactly once; all 5 get the same result.
//   2. Different keys run independently (fn invocation count == 2).
//   3. Error propagation: Do returns the error verbatim.
//   4. shared boolean: original returns shared=true when duplicates
//      arrived; lone caller returns shared=false.
//   5. DoChan: returns a channel with cap=1; buffered Result delivered
//      asynchronously.
//   6. ForgetUnshared: removes a key with no waiters; returns true.
//   7. Sequential calls (no overlap) — each call runs fn fresh.
//   8. Mixed Do + DoChan dedup: a Do caller that arrives mid-flight
//      while a DoChan worker is running gets the same result.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::errors::nil;
use goish::gostring::string;
use goish::runtime::sched::schedule;
use goish::sync::singleflight::Group;
use goish::sync::WaitGroup;
use goish::{go, syscall, time, Println};

const KB: usize = 1024;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn ok(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

#[goish::main]
fn main() {
    // Bootstrap thread isn't a goroutine — wrap blocking work.
    go!(stack(128 * KB), || {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            Println!("ok 8/8");
            syscall::Exit(0);
        } else {
            Println!("FAIL", f as i64, "of 8");
            syscall::Exit(1);
        }
    });
    schedule();
}

fn run_tests() {
    test_1_dedup();
    test_2_independent_keys();
    test_3_error_prop();
    test_4_shared_false_for_lone();
    test_5_dochan();
    test_6_forget_unshared();
    test_7_sequential();
    test_8_mixed_do_dochan();
}

// 1. Single-flight de-dup.
fn test_1_dedup() {
    let g: Arc<Group<i64>> = Arc::new(Group::new());
    let calls = Arc::new(AtomicI64::new(0));
    let wg = Arc::new(WaitGroup::new());

    let n_callers: i64 = 5;
    let got_42 = Arc::new(AtomicI64::new(0));

    wg.Add(n_callers);
    for _i in 0..n_callers {
        let g = g.clone();
        let calls = calls.clone();
        let wg2 = wg.clone();
        let got_42 = got_42.clone();
        go!(stack(64 * KB), move || {
            let (v, _e, _shared) = g.Do(string::from_static("k"), || {
                calls.fetch_add(1, Ordering::AcqRel);
                // Hold long enough for siblings to queue up.
                time::Sleep(time::Millisecond * 30);
                (42i64, nil.clone())
            });
            if v == 42 {
                got_42.fetch_add(1, Ordering::AcqRel);
            }
            wg2.Done();
        });
    }
    wg.Wait();
    let n_calls = calls.load(Ordering::Acquire);
    let got = got_42.load(Ordering::Acquire);
    if n_calls == 1 && got == n_callers {
        ok(b"[ 1] singleflight dedup          PASS\n");
    } else {
        ok(b"[ 1] singleflight dedup          FAIL\n");
        fail();
    }
}

// 2. Different keys run independently.
fn test_2_independent_keys() {
    let g: Arc<Group<i64>> = Arc::new(Group::new());
    let calls = Arc::new(AtomicI64::new(0));
    let wg = Arc::new(WaitGroup::new());

    wg.Add(2);
    for k in &["a", "b"] {
        let g = g.clone();
        let calls = calls.clone();
        let wg2 = wg.clone();
        let key = string::from_static(k);
        go!(stack(64 * KB), move || {
            let (_v, _e, _shared) = g.Do(key, || {
                calls.fetch_add(1, Ordering::AcqRel);
                time::Sleep(time::Millisecond * 20);
                (1i64, nil.clone())
            });
            wg2.Done();
        });
    }
    wg.Wait();
    if calls.load(Ordering::Acquire) == 2 {
        ok(b"[ 2] independent keys            PASS\n");
    } else {
        ok(b"[ 2] independent keys            FAIL\n");
        fail();
    }
}

// 3. Error propagation.
fn test_3_error_prop() {
    let g: Group<i64> = Group::new();
    let want = goish::errors::New(string::from_static("boom"));
    let want2 = want.clone();
    let (v, e, _) = g.Do(string::from_static("err"), move || (0i64, want2));
    if v == 0 && e.Error() == want.Error() {
        ok(b"[ 3] error propagation           PASS\n");
    } else {
        ok(b"[ 3] error propagation           FAIL\n");
        fail();
    }
}

// 4. shared=false for lone call.
fn test_4_shared_false_for_lone() {
    let g: Group<i64> = Group::new();
    let (_v, _e, shared) =
        g.Do(string::from_static("solo"), || (7i64, nil.clone()));
    if !shared {
        ok(b"[ 4] shared=false for lone call  PASS\n");
    } else {
        ok(b"[ 4] shared=false for lone call  FAIL\n");
        fail();
    }
}

// 5. DoChan delivers Result.
fn test_5_dochan() {
    let g: Arc<Group<i64>> = Arc::new(Group::new());
    let ch = g.DoChan(string::from_static("dc"), || {
        time::Sleep(time::Millisecond * 10);
        (99i64, nil.clone())
    });
    let (r, ok_recv) = ch.Recv();
    if ok_recv && r.Val == 99 && r.Err.IsNil() && !r.Shared {
        ok(b"[ 5] DoChan delivers result      PASS\n");
    } else {
        ok(b"[ 5] DoChan delivers result      FAIL\n");
        fail();
    }
}

// 6. ForgetUnshared on absent key returns true; same after Do completes.
fn test_6_forget_unshared() {
    let g: Group<i64> = Group::new();
    let absent = g.ForgetUnshared(string::from_static("never-seen"));
    let _ = g.Do(string::from_static("done"), || (1i64, nil.clone()));
    let after_done = g.ForgetUnshared(string::from_static("done"));
    if absent && after_done {
        ok(b"[ 6] ForgetUnshared              PASS\n");
    } else {
        ok(b"[ 6] ForgetUnshared              FAIL\n");
        fail();
    }
}

// 7. Sequential calls run fresh each time.
fn test_7_sequential() {
    let g: Group<i64> = Group::new();
    let calls = AtomicI64::new(0);
    for _ in 0..3 {
        let _ = g.Do(string::from_static("seq"), || {
            calls.fetch_add(1, Ordering::AcqRel);
            (1i64, nil.clone())
        });
    }
    if calls.load(Ordering::Acquire) == 3 {
        ok(b"[ 7] sequential calls run fresh  PASS\n");
    } else {
        ok(b"[ 7] sequential calls run fresh  FAIL\n");
        fail();
    }
}

// 8. Mixed Do + DoChan dedup.
fn test_8_mixed_do_dochan() {
    let g: Arc<Group<i64>> = Arc::new(Group::new());
    let key = string::from_static("mixed");

    // DoChan worker holds for 50ms.
    let key2 = key.clone();
    let ch = g.DoChan(key2, || {
        time::Sleep(time::Millisecond * 50);
        (314i64, nil.clone())
    });

    // Wait, then call Do — should join the in-flight worker.
    time::Sleep(time::Millisecond * 5);
    let (v, _e, shared) = g.Do(key, || {
        // Should not run (deduped against in-flight DoChan worker).
        (0i64, nil.clone())
    });

    let (r, ok_recv) = ch.Recv();
    if ok_recv && r.Val == 314 && v == 314 && shared {
        ok(b"[ 8] Do joins in-flight DoChan   PASS\n");
    } else {
        ok(b"[ 8] Do joins in-flight DoChan   FAIL\n");
        fail();
    }
}
