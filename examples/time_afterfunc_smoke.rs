// time_afterfunc_smoke — exercise time.AfterFunc + Stop semantics.
// (sleep.go:188)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI32, Ordering};
use goish::fmt;
use goish::syscall;
use goish::time;
use goish::types::int;

static FIRED: AtomicI32 = AtomicI32::new(0);
static FIRED_NO_STOP: AtomicI32 = AtomicI32::new(0);

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. AfterFunc fires after the duration.
    {
        FIRED.store(0, Ordering::SeqCst);
        let _t = time::AfterFunc(time::Millisecond * 40, || {
            FIRED.fetch_add(1, Ordering::SeqCst);
        });
        time::Sleep(time::Millisecond * 120);
        if FIRED.load(Ordering::SeqCst) == 1 {
            fmt::Println!("[ 1] AfterFunc fired            PASS");
        } else {
            fmt::Println!("[ 1] AfterFunc fired            FAIL");
            failed += 1;
        }
    }

    // 2. AfterFunc Stop before fire cancels f.
    {
        FIRED.store(0, Ordering::SeqCst);
        let t = time::AfterFunc(time::Millisecond * 80, || {
            FIRED.fetch_add(1, Ordering::SeqCst);
        });
        // Stop before firing.
        let stopped = t.Stop();
        time::Sleep(time::Millisecond * 150);
        if stopped && FIRED.load(Ordering::SeqCst) == 0 {
            fmt::Println!("[ 2] Stop cancels               PASS");
        } else {
            fmt::Println!(
                "[ 2] Stop cancels               FAIL stopped=",
                stopped,
                " fired=",
                FIRED.load(Ordering::SeqCst)
            );
            failed += 1;
        }
    }

    // 3. AfterFunc still fires when caller doesn't Stop.
    //    (Goish Timer.Stop is "first-call wins" by design and doesn't
    //    inspect whether the watcher already fired, so we only check
    //    that f ran here.)
    {
        FIRED_NO_STOP.store(0, Ordering::SeqCst);
        let _t = time::AfterFunc(time::Millisecond * 20, || {
            FIRED_NO_STOP.fetch_add(1, Ordering::SeqCst);
        });
        time::Sleep(time::Millisecond * 120);
        if FIRED_NO_STOP.load(Ordering::SeqCst) == 1 {
            fmt::Println!("[ 3] f ran without Stop        PASS");
        } else {
            fmt::Println!("[ 3] f ran without Stop        FAIL");
            failed += 1;
        }
    }

    // 4. Repeat Stop is idempotent — second call returns false.
    {
        let t = time::AfterFunc(time::Millisecond * 200, || {});
        let s1 = t.Stop();
        let s2 = t.Stop();
        if s1 && !s2 {
            fmt::Println!("[ 4] Stop idempotent            PASS");
        } else {
            fmt::Println!("[ 4] Stop idempotent            FAIL");
            failed += 1;
        }
    }

    let total: int = 4;
    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of", total);
        syscall::Exit(1);
    }
}
