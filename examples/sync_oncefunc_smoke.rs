// sync_oncefunc_smoke — exercise sync.OnceFunc + sync.OnceValue.
// (oncefunc.go:11, 46)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI32, Ordering};
use goish::fmt;
use goish::string;
use goish::sync;
use goish::syscall;
use goish::types::int;

static CALLS: AtomicI32 = AtomicI32::new(0);
static EXPENSIVE: AtomicI32 = AtomicI32::new(0);

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. OnceFunc — call multiple times, f runs once.
    {
        CALLS.store(0, Ordering::SeqCst);
        let g = sync::OnceFunc(|| {
            CALLS.fetch_add(1, Ordering::SeqCst);
        });
        g();
        g();
        g();
        if CALLS.load(Ordering::SeqCst) == 1 {
            fmt::Println!("[ 1] OnceFunc once             PASS");
        } else {
            fmt::Println!(
                "[ 1] OnceFunc once             FAIL: ",
                CALLS.load(Ordering::SeqCst)
            );
            failed += 1;
        }
    }

    // 2. OnceValue — caches and replays.
    {
        EXPENSIVE.store(0, Ordering::SeqCst);
        let v = sync::OnceValue(|| -> int {
            EXPENSIVE.fetch_add(1, Ordering::SeqCst);
            42
        });
        let a = v();
        let b = v();
        let c = v();
        if a == 42 && b == 42 && c == 42 && EXPENSIVE.load(Ordering::SeqCst) == 1 {
            fmt::Println!("[ 2] OnceValue once            PASS");
        } else {
            fmt::Println!("[ 2] OnceValue once            FAIL");
            failed += 1;
        }
    }

    // 3. OnceValue — string result.
    {
        let v = sync::OnceValue(|| -> string { string("hello") });
        let a = v();
        let b = v();
        if a == string("hello") && b == string("hello") {
            fmt::Println!("[ 3] OnceValue string          PASS");
        } else {
            fmt::Println!("[ 3] OnceValue string          FAIL");
            failed += 1;
        }
    }

    // 4. OnceValue — closure with captured input.
    {
        let v = sync::OnceValue(|| -> int {
            // Mimic an "expensive" lookup that returns the same value.
            let mut sum: int = 0;
            for i in 1..=10 {
                sum += i;
            }
            sum
        });
        let a = v();
        let b = v();
        if a == 55 && b == 55 {
            fmt::Println!("[ 4] OnceValue captures        PASS");
        } else {
            fmt::Println!("[ 4] OnceValue captures        FAIL");
            failed += 1;
        }
    }

    // 5. OnceValues — replays both values across calls.
    {
        let p = sync::OnceValues(|| -> (int, string) { (7, string("widgets")) });
        let (a, b) = p();
        let (c, d) = p();
        if a == 7 && c == 7 && b == string("widgets") && d == string("widgets") {
            fmt::Println!("[ 5] OnceValues pair           PASS");
        } else {
            fmt::Println!("[ 5] OnceValues pair           FAIL");
            failed += 1;
        }
    }

    // 6. OnceValues — runs producer once.
    {
        static RUNS: AtomicI32 = AtomicI32::new(0);
        let p = sync::OnceValues(|| -> (int, int) {
            RUNS.fetch_add(1, Ordering::SeqCst);
            (1, 2)
        });
        let _ = p();
        let _ = p();
        let _ = p();
        if RUNS.load(Ordering::SeqCst) == 1 {
            fmt::Println!("[ 6] OnceValues once           PASS");
        } else {
            fmt::Println!("[ 6] OnceValues once           FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
