// sync_cond_smoke — exercise sync.Cond (slim port).
// (sync/cond.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI64, Ordering};
use goish::fmt;
use goish::runtime::sched::schedule;
use goish::sync::{Locker, Mutex, NewCond, WaitGroup};
use goish::{go, syscall, KB};

#[goish::main]
fn main() {
    go!(|| run_tests());
    schedule();
}

fn run_tests() {
    let mut failed = 0;

    // 1. Signal with one waiter wakes that waiter.
    {
        let mu: Mutex = Mutex::new(());
        let cond = NewCond(&mu);
        let woke = AtomicI64::new(0);

        let wg = WaitGroup::new();
        wg.GoStack(64 * KB, || {
            mu.LockManual();
            cond.Wait();
            woke.fetch_add(1, Ordering::Release);
            mu.Unlock();
        });

        // Give the waiter a chance to enter Wait.
        for _ in 0..100 {
            goish::runtime::sched::Gosched();
        }
        cond.Signal();
        wg.Wait();
        if woke.load(Ordering::Acquire) == 1 {
            fmt::Println!("[ 1] Signal one waiter        PASS");
        } else {
            fmt::Println!("[ 1] Signal one waiter        FAIL");
            failed += 1;
        }
    }

    // 2. Broadcast wakes all waiters.
    {
        let mu: Mutex = Mutex::new(());
        let cond = NewCond(&mu);
        let woke = AtomicI64::new(0);
        let wg = WaitGroup::new();

        for _ in 0..5 {
            wg.GoStack(64 * KB, || {
                mu.LockManual();
                cond.Wait();
                woke.fetch_add(1, Ordering::Release);
                mu.Unlock();
            });
        }

        // Wait for all 5 to be parked.
        for _ in 0..200 {
            goish::runtime::sched::Gosched();
        }
        cond.Broadcast();
        wg.Wait();
        if woke.load(Ordering::Acquire) == 5 {
            fmt::Println!("[ 2] Broadcast 5 waiters      PASS");
        } else {
            fmt::Println!(
                "[ 2] Broadcast 5 waiters      FAIL n={}",
                woke.load(Ordering::Acquire)
            );
            failed += 1;
        }
    }

    // 3. Signal with no waiter is a no-op (does NOT store credit).
    //    A subsequent Wait should still block until a real Signal.
    {
        let mu: Mutex = Mutex::new(());
        let cond = NewCond(&mu);
        // Signal with zero waiters: must not affect future Wait.
        cond.Signal();
        cond.Signal();
        cond.Signal();

        let woke = AtomicI64::new(0);
        let wg = WaitGroup::new();
        wg.GoStack(64 * KB, || {
            mu.LockManual();
            cond.Wait();
            woke.fetch_add(1, Ordering::Release);
            mu.Unlock();
        });

        for _ in 0..100 {
            goish::runtime::sched::Gosched();
        }
        // Waiter should still be parked.
        if woke.load(Ordering::Acquire) != 0 {
            fmt::Println!("[ 3] Signal no-op when empty  FAIL early wake");
            failed += 1;
        } else {
            cond.Signal();
            wg.Wait();
            if woke.load(Ordering::Acquire) == 1 {
                fmt::Println!("[ 3] Signal no-op when empty  PASS");
            } else {
                fmt::Println!("[ 3] Signal no-op when empty  FAIL");
                failed += 1;
            }
        }
    }

    // 4. Wait/Signal in a tight loop: bounded ping-pong.
    {
        let mu: Mutex = Mutex::new(());
        let cond = NewCond(&mu);
        let phase = AtomicI64::new(0);
        let wg = WaitGroup::new();

        // Goroutine A: increment phase to even, then signal.
        wg.GoStack(64 * KB, || {
            for _ in 0..10 {
                mu.LockManual();
                while phase.load(Ordering::Acquire) % 2 != 0 {
                    cond.Wait();
                }
                phase.fetch_add(1, Ordering::AcqRel);
                mu.Unlock();
                cond.Broadcast();
            }
        });

        // Goroutine B: increment phase to odd, then signal.
        wg.GoStack(64 * KB, || {
            for _ in 0..10 {
                mu.LockManual();
                while phase.load(Ordering::Acquire) % 2 != 1 {
                    cond.Wait();
                }
                phase.fetch_add(1, Ordering::AcqRel);
                mu.Unlock();
                cond.Broadcast();
            }
        });

        wg.Wait();
        if phase.load(Ordering::Acquire) == 20 {
            fmt::Println!("[ 4] Ping-pong loop          PASS");
        } else {
            fmt::Println!(
                "[ 4] Ping-pong loop          FAIL phase={}",
                phase.load(Ordering::Acquire)
            );
            failed += 1;
        }
    }

    // 5. Locker trait impl on Mutex works.
    {
        let mu: Mutex = Mutex::new(());
        Locker::Lock(&mu);
        Locker::Unlock(&mu);
        fmt::Println!("[ 5] Locker trait dispatch    PASS");
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
