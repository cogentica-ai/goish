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


/// Spin until `n` goroutines have registered with the Cond, using the
/// mutex as the barrier rather than a fixed number of `Gosched` calls.
///
/// `Cond::Wait` increments its waiter count and only THEN unlocks the
/// mutex, so if this can take the mutex and see `ready == n`, all `n`
/// goroutines are registered and a following Signal or Broadcast
/// cannot miss them. Go's Cond has the same ordering
/// (`runtime_notifyListAdd` before `c.L.Unlock()`), so a goroutine
/// that has not reached Wait is not woken there either — which is why
/// the barrier has to be here and not in Cond.
///
/// This replaces `for _ in 0..200 { Gosched() }`, which was a guess.
/// On 2026-09-05 that guess lost on a loaded CI runner: Broadcast ran
/// while fewer than five waiters had registered, swapped a count of
/// less than five, released that many credits, and the stragglers
/// parked forever. The example did not fail, it HUNG, and e2e reported
/// it as a 15s timeout. Locally the same binary passed five for five
/// in 1.6s, which is what a fixed spin buys you: it works until the
/// machine is busy.
///
/// Bounded, so a genuinely broken Cond fails the example quickly
/// instead of hanging until the harness kills it.
fn await_registered(mu: &Mutex<()>, ready: &AtomicI64, n: i64) -> bool {
    for _ in 0..500_000 {
        mu.LockManual();
        let r = ready.load(Ordering::Acquire);
        mu.Unlock();
        if r >= n {
            return true;
        }
        goish::runtime::sched::Gosched();
    }
    return false;
}

fn run_tests() {
    let mut failed = 0;

    // 1. Signal with one waiter wakes that waiter.
    {
        let mu: Mutex = Mutex::new(());
        let cond = NewCond(&mu);
        let woke = AtomicI64::new(0);

        let wg = WaitGroup::new();
        let ready = AtomicI64::new(0);
        wg.GoStack(64 * KB, || {
            mu.LockManual();
            ready.fetch_add(1, Ordering::Release);
            cond.Wait();
            woke.fetch_add(1, Ordering::Release);
            mu.Unlock();
        });

        // Signal only once the waiter is registered; a Signal that
        // arrives first is a no-op and the waiter parks forever.
        if !await_registered(&mu, &ready, 1) {
            fmt::Println!("[ 1] Signal one waiter        FAIL waiter never registered");
            failed += 1;
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

        let ready = AtomicI64::new(0);
        for _ in 0..5 {
            wg.GoStack(64 * KB, || {
                mu.LockManual();
                ready.fetch_add(1, Ordering::Release);
                cond.Wait();
                woke.fetch_add(1, Ordering::Release);
                mu.Unlock();
            });
        }

        // All five must be registered before Broadcast: it swaps the
        // waiter count to zero and releases exactly that many credits,
        // so a straggler gets nothing and never wakes.
        if !await_registered(&mu, &ready, 5) {
            fmt::Println!("[ 2] Broadcast 5 waiters      FAIL waiters never registered");
            failed += 1;
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
        let ready = AtomicI64::new(0);
        wg.GoStack(64 * KB, || {
            mu.LockManual();
            ready.fetch_add(1, Ordering::Release);
            cond.Wait();
            woke.fetch_add(1, Ordering::Release);
            mu.Unlock();
        });

        // Registration is the right barrier for the NEGATIVE check
        // too. Once the waiter is registered and no Signal has been
        // issued since, `woke == 0` is a fact rather than a race: the
        // three earlier Signals found no waiter and must have stored
        // nothing.
        if !await_registered(&mu, &ready, 1) {
            fmt::Println!("[ 3] Signal no-op when empty  FAIL waiter never registered");
            failed += 1;
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
