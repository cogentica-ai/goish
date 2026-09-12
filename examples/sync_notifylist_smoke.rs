// sync_notifylist_smoke — the ticket contract that fixes Cond's lost
// notifications, tested DETERMINISTICALLY (ROADMAP §2w).
//
// `sync_cond_smoke`'s ping-pong found the original bug, but only about
// once in fifty runs: it needs a notification to land inside the window
// between a waiter's ticket and its park, and that is a race. This file
// drives `NotifyList` directly and forces the window open by hand, so
// every row fails outright without the fix rather than occasionally.
//
// The contract, from Go (runtime/sema.go):
//
//   `Add` hands out `t = wait++` while the caller's lock is STILL HELD.
//   `NotifyAll` stores `notify = wait`.
//   `Wait(t)` returns IMMEDIATELY when `less(t, notify)`.
//
// So `Add` then `NotifyAll` then `Wait` must NOT block — the waiter was
// notified before it parked, and the watermark is what tells it. The old
// implementation (a waiter count plus the semaphore's credit) had
// nothing to record that in: `Broadcast` read a count of zero and did
// nothing at all, and the waiter parked forever.
//
// `notified_before_wait` is therefore the row that matters. Without the
// `less(t, notify)` early return it does not fail an assertion, it
// HANGS — so this example is a timeout in e2e rather than a diff, which
// is the honest shape for "a wakeup was lost".
//
// `wrap_is_not_ordering` pins the other half of Go's `less`: a plain
// `a < b` would make every outstanding ticket look already-notified the
// moment `wait` passes u32::MAX.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::sync::notifylist::NotifyList;
use goish::{go, time};

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(cond: bool, what: &str) {
    if cond {
        fmt::Printf!("[ok] %s\n", string::from_bytes(what.as_bytes()));
    } else {
        fmt::Printf!("[!!] %s\n", string::from_bytes(what.as_bytes()));
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
}

#[goish::main]
fn main() {
    // ── the regression: notified BEFORE parking ──────────────────────
    //
    // This is the window the old code lost. Taking the ticket first and
    // notifying before `Wait` is exactly what a Broadcast racing an
    // unlock does, except here it is guaranteed rather than hoped for.
    {
        let l = NotifyList::new();
        let t = l.Add();
        l.NotifyAll();
        // Must return immediately. Without the watermark check this
        // parks forever and the example times out.
        l.Wait(t);
        check(true, "notified_before_wait returns without parking");
    }

    // Same through NotifyOne, which wakes one specific ticket.
    {
        let l = NotifyList::new();
        let t = l.Add();
        l.NotifyOne();
        l.Wait(t);
        check(true, "notify_one before wait returns without parking");
    }

    // ── a notification with no waiters is not stored as a credit ─────
    //
    // Go's watermark moves to `wait`, which has issued nothing, so a
    // LATER waiter is not spuriously woken. The old credit scheme got
    // this right too; it is pinned so a future change cannot trade one
    // bug for the other.
    {
        let l = NotifyList::new();
        l.NotifyAll();
        let (w, n, q) = l.__debug_state();
        check(
            w == 0 && n == 0 && q == 0,
            "notify with no waiters issues nothing",
        );
    }

    // ── a real park and wake, across goroutines ──────────────────────
    {
        static WOKE: AtomicUsize = AtomicUsize::new(0);
        let l = alloc::sync::Arc::new(NotifyList::new());
        let l2 = l.clone();
        let t = l.Add();
        go!(move || {
            l2.Wait(t);
            WOKE.fetch_add(1, Ordering::Release);
        });
        // Give the waiter time to actually park, so this exercises the
        // queue rather than the watermark shortcut above.
        time::Sleep(time::Millisecond * 30);
        let (_, _, q) = l.__debug_state();
        check(q == 1, "a waiter that parks is on the queue");
        l.NotifyAll();
        let mut spins = 0;
        while WOKE.load(Ordering::Acquire) == 0 && spins < 200 {
            time::Sleep(time::Millisecond * 5);
            spins += 1;
        }
        check(WOKE.load(Ordering::Acquire) == 1, "a parked waiter is woken");
        let (_, _, q) = l.__debug_state();
        check(q == 0, "the queue is empty after NotifyAll");
    }

    // ── tickets are sequential, and the watermark catches up ─────────
    {
        let l = NotifyList::new();
        let a = l.Add();
        let b = l.Add();
        let c = l.Add();
        check(a == 0 && b == 1 && c == 2, "tickets are issued in order");
        l.NotifyAll();
        let (w, n, _) = l.__debug_state();
        check(w == 3 && n == 3, "NotifyAll moves notify to wait");
        // All three were notified, so none of them parks.
        l.Wait(a);
        l.Wait(b);
        l.Wait(c);
        check(true, "every outstanding ticket returns without parking");
    }

    let f = FAILED.load(Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok\n");
}
