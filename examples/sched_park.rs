// Smoke test: M16c — gopark / goready.
//
// Exercises the wait-state primitive that channels (M16d) and sync
// (M16g) build on. Two patterns:
//
//   1. **Park-then-wake.** A goroutine identifies itself, calls
//      `gopark(|| true)`, and is suspended. A second goroutine
//      finds the parked G's pointer and calls `goready` on it.
//      The parked G must resume exactly once.
//
//   2. **Park rejection.** A goroutine calls `gopark(|| false)`.
//      `unlockf` returns false, so the G is *not* parked — it
//      continues executing immediately, with status restored to
//      `Running`. This mirrors Go's pattern where channel
//      operations check for a competing peer in `unlockf` and
//      bail out if found.

#![no_std]
#![no_main]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use goish::go;
use goish::runtime::sched::{current_g, gopark, goready, schedule, GStatus, Gosched, G};
use goish::syscall;

unsafe fn always_park(_g: NonNull<G>) -> bool {
    UNLOCKF_CALLS_T1.fetch_add(1, Ordering::Relaxed);
    true
}

unsafe fn never_park(_g: NonNull<G>) -> bool {
    UNLOCKF_CALLS_T2.fetch_add(1, Ordering::Relaxed);
    false
}

static UNLOCKF_CALLS_T1: AtomicUsize = AtomicUsize::new(0);
static UNLOCKF_CALLS_T2: AtomicUsize = AtomicUsize::new(0);

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    test_park_and_wake();
    test_park_rejected();

    const OK: &[u8] = b"sched_park: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ─── Test 1: park then wake ──────────────────────────────────────────

fn test_park_and_wake() {
    static SLEEPER_PTR: AtomicPtr<G> = AtomicPtr::new(core::ptr::null_mut());
    static A_BEFORE_PARK: AtomicBool = AtomicBool::new(false);
    static A_AFTER_WAKE: AtomicBool = AtomicBool::new(false);
    static B_RAN: AtomicBool = AtomicBool::new(false);

    // Goroutine A: registers itself and parks.
    go!(|| {
        A_BEFORE_PARK.store(true, Ordering::Relaxed);
        let g = current_g().expect("current_g in goroutine");
        SLEEPER_PTR.store(g.as_ptr(), Ordering::Release);
        gopark(always_park, core::ptr::null());
        A_AFTER_WAKE.store(true, Ordering::Relaxed);
    });

    // Goroutine B: spins (with Gosched) until A registers AND its
    // park has committed, then wakes A.
    //
    // Waiting for the pointer alone is not enough on multi-M: it is
    // published *before* `gopark`, so B could `goready` a G whose
    // status is still `Running` (mid-park-transition) — a contract
    // violation (Go's `ready()` throws "bad g->status in ready" for
    // the same misuse). Real primitives (chan/sema/timer) linearize
    // wake-after-park through a lock released by the park commit;
    // this raw smoke test must poll the status instead.
    go!(|| {
        loop {
            let p = SLEEPER_PTR.load(Ordering::Acquire);
            if !p.is_null() {
                let parked =
                    unsafe { core::ptr::addr_of!((*p).status).read_volatile() == GStatus::Waiting };
                if parked {
                    B_RAN.store(true, Ordering::Relaxed);
                    let g = NonNull::new(p).expect("non-null sleeper");
                    goready(g);
                    break;
                }
            }
            Gosched();
        }
    });

    schedule();

    check(
        A_BEFORE_PARK.load(Ordering::Relaxed),
        b"park-and-wake: A didn't reach park\n",
    );
    check(
        B_RAN.load(Ordering::Relaxed),
        b"park-and-wake: B didn't run\n",
    );
    check(
        A_AFTER_WAKE.load(Ordering::Relaxed),
        b"park-and-wake: A didn't resume after goready\n",
    );
}

// ─── Test 2: gopark rejection (unlockf returns false) ───────────────

fn test_park_rejected() {
    static REACHED_AFTER: AtomicUsize = AtomicUsize::new(0);

    go!(|| {
        gopark(never_park, core::ptr::null());
        // Should reach here after the rejected park is requeued and
        // the scheduler dispatches us again.
        REACHED_AFTER.fetch_add(1, Ordering::Relaxed);
    });

    schedule();

    check(
        UNLOCKF_CALLS_T2.load(Ordering::Relaxed) == 1,
        b"park-rejected: unlockf not called\n",
    );
    check(
        REACHED_AFTER.load(Ordering::Relaxed) == 1,
        b"park-rejected: G didn't resume after rejected park\n",
    );
}
