// testing_nested_parallel_smoke — a parallel subtest under a parallel
// parent.
//
// `testing_parallel_smoke` covers one level of Parallel: a sequential
// parent with parallel children. This is the level below it, and it is
// where the ordering in `tRunner` stops being an implementation detail.
//
// A test that calls Parallel signals its parent TWICE: once when it
// parks (Go's "Release calling test") and once when it really finishes.
// The work Go does in tRunner's deferred func — closing the barrier,
// waiting for the parked subtests, reporting them — belongs to the
// SECOND signal. Doing it after the first releases nothing, because at
// that point the parent's body has not run and `sub` is still empty; a
// child the parent creates afterwards then parks on a barrier nobody
// will ever close, and the run reports PASS with the child's body
// never executed.
//
// Both tests below are identical except for one line — whether the
// PARENT calls Parallel. Each has one child that calls Parallel and
// then fails on purpose, so both runs must report FAIL, and both
// children must have run.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicBool, Ordering};

use goish::gostring::string;
use goish::testing;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

/// Set by whichever child body actually executes; reset between runs.
static CHILD_RAN: AtomicBool = AtomicBool::new(false);

/// Set by the parent's Cleanup, which Go runs only after every parallel
/// subtest has completed. A child that never ran leaves this false.
static CHILD_DONE_AT_CLEANUP: AtomicBool = AtomicBool::new(false);

/// The parent is parallel, and so is its child.
fn nested_parallel(t: &mut testing::T) {
    t.Parallel();
    t.Cleanup(|| {
        CHILD_DONE_AT_CLEANUP.store(CHILD_RAN.load(Ordering::SeqCst), Ordering::SeqCst);
    });
    t.Run(s("child"), |t| {
        t.Parallel();
        CHILD_RAN.store(true, Ordering::SeqCst);
        t.Error(s("deliberate"));
    });
}

/// The same test with the parent's Parallel removed — the shape
/// `testing_parallel_smoke` already covers, kept here as the control.
fn sequential_parent(t: &mut testing::T) {
    t.Cleanup(|| {
        CHILD_DONE_AT_CLEANUP.store(CHILD_RAN.load(Ordering::SeqCst), Ordering::SeqCst);
    });
    t.Run(s("child"), |t| {
        t.Parallel();
        CHILD_RAN.store(true, Ordering::SeqCst);
        t.Error(s("deliberate"));
    });
}

/// Three levels of Parallel, to show the fix is not special-cased to
/// two: the grandchild must run and its failure must reach the root.
fn three_deep(t: &mut testing::T) {
    t.Parallel();
    t.Run(s("child"), |t| {
        t.Parallel();
        t.Run(s("grandchild"), |t| {
            t.Parallel();
            CHILD_RAN.store(true, Ordering::SeqCst);
            t.Error(s("deliberate"));
        });
    });
}

/// Run one test alone and report whether the child body executed,
/// whether the child had finished by the time the parent's cleanup
/// ran, and whether the run failed. `testing::Main` returns 0 when the
/// run passes.
fn check(name: &'static str, f: testing::TestFn) -> (bool, bool, bool) {
    CHILD_RAN.store(false, Ordering::SeqCst);
    CHILD_DONE_AT_CLEANUP.store(false, Ordering::SeqCst);
    let code = testing::Main(&[(name, f)]);
    return (
        CHILD_RAN.load(Ordering::SeqCst),
        CHILD_DONE_AT_CLEANUP.load(Ordering::SeqCst),
        code != 0,
    );
}

#[goish::main]
fn main() {
    let mut failed = 0;

    fmt::Println!("--- parallel parent (the FAIL is expected):");
    let (nestedRan, nestedCleanup, nestedFailed) = check("Nested", nested_parallel);

    fmt::Println!("--- sequential parent (the FAIL is expected):");
    let (seqRan, seqCleanup, seqFailed) = check("Seq", sequential_parent);

    fmt::Println!("--- three levels (the FAIL is expected):");
    let (deepRan, _deepCleanup, deepFailed) = check("Deep", three_deep);
    fmt::Println!("--- end");

    // 1. The child under a parallel parent runs at all. Before the
    //    barrier moved to the second signal it parked forever, and the
    //    run still exited 0 — the silence is the dangerous part.
    {
        if nestedRan {
            fmt::Println!("[ 1] nested child runs         PASS");
        } else {
            fmt::Println!("[ 1] nested child runs         FAIL");
            failed += 1;
        }
    }

    // 2. …and its failure turns the run red. A child that runs but is
    //    reported after its parent's status line would still exit 0.
    {
        if nestedFailed {
            fmt::Println!("[ 2] nested failure reported   PASS");
        } else {
            fmt::Println!("[ 2] nested failure reported   FAIL");
            failed += 1;
        }
    }

    // 3. Go: "Cleanup registers a function to be called when the test
    //    (or subtest) AND ALL ITS SUBTESTS complete" — the parent's
    //    cleanup runs after the barrier has released the child and the
    //    child has finished, not when the parent's body returns.
    {
        if nestedCleanup {
            fmt::Println!("[ 3] cleanup after subtests    PASS");
        } else {
            fmt::Println!("[ 3] cleanup after subtests    FAIL");
            failed += 1;
        }
    }

    // 4. The one-level case is unchanged: this is the shape that
    //    already worked, so a fix that traded one for the other is
    //    caught here rather than in the suite.
    {
        if seqRan && seqCleanup && seqFailed {
            fmt::Println!("[ 4] sequential parent intact  PASS");
        } else {
            fmt::Println!(
                "[ 4] sequential parent intact  FAIL ran=",
                seqRan,
                " cleanup=",
                seqCleanup,
                " failed=",
                seqFailed
            );
            failed += 1;
        }
    }

    // 5. Three levels of Parallel: the release has to happen at every
    //    level, so the grandchild runs and its failure reaches the root.
    {
        if deepRan && deepFailed {
            fmt::Println!("[ 5] three levels release      PASS");
        } else {
            fmt::Println!(
                "[ 5] three levels release      FAIL ran=",
                deepRan,
                " failed=",
                deepFailed
            );
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
