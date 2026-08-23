// testing_destination_smoke — common.setRan and common.destination.
//
// These two are the plumbing under late test output. Go's rule is that
// output written after a test has completed does not vanish and does
// not panic: it is re-homed onto the nearest ancestor that is still
// running. destination is the walk that finds that ancestor, and
// returning nil is a meaningful answer — it means everything up the
// chain has finished, which the callers turn into a panic naming the
// test that was written to too late.
//
// setRan is recursive on purpose. A parent whose body contains nothing
// but t.Run calls never executes a line of its own, and would report
// as not-run if only the leaf were marked.
//
// The two directions that matter:
//
//   * check 3 — a live test is its own destination
//   * check 4 — a DONE test re-homes to its live parent, not to itself

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::sync::Mutex;
use goish::testing::{self, __shim_destination, __shim_mark_done, __shim_ran_done};
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

/// Observations recorded from inside the test tree, since TestFn is a
/// bare fn pointer.
static OBS: Mutex<alloc::vec::Vec<(string, string)>> = Mutex::new(alloc::vec::Vec::new());

fn record(k: &str, v: string) {
    OBS.Lock().push((s(k), v));
}

fn get(k: &str) -> string {
    for (a, b) in OBS.Lock().iter() {
        if a == &s(k) {
            return b.clone();
        }
    }
    return s("<unset>");
}

fn parent_test(t: &mut testing::T) {
    // The parent's own ran flag before it runs any subtest. tRunner
    // sets it on entry, so this is already true.
    let (ran, done) = __shim_ran_done(t);
    record("parent.ran", if ran { s("true") } else { s("false") });
    record("parent.done", if done { s("true") } else { s("false") });

    t.Run(s("child"), |t| {
        // 1. A live test is its own destination.
        record(
            "child.dest.live",
            __shim_destination(t).unwrap_or_else(|| s("<nil>")),
        );

        // 2. Once marked done, output re-homes to the nearest live
        //    ancestor — the parent, which is still inside t.Run.
        __shim_mark_done(t);
        record(
            "child.dest.done",
            __shim_destination(t).unwrap_or_else(|| s("<nil>")),
        );

        let (ran, _) = __shim_ran_done(t);
        record("child.ran", if ran { s("true") } else { s("false") });
    });
}

/// A parent whose body is nothing but a t.Run still counts as ran —
/// which is the whole reason setRan recurses.
fn only_subtests(t: &mut testing::T) {
    t.Run(s("leaf"), |t| {
        let (ran, _) = __shim_ran_done(t);
        record("leaf.ran", if ran { s("true") } else { s("false") });
    });
    let (ran, _) = __shim_ran_done(t);
    record("outer.ran", if ran { s("true") } else { s("false") });
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let code = testing::Main(&[("Parent", parent_test), ("OnlySubtests", only_subtests)]);

    // 1. The tree ran green — none of the shims perturbed it.
    {
        if code == 0 {
            fmt::Println!("[ 1] tree runs green           PASS");
        } else {
            fmt::Println!("[ 1] tree runs green           FAIL");
            failed += 1;
        }
    }

    // 2. tRunner marks a test as ran on entry and not-done until it
    //    returns. A test that saw itself as done would re-home its own
    //    output onto its parent for its whole body.
    {
        if get("parent.ran") == s("true") && get("parent.done") == s("false") {
            fmt::Println!("[ 2] ran set, done clear       PASS");
        } else {
            fmt::Println!("[ 2] ran set, done clear       FAIL");
            failed += 1;
        }
    }

    // 3. A live test is its own destination — the common case, and the
    //    one a broken walk would still get right by accident if it
    //    always returned the receiver.
    {
        if get("child.dest.live") == s("Parent/child") {
            fmt::Println!("[ 3] live test is its own dest PASS");
        } else {
            fmt::Println!(
                "[ 3] live test is its own dest FAIL [",
                get("child.dest.live"),
                "]"
            );
            failed += 1;
        }
    }

    // 4. …and a DONE test re-homes to its still-live parent. This is
    //    the branch that distinguishes a real parent walk from
    //    `return self`.
    {
        if get("child.dest.done") == s("Parent") {
            fmt::Println!("[ 4] done test re-homes up     PASS");
        } else {
            fmt::Println!(
                "[ 4] done test re-homes up     FAIL [",
                get("child.dest.done"),
                "]"
            );
            failed += 1;
        }
    }

    // 5. setRan recurses: a parent that only calls t.Run still reports
    //    as ran, and so does the leaf.
    {
        if get("outer.ran") == s("true") && get("leaf.ran") == s("true") {
            fmt::Println!("[ 5] setRan reaches ancestors  PASS");
        } else {
            fmt::Println!("[ 5] setRan reaches ancestors  FAIL");
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
