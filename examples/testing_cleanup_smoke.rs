// testing_cleanup_smoke — common.runCleanup.
//
// Two properties, and the second is the reason this is a port rather
// than a hand-written drain:
//
//   * Cleanups run LIFO. A test that opens A then B tears down B then
//     A, which is the only order where B's teardown can still rely on
//     A existing.
//
//   * A cleanup may register ANOTHER cleanup, and it runs. Go's loop
//     re-takes the lock on every iteration, so anything pushed during
//     teardown is picked up. The obvious Rust rewrite — take the whole
//     list once, then pop — pushes the new callback onto a list nobody
//     reads again and it is silently never called. goish had exactly
//     that bug until runCleanup was ported — drain_cleanups took the
//     list with mem::take and popped from the copy. Check 2 catches it.
//
// Check 3 covers the recursive case, since a nested registration that
// itself registers is where a one-shot "run the leftovers once" patch
// would still come up short.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::sync::Mutex;
use goish::testing;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

static LOG: Mutex<alloc::vec::Vec<string>> = Mutex::new(alloc::vec::Vec::new());

fn note(x: &str) {
    LOG.Lock().push(s(x));
}

fn joined() -> string {
    let mut out = alloc::vec::Vec::new();
    for (i, e) in LOG.Lock().iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(e.as_bytes());
    }
    return string::from_bytes(&out);
}

/// Three cleanups, torn down in reverse.
fn lifo(t: &mut testing::T) {
    t.Cleanup(|| note("first"));
    t.Cleanup(|| note("second"));
    t.Cleanup(|| note("third"));
    note("body");
}

/// A cleanup that registers another one. Both must run.
fn nested(t: &mut testing::T) {
    let h = goish::testing::__shim_cleanup_handle(t);
    t.Cleanup(move || {
        note("outer");
        // Registered DURING teardown. Go picks it up because the loop
        // re-reads the list; a one-shot drain loses it entirely.
        h.Cleanup(|| note("inner"));
    });
    note("body");
}

/// …and one that registers a cleanup which itself registers one.
fn nested_twice(t: &mut testing::T) {
    let h1 = goish::testing::__shim_cleanup_handle(t);
    let h2 = goish::testing::__shim_cleanup_handle(t);
    t.Cleanup(move || {
        note("l1");
        h1.Cleanup(move || {
            note("l2");
            h2.Cleanup(|| note("l3"));
        });
    });
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let _ = testing::Main(&[("Lifo", lifo)]);
    let lifo_order = joined();
    LOG.Lock().clear();

    let _ = testing::Main(&[("Nested", nested)]);
    let nested_order = joined();
    LOG.Lock().clear();

    let _ = testing::Main(&[("NestedTwice", nested_twice)]);
    let twice_order = joined();
    LOG.Lock().clear();

    // 1. Cleanups run after the test body, not at registration, and
    //    in LIFO order.
    {
        if lifo_order == s("body,third,second,first") {
            fmt::Println!("[ 1] cleanups run LIFO after body PASS");
        } else {
            fmt::Println!("[ 1] cleanups run LIFO after body FAIL [", lifo_order, "]");
            failed += 1;
        }
    }

    // 2. A cleanup registered DURING teardown still runs. This is the
    //    one a take-the-whole-list-once drain gets wrong.
    {
        if nested_order == s("body,outer,inner") {
            fmt::Println!("[ 2] nested registration runs  PASS");
        } else {
            fmt::Println!("[ 2] nested registration runs  FAIL [", nested_order, "]");
            failed += 1;
        }
    }

    // 3. …and it recurses: a cleanup added by a cleanup added by a
    //    cleanup runs too, so the loop is a real fixpoint and not a
    //    single extra pass.
    {
        if twice_order == s("l1,l2,l3") {
            fmt::Println!("[ 3] nesting recurses          PASS");
        } else {
            fmt::Println!("[ 3] nesting recurses          FAIL [", twice_order, "]");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 3");
        syscall::Exit(1);
    }
}
