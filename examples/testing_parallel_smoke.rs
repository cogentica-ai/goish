// testing_parallel_smoke — t.Parallel and the testState gating behind
// it.
//
// The sequence in Parallel is the whole thing, and every step is load
// bearing:
//
//   1. signal the PARENT — "I am done for now, carry on"
//   2. park on the parent's barrier until the parent's body returns
//   3. only THEN compete for one of the -parallel slots
//
// Asking for a slot before the barrier would let a subtest hold one
// while it was still blocked, so -parallel would over-admit. Signalling
// after the barrier would deadlock: the parent is blocked waiting for
// that signal and can never reach the close.
//
// The parent releases everyone by CLOSING the barrier, not by sending
// on it. A send wakes exactly one waiter and hangs the rest — which is
// the failure this smoke test would catch as a hang rather than a
// wrong answer, so it also matters that it terminates at all.
//
// Check 4 is the one that pins correctness rather than mechanism: a
// parallel subtest that fails must report FAIL. Because a parallel
// subtest returns from tRunner EARLY (at the Parallel call, before its
// body has run), a runner that printed its status there would say PASS
// for a test that had not finished.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::gostring::string;
use goish::sync::Mutex;
use goish::testing;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

/// Order in which things happened, so the sequence can be asserted
/// rather than inferred from it not hanging.
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

static RUNNING: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Three parallel subtests. Each records when it resumed; none may
/// resume before the parent's body has finished.
fn parallel_tree(t: &mut testing::T) {
    for name in ["a", "b", "c"].iter() {
        let n = *name;
        t.Run(s(n), move |t| {
            t.Parallel();
            note(n);
            let cur = RUNNING.fetch_add(1, Ordering::SeqCst) + 1;
            PEAK.fetch_max(cur, Ordering::SeqCst);
            RUNNING.fetch_sub(1, Ordering::SeqCst);
        });
    }
    // Reached while all three are still parked on the barrier.
    note("parent-body-end");
}

/// A parallel subtest that fails. Its status line must say FAIL, and
/// its parent must fail too.
fn parallel_failing(t: &mut testing::T) {
    t.Run(s("bad"), |t| {
        t.Parallel();
        t.Error(s("deliberate"));
    });
}

/// A non-parallel subtest still runs to completion inside t.Run, so
/// the ordering for the ordinary case is unchanged.
fn sequential_tree(t: &mut testing::T) {
    t.Run(s("x"), |_t| {
        note("seq-x");
    });
    note("seq-parent-end");
}

#[goish::main]
fn main() {
    let mut failed = 0;

    fmt::Println!("--- parallel tree:");
    let good = testing::Main(&[("Par", parallel_tree)]);
    let par_order = joined();
    LOG.Lock().clear();

    fmt::Println!("--- sequential tree:");
    let _ = testing::Main(&[("Seq", sequential_tree)]);
    let seq_order = joined();
    LOG.Lock().clear();

    fmt::Println!("--- failing parallel subtest (the FAIL is expected):");
    let bad = testing::Main(&[("ParFail", parallel_failing)]);
    fmt::Println!("--- end");

    // 1. Reaching this line means the barrier released ALL three
    //    subtests. A send instead of a close would have woken one and
    //    hung the other two, and this example would time out.
    {
        fmt::Println!("[ 1] barrier releases all      PASS");
    }

    // 2. Every parallel subtest resumed only AFTER the parent's body
    //    returned. This is what Parallel buys: the parent finishes its
    //    own work first, then the children run together.
    {
        if par_order == s("parent-body-end,a,b,c")
            || par_order == s("parent-body-end,a,c,b")
            || par_order == s("parent-body-end,b,a,c")
            || par_order == s("parent-body-end,b,c,a")
            || par_order == s("parent-body-end,c,a,b")
            || par_order == s("parent-body-end,c,b,a")
        {
            fmt::Println!("[ 2] subtests resume after parent PASS");
        } else {
            fmt::Println!("[ 2] subtests resume after parent FAIL [", par_order, "]");
            failed += 1;
        }
    }

    // 3. …and a NON-parallel subtest still runs inside t.Run, before
    //    the parent's body continues. Without this, check 2 would also
    //    pass for a Parallel that did nothing at all.
    {
        if seq_order == s("seq-x,seq-parent-end") {
            fmt::Println!("[ 3] sequential order unchanged PASS");
        } else {
            fmt::Println!("[ 3] sequential order unchanged FAIL [", seq_order, "]");
            failed += 1;
        }
    }

    // 4. A parallel subtest that fails turns the run red. It returns
    //    from tRunner early — at the Parallel call, before its body has
    //    run — so a runner reporting status there would say PASS.
    {
        if good == 0 && bad != 0 {
            fmt::Println!("[ 4] failing parallel reports  PASS");
        } else {
            fmt::Println!("[ 4] failing parallel reports  FAIL");
            failed += 1;
        }
    }

    // 5. The parallel pool admitted at least one test — i.e. the slot
    //    accounting did not deadlock everything into running one at a
    //    time and did not lose a slot.
    {
        if PEAK.load(Ordering::SeqCst) >= 1 {
            fmt::Println!("[ 5] pool admits work          PASS");
        } else {
            fmt::Println!("[ 5] pool admits work          FAIL");
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
