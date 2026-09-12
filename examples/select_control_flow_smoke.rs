// select_control_flow_smoke — labeled `continue` / `break` and
// `return` out of a selected body keep `m.locks` balanced (issue #21).
//
// The reported failure was a process abort, `releasem UNDERFLOW`
// (status 87), from a `continue` in a select receive body. The cause
// was macro hygiene, not lock accounting: `select!` expanded to
// `'select_blk: loop { … }`, and an unlabeled `continue` in a user
// body binds to the nearest enclosing LOOP — which was the SELECT's,
// not the user's. Pass-1 then re-ran with the chan locks already
// released and the m.locks epoch already closed, so the next
// `__select_release_all` called `raw_unlock` at `m.locks == 0`.
//
// Nothing ever iterated that loop; it was one only to get
// `break 'select_blk value`. It is a labeled BLOCK now, which cannot
// be continued, so an unlabeled `continue` is rustc's E0695 at compile
// time rather than scheduler corruption at run time.
//
// What this file pins is that the LABELED forms — which are what Go's
// `continue` in a select case corresponds to here — stay balanced
// across every dispatch path:
//
//   pass-1  a case already ready when select runs
//   default a select with a default arm and nothing ready
//   pass-3  a case that had to park and was woken
//
// Each is exercised with `continue 'outer`, `break 'outer` and
// `return`, and one body parks (a channel send that blocks) before
// escaping — the case the issue asks for, because a body that parks
// can resume on a different M and that is what splits a bump/drop
// pair.
//
// The assertion is the exit status and the loop's own arithmetic: an
// unbalanced epoch aborts the process rather than returning a wrong
// answer, so reaching the end at all is most of the test. The counts
// catch control flow going to the wrong place while staying balanced.
//
// WHAT THIS FILE DOES NOT DO, checked rather than assumed: it does not
// regression-test issue #21. Run it against the pre-fix macro and it
// PASSES — the labeled forms were always balanced, and only the
// unlabeled `continue` bound to the wrong loop. The test for that fix
// is that the bad form no longer compiles, which no runtime example
// can assert. What this file adds is coverage that did not exist
// before: escapes from all three dispatch paths, and a body that
// parks. Treating a green run here as evidence about #21 would be
// wrong.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gochan::chan;
use goish::gostring::string;
use goish::{go, select, time};

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(cond: bool, what: &'static str) {
    if cond {
        fmt::Printf!("[ok] %s\n", string::from_static(what));
    } else {
        fmt::Printf!("[!!] %s\n", string::from_static(what));
        FAILED.fetch_add(1, Ordering::Relaxed);
    }
}

/// pass-1: the channel is already buffered-ready, so select takes it
/// without parking. `continue 'outer` five times, then `break 'outer`.
fn pass1_continue_and_break() -> usize {
    let c: chan<u8> = chan::new_buffered(16);
    for i in 0..6u8 {
        c.Send(i);
    }
    let mut seen = 0usize;
    'outer: loop {
        select! {
            let (v, _) = (c).Recv() => {
                if v < 5 {
                    seen += 1;
                    continue 'outer;
                }
                break 'outer;
            },
        }
    }
    return seen;
}

/// default arm: nothing ready, so the default body runs — and escapes.
fn default_continue() -> usize {
    let empty: chan<u8> = chan::new_buffered(1);
    let mut rounds = 0usize;
    'outer: loop {
        select! {
            let (_v, _) = (empty).Recv() => {
                break 'outer;
            },
            default => {
                rounds += 1;
                if rounds < 4 {
                    continue 'outer;
                }
                break 'outer;
            },
        }
    }
    return rounds;
}

/// pass-3: nothing is ready when select runs, so it registers and
/// parks; a goroutine wakes it. The woken body then escapes.
fn pass3_continue() -> usize {
    let c: chan<u8> = chan::new_unbuffered();
    let w = c.clone();
    go!(move || {
        for i in 0..4u8 {
            w.Send(i);
        }
    });
    let mut seen = 0usize;
    'outer: loop {
        select! {
            let (v, _) = (c).Recv() => {
                seen += 1;
                if v < 3 {
                    continue 'outer;
                }
                break 'outer;
            },
        }
    }
    return seen;
}

/// A body that PARKS before escaping. The send blocks until the reader
/// takes it, so the G suspends inside the body and may resume on a
/// different M — which is what splits an m.locks pair if the epoch is
/// open across it.
fn body_parks_then_continues() -> usize {
    let trigger: chan<u8> = chan::new_buffered(8);
    let sink: chan<u8> = chan::new_unbuffered();
    for i in 0..4u8 {
        trigger.Send(i);
    }
    let r = sink.clone();
    go!(move || {
        for _ in 0..4 {
            let _ = r.Recv();
        }
    });
    let mut sent = 0usize;
    'outer: loop {
        select! {
            let (v, _) = (trigger).Recv() => {
                // Parks here until the reader goroutine arrives.
                sink.Send(v);
                sent += 1;
                if v < 3 {
                    continue 'outer;
                }
                break 'outer;
            },
        }
    }
    return sent;
}

/// `return` out of a selected body, which skips the trailing
/// `releasem` the same way an escape does.
fn returns_from_body() -> usize {
    let c: chan<u8> = chan::new_buffered(4);
    c.Send(7);
    loop {
        select! {
            let (v, _) = (c).Recv() => {
                return v as usize;
            },
        }
    }
}

#[goish::main]
fn main() {
    check(pass1_continue_and_break() == 5, "pass-1: continue 'outer x5 then break");
    check(default_continue() == 4, "default: continue 'outer then break");
    check(pass3_continue() == 4, "pass-3: woken body continues");
    check(body_parks_then_continues() == 4, "body parks, then continue 'outer");
    check(returns_from_body() == 7, "return out of a selected body");

    // Several rounds, so an epoch that leaks by one per select is
    // visible as an abort rather than absorbed.
    let mut total = 0usize;
    for _ in 0..20 {
        total += pass1_continue_and_break();
    }
    check(total == 100, "20 rounds stay balanced");

    // Anything unbalanced aborts before here, so reaching this line is
    // itself the main assertion.
    time::Sleep(time::Millisecond * 20);
    let f = FAILED.load(Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok\n");
}
