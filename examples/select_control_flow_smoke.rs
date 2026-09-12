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
// The bodies run OUTSIDE the select machinery now. Every dispatch site
// stores its received value and breaks with a case index; the body runs
// after the block and after the trailing `releasem`, inside nothing but
// a `match`. A match arm is neither a loop nor a labeled block, so
// `continue`, `break` and `return` reach the user's own enclosing
// construct — which is what Go's `continue` in a select case means.
// No mask is open across user code at all, so there is no epoch left
// for a parking body to split.
//
// What this file pins is that the LABELED forms — which are what Go's
// `continue` in a select case corresponds to here — stay balanced
// across every dispatch path:
//
//   pass-1  a case already ready when select runs
//   default a select with a default arm and nothing ready
//   pass-3  a case that had to park and was woken
//
// Each is exercised with UNLABELED `continue`/`break` — the form the
// issue reported and the form Go permits — as well as the labeled ones
// and `return`. One body parks (a channel send that blocks) before
// escaping, the case the issue asks for, because a body that parks can
// resume on a different M and that is what used to split a bump/drop
// pair.
//
// The assertion is the exit status and the loop's own arithmetic: an
// unbalanced epoch aborts the process rather than returning a wrong
// answer, so reaching the end at all is most of the test. The counts
// catch control flow going to the wrong place while staying balanced.
//
// The `unlabeled_*` rows ARE the regression test for #21: against the
// pre-fix macro they abort the process with `releasem UNDERFLOW`. The
// labeled rows are not — they were balanced all along, and an earlier
// version of this file consisted only of those and passed against the
// unfixed macro, which is why the distinction is spelled out here.

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

/// pass-1 with an UNLABELED `continue` — issue #21's exact shape.
/// Against the pre-fix macro this aborts with `releasem UNDERFLOW`.
fn pass1_unlabeled_continue() -> usize {
    let c: chan<u8> = chan::new_buffered(16);
    for i in 0..6u8 {
        c.Send(i);
    }
    let mut seen = 0usize;
    loop {
        select! {
            let (v, _) = (c).Recv() => {
                if v < 5 {
                    seen += 1;
                    continue;
                }
                break;
            },
        }
    }
    return seen;
}

/// The default arm, unlabeled.
fn default_unlabeled_continue() -> usize {
    let empty: chan<u8> = chan::new_buffered(1);
    let mut rounds = 0usize;
    loop {
        select! {
            let (_v, _) = (empty).Recv() => { break; },
            default => {
                rounds += 1;
                if rounds < 4 {
                    continue;
                }
                break;
            },
        }
    }
    return rounds;
}

/// pass-3 — the woken body — unlabeled.
fn pass3_unlabeled_continue() -> usize {
    let c: chan<u8> = chan::new_unbuffered();
    let w = c.clone();
    go!(move || {
        for i in 0..4u8 {
            w.Send(i);
        }
    });
    let mut seen = 0usize;
    loop {
        select! {
            let (v, _) = (c).Recv() => {
                seen += 1;
                if v < 3 {
                    continue;
                }
                break;
            },
        }
    }
    return seen;
}

/// Shapes the restructure could have broken but no existing example
/// covers: a select with ONLY a default arm, arms of mixed
/// diverging/valued type, and a send case as the winner. The bodies now
/// run in a `match` whose arms must unify, where before they were the
/// break values of a `loop` — the same constraint, but re-established
/// by different code, so it is worth an assertion rather than an
/// assumption.
fn expression_shapes() -> (u8, u8, u8, usize) {
    let empty: chan<u8> = chan::new_buffered(1);
    let default_only: u8 = select! {
        let (_v, _) = (empty).Recv() => 1u8,
        default => 9u8,
    };

    // One arm yields, the other diverges.
    let c: chan<u8> = chan::new_buffered(4);
    c.Send(3);
    let mixed: u8 = loop {
        let got: u8 = select! {
            let (v, _) = (c).Recv() => v,
            default => { break 0u8; },
        };
        break got;
    };

    // A send case winning, and its value actually landing.
    let s: chan<u8> = chan::new_buffered(2);
    let send_arm: u8 = select! {
        (s).Send(7u8) => 5u8,
        default => 0u8,
    };
    return (default_only, mixed, send_arm, s.Len());
}

#[goish::main]
fn main() {
    check(pass1_unlabeled_continue() == 5, "pass-1: UNLABELED continue x5 then break");
    check(default_unlabeled_continue() == 4, "default: UNLABELED continue then break");
    check(pass3_unlabeled_continue() == 4, "pass-3: UNLABELED continue in a woken body");
    check(pass1_continue_and_break() == 5, "pass-1: continue 'outer x5 then break");
    check(default_continue() == 4, "default: continue 'outer then break");
    check(pass3_continue() == 4, "pass-3: woken body continues");
    check(body_parks_then_continues() == 4, "body parks, then continue 'outer");
    check(returns_from_body() == 7, "return out of a selected body");

    let (d, m, sa, slen) = expression_shapes();
    check(d == 9, "select with only a default arm yields its body");
    check(m == 3, "arms of mixed diverging/valued type unify");
    check(sa == 5 && slen == 1, "a send arm wins and its value lands");

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
