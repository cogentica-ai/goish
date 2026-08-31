// context_ref_smoke — the `context` package against a running Go.
// (context/context.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_context_ref.go` run in
// `package context_test` by `scripts/goref.sh`.
//
// The package had one anchor. Four things were missing outright, and
// each is the kind a caller only discovers when they reach for it:
//
//   * `WithoutCancel` — what a handler needs when it starts work that
//     must outlive the request but still wants the request's values.
//     The alternatives were `Background()`, losing every value, or the
//     request context, and having the work cancelled underneath.
//   * `AfterFunc` — run something when a context is cancelled.
//   * `WithDeadlineCause` / `WithTimeoutCause`.
//   * `DeadlineExceeded.Timeout()` and `.Temporary()`. Go's satisfies
//     `net.Error`, which is how a caller that already branches on a
//     socket timeout treats a context deadline the same way. Neither
//     method existed, so it did not.
//
// The cases are the ones where a plausible implementation and Go's
// part company: cancellation has to propagate DOWN and never up, a
// cause has to stay distinguishable from the Err that carries it, a
// later child deadline must not extend an earlier parent one, and a
// cancel in the middle of a chain must not sever the values above it.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::context;
use goish::errors;
use goish::gostring::string;
use goish::time::Duration;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

fn ms(n: i64) -> Duration {
    return Duration(n * 1_000_000);
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let bg = context::Background();

    // 1. Background and TODO: no deadline, a nil Done, a nil Err and a
    //    nil Cause. A nil Done is what "never cancellable" means — a
    //    receive on it blocks forever and `select!` skips the case.
    {
        let mut ok = true;
        for c in [context::Background(), context::TODO()] {
            if c.Deadline().is_some() {
                ok = false;
            }
            if !c.Done().is_nil() {
                ok = false;
            }
            if !c.Err().IsNil() || !context::Cause(&c).IsNil() {
                ok = false;
            }
        }
        report(&mut failed, ok, " 1", "Background/TODO are inert");
    }

    // 2. WithCancel: nil before, Canceled after, and cancelling twice
    //    changes nothing.
    {
        let mut ok = true;
        let (ctx, cancel) = context::WithCancel(bg.clone());
        if !ctx.Err().IsNil() || !context::Cause(&ctx).IsNil() {
            ok = false;
        }
        cancel();
        ctx.Done().Recv();
        if !errors::Is(ctx.Err(), context::Canceled) {
            ok = false;
        }
        if !errors::Is(context::Cause(&ctx), context::Canceled) {
            ok = false;
        }
        cancel();
        if !errors::Is(ctx.Err(), context::Canceled) {
            ok = false;
        }
        report(&mut failed, ok, " 2", "WithCancel (idempotent)");
    }

    // 3. Cancellation goes DOWN. Cancelling the parent cancels the
    //    child; cancelling the child leaves the parent running.
    {
        let mut ok = true;
        let (parent, pcancel) = context::WithCancel(bg.clone());
        let (child, _ccancel) = context::WithCancel(parent.clone());
        pcancel();
        child.Done().Recv();
        if !errors::Is(parent.Err(), context::Canceled) {
            ok = false;
        }
        if !errors::Is(child.Err(), context::Canceled) {
            ok = false;
        }

        let (p2, _p2cancel) = context::WithCancel(bg.clone());
        let (c2, c2cancel) = context::WithCancel(p2.clone());
        c2cancel();
        c2.Done().Recv();
        // Go: up parent=<nil> child=context canceled
        if !p2.Err().IsNil() {
            ok = false;
        }
        if !errors::Is(c2.Err(), context::Canceled) {
            ok = false;
        }
        report(&mut failed, ok, " 3", "cancel propagates down, not up");
    }

    // 4. WithCancelCause. Err stays Canceled and Cause carries the
    //    reason — that split is the whole point: Err is what a caller
    //    branches on, Cause is what it logs. A nil cause falls back.
    {
        let mut ok = true;
        let boom = errors::New("boom");
        let (ctx, cancel) = context::WithCancelCause(bg.clone());
        cancel(boom.clone());
        ctx.Done().Recv();
        if !errors::Is(ctx.Err(), context::Canceled) {
            ok = false;
        }
        if !errors::Is(context::Cause(&ctx), boom) {
            ok = false;
        }
        let (c2, cancel2) = context::WithCancelCause(bg.clone());
        cancel2(errors::nil);
        c2.Done().Recv();
        if !errors::Is(c2.Err(), context::Canceled) {
            ok = false;
        }
        if !errors::Is(context::Cause(&c2), context::Canceled) {
            ok = false;
        }
        report(&mut failed, ok, " 4", "WithCancelCause (Err vs Cause)");
    }

    // 5. Deadlines. One already past fires at once, and a LATER child
    //    deadline does not extend an earlier parent one — the child
    //    inherits the parent's.
    {
        let mut ok = true;
        let past = goish::time::Now().Add(Duration(-3_600_000_000_000));
        let (pctx, _pc) = context::WithDeadline(bg.clone(), past);
        pctx.Done().Recv();
        if !errors::Is(pctx.Err(), context::DeadlineExceeded) {
            ok = false;
        }

        let (soon, _c1) = context::WithTimeout(bg.clone(), ms(50));
        let (later, _c2) = context::WithTimeout(soon.clone(), Duration(3_600_000_000_000));
        match (soon.Deadline(), later.Deadline()) {
            (Some(sd), Some(ld)) => {
                // Go: nested-deadline child-not-later=true
                if ld.After(sd) {
                    ok = false;
                }
            }
            _ => ok = false,
        }
        later.Done().Recv();
        if !errors::Is(later.Err(), context::DeadlineExceeded) {
            ok = false;
        }
        report(&mut failed, ok, " 5", "deadlines (child cannot extend)");
    }

    // 6. DeadlineExceeded is a net.Error: Timeout() and Temporary() are
    //    both true. Neither method existed, so a caller that already
    //    branches on a socket timeout could not treat a context
    //    deadline the same way.
    //
    //    Go reaches them with `errors.As(err, &netErr)` on the `error`
    //    interface. goish cannot: `cast!` on an `error` handle
    //    downcasts the HANDLE, not what it wraps, so an interface
    //    assertion against a wrapped error is a silent miss. The
    //    concrete type is public for that reason, and this checks the
    //    methods through it. The handle limitation is wider than this
    //    package — net::OpError::Timeout hits it too — and is worth its
    //    own fix.
    {
        let mut ok = true;
        let de_concrete = context::DeadlineExceededError;
        if !goish::net::net::timeout::Timeout(&de_concrete) {
            ok = false;
        }
        if !goish::net::net::temporary::Temporary(&de_concrete) {
            ok = false;
        }
        let de: errors::error = context::DeadlineExceeded.into();
        let cx: errors::error = context::Canceled.into();
        if cx.Error() != s("context canceled") {
            ok = false;
        }
        if de.Error() != s("context deadline exceeded") {
            ok = false;
        }
        report(&mut failed, ok, " 6", "DeadlineExceeded is a net.Error");
    }

    // 7. WithTimeoutCause: Err is still DeadlineExceeded, Cause is the
    //    reason given.
    {
        let mut ok = true;
        let why = errors::New("too slow");
        let (ctx, _cancel) = context::WithTimeoutCause(bg.clone(), ms(20), why.clone());
        ctx.Done().Recv();
        if !errors::Is(ctx.Err(), context::DeadlineExceeded) {
            ok = false;
        }
        if !errors::Is(context::Cause(&ctx), why) {
            ok = false;
        }
        report(&mut failed, ok, " 7", "WithTimeoutCause");
    }

    // 8. WithValue: lookup walks up, a miss is nil, and a WithCancel in
    //    the middle of the chain does NOT sever the values above it.
    {
        let mut ok = true;
        let v1 = context::WithValue(bg.clone(), "a", 1i64);
        let v2 = context::WithValue(v1, "b", 2i64);
        let (cctx, _cancel) = context::WithCancel(v2.clone());
        let v3 = context::WithValue(cctx, "c", 3i64);
        // Go: a and b visible from both; c only through v3; d nowhere.
        for (key, in_v2, in_v3) in [
            ("a", true, true),
            ("b", true, true),
            ("c", false, true),
            ("d", false, false),
        ] {
            if v2.Value(key).is_some() != in_v2 {
                ok = false;
            }
            if v3.Value(key).is_some() != in_v3 {
                ok = false;
            }
        }
        match v3.Value("a") {
            Some(v) => match v.downcast_ref::<i64>() {
                Some(n) => {
                    if *n != 1 {
                        ok = false;
                    }
                }
                None => ok = false,
            },
            None => ok = false,
        }
        report(&mut failed, ok, " 8", "WithValue survives a cancel");
    }

    // 9. WithoutCancel keeps the values and drops the cancellation:
    //    the parent is cancelled, this one is not, and its Done is nil.
    {
        let mut ok = true;
        let base = context::WithValue(bg.clone(), "a", 1i64);
        let (ctx, cancel) = context::WithCancel(base);
        let free = context::WithoutCancel(ctx.clone());
        cancel();
        ctx.Done().Recv();
        if !errors::Is(ctx.Err(), context::Canceled) {
            ok = false;
        }
        // Go: free-err=<nil> done-nil=true deadline=(true,false)
        if !free.Err().IsNil() || !free.Done().is_nil() || free.Deadline().is_some() {
            ok = false;
        }
        if free.Value("a").is_none() {
            ok = false;
        }
        report(&mut failed, ok, " 9", "WithoutCancel keeps values only");
    }

    // 10. AfterFunc runs on cancel; stop() before the cancel prevents
    //     it and returns true; a second stop() returns false; and on an
    //     ALREADY-cancelled context the callback runs anyway and stop()
    //     returns false.
    {
        let mut ok = true;
        let ran: goish::gochan::chan<()> = goish::make!(chan());
        let (ctx, cancel) = context::WithCancel(bg.clone());
        let ran_tx = ran.clone();
        let _stop1 = context::AfterFunc(ctx, move || {
            ran_tx.Close();
        });
        cancel();
        ran.Recv();

        let (c2, cancel2) = context::WithCancel(bg.clone());
        let fired: goish::gochan::chan<()> = goish::make!(chan());
        let fired_tx = fired.clone();
        let stop = context::AfterFunc(c2.clone(), move || {
            fired_tx.Close();
        });
        if !stop() {
            ok = false;
        }
        // Go: stop-twice=false
        if stop() {
            ok = false;
        }
        cancel2();
        c2.Done().Recv();
        // Go: ran-after-stop=false — a stopped callback never runs.
        // A non-blocking receive is the only way to ask; a plain Recv
        // on a chan nobody will ever close would hang the smoke.
        goish::select! {
            let _ = fired.Recv() => { ok = false; },
            default => {},
        }

        let (c3, cancel3) = context::WithCancel(bg.clone());
        cancel3();
        c3.Done().Recv();
        let done3: goish::gochan::chan<()> = goish::make!(chan());
        let done3_tx = done3.clone();
        let stop3 = context::AfterFunc(c3, move || {
            done3_tx.Close();
        });
        done3.Recv();
        // Go: stop-after=false — the callback has already started.
        if stop3() {
            ok = false;
        }
        report(&mut failed, ok, "10", "AfterFunc (run, stop, already-done)");
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
