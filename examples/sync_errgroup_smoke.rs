// sync_errgroup_smoke — x/sync/errgroup port: the parallelism
// primitive typescript-go's core.WorkGroup and LSP server run on.
//
// Covers:
//   1. Zero Group: Go + Wait with no errors.
//   2. First-error-wins (errOnce): a sequenced pair of failing tasks;
//      Wait returns the first.
//   3. WithContext: first error cancels the derived context with
//      that error as Cause; Wait cancels even on success.
//   4. SetLimit: concurrency actually bounded (peak-active tracking).
//   5. TryGo: rejected at the limit, accepted after drain.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;

use core::sync::atomic::{AtomicI64, Ordering};

use goish::error;
use goish::sync::errgroup;
use goish::{chan, context, errors, make, syscall, time};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

goish::var! {
    pub ErrFirst: error  = "first failure";
    pub ErrSecond: error = "second failure";
}

#[goish::main]
fn main() {
    // ─── 1. zero Group, all tasks succeed ──────────────────────────
    static SUM: AtomicI64 = AtomicI64::new(0);
    let g = errgroup::Group::new();
    for i in 1..=4_i64 {
        g.Go(move || {
            SUM.fetch_add(i, Ordering::AcqRel);
            goish::nil.into()
        });
    }
    let err = g.Wait();
    check(err == goish::nil, b"t1: Wait err on success\n");
    check(SUM.load(Ordering::Acquire) == 10, b"t1: all tasks ran\n");

    // ─── 2. first error wins ───────────────────────────────────────
    let g = errgroup::Group::new();
    let gate: chan<()> = make!(chan ());
    let gate2 = gate.clone();
    g.Go(move || {
        // Errors first, then releases the second task.
        gate2.Send(());
        ErrFirst.into()
    });
    g.Go(move || {
        let _ = gate.Recv(); // strictly after the first task returned...
        // (Send on an unbuffered chan completes at the rendezvous, so
        // the first task's error records before or at this point;
        // give the errOnce a beat to land regardless.)
        time::Sleep(time::Millisecond * 20);
        ErrSecond.into()
    });
    let err = g.Wait();
    check(err == ErrFirst, b"t2: first error returned\n");
    check(errors::Is(err, ErrFirst), b"t2: errors.Is on group err\n");

    // ─── 3. WithContext: error cancels the derived ctx ─────────────
    let (g, ctx) = errgroup::WithContext(context::Background());
    check(ctx.Err() == goish::nil, b"t3: ctx live before error\n");
    let ctx2 = ctx.clone();
    g.Go(move || {
        let _ = &ctx2;
        ErrFirst.into()
    });
    let err = g.Wait();
    check(err == ErrFirst, b"t3: Wait returns error\n");
    check(ctx.Err() != goish::nil, b"t3: ctx canceled after error\n");
    check(context::Cause(&ctx) == ErrFirst, b"t3: Cause is the group error\n");

    // Success path: Wait itself cancels the derived ctx.
    let (g, ctx) = errgroup::WithContext(context::Background());
    g.Go(|| goish::nil.into());
    let err = g.Wait();
    check(err == goish::nil, b"t3b: success Wait\n");
    check(ctx.Err() != goish::nil, b"t3b: ctx canceled by Wait\n");

    // ─── 4. SetLimit bounds concurrency ────────────────────────────
    static ACTIVE: AtomicI64 = AtomicI64::new(0);
    static PEAK: AtomicI64 = AtomicI64::new(0);
    let g = errgroup::Group::new();
    g.SetLimit(2);
    for _ in 0..6 {
        g.Go(|| {
            let now = ACTIVE.fetch_add(1, Ordering::AcqRel) + 1;
            PEAK.fetch_max(now, Ordering::AcqRel);
            time::Sleep(time::Millisecond * 10);
            ACTIVE.fetch_sub(1, Ordering::AcqRel);
            goish::nil.into()
        });
    }
    let err = g.Wait();
    check(err == goish::nil, b"t4: limited group Wait\n");
    let peak = PEAK.load(Ordering::Acquire);
    check(peak >= 1 && peak <= 2, b"t4: concurrency bounded by limit\n");

    // ─── 5. TryGo at and below the limit ───────────────────────────
    let g = errgroup::Group::new();
    g.SetLimit(1);
    let hold: chan<()> = make!(chan ());
    let hold2 = hold.clone();
    let started = g.TryGo(move || {
        let _ = hold2.Recv();
        goish::nil.into()
    });
    check(started, b"t5: first TryGo accepted\n");
    // Give the spawned task a beat to occupy the slot, then TryGo
    // must be rejected while it holds the only slot.
    time::Sleep(time::Millisecond * 10);
    let started = g.TryGo(|| goish::nil.into());
    check(!started, b"t5: TryGo rejected at limit\n");
    hold.Send(());
    let err = g.Wait();
    check(err == goish::nil, b"t5: Wait after drain\n");
    let started = g.TryGo(|| goish::nil.into());
    check(started, b"t5: TryGo accepted after drain\n");
    let err = g.Wait();
    check(err == goish::nil, b"t5: final Wait\n");

    let msg = b"SYNC_ERRGROUP_OK all 5 test groups passed\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
