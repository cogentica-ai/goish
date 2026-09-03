// timer_reset_ref_smoke — Timer.Reset and Ticker.Reset.
//
// Reference: Go 1.25.5 time, measured by tools/gen_timer_reset_ref.go.
// Every GO[] line is Go's verbatim output.
//
// Both methods were MISSING from the port until this commit —
// sleep.rs listed "Reset is not implemented (now possible on this
// design; not ported yet)" among its v1 limitations. This is the
// measurement that defined what to build, taken before writing any of
// it.
//
// The boolean cases pin what Reset REPORTS, which is the same question
// Stop answers: did this call catch the timer still pending. Active ->
// true, stopped -> false, already fired -> false. The value describes
// what the timer WAS, not whether the reset took effect — a reset
// always re-arms.
//
// The behavioural cases pin what Reset DOES, and they are the ones a
// plausible-looking implementation fails:
//
//   reset-extends — a pending 20ms timer reset to 400ms must NOT fire
//   at 20ms. An implementation that re-arms without cancelling the
//   original leaves both running, and the old one still fires. The
//   test waits 150ms for the wrong answer.
//
//   reset-refires — the SAME channel fires again. Callers hold C, so
//   a reset that swapped in a new channel would leave every existing
//   receiver waiting on a channel nothing sends to.
//
//   ticker-restart — Reset on a STOPPED ticker restarts it. Go has
//   done this since 1.15, and it is the case a port skips: goish's
//   tick loop is a goroutine that has already RETURNED by then, so
//   clearing a flag achieves nothing and a fresh loop has to be
//   started on the caller's existing channel.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::time;

// Go's verbatim output.
const GO: [&str; 7] = [
    "reset-active   true",
    "reset-stopped  false",
    "reset-expired  false",
    "reset-refires  true",
    "reset-extends  true",
    "ticker-reset   ticks>=3 true",
    "ticker-restart true",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            goish::string(GO[i])
        );
    }
}

const MS: i64 = 1_000_000;

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    {
        let mut tm = time::NewTimer(time::Duration(50 * MS));
        chk(fmt::Sprintf!(
            "reset-active   %v",
            tm.Reset(time::Duration(50 * MS))
        ));
        tm.Stop();
    }
    {
        let mut tm = time::NewTimer(time::Duration(50 * MS));
        tm.Stop();
        chk(fmt::Sprintf!(
            "reset-stopped  %v",
            tm.Reset(time::Duration(50 * MS))
        ));
        tm.Stop();
    }
    {
        let mut tm = time::NewTimer(time::Duration(5 * MS));
        let _ = tm.C.Recv();
        chk(fmt::Sprintf!(
            "reset-expired  %v",
            tm.Reset(time::Duration(50 * MS))
        ));
        tm.Stop();
    }
    {
        let mut tm = time::NewTimer(time::Duration(5 * MS));
        let _ = tm.C.Recv();
        tm.Reset(time::Duration(5 * MS));
        let deadline = time::After(time::Duration(2000 * MS));
        let tc = tm.C.clone();
        let fired = goish::select! {
            let _ = tc.Recv() => true,
            let _ = deadline.Recv() => false,
        };
        chk(fmt::Sprintf!("reset-refires  %v", fired));
    }
    {
        let mut tm = time::NewTimer(time::Duration(20 * MS));
        tm.Reset(time::Duration(400 * MS));
        let deadline = time::After(time::Duration(150 * MS));
        let tc = tm.C.clone();
        let extended = goish::select! {
            let _ = tc.Recv() => false,
            let _ = deadline.Recv() => true,
        };
        chk(fmt::Sprintf!("reset-extends  %v", extended));
        tm.Stop();
    }
    {
        let mut tk = time::NewTicker(time::Duration(400 * MS));
        tk.Reset(time::Duration(10 * MS));
        let mut got = 0i64;
        let deadline = time::After(time::Duration(1000 * MS));
        let kc = tk.C.clone();
        while got < 3 {
            let more = goish::select! {
                let _ = kc.Recv() => { true },
                let _ = deadline.Recv() => { false },
            };
            if !more {
                break;
            }
            got += 1;
        }
        tk.Stop();
        chk(fmt::Sprintf!("ticker-reset   ticks>=3 %v", got >= 3));
    }
    {
        let mut tk = time::NewTicker(time::Duration(10 * MS));
        tk.Stop();
        tk.Reset(time::Duration(10 * MS));
        let deadline = time::After(time::Duration(500 * MS));
        let kc = tk.C.clone();
        let ticked = goish::select! {
            let _ = kc.Recv() => true,
            let _ = deadline.Recv() => false,
        };
        chk(fmt::Sprintf!("ticker-restart %v", ticked));
        tk.Stop();
    }
    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
