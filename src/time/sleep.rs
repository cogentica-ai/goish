// go: file time/sleep.go decls: Sleep, Timer.Stop, NewTimer, AfterFunc, After
//
// sleep.go — Sleep, Timer, NewTimer, AfterFunc and After.

extern crate alloc;
#[allow(unused_imports)]
use alloc::vec::Vec;
#[allow(unused_imports)]
use core::ops::{Add, Div, Mul, Sub};

#[allow(unused_imports)]
use crate::convert::{
    byte as tobyte, int as toint, int16 as toint16, int32 as toint32, int64 as toint64,
    uint as touint, uint16 as touint16, uint32 as touint32, uint64 as touint64,
};
#[allow(unused_imports)]
use crate::fmt::{self, FmtBuf};
#[allow(unused_imports)]
use crate::gostring::string;
#[allow(unused_imports)]
use crate::syscall::{self, Timespec};
#[allow(unused_imports)]
use crate::types::int;

#[allow(unused_imports)]
use super::*;

// go: sdk 1.25.5 time/sleep.go:14-14 Sleep
///
/// Outside of any goroutine (e.g., from within `__goish_rt0`
/// before main launches goroutines), this falls back to
/// `nanosleep(2)` since there's no G to park.
pub fn Sleep(d: Duration) {
    if d.0 <= 0 {
        return;
    }
    if crate::runtime::sched::current_g().is_none() {
        // No goroutine context — fall back to thread-blocking sleep.
        let req = Timespec {
            tv_sec: d.0 / 1_000_000_000,
            tv_nsec: d.0 % 1_000_000_000,
        };
        let _ = syscall::Nanosleep(&req, core::ptr::null_mut());
        return;
    }
    crate::runtime::sysmon::timer_park(d.0);
}

// ─── Timer / Ticker / After (M18a-+) ────────────────────────────────
//
// Channel-based timers built on the runtime's cancellable timer park
// (`sysmon::timer_park_cancellable` / `timer_cancel`). Each timer is
// exactly ONE goroutine parked on the sysmon timer heap; `Stop` CASes
// the shared `TimerToken` and wakes the sleeper, which exits at once.
// Nothing outlives a Stop — this matters because goish waits for
// LIVE_G_COUNT == 0 at process exit, so the previous design (a
// Sleep(d) sleeper that Stop could not shorten) pinned exit for the
// timer's full duration.
//
// Mirror of Go's time/sleep.go: After == NewTimer(d).C; NewTimer
// returns a Timer with public C field and Stop method. Ticker
// likewise but periodic.
//
// Goish v1 limitations vs Go:
//   - Reset is not implemented (now possible on this design; not
//     ported yet).
//   - Timer's chan is buffered cap=1 (matches Go's pre-1.23
//     behavior; post-1.23 sync mode is not faithful here).
//   - AfterFunc returns a Timer with a fresh (unused) C chan, since
//     goish has no nil chan to mirror Go's nil-C convention.

use alloc::sync::Arc;
#[allow(unused_imports)]
use core::sync::atomic::{AtomicBool, Ordering};

use crate::gochan::chan;
use crate::runtime::sysmon::{timer_cancel, timer_park_cancellable, TimerToken};

/// `time.Timer` — single-fire timer that sends on `C` after a
/// duration. Mirror of `time.Timer` (sleep.go).
pub struct Timer {
    /// `<-chan Time` — receives one `Time` value when the timer
    /// fires (unless `Stop` cancelled it first).
    pub C: chan<Time>,
    /// Shared with the sleeper goroutine; `Stop` cancels through it.
    token: Arc<TimerToken>,
}

impl Timer {
    // go: sdk 1.25.5 time/sleep.go:113-118 Timer.Stop
    /// Stop prevents the Timer from firing. Returns `true` if the
    /// call stops the timer, `false` if it has already expired or
    /// been stopped. Mirrors `Timer.Stop` (sleep.go:107).
    ///
    /// Note: Stop does not close the channel. After Stop, no value
    /// will be sent on C.
    pub fn Stop(&self) -> bool {
        // The token CAS is the single source of truth: it both wakes
        // the parked sleeper (which exits immediately) and reports
        // whether cancellation beat the fire. A second Stop, or a
        // Stop after the fire, loses the CAS and returns false —
        // exactly Go's contract.
        return timer_cancel(&self.token);
    }
}

// go: sdk 1.25.5 time/sleep.go:143-148 NewTimer
/// `time.NewTimer(d)` — create a Timer that fires after `d`.
/// Mirrors `NewTimer` (sleep.go:143).
#[allow(non_snake_case)]
pub fn NewTimer(d: Duration) -> Timer {
    let c: chan<Time> = crate::make!(chan Time, 1);
    let token = TimerToken::new();
    let c_inner = c.clone();
    let tok = token.clone();
    crate::go!(stack(64 * crate::KB), move || {
        if timer_park_cancellable(d.0, &tok) {
            // Non-blocking — Go's sendTime (sleep.go:179).
            let _ = c_inner.__try_send(Now());
        }
        // Cancelled: exit at once; nothing is leaked.
    });
    return Timer { C: c, token };
}

// go: sdk 1.25.5 time/sleep.go:210-212 AfterFunc
/// `time.AfterFunc(d, f)` (sleep.go:188) — wait `d`, then run `f` in
/// its own goroutine. Returns a Timer whose `Stop` cancels the call
/// (returning `true` if cancellation beat the fire).
///
/// Slim deviation: Go documents `Timer.C` as nil for AfterFunc; goish
/// has no nil chan, so `C` is a fresh cap=1 chan that nothing ever
/// sends on. Don't read from it.
#[allow(non_snake_case)]
pub fn AfterFunc<F>(d: Duration, f: F) -> Timer
where
    F: FnOnce() + Send + 'static,
{
    // Go: c := make(chan Time, 1)  // not actually wired up; slim mirrors.
    let c: chan<Time> = crate::make!(chan Time, 1);
    let token = TimerToken::new();
    let tok = token.clone();
    crate::go!(stack(64 * crate::KB), move || {
        // Race: timer firing vs Stop — whichever wins the token CAS.
        if timer_park_cancellable(d.0, &tok) {
            // Go: `go f()` — f runs on its own goroutine.
            // Slim: run f directly on this sleeper gor — it has no
            // other work, so giving f a fresh gor would just add a
            // hop. Single-shot semantics are identical.
            f();
        }
        // Stop won — drop f, exit at once.
    });
    return Timer { C: c, token };
}

// go: sdk 1.25.5 time/sleep.go:202-204 After
/// `time.After(d)` — equivalent to `NewTimer(d).C` semantically,
/// but implemented standalone so it's the leaf of the timer-call
/// graph and can be used inside `NewTimer`/`NewTicker` watchers
/// without recursion. Mirrors `After` (sleep.go:202).
///
///   select! {
///       let v = ch.Recv()       => handle(v),
///       let _ = (After(...)).Recv() => timeout(),
///   }
#[allow(non_snake_case)]
pub fn After(d: Duration) -> chan<Time> {
    let c: chan<Time> = crate::make!(chan Time, 1);
    let c_inner = c.clone();
    crate::go!(stack(64 * crate::KB), move || {
        Sleep(d);
        let _ = c_inner.__try_send(Now());
    });
    return c;
}
