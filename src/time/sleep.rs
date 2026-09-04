// go: file time/sleep.go decls: Sleep, Timer.Stop, Timer.Reset, NewTimer, AfterFunc, After
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
//   - Reset IS implemented for both Timer and Ticker (see the methods
//     below and examples/timer_reset_ref_smoke.rs), with one carve-out:
//     resetting an AfterFunc timer re-arms the channel, not the
//     function, because goish's AfterFunc takes `FnOnce`. Documented
//     on `Timer::Reset`.
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

    // go: sdk 1.25.5 time/sleep.go:171-177 Timer.Reset
    /// Go: "Reset changes the timer to expire after duration d. It
    /// returns true if the timer had been active, false if the timer
    /// had expired or been stopped."
    ///
    /// The return value is the SAME question Stop answers — did this
    /// call catch the timer still pending — so it is answered the same
    /// way, by the token CAS. A Reset that loses the CAS reports
    /// false and still re-arms, which is Go's behaviour: the boolean
    /// says what the timer WAS, not whether the reset took.
    ///
    /// goish re-arms by starting a fresh sleeper on the SAME channel
    /// rather than re-arming one runtime timer, because that is what
    /// this design has: the old sleeper has already been cancelled and
    /// exits without sending. The channel identity is what callers
    /// hold, and it is preserved.
    ///
    /// DIVERGENCE, on AfterFunc timers only. Go's Reset re-arms the
    /// FUNCTION; goish's re-arms only the channel, which for an
    /// AfterFunc timer is the chan nothing ever sends on — so the
    /// function does not run again. The cause is the signature:
    /// goish's AfterFunc takes `FnOnce`, which by construction cannot
    /// be called twice, and widening it to `Fn` would reject every
    /// caller whose closure moves a captured value — several in this
    /// tree do. Resetting an AfterFunc timer is therefore not
    /// supported; Stop still is.
    pub fn Reset(&mut self, d: Duration) -> bool {
        let was_active = timer_cancel(&self.token);
        let token = TimerToken::new();
        let c_inner = self.C.clone();
        let tok = token.clone();
        crate::go!(stack(64 * crate::KB), move || {
            if timer_park_cancellable(d.0, &tok) {
                let _ = c_inner.__try_send(Now());
            }
        });
        self.token = token;
        return was_active;
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
