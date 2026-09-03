// go: file time/tick.go decls: Ticker.Stop, Ticker.Reset, Tick, NewTicker
//
// tick.go — Ticker, NewTicker and Tick.

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
use alloc::sync::Arc;
#[allow(unused_imports)]
use core::sync::atomic::{AtomicBool, Ordering};

#[allow(unused_imports)]
use crate::gochan::chan;
#[allow(unused_imports)]
use crate::runtime::sysmon::{timer_cancel, timer_park_cancellable, TimerToken};

#[allow(unused_imports)]
use super::*;

/// `time.Ticker` — periodic timer. Mirrors `time.Ticker`.
pub struct Ticker {
    /// `<-chan Time` — receives a `Time` value approximately every
    /// `d` duration.
    pub C: chan<Time>,
    /// Loop-exit flag: the tick loop re-checks it after every wake.
    /// Needed alongside the token because the token is re-armed each
    /// round — a Stop that lands in the FIRED→rearm gap loses its
    /// CAS, and this flag is what still ends the loop.
    stopped: Arc<AtomicBool>,
    /// Shared with the tick loop; `Stop` cancels the in-flight park.
    token: Arc<TimerToken>,
    /// Shared with the tick loop, in nanoseconds, so `Reset` can
    /// change the period of a loop that is already running. Go keeps
    /// the period in the runtime timer it re-arms; goish's loop owns
    /// its own park, so the period has to be reachable from outside
    /// it.
    period: Arc<core::sync::atomic::AtomicI64>,
}

impl Ticker {
    // go: sdk 1.25.5 time/tick.go:52-60 Ticker.Stop
    /// Stop turns off a ticker. After Stop, no more ticks will
    /// be sent on C. Stop does not close the channel.
    pub fn Stop(&self) {
        // Order matters: the flag must be visible BEFORE the wake, so
        // a sleeper that wins the fire-CAS anyway still sees `stopped`
        // on its post-wake check and exits.
        self.stopped.store(true, Ordering::Release);
        let _ = timer_cancel(&self.token);
    }

    // go: sdk 1.25.5 time/tick.go:62-79 Ticker.Reset
    /// Go: "Reset stops a ticker and resets its period to the
    /// specified duration. The next tick will arrive after the new
    /// period elapses. The duration d must be greater than zero; if
    /// not, Reset will panic."
    ///
    /// Two cases, and the second is the one that is easy to miss.
    ///
    /// A RUNNING ticker: the period is published and the in-flight
    /// park is cancelled, so the loop wakes at once and re-parks on
    /// the new duration. The loop tells this cancel from a Stop by
    /// re-reading `stopped` — a Stop always sets that flag before it
    /// cancels, so a cancel with the flag clear can only be a Reset.
    ///
    /// A STOPPED ticker: Go RESTARTS it (this has been true since
    /// 1.15), and goish must too — the old loop goroutine has already
    /// returned, so there is nothing left to wake. Clearing the flag
    /// alone would not do it; a fresh token and a fresh loop are
    /// required, sending on the SAME channel the caller already holds.
    pub fn Reset(&mut self, d: Duration) {
        if d.0 <= 0 {
            // Go panics; we abort, as NewTicker does.
            const MSG: &[u8] = b"goish: time: non-positive interval for Ticker.Reset\n";
            syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
            syscall::Exit(2);
        }
        self.period.store(d.0, Ordering::Release);
        if self.stopped.load(Ordering::Acquire) {
            self.stopped.store(false, Ordering::Release);
            self.token = TimerToken::new();
            spawn_tick_loop(
                self.C.clone(),
                self.token.clone(),
                self.stopped.clone(),
                self.period.clone(),
            );
            return;
        }
        // Running: wake the park so the new period takes effect now
        // rather than after the old one elapses.
        let _ = timer_cancel(&self.token);
    }
}

// go: none — goish-only: Go re-arms one runtime timer; goish's ticker
// is a parked goroutine, so both NewTicker and a Reset that restarts a
// stopped ticker need to start one, and they must start the SAME loop.
fn spawn_tick_loop(
    c: chan<Time>,
    tok: Arc<TimerToken>,
    stop_flag: Arc<AtomicBool>,
    period: Arc<core::sync::atomic::AtomicI64>,
) {
    crate::go!(stack(64 * crate::KB), move || {
        loop {
            if stop_flag.load(Ordering::Acquire) {
                return;
            }
            if !timer_park_cancellable(period.load(Ordering::Acquire), &tok) {
                // The park was cancelled. Stop sets `stopped` BEFORE
                // it cancels, so a clear flag here means the cancel
                // came from Reset: re-arm and park again, picking up
                // the period it just published.
                if stop_flag.load(Ordering::Acquire) {
                    return;
                }
                tok.rearm();
                continue;
            }
            // The fire won the CAS, but Stop may have landed just
            // after losing it — honour the flag before ticking.
            if stop_flag.load(Ordering::Acquire) {
                return;
            }
            let _ = c.__try_send(Now());
            // Re-arm for the next round. Owner-only, no park in
            // flight here; a Stop racing this is caught by the flag
            // check at the top (its cancel either loses to nothing
            // or pre-cancels the next park).
            tok.rearm();
        }
    });
}

// go: sdk 1.25.5 time/tick.go:86-91 Tick
/// `time.Tick(d)` (tick.go:86) — convenience wrapper that returns a
/// channel which delivers ticks every `d`. Equivalent to
/// `NewTicker(d).C`.
///
/// Slim deviation: Go returns a typed-nil `<-chan Time` when `d <= 0`,
/// causing receives to block forever (Go's nil-channel semantics).
/// Goish channels have no nil representation, so we instead return an
/// unbuffered `chan<Time>` with no producer — receives on it block
/// indefinitely, matching the observable behavior of Go's nil-channel
/// case for the common usage pattern `for now := range time.Tick(d)`.
#[allow(non_snake_case)]
pub fn Tick(d: Duration) -> chan<Time> {
    // Go: if d <= 0 { return nil }
    if d.0 <= 0 {
        // No producer goroutine; receives block forever — closest
        // possible match to Go's nil-channel semantics.
        return crate::make!(chan Time, 0);
    }
    // Go: return NewTicker(d).C
    return NewTicker(d).C;
}

// go: sdk 1.25.5 time/tick.go:36-47 NewTicker
/// `time.NewTicker(d)` — fires roughly every `d`. Mirrors
/// `NewTicker`.
#[allow(non_snake_case)]
pub fn NewTicker(d: Duration) -> Ticker {
    if d.0 <= 0 {
        // Go panics; we abort.
        const MSG: &[u8] = b"goish: time: non-positive interval for NewTicker\n";
        syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
        syscall::Exit(2);
    }
    let c: chan<Time> = crate::make!(chan Time, 1);
    let token = TimerToken::new();
    let stopped = Arc::new(AtomicBool::new(false));
    let period = Arc::new(core::sync::atomic::AtomicI64::new(d.0));
    spawn_tick_loop(c.clone(), token.clone(), stopped.clone(), period.clone());
    return Ticker {
        C: c,
        stopped,
        token,
        period,
    };
}
