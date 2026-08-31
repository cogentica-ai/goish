// go: file time/tick.go decls: Ticker.Stop, Tick, NewTicker
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
    let c_inner = c.clone();
    let tok = token.clone();
    let stop_flag = stopped.clone();
    crate::go!(stack(64 * crate::KB), move || {
        loop {
            if stop_flag.load(Ordering::Acquire) {
                return;
            }
            if !timer_park_cancellable(d.0, &tok) {
                // Stop cancelled the in-flight park.
                return;
            }
            // The fire won the CAS, but Stop may have landed just
            // after losing it — honour the flag before ticking.
            if stop_flag.load(Ordering::Acquire) {
                return;
            }
            let _ = c_inner.__try_send(Now());
            // Re-arm for the next round. Owner-only, no park in
            // flight here; a Stop racing this is caught by the flag
            // check at the top (its cancel either loses to nothing
            // or pre-cancels the next park).
            tok.rearm();
        }
    });
    return Ticker {
        C: c,
        stopped,
        token,
    };
}
