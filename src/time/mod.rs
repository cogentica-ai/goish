// time — Go's `time` package, ported. M13 subset.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   start := time.Now()                  let start = time::Now();
//   time.Sleep(100 * time.Millisecond)   time::Sleep(time::Millisecond * 100);
//   elapsed := time.Since(start)         let elapsed = time::Since(start);
//   fmt.Println(elapsed)                 Println!(elapsed);
//
// v1 surface:
//
//   * Now / Sleep / Since / Until — wall + monotonic via clock_gettime.
//   * Duration — newtype around int (i64 nanoseconds), with arithmetic
//     and a Go-faithful `.String()` (uses ASCII "us" for micro instead
//     of Go's "µs", since our string formatter is ASCII-clean).
//   * Time — wall + monotonic. Comparisons use wall; Sub prefers
//     monotonic when both operands have it. No timezone (UTC only).
//   * Constants Nanosecond..Hour.
//   * Constructors Nanoseconds(n)/Microseconds(n)/Milliseconds(n)/Seconds(n).
//
// Deferred:
//   * Y/M/D accessors — Gregorian conversion (~150 LOC port).
//   * Format / Parse — ~1700 LOC of Go source.
//   * Locations / timezones — out-of-scope for v1.
//   * Tickers / Timers — depend on goroutines (M15).
//   * Truncate / Round / AddDate — small additions, defer.
//   * Float-returning Seconds/Minutes/Hours — depend on M11b floats.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use core::ops::{Add, Mul, Sub};

use crate::fmt::{self, FmtBuf};
use crate::gostring::string;
use crate::syscall::{self, Timespec};
use crate::types::int;

// ─── Duration ────────────────────────────────────────────────────────

/// `time.Duration` — int64 count of nanoseconds.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(pub int);

pub const Nanosecond: Duration = Duration(1);
pub const Microsecond: Duration = Duration(1_000);
pub const Millisecond: Duration = Duration(1_000_000);
pub const Second: Duration = Duration(1_000_000_000);
pub const Minute: Duration = Duration(60 * 1_000_000_000);
pub const Hour: Duration = Duration(60 * 60 * 1_000_000_000);

impl Duration {
    pub fn Nanoseconds(self) -> int {
        self.0
    }
    pub fn Microseconds(self) -> int {
        self.0 / 1_000
    }
    pub fn Milliseconds(self) -> int {
        self.0 / 1_000_000
    }
    /// Go-faithful "1h2m3.456s" / "100ms" / "1.2us" / "5ns" / "0s" form.
    pub fn String(self) -> string {
        format_duration(self.0)
    }
}

impl Mul<int> for Duration {
    type Output = Duration;
    fn mul(self, rhs: int) -> Duration {
        Duration(self.0.wrapping_mul(rhs))
    }
}

impl Add<Duration> for Duration {
    type Output = Duration;
    fn add(self, rhs: Duration) -> Duration {
        Duration(self.0.wrapping_add(rhs.0))
    }
}

impl Sub<Duration> for Duration {
    type Output = Duration;
    fn sub(self, rhs: Duration) -> Duration {
        Duration(self.0.wrapping_sub(rhs.0))
    }
}

// Make Duration printable via fmt's %v / %s / Println!.
impl fmt::Format for Duration {
    fn fmt(&self, verb: u8, buf: &mut FmtBuf) {
        let s = self.String();
        match verb {
            b's' | b'v' => {
                buf.extend(s.as_bytes());
            }
            _ => {
                // Fallback: print as a plain string for unknown verbs.
                buf.extend(s.as_bytes());
            }
        }
    }
}

/// Construct a `Duration` of `n` nanoseconds.
pub fn Nanoseconds(n: int) -> Duration {
    Duration(n)
}
pub fn Microseconds(n: int) -> Duration {
    Duration(n.wrapping_mul(1_000))
}
pub fn Milliseconds(n: int) -> Duration {
    Duration(n.wrapping_mul(1_000_000))
}
pub fn Seconds(n: int) -> Duration {
    Duration(n.wrapping_mul(1_000_000_000))
}

// ─── Time ─────────────────────────────────────────────────────────────

/// `time.Time` — wall (Unix sec + nsec) + optional monotonic clock.
///
/// `mono == 0` means "no monotonic component" (e.g., constructed via
/// `time::Unix(...)`); `Now()` always sets it. `Sub` prefers monotonic
/// when both sides have it.
#[derive(Clone, Copy, Default)]
pub struct Time {
    sec: int,
    nsec: i32,
    mono: int, // 0 = absent
}

impl Time {
    pub fn IsZero(self) -> bool {
        self.sec == 0 && self.nsec == 0
    }
    pub fn Unix(self) -> int {
        self.sec
    }
    pub fn UnixMilli(self) -> int {
        self.sec
            .wrapping_mul(1_000)
            .wrapping_add((self.nsec as int) / 1_000_000)
    }
    pub fn UnixMicro(self) -> int {
        self.sec
            .wrapping_mul(1_000_000)
            .wrapping_add((self.nsec as int) / 1_000)
    }
    pub fn UnixNano(self) -> int {
        self.sec.wrapping_mul(1_000_000_000).wrapping_add(self.nsec as int)
    }
    pub fn After(self, u: Time) -> bool {
        self.sec > u.sec || (self.sec == u.sec && self.nsec > u.nsec)
    }
    pub fn Before(self, u: Time) -> bool {
        self.sec < u.sec || (self.sec == u.sec && self.nsec < u.nsec)
    }
    pub fn Equal(self, u: Time) -> bool {
        self.sec == u.sec && self.nsec == u.nsec
    }
    pub fn Sub(self, u: Time) -> Duration {
        // Prefer monotonic when both have it.
        if self.mono != 0 && u.mono != 0 {
            return Duration(self.mono.wrapping_sub(u.mono));
        }
        let sec_diff = self.sec.wrapping_sub(u.sec);
        let nsec_diff = (self.nsec as int).wrapping_sub(u.nsec as int);
        Duration(sec_diff.wrapping_mul(1_000_000_000).wrapping_add(nsec_diff))
    }
    pub fn Add(self, d: Duration) -> Time {
        let total_nsec = (self.nsec as int).wrapping_add(d.0);
        let extra_sec = total_nsec.div_euclid(1_000_000_000);
        let new_nsec = total_nsec.rem_euclid(1_000_000_000) as i32;
        let new_sec = self.sec.wrapping_add(extra_sec);
        let new_mono = if self.mono != 0 {
            self.mono.wrapping_add(d.0)
        } else {
            0
        };
        Time {
            sec: new_sec,
            nsec: new_nsec,
            mono: new_mono,
        }
    }

    // ─── Y/M/D + clock accessors (UTC only, v1) ───────────────────────
    //
    // Backed by the Howard Hinnant "civil from days" algorithm — same
    // numeric output as Go's table-based approach, ~20 LOC instead of
    // ~150. Output verified against `date -u -d @<unix>` on the test
    // corpus.

    /// `t.Date()` — `(year, month, day)`. Month is 1..=12.
    pub fn Date(self) -> (int, int, int) {
        let (y, m, d, _, _, _) = civil_from_unix(self.sec);
        (y, m, d)
    }

    pub fn Year(self) -> int {
        self.Date().0
    }
    /// 1=January .. 12=December.
    pub fn Month(self) -> int {
        self.Date().1
    }
    pub fn Day(self) -> int {
        self.Date().2
    }

    /// `t.Clock()` — `(hour, minute, second)` within the day, UTC.
    pub fn Clock(self) -> (int, int, int) {
        let (_, _, _, hh, mm, ss) = civil_from_unix(self.sec);
        (hh, mm, ss)
    }
    pub fn Hour(self) -> int {
        self.Clock().0
    }
    pub fn Minute(self) -> int {
        self.Clock().1
    }
    pub fn Second(self) -> int {
        self.Clock().2
    }

    pub fn Nanosecond(self) -> int {
        self.nsec as int
    }

    /// `t.Weekday()` — 0=Sunday .. 6=Saturday (Go convention).
    pub fn Weekday(self) -> int {
        let days = self.sec.div_euclid(86_400);
        // 1970-01-01 was a Thursday (=4 in Sun..Sat = 0..6).
        ((days + 4).rem_euclid(7)) as int
    }
}

// Civil date from Unix seconds. Returns (year, month, day, hour, min, sec)
// — all UTC. Howard Hinnant's algorithm. Public domain.
fn civil_from_unix(sec: int) -> (int, int, int, int, int, int) {
    let days = sec.div_euclid(86_400);
    let secs = sec.rem_euclid(86_400);
    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;

    // Convert Unix day (epoch 1970-01-01) to "civil" day (epoch 0000-03-01).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146_096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, hh, mm, ss)
}

// ─── Free functions ──────────────────────────────────────────────────

/// `time.Now()` — current wall clock + monotonic reading.
pub fn Now() -> Time {
    let mut wall = Timespec::default();
    let mut mono = Timespec::default();
    let _ = syscall::ClockGettime(syscall::CLOCK_REALTIME, &mut wall);
    let _ = syscall::ClockGettime(syscall::CLOCK_MONOTONIC, &mut mono);
    let mono_ns = mono
        .tv_sec
        .wrapping_mul(1_000_000_000)
        .wrapping_add(mono.tv_nsec);
    // mono == 0 is the "absent" sentinel; bump to 1 in the unlikely
    // case that monotonic time read exactly zero (kernel boot in some
    // virtualization scenarios).
    let mono_safe = if mono_ns == 0 { 1 } else { mono_ns };
    Time {
        sec: wall.tv_sec,
        nsec: wall.tv_nsec as i32,
        mono: mono_safe,
    }
}

/// `time.Sleep(d)` — pause the current goroutine for at least `d`.
/// Negative or zero `d` returns immediately. Mirrors `time.Sleep`
/// (sleep.go:14).
///
/// Implementation (M18a): pushes a (deadline, current G) entry on
/// the runtime's timer heap and `gopark`s until sysmon wakes it.
/// This releases the M to run other goroutines — unlike a raw
/// `nanosleep(2)` which would block the OS thread.
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

/// `time.Since(t)` — `Now().Sub(t)`. Common idiom for elapsed time.
pub fn Since(t: Time) -> Duration {
    Now().Sub(t)
}

/// `time.Until(t)` — `t.Sub(Now())`.
pub fn Until(t: Time) -> Duration {
    t.Sub(Now())
}

// ─── Timer / Ticker / After (M18a-+) ────────────────────────────────
//
// Channel-based timers built on `Sleep`. Each timer owns a goroutine
// that sleeps the deadline then non-blocking-sends on the chan. Stop
// is an atomic cancel flag checked just before the send.
//
// Mirror of Go's time/sleep.go: After == NewTimer(d).C; NewTimer
// returns a Timer with public C field and Stop method. Ticker
// likewise but periodic.
//
// Goish v1 limitations vs Go:
//   - Reset is not implemented (would need to wake the sleeper).
//   - Timer's chan is buffered cap=1 (matches Go's pre-1.23
//     behavior; post-1.23 sync mode is not faithful here).
//   - AfterFunc is not implemented (use `go!()` with Sleep instead).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::gochan::chan;

/// `time.Timer` — single-fire timer that sends on `C` after a
/// duration. Mirror of `time.Timer` (sleep.go).
pub struct Timer {
    /// `<-chan Time` — receives one `Time` value when the timer
    /// fires (unless `Stop` cancelled it first).
    pub C: chan<Time>,
    cancel: Arc<AtomicBool>,
}

impl Timer {
    /// Stop prevents the Timer from firing. Returns `true` if the
    /// call stops the timer, `false` if it has already expired or
    /// been stopped. Mirrors `Timer.Stop` (sleep.go:107).
    ///
    /// Note: Stop does not close the channel. After Stop, no value
    /// will be sent on C.
    pub fn Stop(&self) -> bool {
        // swap returns OLD value. If old was false (timer was
        // active), we successfully cancelled — return true.
        !self.cancel.swap(true, Ordering::AcqRel)
    }
}

/// `time.NewTimer(d)` — create a Timer that fires after `d`.
/// Mirrors `NewTimer` (sleep.go:143).
#[allow(non_snake_case)]
pub fn NewTimer(d: Duration) -> Timer {
    let c: chan<Time> = crate::make!(chan Time, 1);
    let cancel = Arc::new(AtomicBool::new(false));
    let c_inner = c.clone();
    let cancel_inner = cancel.clone();
    crate::go!(move || {
        Sleep(d);
        if cancel_inner.load(Ordering::Acquire) {
            return;
        }
        // Non-blocking send: matches Go's sendTime
        // (sleep.go:179) which uses select+default to avoid
        // blocking when the chan buffer is full.
        crate::select! {
            c_inner.Send(Now()) => {},
            default => {},
        }
    });
    Timer { C: c, cancel }
}

/// `time.After(d)` — equivalent to `NewTimer(d).C`. Mirrors
/// `After` (sleep.go:202). Useful for timeouts in `select!`:
///
///   select! {
///       let v = ch.Recv()       => handle(v),
///       let _ = (After(...)).Recv() => timeout(),
///   }
#[allow(non_snake_case)]
pub fn After(d: Duration) -> chan<Time> {
    NewTimer(d).C
}

/// `time.Ticker` — periodic timer. Mirrors `time.Ticker`.
pub struct Ticker {
    /// `<-chan Time` — receives a `Time` value approximately every
    /// `d` duration.
    pub C: chan<Time>,
    cancel: Arc<AtomicBool>,
}

impl Ticker {
    /// Stop turns off a ticker. After Stop, no more ticks will
    /// be sent on C. Stop does not close the channel.
    pub fn Stop(&self) {
        self.cancel.store(true, Ordering::Release);
    }
}

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
    let cancel = Arc::new(AtomicBool::new(false));
    let c_inner = c.clone();
    let cancel_inner = cancel.clone();
    crate::go!(move || {
        loop {
            Sleep(d);
            if cancel_inner.load(Ordering::Acquire) {
                return;
            }
            crate::select! {
                c_inner.Send(Now()) => {},
                default => {},
            }
        }
    });
    Ticker { C: c, cancel }
}

/// `time.Unix(sec, nsec)` — construct a Time from a Unix timestamp.
/// No monotonic component (will use wall arithmetic in `Sub`).
pub fn Unix(sec: int, nsec: int) -> Time {
    let extra_sec = nsec.div_euclid(1_000_000_000);
    let final_nsec = nsec.rem_euclid(1_000_000_000) as i32;
    Time {
        sec: sec.wrapping_add(extra_sec),
        nsec: final_nsec,
        mono: 0,
    }
}

// ─── Duration formatting (Go-faithful, ASCII "us") ────────────────────

fn format_duration(d: int) -> string {
    // Largest representable Time in i64 nanoseconds → ~292 years; fits in 32 bytes.
    let mut buf = [0u8; 32];
    let mut w = buf.len();

    let neg = d < 0;
    let mut u: u64 = if neg {
        (d as i64).wrapping_neg() as u64
    } else {
        d as u64
    };

    if u < Second.0 as u64 {
        // Sub-second: "0s", "Nns", "N.Nus", or "N.Nms". Each branch
        // emits its own suffix; we don't pre-place 's' (otherwise the
        // 'us' case would double-write it).
        if u == 0 {
            w -= 2;
            buf[w] = b'0';
            buf[w + 1] = b's';
        } else if u < Microsecond.0 as u64 {
            // ns
            w -= 1;
            buf[w] = b's';
            w -= 1;
            buf[w] = b'n';
            let (nw, nu) = fmt_frac(&mut buf[..w], u, 0);
            w = nw;
            w = fmt_int(&mut buf[..w], nu);
        } else if u < Millisecond.0 as u64 {
            // us (ASCII; Go uses "µs" — see module docs)
            w -= 1;
            buf[w] = b's';
            w -= 1;
            buf[w] = b'u';
            let (nw, nu) = fmt_frac(&mut buf[..w], u, 3);
            w = nw;
            w = fmt_int(&mut buf[..w], nu);
        } else {
            // ms
            w -= 1;
            buf[w] = b's';
            w -= 1;
            buf[w] = b'm';
            let (nw, nu) = fmt_frac(&mut buf[..w], u, 6);
            w = nw;
            w = fmt_int(&mut buf[..w], nu);
        }
    } else {
        // ≥ 1s: "[Nh][Nm]N.NNNNNNNNNs", omit leading zero units.
        w -= 1;
        buf[w] = b's';
        let (nw, nu) = fmt_frac(&mut buf[..w], u, 9);
        w = nw;
        u = nu;
        // u is now integer seconds
        w = fmt_int(&mut buf[..w], u % 60);
        u /= 60;
        if u > 0 {
            w -= 1;
            buf[w] = b'm';
            w = fmt_int(&mut buf[..w], u % 60);
            u /= 60;
            if u > 0 {
                w -= 1;
                buf[w] = b'h';
                w = fmt_int(&mut buf[..w], u);
            }
        }
    }

    if neg {
        w -= 1;
        buf[w] = b'-';
    }

    let mut v: Vec<u8> = Vec::with_capacity(buf.len() - w);
    v.extend_from_slice(&buf[w..]);
    string::__from_vec(v)
}

/// Format `v / 10^prec` as ".XXX" into the tail of `buf`, omitting
/// trailing zeros (and the decimal point if all-zero). Returns the new
/// write index and `v / 10^prec`.
fn fmt_frac(buf: &mut [u8], mut v: u64, prec: i32) -> (usize, u64) {
    let mut w = buf.len();
    let mut printing = false;
    for _ in 0..prec {
        let digit = v % 10;
        printing = printing || digit != 0;
        if printing {
            w -= 1;
            buf[w] = b'0' + digit as u8;
        }
        v /= 10;
    }
    if printing {
        w -= 1;
        buf[w] = b'.';
    }
    (w, v)
}

/// Format `v` as a decimal integer into the tail of `buf`. Always emits
/// at least one digit (`'0'`). Returns the new write index.
fn fmt_int(buf: &mut [u8], mut v: u64) -> usize {
    let mut w = buf.len();
    if v == 0 {
        w -= 1;
        buf[w] = b'0';
    } else {
        while v > 0 {
            w -= 1;
            buf[w] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    w
}
