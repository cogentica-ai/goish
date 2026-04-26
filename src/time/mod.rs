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
#[derive(Clone, Copy)]
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

/// `time.Sleep(d)` — sleep for `d` nanoseconds via `nanosleep(2)`.
/// Negative or zero `d` returns immediately.
pub fn Sleep(d: Duration) {
    if d.0 <= 0 {
        return;
    }
    let req = Timespec {
        tv_sec: d.0 / 1_000_000_000,
        tv_nsec: d.0 % 1_000_000_000,
    };
    let _ = syscall::Nanosleep(&req, core::ptr::null_mut());
}

/// `time.Since(t)` — `Now().Sub(t)`. Common idiom for elapsed time.
pub fn Since(t: Time) -> Duration {
    Now().Sub(t)
}

/// `time.Until(t)` — `t.Sub(Now())`.
pub fn Until(t: Time) -> Duration {
    t.Sub(Now())
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
