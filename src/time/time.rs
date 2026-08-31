// go: file time/time.go decls: subMono, Month.String, Weekday.String, Duration.Nanoseconds, Duration.Microseconds, Duration.Milliseconds, Duration.Seconds, Duration.Minutes, Duration.Hours, Duration.Truncate, Duration.Round, Duration.Abs, Duration.String, fmtFrac, fmtInt, lessThanHalf, div, Time.IsZero, Time.Unix, Time.UnixMilli, Time.UnixMicro, Time.UnixNano, Time.After, Time.Before, Time.Equal, Time.Compare, Time.Sub, Time.Add, Time.Date, Time.Year, Time.Month, Time.Day, Time.Clock, Time.Hour, Time.Minute, Time.Second, Time.Nanosecond, Time.Weekday, Time.YearDay, Time.ISOWeek, Time.AddDate, Time.UTC, Time.Local, Time.Truncate, Time.Round, Time.Zone, Time.IsDST, Time.MarshalText, Time.UnmarshalText, Time.MarshalJSON, Time.UnmarshalJSON, Time.AppendBinary, Time.MarshalBinary, Time.UnmarshalBinary, Time.GobEncode, Time.GobDecode, Now, Since, Until, Unix, UnixMilli, UnixMicro, Date
//
// time.go — Time and Duration themselves, Month and Weekday, the
// constructors (Now, Unix, Date) and the calendar arithmetic they all
// stand on.

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
use super::format::{DAY_LONG, MONTH_LONG};
#[allow(unused_imports)]
use super::*;

// ─── Duration ────────────────────────────────────────────────────────

/// `time.Duration` — int64 count of nanoseconds.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(pub int);

// go: sdk 1.25.5 time/time.go:913-916 minDuration
/// Go: `minDuration Duration = -1 << 63` — the value `Sub` saturates to
/// when the gap is negative and does not fit.
pub const minDuration: Duration = Duration(int::MIN);

// go: sdk 1.25.5 time/time.go:913-916 maxDuration
/// Go: `maxDuration Duration = 1<<63 - 1` — the positive saturation.
pub const maxDuration: Duration = Duration(int::MAX);

// go: sdk 1.25.5 time/time.go:1210-1219 subMono
/// The monotonic-clock arm of [`Time::Sub`], with the same saturation.
fn subMono(t: int, u: int) -> Duration {
    let d = Duration(t.wrapping_sub(u));
    if d.0 < 0 && t > u {
        return maxDuration;
    }
    if d.0 > 0 && t < u {
        return minDuration;
    }
    return d;
}

pub const Nanosecond: Duration = Duration(1);
pub const Microsecond: Duration = Duration(1_000);
pub const Millisecond: Duration = Duration(1_000_000);
pub const Second: Duration = Duration(1_000_000_000);
pub const Minute: Duration = Duration(60 * 1_000_000_000);
pub const Hour: Duration = Duration(60 * 60 * 1_000_000_000);

// ─── Month + Weekday (time/time.go:319-368) ──────────────────────────
//
// Line-by-line port of Go's `Month` and `Weekday` typed enums.
//
// Slim deviations:
//   * Go `type Month int` — Goish `pub struct Month(int)`. Rust has
//     no native typed-int alias; the wrapper is the closest analogue.
//   * `m.String()` for an out-of-range Month renders
//     "%!Month(N)" exactly like Go (time.go:343).
//   * Cross-type comparison (`m == 5`) is enabled via PartialEq<int>
//     to mirror Go's untyped-const promotion. Use `.Int()` for the
//     underlying number when an explicit `i64` is needed.

// Go: time.go:320  type Month int
//     time.go:319  // A Month specifies a month of the year (January = 1, ...).
/// `time.Month` — typed month-of-year (1=January .. 12=December).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Month(int);

// Go: time.go:322-335
//     const ( January Month = 1 + iota; ... December )
pub const January: Month = Month(1);
pub const February: Month = Month(2);
pub const March: Month = Month(3);
pub const April: Month = Month(4);
pub const May: Month = Month(5);
pub const June: Month = Month(6);
pub const July: Month = Month(7);
pub const August: Month = Month(8);
pub const September: Month = Month(9);
pub const October: Month = Month(10);
pub const November: Month = Month(11);
pub const December: Month = Month(12);

impl Month {
    // go: none — goish idiom: Go's `Month` is a defined type over
    //     `int`, so `Month(5)` is already a conversion; goish's is a
    //     newtype struct. `new` and `Int` are that conversion, both
    //     ways.
    /// Construct a Month from a raw 1..=12 value. No bounds check;
    /// out-of-range values render via `String()` as `%!Month(N)`.
    pub const fn new(v: int) -> Self {
        return Month(v);
    }

    // go: none — goish idiom: see the note on `Month::new`.
    /// The underlying month number, 1=January .. 12=December.
    pub const fn Int(self) -> int {
        return self.0;
    }

    // go: sdk 1.25.5 time/time.go:338-345 Month.String
    // Go: time.go:338  func (m Month) String() string
    /// English name ("January" .. "December"). Out-of-range values
    /// render as "%!Month(N)".
    pub fn String(self) -> string {
        if self.0 >= 1 && self.0 <= 12 {
            return string::from_static(MONTH_LONG[self.0 as usize - 1]);
        }
        // Go: "%!Month(" + fmtInt(buf, uint64(m)) + ")"
        return crate::Sprintf!("%%!Month(%d)", self.0);
    }
}

// Go: time.go:347  type Weekday int
/// `time.Weekday` — typed day-of-week (0=Sunday .. 6=Saturday).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Weekday(int);

// Go: time.go:350-358
//     const ( Sunday Weekday = iota; ... Saturday )
pub const Sunday: Weekday = Weekday(0);
pub const Monday: Weekday = Weekday(1);
pub const Tuesday: Weekday = Weekday(2);
pub const Wednesday: Weekday = Weekday(3);
pub const Thursday: Weekday = Weekday(4);
pub const Friday: Weekday = Weekday(5);
pub const Saturday: Weekday = Weekday(6);

impl Weekday {
    // go: none — goish idiom: see the note on `Month::new`.
    /// Construct a Weekday from a raw 0..=6 value.
    pub const fn new(v: int) -> Self {
        return Weekday(v);
    }

    // go: none — goish idiom: see the note on `Month::new`.
    /// The underlying day-of-week number, 0=Sunday .. 6=Saturday.
    pub const fn Int(self) -> int {
        return self.0;
    }

    // go: sdk 1.25.5 time/time.go:361-368 Weekday.String
    // Go: time.go:361  func (d Weekday) String() string
    /// English name ("Sunday" .. "Saturday"). Out-of-range values
    /// render as "%!Weekday(N)".
    pub fn String(self) -> string {
        if self.0 >= 0 && self.0 <= 6 {
            return string::from_static(DAY_LONG[self.0 as usize]);
        }
        return crate::Sprintf!("%%!Weekday(%d)", self.0);
    }
}

// go: none — goish idiom: Go compares a `Month` to an untyped
//     constant directly; goish's newtype needs the cross-type
//     `PartialEq` impls to keep `m == 5` working.
// Cross-type equality with `int` to mirror Go's untyped-const
// promotion. Without these, callers would need `m == time::January`
// instead of `m == 1`. Both work; the int form keeps existing code
// portable.
impl PartialEq<int> for Month {
    // go: none — goish idiom: Go compares a `Month` to an untyped
    //     constant directly; goish's newtype needs a cross-type `PartialEq`
    //     to keep `m == 5` working.
    fn eq(&self, other: &int) -> bool {
        return self.0 == *other;
    }
}
// go: none — goish idiom: see the note on `PartialEq<int> for Month`.
impl PartialEq<Month> for int {
    // go: none — goish idiom: see the note on `PartialEq<int> for Month`.
    fn eq(&self, other: &Month) -> bool {
        return *self == other.0;
    }
}
// go: none — goish idiom: see the note on `PartialEq<int> for Month`.
impl PartialEq<int> for Weekday {
    // go: none — goish idiom: see the note on `PartialEq<int> for Month`.
    fn eq(&self, other: &int) -> bool {
        return self.0 == *other;
    }
}
// go: none — goish idiom: see the note on `PartialEq<int> for Month`.
impl PartialEq<Weekday> for int {
    // go: none — goish idiom: see the note on `PartialEq<int> for Month`.
    fn eq(&self, other: &Weekday) -> bool {
        return *self == other.0;
    }
}

// go: none — goish idiom: Go's Month/Weekday satisfy `Stringer` and
//     the printer finds them through the interface. goish's fmt
//     dispatches on a trait, so the bridge is written out.
// fmt::Format impls — `%d`/`%b`/`%o`/`%x` print the underlying int;
// any other verb (`%s`, `%v`, default) prints the English name.
// Mirrors Go: Month/Weekday implement Stringer, and the printer
// dispatches numeric verbs to the underlying int.
impl crate::fmt::Format for Month {
    // go: none — goish idiom: Go's Month satisfies `Stringer` and the
    //     printer finds it through the interface; goish's fmt dispatches on
    //     a trait, so the bridge is written out.
    fn fmt(&self, verb: crate::types::byte, f: &mut crate::fmt::FmtBuf) {
        match verb {
            b'd' | b'b' | b'o' | b'x' | b'X' | b'c' | b'U' => self.0.fmt(verb, f),
            _ => f.extend(self.String().as_bytes()),
        }
    }
}
// go: none — goish idiom: see the note on `Format for Month`.
impl crate::fmt::Format for Weekday {
    // go: none — goish idiom: see the note on `Format for Month`.
    fn fmt(&self, verb: crate::types::byte, f: &mut crate::fmt::FmtBuf) {
        match verb {
            b'd' | b'b' | b'o' | b'x' | b'X' | b'c' | b'U' => self.0.fmt(verb, f),
            _ => f.extend(self.String().as_bytes()),
        }
    }
}

impl Duration {
    // go: sdk 1.25.5 time/time.go:1068-1068 Duration.Nanoseconds
    pub fn Nanoseconds(self) -> int {
        return self.0;
    }
    // go: sdk 1.25.5 time/time.go:1071-1071 Duration.Microseconds
    pub fn Microseconds(self) -> int {
        return self.0 / 1_000;
    }
    // go: sdk 1.25.5 time/time.go:1074-1074 Duration.Milliseconds
    pub fn Milliseconds(self) -> int {
        return self.0 / 1_000_000;
    }
    // go: sdk 1.25.5 time/time.go:1086-1090 Duration.Seconds
    /// `(d Duration).Seconds() float64` — Go time/time.go:1086.
    pub fn Seconds(self) -> f64 {
        let sec = self.0 / Second.0;
        let nsec = self.0 % Second.0;
        return (sec as f64) + (nsec as f64) / 1e9;
    }
    // go: sdk 1.25.5 time/time.go:1093-1097 Duration.Minutes
    /// `(d Duration).Minutes() float64` — Go time/time.go:1093.
    pub fn Minutes(self) -> f64 {
        let min = self.0 / Minute.0;
        let nsec = self.0 % Minute.0;
        return (min as f64) + (nsec as f64) / (60.0 * 1e9);
    }
    // go: sdk 1.25.5 time/time.go:1100-1104 Duration.Hours
    /// `(d Duration).Hours() float64` — Go time/time.go:1100.
    pub fn Hours(self) -> f64 {
        let hour = self.0 / Hour.0;
        let nsec = self.0 % Hour.0;
        return (hour as f64) + (nsec as f64) / (60.0 * 60.0 * 1e9);
    }
    // go: sdk 1.25.5 time/time.go:1108-1113 Duration.Truncate
    /// `(d Duration).Truncate(m Duration) Duration` — Go time/time.go:1108.
    /// Rounds toward zero to a multiple of `m`. m ≤ 0 returns d unchanged.
    pub fn Truncate(self, m: Duration) -> Duration {
        if m.0 <= 0 {
            return self;
        }
        return Duration(self.0 - self.0 % m.0);
    }
    // go: sdk 1.25.5 time/time.go:1127-1149 Duration.Round
    /// `(d Duration).Round(m Duration) Duration` — Go time/time.go:1127.
    /// Rounds to the nearest multiple of `m`; halfway rounds away from
    /// zero. Saturates at min/max Duration on overflow. m ≤ 0 returns
    /// d unchanged.
    pub fn Round(self, m: Duration) -> Duration {
        if m.0 <= 0 {
            return self;
        }
        let mut r = self.0 % m.0;
        if self.0 < 0 {
            r = -r;
            if less_than_half(r, m.0) {
                return Duration(self.0 + r);
            }
            let d1 = self.0.wrapping_sub(m.0).wrapping_add(r);
            if d1 < self.0 {
                return Duration(d1);
            }
            return Duration(int::MIN); // overflow → minDuration
        }
        if less_than_half(r, m.0) {
            return Duration(self.0 - r);
        }
        let d1 = self.0.wrapping_add(m.0).wrapping_sub(r);
        if d1 > self.0 {
            return Duration(d1);
        }
        return Duration(int::MAX); // overflow → maxDuration;
    }
    // go: sdk 1.25.5 time/time.go:1154-1163 Duration.Abs
    /// `(d Duration).Abs() Duration` — Go time/time.go:1154. As a
    /// special case, Duration(MinInt64) is converted to Duration(MaxInt64).
    pub fn Abs(self) -> Duration {
        return if self.0 >= 0 {
            self
        } else if self.0 == int::MIN {
            Duration(int::MAX)
        } else {
            Duration(-self.0)
        };
    }
    // go: sdk 1.25.5 time/time.go:943-949 Duration.String
    /// Go-faithful "1h2m3.456s" / "100ms" / "1.2us" / "5ns" / "0s" form.
    pub fn String(self) -> string {
        return format_duration(self.0);
    }
}

// ─── Duration formatting ──────────────────────────────────────────────

// go: none — goish idiom: the body of `Duration::String`, which Go
//     writes inline in the method. It sits out here so the 90-line
//     buffer walk does not bury Duration's other methods; the method
//     itself carries the anchor.
/// The body of `Duration::String` — Go writes it inline in the method;
/// goish keeps the method on `Duration` next to its siblings and the
/// 90-line buffer walk here.
///
/// One deliberate divergence: goish writes ASCII "us" where Go writes
/// "µs", because the rest of the formatter is ASCII-clean.
pub(crate) fn format_duration(d: int) -> string {
    // Largest representable Time in i64 nanoseconds → ~292 years; fits in 32 bytes.
    let mut buf = [0u8; 32];
    let mut w = buf.len();

    let neg = d < 0;
    let mut u: u64 = if neg {
        touint64(d).wrapping_neg()
    } else {
        touint64(d)
    };

    if u < touint64(Second.0) {
        // Sub-second: "0s", "Nns", "N.Nus", or "N.Nms". Each branch
        // emits its own suffix; we don't pre-place 's' (otherwise the
        // 'us' case would double-write it).
        if u == 0 {
            w -= 2;
            buf[w] = b'0';
            buf[w + 1] = b's';
        } else if u < touint64(Microsecond.0) {
            // ns
            w -= 1;
            buf[w] = b's';
            w -= 1;
            buf[w] = b'n';
            let (nw, nu) = fmt_frac(&mut buf[..w], u, 0);
            w = nw;
            w = fmt_int(&mut buf[..w], nu);
        } else if u < touint64(Millisecond.0) {
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
    return string::__from_vec(v);
}

// go: sdk 1.25.5 time/time.go:1025-1049 fmtFrac
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
            buf[w] = b'0' + tobyte(digit);
        }
        v /= 10;
    }
    if printing {
        w -= 1;
        buf[w] = b'.';
    }
    return (w, v);
}

// go: sdk 1.25.5 time/time.go:1051-1065 fmtInt
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
            buf[w] = b'0' + tobyte(v % 10);
            v /= 10;
        }
    }
    return w;
}

// go: sdk 1.25.5 time/time.go:1115-1120 lessThanHalf
/// `lessThanHalf` (time.go:1117): reports whether x+x < y, treating
/// inputs as positive uint64 to avoid signed overflow.
#[inline]
fn less_than_half(x: int, y: int) -> bool {
    let xu = touint64(x);
    let yu = touint64(y);
    return xu.wrapping_add(xu) < yu;
}

// go: none — goish idiom: Go writes `d * 3` because `Duration` is a
//     defined integer type; Rust needs the operator impls spelled out.
impl Mul<int> for Duration {
    type Output = Duration;
    // go: none — goish idiom: Go writes `d * 3` because `Duration` is a
    //     defined integer type; Rust needs the operator impl spelled out.
    fn mul(self, rhs: int) -> Duration {
        return Duration(self.0.wrapping_mul(rhs));
    }
}

// go: none — goish idiom: makes `int(d)` work, which Go gets from
//     Duration's underlying type.
// Go's `int(time.Millisecond)` is a typed conversion to the
// underlying nanosecond count. Wire `__IntConv` so call sites match.
// `__Int64Conv` is impl'd in lockstep so `int64(d)` works the same way.
impl crate::convert::__IntConv for Duration {
    // go: none — goish idiom: makes `int(d)` work, which Go gets from
    //     Duration's underlying type.
    #[inline]
    fn __conv(self) -> int {
        return self.0;
    }
}
// go: none — goish idiom: see the note on `__IntConv for Duration`.
impl crate::convert::__Int64Conv for Duration {
    // go: none — goish idiom: see the note on `__IntConv for Duration`.
    #[inline]
    fn __conv(self) -> i64 {
        return toint64(self.0);
    }
}

// go: none — goish idiom: see the note on `Mul<int> for Duration`.
/// Symmetric: Go's `60 * time.Second` writes the integer on the left.
/// Without this impl Rust would reject the multiplication direction.
impl Mul<Duration> for int {
    type Output = Duration;
    // go: none — goish idiom: see the note on `Mul<int> for Duration`.
    fn mul(self, rhs: Duration) -> Duration {
        return Duration(self.wrapping_mul(rhs.0));
    }
}

// go: none — goish idiom: see the note on `Mul<int> for Duration`.
impl Add<Duration> for Duration {
    type Output = Duration;
    // go: none — goish idiom: see the note on `Mul<int> for Duration`.
    fn add(self, rhs: Duration) -> Duration {
        return Duration(self.0.wrapping_add(rhs.0));
    }
}

// go: none — goish idiom: see the note on `Mul<int> for Duration`.
impl Sub<Duration> for Duration {
    type Output = Duration;
    // go: none — goish idiom: see the note on `Mul<int> for Duration`.
    fn sub(self, rhs: Duration) -> Duration {
        return Duration(self.0.wrapping_sub(rhs.0));
    }
}

/// `time.Duration / time.Duration` — Go's `time.Duration` is `int64`,
/// so the division is plain integer division: returns the unitless
/// quotient as a `Duration` (the wrapper is preserved so that callers
/// who format it with `%d` still see an integer count of nanoseconds-
/// equivalent ratio, matching Go's semantics where the result type
/// stays `time.Duration`).
impl Div<Duration> for Duration {
    type Output = Duration;
    // go: sdk 1.25.5 time/time.go:1810-1896 div
    fn div(self, rhs: Duration) -> Duration {
        if rhs.0 == 0 {
            panic!("time::Duration: integer divide by zero");
        }
        return Duration(self.0 / rhs.0);
    }
}

/// `time.Duration / int` — divide a duration by a scalar.
impl Div<int> for Duration {
    type Output = Duration;
    // go: sdk 1.25.5 time/time.go:1810-1896 div
    fn div(self, rhs: int) -> Duration {
        if rhs == 0 {
            panic!("time::Duration: integer divide by zero");
        }
        return Duration(self.0 / rhs);
    }
}

// go: none — goish idiom: Go's Duration satisfies `Stringer`; see
//     the note on `Format for Month`.
// Make Duration printable via fmt's %v / %s / Println!.
impl fmt::Format for Duration {
    // go: none — goish idiom: Go's Duration satisfies `Stringer`; see the
    //     note on `Format for Month`.
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

// go: none — goish idiom: Go writes a Duration as `n * time.Second`,
//     which needs an untyped constant on the left; goish's `int` is a
//     concrete type, so these four constructors stand in for the
//     multiplication. Go's same-named `Nanoseconds`/`Microseconds`/
//     `Milliseconds`/`Seconds` are METHODS on Duration going the other
//     way, and those are ported separately in `impl Duration`.
/// Construct a `Duration` of `n` nanoseconds.
pub fn Nanoseconds(n: int) -> Duration {
    return Duration(n);
}
// go: none — goish idiom: see the note on `Nanoseconds`.
pub fn Microseconds(n: int) -> Duration {
    return Duration(n.wrapping_mul(1_000));
}
// go: none — goish idiom: see the note on `Nanoseconds`.
pub fn Milliseconds(n: int) -> Duration {
    return Duration(n.wrapping_mul(1_000_000));
}
// go: none — goish idiom: see the note on `Nanoseconds`.
pub fn Seconds(n: int) -> Duration {
    return Duration(n.wrapping_mul(1_000_000_000));
}

// ─── Time ─────────────────────────────────────────────────────────────

/// `time.Time` — wall (Unix sec + nsec) + optional monotonic clock.
///
/// `mono == 0` means "no monotonic component" (e.g., constructed via
/// `time::Unix(...)`); `Now()` always sets it. `Sub` prefers monotonic
/// when both sides have it.
// `PartialEq` mirrors Go: `time.Time` is a comparable struct, so `==`
// is legal and compares wall+ext+mono field-wise. Go's docs steer
// callers to `Equal` because `==` also distinguishes the monotonic
// reading and the location; that caveat is Go's, not a goish deviation.
// Needed because `goany::Any` requires `PartialEq` at the wrap site,
// and an ASN.1 ANY field can hold a UTCTime.
#[derive(Clone, Copy, Default, PartialEq)]
pub struct Time {
    pub(crate) sec: int,
    pub(crate) nsec: i32,
    pub(crate) mono: int, // 0 = absent
}

// go: sdk 1.25.5 time/time.go:531-563 unixToInternal
/// Seconds from January 1, year 1 to January 1, 1970 — the offset
/// between Go's internal epoch and the Unix one.
///
/// `Time.sec` counts from the ABSOLUTE ZERO YEAR, as Go's does, so the
/// zero `Time` is January 1 of year 1 and not the Unix epoch. It used
/// to count Unix seconds, which made `Time{}` read as 1970-01-01 — a
/// divergence visible wherever a zero time is formatted, and one this
/// tree had already recorded twice, in `io/fs.FormatFileInfo` and in
/// `archive/tar`'s FileInfo rendering. Both of those notes are now
/// stale in the good direction.
///
/// The binary encoding gets fixed with it: Go's `AppendBinary` writes
/// `t.sec()`, the internal count, and goish was writing Unix seconds —
/// so a `MarshalBinary` here and an `UnmarshalBinary` in Go disagreed
/// by 62135596800 seconds.
const unixToInternal: int = (1969 * 365 + 1969 / 4 - 1969 / 100 + 1969 / 400) * 86400;

// go: sdk 1.25.5 time/time.go:531-563 internalToUnix
const internalToUnix: int = -unixToInternal;

impl Time {
    // go: sdk 1.25.5 time/time.go:262-264 Time.IsZero
    /// Whether `t` is the zero instant — January 1, year 1, 00:00:00
    /// UTC.
    pub fn IsZero(self) -> bool {
        return self.sec == 0 && self.nsec == 0;
    }

    // go: none — goish idiom: the read-back half of `__reflect_value`,
    //     which emits the internal second count. `encoding/asn1` is the
    //     only caller.
    #[doc(hidden)]
    pub fn __from_internal(sec: int, nsec: int) -> Time {
        return Time {
            sec,
            nsec: toint32(nsec),
            mono: 0,
        };
    }

    // go: none — goish idiom: the monotonic reading, which Go keeps
    //     packed into `Time.ext` and reads with `t.mono()`. Exposed to
    //     `format.rs` so `String` can render the `m=±…` suffix.
    #[doc(hidden)]
    pub(crate) fn __mono(self) -> int {
        return self.mono;
    }

    // go: none — goish idiom: Go's `unixSec` is a method on the packed
    //     wall/ext representation. goish stores the internal second
    //     count in a plain field, so this is the one place the epoch
    //     shift is spelled and everything Unix-shaped goes through it.
    pub(crate) fn unixSec(self) -> int {
        return self.sec + internalToUnix;
    }

    // go: sdk 1.25.5 time/time.go:1428-1430 Time.Unix
    pub fn Unix(self) -> int {
        return self.unixSec();
    }
    // go: sdk 1.25.5 time/time.go:1437-1439 Time.UnixMilli
    pub fn UnixMilli(self) -> int {
        return self
            .unixSec()
            .wrapping_mul(1_000)
            .wrapping_add(toint(self.nsec) / 1_000_000);
    }
    // go: sdk 1.25.5 time/time.go:1446-1448 Time.UnixMicro
    pub fn UnixMicro(self) -> int {
        return self
            .unixSec()
            .wrapping_mul(1_000_000)
            .wrapping_add(toint(self.nsec) / 1_000);
    }
    // go: sdk 1.25.5 time/time.go:1456-1458 Time.UnixNano
    pub fn UnixNano(self) -> int {
        return self
            .unixSec()
            .wrapping_mul(1_000_000_000)
            .wrapping_add(toint(self.nsec));
    }
    // go: sdk 1.25.5 time/time.go:267-274 Time.After
    pub fn After(self, u: Time) -> bool {
        return self.sec > u.sec || (self.sec == u.sec && self.nsec > u.nsec);
    }
    // go: sdk 1.25.5 time/time.go:277-284 Time.Before
    pub fn Before(self, u: Time) -> bool {
        return self.sec < u.sec || (self.sec == u.sec && self.nsec < u.nsec);
    }
    // go: sdk 1.25.5 time/time.go:312-317 Time.Equal
    pub fn Equal(self, u: Time) -> bool {
        return self.sec == u.sec && self.nsec == u.nsec;
    }

    // go: sdk 1.25.5 time/time.go:288-305 Time.Compare
    /// `(t Time).Compare(u)` (time/time.go:288). Returns -1 if t < u,
    /// +1 if t > u, 0 if equal. Slim port: no monotonic-clock fast path
    /// (goish stores monotonic alongside sec/nsec but Compare semantics
    /// match Sub-then-Sign in a way that's correct for both wall- and
    /// monotonic-time inputs).
    pub fn Compare(self, u: Time) -> crate::types::int {
        // Prefer monotonic when both have it.
        if self.mono != 0 && u.mono != 0 {
            if self.mono < u.mono {
                return -1;
            }
            if self.mono > u.mono {
                return 1;
            }
            return 0;
        }
        // Fall back to wall-clock (sec, nsec).
        if self.sec < u.sec {
            return -1;
        }
        if self.sec > u.sec {
            return 1;
        }
        if (self.nsec as crate::types::int) < (u.nsec as crate::types::int) {
            return -1;
        }
        if (self.nsec as crate::types::int) > (u.nsec as crate::types::int) {
            return 1;
        }
        return 0;
    }
    // go: sdk 1.25.5 time/time.go:1194-1208 Time.Sub
    /// The duration `t - u`.
    ///
    /// A `Duration` is an int64 of NANOSECONDS, so it spans about 292
    /// years and a wider gap does not fit. Go SATURATES — maxDuration
    /// or minDuration by direction — rather than wrapping. This used to
    /// wrap, which reports a negative gap between two correctly ordered
    /// instants; the zero `Time` is nineteen centuries from the epoch,
    /// so every uninitialised Time is on the wrong side of that.
    pub fn Sub(self, u: Time) -> Duration {
        // Go: if t.wall&u.wall&hasMonotonic != 0 { return subMono(...) }
        if self.mono != 0 && u.mono != 0 {
            return subMono(self.mono, u.mono);
        }
        let sec_diff = self.sec.wrapping_sub(u.sec);
        let nsec_diff = toint(self.nsec).wrapping_sub(toint(u.nsec));
        let d = Duration(sec_diff.wrapping_mul(1_000_000_000).wrapping_add(nsec_diff));
        // Go: switch { case u.Add(d).Equal(t): return d; case t.Before(u):
        //     return minDuration; default: return maxDuration }
        if u.Add(d).Equal(self) {
            return d;
        }
        if self.Before(u) {
            return minDuration;
        }
        return maxDuration;
    }
    // go: sdk 1.25.5 time/time.go:1166-1188 Time.Add
    pub fn Add(self, d: Duration) -> Time {
        let total_nsec = toint(self.nsec).wrapping_add(d.0);
        let extra_sec = total_nsec.div_euclid(1_000_000_000);
        let new_nsec = toint32(total_nsec.rem_euclid(1_000_000_000));
        let new_sec = self.sec.wrapping_add(extra_sec);
        let new_mono = if self.mono != 0 {
            self.mono.wrapping_add(d.0)
        } else {
            0
        };
        return Time {
            sec: new_sec,
            nsec: new_nsec,
            mono: new_mono,
        };
    }

    // ─── Y/M/D + clock accessors (UTC only, v1) ───────────────────────
    //
    // Backed by the Howard Hinnant "civil from days" algorithm — same
    // numeric output as Go's table-based approach, ~20 LOC instead of
    // ~150. Output verified against `date -u -d @<unix>` on the test
    // corpus.

    // go: sdk 1.25.5 time/time.go:808-810 Time.Date
    /// `t.Date()` — `(year, month, day)`. Month is 1..=12.
    pub fn Date(self) -> (int, int, int) {
        let (y, m, d, _, _, _) = civil_from_unix(self.unixSec());
        return (y, m, d);
    }

    // go: sdk 1.25.5 time/time.go:813-817 Time.Year
    pub fn Year(self) -> int {
        return self.Date().0;
    }
    // go: sdk 1.25.5 time/time.go:820-824 Time.Month
    /// `t.Month()` (time.go:1126) — Month-of-year as a typed
    /// [`Month`]. Use `.Int()` for the underlying 1..=12 number.
    pub fn Month(self) -> Month {
        return Month(self.Date().1);
    }
    // go: sdk 1.25.5 time/time.go:827-831 Time.Day
    pub fn Day(self) -> int {
        return self.Date().2;
    }

    // go: sdk 1.25.5 time/time.go:866-868 Time.Clock
    /// `t.Clock()` — `(hour, minute, second)` within the day, UTC.
    pub fn Clock(self) -> (int, int, int) {
        let (_, _, _, hh, mm, ss) = civil_from_unix(self.unixSec());
        return (hh, mm, ss);
    }
    // go: sdk 1.25.5 time/time.go:881-883 Time.Hour
    pub fn Hour(self) -> int {
        return self.Clock().0;
    }
    // go: sdk 1.25.5 time/time.go:886-888 Time.Minute
    pub fn Minute(self) -> int {
        return self.Clock().1;
    }
    // go: sdk 1.25.5 time/time.go:891-893 Time.Second
    pub fn Second(self) -> int {
        return self.Clock().2;
    }

    // go: sdk 1.25.5 time/time.go:897-899 Time.Nanosecond
    pub fn Nanosecond(self) -> int {
        return toint(self.nsec);
    }

    // go: sdk 1.25.5 time/time.go:834-836 Time.Weekday
    /// `t.Weekday()` (time.go:1145) — day-of-week as a typed
    /// [`Weekday`]. Use `.Int()` for the underlying 0..=6 number
    /// (0=Sunday .. 6=Saturday).
    pub fn Weekday(self) -> Weekday {
        let days = self.unixSec().div_euclid(86_400);
        // 1970-01-01 was a Thursday (=4 in Sun..Sat = 0..6).
        return Weekday((days + 4).rem_euclid(7));
    }

    // go: sdk 1.25.5 time/time.go:903-906 Time.YearDay
    /// `t.YearDay()` (time.go:903) — day of the year, [1, 365] for non-leap,
    /// [1, 366] for leap years.
    pub fn YearDay(self) -> int {
        // Go: time.go:904 — `_, yday := t.absSec().days().yearYday()`.
        // Slim: derive from current Date() vs Jan 1 of the same year.
        let (y, _, _) = self.Date();
        let unix_days_now = self.unixSec().div_euclid(86_400);
        let unix_days_jan1 = days_from_civil(y, 1, 1);
        // Go: yday is 1-based.
        return toint(unix_days_now - unix_days_jan1 + 1);
    }

    // go: sdk 1.25.5 time/time.go:848-863 Time.ISOWeek
    /// `t.ISOWeek()` (time.go:848) — ISO 8601 (year, week) for t.
    /// Week 1 contains the first Thursday of the ISO year. A January 1 in
    /// some years can belong to week 52 or 53 of the previous ISO year;
    /// likewise December 31 can fall in week 1 of the next ISO year.
    pub fn ISOWeek(self) -> (int, int) {
        // Go: time.go:859 — `days := t.absSec().days()`.
        let days = self.unixSec().div_euclid(86_400);
        // Go: time.go:860 — `thu := days + absDays(Thursday - ((days-1).weekday()+1))`.
        // `weekday()` on absDays returns Sun=0..Sat=6 (Go's standard
        // `Weekday`). We derive the same numbering from Unix days:
        // 1970-01-01 was a Thursday (=4 in Sun=0..Sat=6), so
        //   weekday_sun(unix_day) = (unix_day + 4) mod 7
        //   weekday_sun(unix_day - 1) = (unix_day + 3) mod 7
        let sun_weekday_yesterday = (days + 3).rem_euclid(7);
        // Thursday = 4. offset = Thursday - (sun_weekday_yesterday + 1)
        //                     = 3 - sun_weekday_yesterday.
        let offset = 3 - sun_weekday_yesterday;
        let thu_days = days + offset;
        // Go: time.go:861 — `year, yday := thu.yearYday()`.
        // Slim: derive year from civil_from_unix on Thursday's epoch sec,
        // then year_day from (thu_days - days_from_civil(year,1,1) + 1).
        let (thu_year, _, _, _, _, _) = civil_from_unix(thu_days * 86_400);
        let thu_jan1 = days_from_civil(thu_year, 1, 1);
        let yday = thu_days - thu_jan1 + 1;
        // Go: time.go:862
        return (thu_year, (yday - 1) / 7 + 1);
    }

    // go: sdk 1.25.5 time/time.go:1258-1262 Time.AddDate
    /// `t.AddDate(years, months, days)` (time.go:1258) — add the given
    /// number of years, months, and days, normalizing the result the
    /// same way `Date` does (e.g. `AddDate(0, 1, 0)` on Oct 31 yields
    /// Dec 1, the normalized form of Nov 31).
    pub fn AddDate(self, years: int, months: int, days: int) -> Time {
        // Go: time.go:1259-1260
        let (year, month, day) = self.Date();
        let (hour, min, sec) = self.Clock();
        // Go: time.go:1261 — Date(year+years, month+Month(months), day+days,
        // hour, min, sec, int(t.nsec()), t.Location()).
        // Slim: no Location parameter (UTC-only).
        return Date(
            year + years,
            month + months,
            day + days,
            hour,
            min,
            sec,
            toint(self.nsec),
            UTC,
        );
    }

    // go: sdk 1.25.5 time/time.go:1364-1367 Time.UTC
    /// `t.UTC()` (time.go:1364) — slim time is always UTC, returns self.
    pub fn UTC(self) -> Time {
        return self;
    }

    // go: sdk 1.25.5 time/time.go:1370-1373 Time.Local
    /// `t.Local()` (time.go:1370) — slim time has no Location, returns self.
    pub fn Local(self) -> Time {
        return self;
    }

    // go: sdk 1.25.5 time/time.go:1778-1785 Time.Truncate
    /// `t.Truncate(d)` (time.go:1778) — round t down to a multiple of d
    /// since the zero time. If d <= 0, returns t unchanged.
    pub fn Truncate(self, d: Duration) -> Time {
        let mut t = self;
        t.mono = 0;
        if d.0 <= 0 {
            return t;
        }
        let r = t.UnixNano().rem_euclid(d.0);
        return t.Add(Duration(-r));
    }

    // go: sdk 1.25.5 time/time.go:1795-1805 Time.Round
    /// `t.Round(d)` (time.go:1798) — round t to the nearest multiple of d
    /// since the zero time; halfway values round up. If d <= 0, returns t
    /// unchanged.
    pub fn Round(self, d: Duration) -> Time {
        let mut t = self;
        t.mono = 0;
        if d.0 <= 0 {
            return t;
        }
        let r = t.UnixNano().rem_euclid(d.0);
        return if r.wrapping_mul(2) < d.0 {
            t.Add(Duration(-r))
        } else {
            t.Add(Duration(d.0 - r))
        };
    }

    // go: sdk 1.25.5 time/time.go:1399-1402 Time.Zone
    /// `t.Zone()` (time.go:1399) — slim port. Always returns
    /// ("UTC", 0) since slim time has no Location.
    pub fn Zone(self) -> (crate::gostring::string, int) {
        return (crate::gostring::string::from("UTC"), 0);
    }

    // go: sdk 1.25.5 time/time.go:1677-1680 Time.IsDST
    /// `t.IsDST()` (time.go:1677) — slim port. Always false (no DST
    /// in UTC-only slim time).
    pub fn IsDST(self) -> bool {
        return false;
    }

    // go: sdk 1.25.5 time/time.go:1634-1636 Time.MarshalText
    /// `t.MarshalText()` (time.go:1634) — encode as RFC3339 bytes.
    /// Implements `encoding.TextMarshaler`. Slim deviation: emits
    /// RFC3339 (no fractional seconds) rather than RFC3339Nano —
    /// the slim Format helper doesn't recognise RFC3339Nano. Parse
    /// pairs cleanly with this output via UnmarshalText.
    pub fn MarshalText(self) -> (crate::goslice::slice<crate::types::byte>, crate::error) {
        let s = self.Format(crate::gostring::string::from(RFC3339));
        return (crate::convert::bytes(s), crate::errors::nil);
    }

    // go: sdk 1.25.5 time/time.go:1640-1644 Time.UnmarshalText
    /// `(*Time).UnmarshalText(data)` (time.go:1640) — parse RFC3339
    /// from bytes. Updates `self` in place. Implements
    /// `encoding.TextUnmarshaler`.
    pub fn UnmarshalText(
        &mut self,
        data: crate::goslice::slice<crate::types::byte>,
    ) -> crate::error {
        let s = crate::gostring::string::from_bytes(&data);
        let (t, err) = Parse(crate::gostring::string::from(RFC3339), s);
        if err.IsNil() {
            *self = t;
        }
        return err;
    }

    // go: sdk 1.25.5 time/time.go:1587-1596 Time.MarshalJSON
    /// `t.MarshalJSON()` (time.go:1587) — encode as a JSON-quoted
    /// RFC3339 string. Slim deviation: emits RFC3339 (no fractional
    /// seconds) instead of RFC3339Nano, mirroring MarshalText.
    pub fn MarshalJSON(self) -> (crate::goslice::slice<crate::types::byte>, crate::error) {
        // b := make([]byte, 0, len(RFC3339Nano)+len(`""`))
        let mut b: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(RFC3339Nano.len() + 2);
        // b = append(b, '"')
        b.push(b'"');
        // appendStrictRFC3339 — slim version: just Format(RFC3339).
        let s = self.Format(crate::gostring::string::from(RFC3339));
        b.extend_from_slice(s.as_bytes());
        // b = append(b, '"')
        b.push(b'"');
        return (crate::goslice::slice::__from_vec(b), crate::errors::nil);
    }

    // go: sdk 1.25.5 time/time.go:1600-1612 Time.UnmarshalJSON
    /// `(*Time).UnmarshalJSON(data)` (time.go:1600) — parse a JSON-
    /// quoted RFC3339 string. Treats the literal `null` as a no-op.
    pub fn UnmarshalJSON(
        &mut self,
        data: crate::goslice::slice<crate::types::byte>,
    ) -> crate::error {
        // if string(data) == "null" { return nil }
        if &*data == b"null" {
            return crate::errors::nil;
        }
        // if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' { error }
        let bs = &*data;
        if bs.len() < 2 || bs[0] != b'"' || bs[bs.len() - 1] != b'"' {
            return crate::errors::New("Time.UnmarshalJSON: input is not a JSON string");
        }
        // data = data[1:len(data)-1]
        let inner = &bs[1..bs.len() - 1];
        let s = crate::gostring::string::from_bytes(inner);
        let (t, err) = Parse(crate::gostring::string::from(RFC3339), s);
        if err.IsNil() {
            *self = t;
        }
        return err;
    }

    // go: sdk 1.25.5 time/time.go:1466-1510 Time.AppendBinary
    /// `t.AppendBinary(b)` (time.go:1466) — append a 15-byte binary
    /// encoding to b. Slim deviation: always emits V1 with
    /// offsetMin = -1 (UTC) since slim time is UTC-only. The wire
    /// format is interoperable with Go's time.UnmarshalBinary.
    pub fn AppendBinary(
        self,
        b: crate::goslice::slice<crate::types::byte>,
    ) -> (crate::goslice::slice<crate::types::byte>, crate::error) {
        // Go: var offsetMin int16  (slim: always UTC → -1)
        let offset_min: i16 = -1;
        // Go: version := timeBinaryVersionV1
        let version: u8 = 1;
        // Go: sec := t.sec(); nsec := t.nsec()
        let sec: i64 = toint64(self.sec);
        let nsec: i32 = self.nsec;
        // Go: b = append(b, version, byte(sec>>56), ..., byte(offsetMin))
        let mut v = b.__into_vec();
        v.push(version);
        v.push(tobyte(sec >> 56));
        v.push(tobyte(sec >> 48));
        v.push(tobyte(sec >> 40));
        v.push(tobyte(sec >> 32));
        v.push(tobyte(sec >> 24));
        v.push(tobyte(sec >> 16));
        v.push(tobyte(sec >> 8));
        v.push(tobyte(sec));
        v.push(tobyte(nsec >> 24));
        v.push(tobyte(nsec >> 16));
        v.push(tobyte(nsec >> 8));
        v.push(tobyte(nsec));
        v.push(tobyte(offset_min >> 8));
        v.push(tobyte(offset_min));
        // Go: return b, nil
        return (crate::goslice::slice::__from_vec(v), crate::errors::nil);
    }

    // go: sdk 1.25.5 time/time.go:1513-1519 Time.MarshalBinary
    /// `t.MarshalBinary()` (time.go:1513) — implements
    /// `encoding.BinaryMarshaler`. Wraps AppendBinary on a fresh
    /// 16-byte capacity buffer.
    pub fn MarshalBinary(self) -> (crate::goslice::slice<crate::types::byte>, crate::error) {
        // Go: b, err := t.AppendBinary(make([]byte, 0, 16))
        let buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(16);
        let (b, err) = self.AppendBinary(crate::goslice::slice::__from_vec(buf));
        if !err.IsNil() {
            // Go: return nil, err
            let empty: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            return (crate::goslice::slice::__from_vec(empty), err);
        }
        // Go: return b, nil
        return (b, crate::errors::nil);
    }

    // go: sdk 1.25.5 time/time.go:1522-1567 Time.UnmarshalBinary
    /// `(*Time).UnmarshalBinary(data)` (time.go:1522) — implements
    /// `encoding.BinaryUnmarshaler`. Slim: zone offset is parsed but
    /// ignored (slim time is UTC-only); accepts both V1 (15-byte) and
    /// V2 (16-byte) inputs.
    pub fn UnmarshalBinary(
        &mut self,
        data: crate::goslice::slice<crate::types::byte>,
    ) -> crate::error {
        // Go: buf := data; if len(buf) == 0 { return errors.New("...: no data") }
        let buf = data.__into_vec();
        if buf.is_empty() {
            return crate::errors::New("Time.UnmarshalBinary: no data");
        }
        // Go: version := buf[0]
        let version = buf[0];
        // Go: if version != V1 && version != V2 { return error }
        if version != 1 && version != 2 {
            return crate::errors::New("Time.UnmarshalBinary: unsupported version");
        }
        // Go: wantLen := 1 + 8 + 4 + 2; if V2 { wantLen++ }
        let mut want_len: usize = 1 + 8 + 4 + 2;
        if version == 2 {
            want_len += 1;
        }
        // Go: if len(buf) != wantLen { return error }
        if buf.len() != want_len {
            return crate::errors::New("Time.UnmarshalBinary: invalid length");
        }
        // Go: buf = buf[1:]; sec := int64(buf[7]) | ... | int64(buf[0])<<56
        let sec: i64 = toint64(buf[8])
            | (toint64(buf[7]) << 8)
            | (toint64(buf[6]) << 16)
            | (toint64(buf[5]) << 24)
            | (toint64(buf[4]) << 32)
            | (toint64(buf[3]) << 40)
            | (toint64(buf[2]) << 48)
            | (toint64(buf[1]) << 56);
        // Go: buf = buf[8:]; nsec := int32(buf[3]) | ... | int32(buf[0])<<24
        let nsec: i32 = toint32(buf[12])
            | (toint32(buf[11]) << 8)
            | (toint32(buf[10]) << 16)
            | (toint32(buf[9]) << 24);
        // Go: buf = buf[4:]; offset := int(int16(buf[1])|int16(buf[0])<<8) * 60
        // (parsed but ignored — slim time is UTC-only)
        let _offset: i16 = toint16(buf[14]) | (toint16(buf[13]) << 8);
        // Go: *t = Time{}; t.wall = uint64(nsec); t.ext = sec
        *self = Time {
            sec: toint(sec),
            nsec,
            mono: 0,
        };
        // Go: return nil
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 time/time.go:1574-1576 Time.GobEncode
    /// `t.GobEncode()` (time.go:1574) — implements
    /// `encoding/gob.GobEncoder`. Delegates to MarshalBinary.
    pub fn GobEncode(self) -> (crate::goslice::slice<crate::types::byte>, crate::error) {
        // Go: return t.MarshalBinary()
        return self.MarshalBinary();
    }

    // go: sdk 1.25.5 time/time.go:1579-1581 Time.GobDecode
    /// `(*Time).GobDecode(data)` (time.go:1579) — implements
    /// `encoding/gob.GobDecoder`. Delegates to UnmarshalBinary.
    pub fn GobDecode(&mut self, data: crate::goslice::slice<crate::types::byte>) -> crate::error {
        // Go: return t.UnmarshalBinary(data)
        return self.UnmarshalBinary(data);
    }
}

// go: none — goish idiom: Go splits this across `absSeconds.days()`,
//     `absDays.date()` and `absSeconds.clock()`, all keyed off its
//     packed absolute-time representation. goish stores seconds
//     directly and computes the whole civil date in one pass (Howard
//     Hinnant's algorithm, public domain).
// Civil date from Unix seconds. Returns (year, month, day, hour, min, sec)
// — all UTC.
pub(crate) fn civil_from_unix(sec: int) -> (int, int, int, int, int, int) {
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
    return (y, m, d, hh, mm, ss);
}

// ─── Free functions ──────────────────────────────────────────────────

// go: sdk 1.25.5 time/time.go:1343-1357 Now
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
    return Time {
        // The clock reports Unix seconds; `Time.sec` counts from year 1.
        sec: wall.tv_sec.wrapping_add(unixToInternal),
        nsec: toint32(wall.tv_nsec),
        mono: mono_safe,
    };
}

/// `time.Sleep(d)` — pause the current goroutine for at least `d`.
/// Negative or zero `d` returns immediately. Mirrors `time.Sleep`
/// Go's `time.Sleep`.
///
/// Implementation (M18a): pushes a (deadline, current G) entry on
/// the runtime's timer heap and `gopark`s until sysmon wakes it.
/// This releases the M to run other goroutines — unlike a raw
/// `nanosleep(2)` which would block the OS thread.

// go: sdk 1.25.5 time/time.go:1223-1229 Since
/// `time.Since(t)` — `Now().Sub(t)`. Common idiom for elapsed time.
pub fn Since(t: Time) -> Duration {
    return Now().Sub(t);
}

// go: sdk 1.25.5 time/time.go:1233-1239 Until
/// `time.Until(t)` — `t.Sub(Now())`.
pub fn Until(t: Time) -> Duration {
    return t.Sub(Now());
}

// go: sdk 1.25.5 time/time.go:1651-1662 Unix
/// `time.Unix(sec, nsec)` — construct a Time from a Unix timestamp.
/// No monotonic component (will use wall arithmetic in `Sub`).
pub fn Unix(sec: int, nsec: int) -> Time {
    let extra_sec = nsec.div_euclid(1_000_000_000);
    let final_nsec = toint32(nsec.rem_euclid(1_000_000_000));
    // `Time.sec` counts from year 1, not from the epoch — see the note
    // on `unixToInternal`. This is where a Unix second becomes one.
    return Time {
        sec: sec.wrapping_add(extra_sec).wrapping_add(unixToInternal),
        nsec: final_nsec,
        mono: 0,
    };
}

// go: sdk 1.25.5 time/time.go:1663-1668 UnixMilli
/// `time.UnixMilli(msec)` — return the Time
/// corresponding to `msec` milliseconds since 1970-01-01 UTC.
pub fn UnixMilli(msec: int) -> Time {
    // Go: return Unix(msec/1e3, (msec%1e3)*1e6)
    return Unix(msec / 1_000, (msec % 1_000) * 1_000_000);
}

// go: sdk 1.25.5 time/time.go:1669-1674 UnixMicro
/// `time.UnixMicro(usec)` — return the Time
/// corresponding to `usec` microseconds since 1970-01-01 UTC.
pub fn UnixMicro(usec: int) -> Time {
    // Go: return Unix(usec/1e6, (usec%1e6)*1e3)
    return Unix(usec / 1_000_000, (usec % 1_000_000) * 1_000);
}

// go: sdk 1.25.5 time/time.go:1730-1768 Date
/// `time.Date(year, month, day, hour, min, sec, nsec, loc)` — construct
/// a Time. Slim port of Go's `time.Date` (time.go:1438). v1 has no
/// real Location support — the `loc` arg is accepted for ABI parity
/// (matches Go's 8-arg signature) but doesn't affect the output:
/// every Time is stored in UTC.
///
/// Accepts either `int` or `Month` for the month parameter via
/// `impl Into<int>` — Go callers spell `time.January` (a `Month`
/// typed const) directly, and `Month` impls `Into<int>` (see
/// `convert::__IntConv for Month`).
pub fn Date<M: __MonthArg>(
    year: int,
    month: M,
    day: int,
    hour: int,
    min: int,
    sec: int,
    nsec: int,
    _loc: Location,
) -> Time {
    let m = month.__as_int();
    let days = days_from_civil(year, m, day);
    let total_sec = days
        .wrapping_mul(86_400)
        .wrapping_add(hour.wrapping_mul(3600))
        .wrapping_add(min.wrapping_mul(60))
        .wrapping_add(sec);
    return Unix(total_sec, nsec);
}

/// Hidden trait so `Date`'s month parameter accepts both `int` and
/// the named `Month` constants (`time.January`, …). Goish's `Month`
/// is `struct Month(int)`; this adapter pulls the underlying number
/// for `days_from_civil`.
#[doc(hidden)]
pub trait __MonthArg {
    fn __as_int(self) -> int;
}
// go: none — goish idiom: `Date`'s month parameter takes both `int`
//     and the named `Month` constants, which Go gets for free from
//     `Month`'s underlying type.
impl __MonthArg for int {
    // go: none — goish idiom: `Date`'s month parameter takes both `int` and
    //     the named `Month` constants, which Go gets for free from `Month`'s
    //     underlying type.
    fn __as_int(self) -> int {
        return self;
    }
}
// go: none — goish idiom: see the note on `__MonthArg for int`.
impl __MonthArg for Month {
    // go: none — goish idiom: see the note on `__MonthArg for int`.
    fn __as_int(self) -> int {
        return self.0;
    }
}

// go: none — goish idiom: the inverse of `civil_from_unix`, which Go
//     writes inline inside `Date` against its absolute-time
//     representation. Howard Hinnant's `days_from_civil`.
/// Returns Unix days (signed, epoch 1970-01-01).
fn days_from_civil(year: int, month: int, day: int) -> int {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146_097 + doe - 719_468;
}

// go: none — goish-only: the field list `__reflect_value` below emits.
// ─── Reflect ─────────────────────────────────────────────────────────
//
// `reflect.TypeOf(time.Time{})` is the common key for fmt-style
// formatter tables — Go's `pretty` / `litter` / `repr` ports register
// `fmt.Sprint` under this key. The runtime only needs Type identity;
// __reflect_value falls back to a name-only struct shape (no field
// reflection — Time's internals are private).
//
// Go's `time.Time` fields (`wall`, `ext`, `loc`) are unexported, so
// `reflect.TypeOf(time.Time{}).NumField()` is 3 but none is readable.
// goish reflects the two values a port actually needs to rebuild a Time.
// These names describe what is emitted; they are not Go's field names,
// and nothing matches on them.
//
// The list has to exist. `__reflect_type` used to declare `&[]` while
// `__reflect_value` emitted two fields, and that mismatch is not
// cosmetic: `reflect::Zero` builds a struct zero by looping `NumField()`,
// so the zero of a `time.Time` had no fields and could never equal a
// reflected one. `encoding/asn1`'s `makeField` omits an OPTIONAL field
// with exactly that test — `v == Zero(v.Type())` — so an absent OPTIONAL
// `time.Time` was *encoded* where Go omits it. Pinned by
// examples/x509_keys_smoke.rs against `scripts/goref.sh encoding/asn1`.
//
// The two fields carry the INTERNAL second count — seconds from year
// 1, the same frame `Time.sec` uses — and not the Unix one. That is
// what makes a reflected zero Time equal `reflect::Zero(Time)`, which
// is the test `encoding/asn1`'s `makeField` uses to omit an OPTIONAL
// field.
//
// This carried a KNOWN DIVERGENCE while `Time` was anchored at the
// epoch: `Time::default()` and `time::Unix(0, 0)` were the same value,
// so goish omitted an OPTIONAL time at BOTH where Go omits only its own
// year-1 zero and emits `170d3730303130313030303030305a` for the epoch.
// A caller who deliberately meant 1970 got the field dropped. Both
// halves are now Go's, and the case in
// examples/x509_create_smoke.rs splits in two as that file predicted.
//
// Found by the crypto/x509 CRL port.
static TIME_FIELDS: [crate::reflect::StructField; 2] = [
    crate::reflect::StructField {
        Name: "sec",
        Tag: crate::reflect::StructTag::__new(""),
        Type: <int as crate::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    crate::reflect::StructField {
        Name: "nsec",
        Tag: crate::reflect::StructTag::__new(""),
        Type: <int as crate::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];

impl crate::reflect::Reflect for Time {
    // go: none — goish idiom: `reflect.TypeOf` finds a Go type through the
    //     runtime's type descriptor; goish builds the descriptor here.
    #[inline]
    fn __reflect_type() -> crate::reflect::Type {
        return crate::reflect::Type::__new(
            crate::reflect::Kind::Struct,
            "time.Time",
            &TIME_FIELDS,
        );
    }
    // go: none — goish idiom: `reflect.TypeOf` finds a Go type through the
    //     runtime's type descriptor; goish builds the descriptor here.
    #[inline]
    fn __reflect_value(&self) -> crate::reflect::Value {
        // Internal seconds, not Unix ones — see TIME_FIELDS above.
        return crate::reflect::Value::Struct {
            ty: <Self as crate::reflect::Reflect>::__reflect_type(),
            fields: alloc::vec![
                crate::reflect::Value::Int(self.sec),
                crate::reflect::Value::Int(self.Nanosecond()),
            ],
        };
    }
}

// `time.Duration` reflects as an int64 newtype — matches Go's
// `reflect.TypeOf(time.Duration(0)).Kind() == reflect.Int64`.
impl crate::reflect::Reflect for Duration {
    // go: none — goish idiom: see the note on `Reflect for Time`.
    #[inline]
    fn __reflect_type() -> crate::reflect::Type {
        return crate::reflect::Type::__new(crate::reflect::Kind::Int64, "time.Duration", &[]);
    }
    // go: none — goish idiom: see the note on `Reflect for Time`.
    #[inline]
    fn __reflect_value(&self) -> crate::reflect::Value {
        return crate::reflect::Value::Int(self.0);
    }
}
