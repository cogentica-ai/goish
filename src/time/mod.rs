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

// ─── Format layouts (time/format.go:80) ──────────────────────────────
//
// Go exposes these as plain `const` strings; goish heap-allocates
// strings, so we expose them as `&'static str` and let callers wrap
// them with `string(layout)` when calling Format. The literals are
// identical to Go's, so existing layout-driven code ports verbatim.

pub const Layout: &str = "01/02 03:04:05PM '06 -0700";
pub const ANSIC: &str = "Mon Jan _2 15:04:05 2006";
pub const UnixDate: &str = "Mon Jan _2 15:04:05 MST 2006";
pub const RubyDate: &str = "Mon Jan 02 15:04:05 -0700 2006";
pub const RFC822: &str = "02 Jan 06 15:04 MST";
pub const RFC822Z: &str = "02 Jan 06 15:04 -0700";
pub const RFC850: &str = "Monday, 02-Jan-06 15:04:05 MST";
pub const RFC1123: &str = "Mon, 02 Jan 2006 15:04:05 MST";
pub const RFC1123Z: &str = "Mon, 02 Jan 2006 15:04:05 -0700";
pub const RFC3339: &str = "2006-01-02T15:04:05Z07:00";
pub const RFC3339Nano: &str = "2006-01-02T15:04:05.999999999Z07:00";
pub const Kitchen: &str = "3:04PM";
pub const Stamp: &str = "Jan _2 15:04:05";
pub const StampMilli: &str = "Jan _2 15:04:05.000";
pub const StampMicro: &str = "Jan _2 15:04:05.000000";
pub const StampNano: &str = "Jan _2 15:04:05.000000000";
pub const DateTime: &str = "2006-01-02 15:04:05";
pub const DateOnly: &str = "2006-01-02";
pub const TimeOnly: &str = "15:04:05";

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
    /// `(d Duration).Seconds() float64` — Go time/time.go:1086.
    pub fn Seconds(self) -> f64 {
        let sec = self.0 / Second.0;
        let nsec = self.0 % Second.0;
        (sec as f64) + (nsec as f64) / 1e9
    }
    /// `(d Duration).Minutes() float64` — Go time/time.go:1093.
    pub fn Minutes(self) -> f64 {
        let min = self.0 / Minute.0;
        let nsec = self.0 % Minute.0;
        (min as f64) + (nsec as f64) / (60.0 * 1e9)
    }
    /// `(d Duration).Hours() float64` — Go time/time.go:1100.
    pub fn Hours(self) -> f64 {
        let hour = self.0 / Hour.0;
        let nsec = self.0 % Hour.0;
        (hour as f64) + (nsec as f64) / (60.0 * 60.0 * 1e9)
    }
    /// `(d Duration).Truncate(m Duration) Duration` — Go time/time.go:1108.
    /// Rounds toward zero to a multiple of `m`. m ≤ 0 returns d unchanged.
    pub fn Truncate(self, m: Duration) -> Duration {
        if m.0 <= 0 {
            return self;
        }
        Duration(self.0 - self.0 % m.0)
    }
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
        Duration(int::MAX) // overflow → maxDuration
    }
    /// `(d Duration).Abs() Duration` — Go time/time.go:1154. As a
    /// special case, Duration(MinInt64) is converted to Duration(MaxInt64).
    pub fn Abs(self) -> Duration {
        if self.0 >= 0 {
            self
        } else if self.0 == int::MIN {
            Duration(int::MAX)
        } else {
            Duration(-self.0)
        }
    }
    /// Go-faithful "1h2m3.456s" / "100ms" / "1.2us" / "5ns" / "0s" form.
    pub fn String(self) -> string {
        format_duration(self.0)
    }
}

/// `lessThanHalf` (time.go:1117): reports whether x+x < y, treating
/// inputs as positive uint64 to avoid signed overflow.
#[inline]
fn less_than_half(x: int, y: int) -> bool {
    let xu = x as u64;
    let yu = y as u64;
    xu.wrapping_add(xu) < yu
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
        0
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

    /// `t.UTC()` (time.go:1364) — slim time is always UTC, returns self.
    pub fn UTC(self) -> Time {
        self
    }

    /// `t.Local()` (time.go:1370) — slim time has no Location, returns self.
    pub fn Local(self) -> Time {
        self
    }

    /// `t.Truncate(d)` (time.go:1778) — round t down to a multiple of d
    /// since the zero time. If d <= 0, returns t unchanged.
    pub fn Truncate(self, d: Duration) -> Time {
        let mut t = self;
        t.mono = 0;
        if d.0 <= 0 {
            return t;
        }
        let r = t.UnixNano().rem_euclid(d.0);
        t.Add(Duration(-r))
    }

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
        if r.wrapping_mul(2) < d.0 {
            t.Add(Duration(-r))
        } else {
            t.Add(Duration(d.0 - r))
        }
    }

    /// `t.Format(layout)` (format.go:639) — slim port. Recognizes the
    /// canonical layout constants (RFC3339, RFC1123, RFC1123Z,
    /// DateTime, DateOnly, TimeOnly, Stamp, Kitchen, ANSIC) and
    /// renders the time directly. Does NOT support arbitrary
    /// reference-time layouts (porting Go's nextStdChunk machinery
    /// is ~1500 LOC).
    ///
    /// Pass the constant via `string(time::RFC3339)`.
    pub fn Format(self, layout: crate::gostring::string) -> crate::gostring::string {
        let (y, m, d, hh, mm, ss) = civil_from_unix(self.sec);
        let wd = self.Weekday();
        let nano = self.nsec;
        format_layout(&layout, y, m, d, hh, mm, ss, wd, nano as int)
    }

    /// `t.AppendFormat(b, layout)` (format.go:655) — append the formatted
    /// time to `b` and return the extended buffer. Slim port: delegates
    /// to `Format` then appends the byte representation.
    pub fn AppendFormat(
        self,
        b: crate::goslice::slice<crate::types::byte>,
        layout: crate::gostring::string,
    ) -> crate::goslice::slice<crate::types::byte> {
        let s = self.Format(layout);
        let extra = crate::convert::bytes(s);
        // Go: return append(b, formatted...). Use range! to mirror.
        let mut out = b;
        for (_, byte_ref) in crate::range!(extra) {
            out = crate::append!(out, *byte_ref);
        }
        out
    }

    /// `t.Zone()` (time.go:1399) — slim port. Always returns
    /// ("UTC", 0) since slim time has no Location.
    pub fn Zone(self) -> (crate::gostring::string, int) {
        (crate::gostring::string::from("UTC"), 0)
    }

    /// `t.IsDST()` (time.go:1677) — slim port. Always false (no DST
    /// in UTC-only slim time).
    pub fn IsDST(self) -> bool {
        false
    }

    /// `t.MarshalText()` (time.go:1634) — encode as RFC3339 bytes.
    /// Implements `encoding.TextMarshaler`. Slim deviation: emits
    /// RFC3339 (no fractional seconds) rather than RFC3339Nano —
    /// the slim Format helper doesn't recognise RFC3339Nano. Parse
    /// pairs cleanly with this output via UnmarshalText.
    pub fn MarshalText(self) -> (crate::goslice::slice<crate::types::byte>, crate::errors::error) {
        let s = self.Format(crate::gostring::string::from(RFC3339));
        (crate::convert::bytes(s), crate::nil)
    }

    /// `(*Time).UnmarshalText(data)` (time.go:1640) — parse RFC3339
    /// from bytes. Updates `self` in place. Implements
    /// `encoding.TextUnmarshaler`.
    pub fn UnmarshalText(
        &mut self,
        data: crate::goslice::slice<crate::types::byte>,
    ) -> crate::errors::error {
        let s = crate::gostring::string::from_bytes(&data);
        let (t, err) = Parse(crate::gostring::string::from(RFC3339), s);
        if err.IsNil() {
            *self = t;
        }
        err
    }

    /// `t.MarshalJSON()` (time.go:1587) — encode as a JSON-quoted
    /// RFC3339 string. Slim deviation: emits RFC3339 (no fractional
    /// seconds) instead of RFC3339Nano, mirroring MarshalText.
    pub fn MarshalJSON(self) -> (crate::goslice::slice<crate::types::byte>, crate::errors::error) {
        // b := make([]byte, 0, len(RFC3339Nano)+len(`""`))
        let mut b: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(RFC3339Nano.len() + 2);
        // b = append(b, '"')
        b.push(b'"');
        // appendStrictRFC3339 — slim version: just Format(RFC3339).
        let s = self.Format(crate::gostring::string::from(RFC3339));
        b.extend_from_slice(s.as_bytes());
        // b = append(b, '"')
        b.push(b'"');
        (crate::goslice::slice::__from_vec(b), crate::nil)
    }

    /// `(*Time).UnmarshalJSON(data)` (time.go:1600) — parse a JSON-
    /// quoted RFC3339 string. Treats the literal `null` as a no-op.
    pub fn UnmarshalJSON(
        &mut self,
        data: crate::goslice::slice<crate::types::byte>,
    ) -> crate::errors::error {
        // if string(data) == "null" { return nil }
        if &*data == b"null" {
            return crate::nil;
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
        err
    }

    /// `t.AppendBinary(b)` (time.go:1466) — append a 15-byte binary
    /// encoding to b. Slim deviation: always emits V1 with
    /// offsetMin = -1 (UTC) since slim time is UTC-only. The wire
    /// format is interoperable with Go's time.UnmarshalBinary.
    pub fn AppendBinary(
        self,
        b: crate::goslice::slice<crate::types::byte>,
    ) -> (crate::goslice::slice<crate::types::byte>, crate::errors::error) {
        // Go: var offsetMin int16  (slim: always UTC → -1)
        let offset_min: i16 = -1;
        // Go: version := timeBinaryVersionV1
        let version: u8 = 1;
        // Go: sec := t.sec(); nsec := t.nsec()
        let sec: i64 = self.sec as i64;
        let nsec: i32 = self.nsec;
        // Go: b = append(b, version, byte(sec>>56), ..., byte(offsetMin))
        let mut v = b.__into_vec();
        v.push(version);
        v.push((sec >> 56) as u8);
        v.push((sec >> 48) as u8);
        v.push((sec >> 40) as u8);
        v.push((sec >> 32) as u8);
        v.push((sec >> 24) as u8);
        v.push((sec >> 16) as u8);
        v.push((sec >> 8) as u8);
        v.push(sec as u8);
        v.push((nsec >> 24) as u8);
        v.push((nsec >> 16) as u8);
        v.push((nsec >> 8) as u8);
        v.push(nsec as u8);
        v.push((offset_min >> 8) as u8);
        v.push(offset_min as u8);
        // Go: return b, nil
        (crate::goslice::slice::__from_vec(v), crate::nil)
    }

    /// `t.MarshalBinary()` (time.go:1513) — implements
    /// `encoding.BinaryMarshaler`. Wraps AppendBinary on a fresh
    /// 16-byte capacity buffer.
    pub fn MarshalBinary(
        self,
    ) -> (crate::goslice::slice<crate::types::byte>, crate::errors::error) {
        // Go: b, err := t.AppendBinary(make([]byte, 0, 16))
        let buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(16);
        let (b, err) = self.AppendBinary(crate::goslice::slice::__from_vec(buf));
        if !err.IsNil() {
            // Go: return nil, err
            let empty: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            return (crate::goslice::slice::__from_vec(empty), err);
        }
        // Go: return b, nil
        (b, crate::nil)
    }

    /// `(*Time).UnmarshalBinary(data)` (time.go:1522) — implements
    /// `encoding.BinaryUnmarshaler`. Slim: zone offset is parsed but
    /// ignored (slim time is UTC-only); accepts both V1 (15-byte) and
    /// V2 (16-byte) inputs.
    pub fn UnmarshalBinary(
        &mut self,
        data: crate::goslice::slice<crate::types::byte>,
    ) -> crate::errors::error {
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
        let sec: i64 = (buf[8] as i64)
            | ((buf[7] as i64) << 8)
            | ((buf[6] as i64) << 16)
            | ((buf[5] as i64) << 24)
            | ((buf[4] as i64) << 32)
            | ((buf[3] as i64) << 40)
            | ((buf[2] as i64) << 48)
            | ((buf[1] as i64) << 56);
        // Go: buf = buf[8:]; nsec := int32(buf[3]) | ... | int32(buf[0])<<24
        let nsec: i32 = (buf[12] as i32)
            | ((buf[11] as i32) << 8)
            | ((buf[10] as i32) << 16)
            | ((buf[9] as i32) << 24);
        // Go: buf = buf[4:]; offset := int(int16(buf[1])|int16(buf[0])<<8) * 60
        // (parsed but ignored — slim time is UTC-only)
        let _offset: i16 = (buf[14] as i16) | ((buf[13] as i16) << 8);
        // Go: *t = Time{}; t.wall = uint64(nsec); t.ext = sec
        *self = Time {
            sec: sec as int,
            nsec,
            mono: 0,
        };
        // Go: return nil
        crate::nil
    }

    /// `t.GobEncode()` (time.go:1574) — implements
    /// `encoding/gob.GobEncoder`. Delegates to MarshalBinary.
    pub fn GobEncode(
        self,
    ) -> (crate::goslice::slice<crate::types::byte>, crate::errors::error) {
        // Go: return t.MarshalBinary()
        self.MarshalBinary()
    }

    /// `(*Time).GobDecode(data)` (time.go:1579) — implements
    /// `encoding/gob.GobDecoder`. Delegates to UnmarshalBinary.
    pub fn GobDecode(
        &mut self,
        data: crate::goslice::slice<crate::types::byte>,
    ) -> crate::errors::error {
        // Go: return t.UnmarshalBinary(data)
        self.UnmarshalBinary(data)
    }
}

const MONTH_SHORT: [&str; 13] = [
    "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const DAY_SHORT: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const DAY_LONG: [&str; 7] = [
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
];

fn pad2(n: int) -> [u8; 2] {
    let n = n as i64;
    [
        b'0' + ((n / 10) % 10) as u8,
        b'0' + (n % 10) as u8,
    ]
}

fn pad4(n: int) -> [u8; 4] {
    let n = n as i64;
    [
        b'0' + ((n / 1000) % 10) as u8,
        b'0' + ((n / 100) % 10) as u8,
        b'0' + ((n / 10) % 10) as u8,
        b'0' + (n % 10) as u8,
    ]
}

fn format_layout(
    layout: &crate::gostring::string,
    y: int,
    m: int,
    d: int,
    hh: int,
    mm: int,
    ss: int,
    wd: int,
    _nano: int,
) -> crate::gostring::string {
    use crate::gostring::string;
    let l = layout.clone();

    // RFC3339: "2006-01-02T15:04:05Z07:00" → "<date>T<time>Z" (UTC)
    if l == "2006-01-02T15:04:05Z07:00" {
        let mut out = alloc::vec::Vec::with_capacity(20);
        out.extend_from_slice(&pad4(y));
        out.push(b'-');
        out.extend_from_slice(&pad2(m));
        out.push(b'-');
        out.extend_from_slice(&pad2(d));
        out.push(b'T');
        out.extend_from_slice(&pad2(hh));
        out.push(b':');
        out.extend_from_slice(&pad2(mm));
        out.push(b':');
        out.extend_from_slice(&pad2(ss));
        out.push(b'Z');
        return string::from_bytes(&out);
    }
    // RFC3339Nano: "2006-01-02T15:04:05.999999999Z07:00"
    //
    // Per Go format.go:fmtFrac the trailing-9 form trims trailing zeros
    // from the fractional seconds; when the fractional part is fully
    // zero the entire ".NNNNNNNNN" suffix is omitted (no leading dot).
    // Slim: UTC only — emit "Z" instead of an offset.
    if l == "2006-01-02T15:04:05.999999999Z07:00" {
        let mut out = alloc::vec::Vec::with_capacity(30);
        out.extend_from_slice(&pad4(y));
        out.push(b'-');
        out.extend_from_slice(&pad2(m));
        out.push(b'-');
        out.extend_from_slice(&pad2(d));
        out.push(b'T');
        out.extend_from_slice(&pad2(hh));
        out.push(b':');
        out.extend_from_slice(&pad2(mm));
        out.push(b':');
        out.extend_from_slice(&pad2(ss));
        // Render fractional seconds: 9 digits left-padded; then strip
        // trailing zeros. If all digits are zero, omit the dot too.
        if _nano > 0 {
            // Go: u := uint64(nsec); for i := 9-1; i >= 0; i-- { ... }
            // Goish: build the 9-digit string then trim trailing zeros.
            let mut frac: [u8; 9] = [b'0'; 9];
            let mut n = _nano as u64;
            let mut i = 9;
            while i > 0 {
                i -= 1;
                frac[i] = b'0' + (n % 10) as u8;
                n /= 10;
            }
            // Trim trailing zeros.
            let mut len = 9;
            while len > 0 && frac[len - 1] == b'0' {
                len -= 1;
            }
            if len > 0 {
                out.push(b'.');
                out.extend_from_slice(&frac[..len]);
            }
        }
        out.push(b'Z');
        return string::from_bytes(&out);
    }
    // DateTime: "2006-01-02 15:04:05"
    if l == "2006-01-02 15:04:05" {
        let mut out = alloc::vec::Vec::with_capacity(19);
        out.extend_from_slice(&pad4(y));
        out.push(b'-');
        out.extend_from_slice(&pad2(m));
        out.push(b'-');
        out.extend_from_slice(&pad2(d));
        out.push(b' ');
        out.extend_from_slice(&pad2(hh));
        out.push(b':');
        out.extend_from_slice(&pad2(mm));
        out.push(b':');
        out.extend_from_slice(&pad2(ss));
        return string::from_bytes(&out);
    }
    // DateOnly: "2006-01-02"
    if l == "2006-01-02" {
        let mut out = alloc::vec::Vec::with_capacity(10);
        out.extend_from_slice(&pad4(y));
        out.push(b'-');
        out.extend_from_slice(&pad2(m));
        out.push(b'-');
        out.extend_from_slice(&pad2(d));
        return string::from_bytes(&out);
    }
    // TimeOnly: "15:04:05"
    if l == "15:04:05" {
        let mut out = alloc::vec::Vec::with_capacity(8);
        out.extend_from_slice(&pad2(hh));
        out.push(b':');
        out.extend_from_slice(&pad2(mm));
        out.push(b':');
        out.extend_from_slice(&pad2(ss));
        return string::from_bytes(&out);
    }
    // RFC1123: "Mon, 02 Jan 2006 15:04:05 MST" — assume UTC → "GMT"
    if l == "Mon, 02 Jan 2006 15:04:05 MST" {
        let mut out = alloc::vec::Vec::with_capacity(29);
        out.extend_from_slice(DAY_SHORT[wd as usize].as_bytes());
        out.extend_from_slice(b", ");
        out.extend_from_slice(&pad2(d));
        out.push(b' ');
        out.extend_from_slice(MONTH_SHORT[m as usize].as_bytes());
        out.push(b' ');
        out.extend_from_slice(&pad4(y));
        out.push(b' ');
        out.extend_from_slice(&pad2(hh));
        out.push(b':');
        out.extend_from_slice(&pad2(mm));
        out.push(b':');
        out.extend_from_slice(&pad2(ss));
        out.extend_from_slice(b" GMT");
        return string::from_bytes(&out);
    }
    // RFC1123Z: "Mon, 02 Jan 2006 15:04:05 -0700" — UTC → "+0000"
    if l == "Mon, 02 Jan 2006 15:04:05 -0700" {
        let mut out = alloc::vec::Vec::with_capacity(31);
        out.extend_from_slice(DAY_SHORT[wd as usize].as_bytes());
        out.extend_from_slice(b", ");
        out.extend_from_slice(&pad2(d));
        out.push(b' ');
        out.extend_from_slice(MONTH_SHORT[m as usize].as_bytes());
        out.push(b' ');
        out.extend_from_slice(&pad4(y));
        out.push(b' ');
        out.extend_from_slice(&pad2(hh));
        out.push(b':');
        out.extend_from_slice(&pad2(mm));
        out.push(b':');
        out.extend_from_slice(&pad2(ss));
        out.extend_from_slice(b" +0000");
        return string::from_bytes(&out);
    }
    // ANSIC: "Mon Jan _2 15:04:05 2006"
    if l == "Mon Jan _2 15:04:05 2006" {
        let mut out = alloc::vec::Vec::with_capacity(24);
        out.extend_from_slice(DAY_SHORT[wd as usize].as_bytes());
        out.push(b' ');
        out.extend_from_slice(MONTH_SHORT[m as usize].as_bytes());
        out.push(b' ');
        // _2 = space-padded day
        if d < 10 {
            out.push(b' ');
            out.push(b'0' + d as u8);
        } else {
            out.extend_from_slice(&pad2(d));
        }
        out.push(b' ');
        out.extend_from_slice(&pad2(hh));
        out.push(b':');
        out.extend_from_slice(&pad2(mm));
        out.push(b':');
        out.extend_from_slice(&pad2(ss));
        out.push(b' ');
        out.extend_from_slice(&pad4(y));
        return string::from_bytes(&out);
    }
    // Stamp: "Jan _2 15:04:05"
    if l == "Jan _2 15:04:05" {
        let mut out = alloc::vec::Vec::with_capacity(15);
        out.extend_from_slice(MONTH_SHORT[m as usize].as_bytes());
        out.push(b' ');
        if d < 10 {
            out.push(b' ');
            out.push(b'0' + d as u8);
        } else {
            out.extend_from_slice(&pad2(d));
        }
        out.push(b' ');
        out.extend_from_slice(&pad2(hh));
        out.push(b':');
        out.extend_from_slice(&pad2(mm));
        out.push(b':');
        out.extend_from_slice(&pad2(ss));
        return string::from_bytes(&out);
    }
    // Kitchen: "3:04PM"
    if l == "3:04PM" {
        let h12 = if hh == 0 { 12 } else if hh > 12 { hh - 12 } else { hh };
        let pm = hh >= 12;
        let mut out = alloc::vec::Vec::with_capacity(7);
        if h12 < 10 {
            out.push(b'0' + h12 as u8);
        } else {
            out.extend_from_slice(&pad2(h12));
        }
        out.push(b':');
        out.extend_from_slice(&pad2(mm));
        out.extend_from_slice(if pm { b"PM" } else { b"AM" });
        return string::from_bytes(&out);
    }
    // Long-day variant (RFC850): "Monday, 02-Jan-06 15:04:05 MST"
    if l == "Monday, 02-Jan-06 15:04:05 MST" {
        let mut out = alloc::vec::Vec::with_capacity(36);
        out.extend_from_slice(DAY_LONG[wd as usize].as_bytes());
        out.extend_from_slice(b", ");
        out.extend_from_slice(&pad2(d));
        out.push(b'-');
        out.extend_from_slice(MONTH_SHORT[m as usize].as_bytes());
        out.push(b'-');
        out.extend_from_slice(&pad2(y % 100));
        out.push(b' ');
        out.extend_from_slice(&pad2(hh));
        out.push(b':');
        out.extend_from_slice(&pad2(mm));
        out.push(b':');
        out.extend_from_slice(&pad2(ss));
        out.extend_from_slice(b" GMT");
        return string::from_bytes(&out);
    }
    // Unrecognized layout — return the layout literal back, mirroring
    // Go's behavior of emitting un-tokenized text verbatim.
    l
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
    /// Set once on Stop; gates the cap=1 stop_chan send so
    /// repeat Stop() calls are idempotent.
    stopped: Arc<AtomicBool>,
    /// Cap=1 chan. Stop sends `()`; the watcher's outer select
    /// races this against the timer fire — first arrival wins
    /// and the watcher exits. Replaces the previous "set flag and
    /// hope the post-Sleep check sees it" pattern, which never
    /// actually shortened the watcher's lifetime.
    stop_chan: chan<()>,
}

impl Timer {
    /// Stop prevents the Timer from firing. Returns `true` if the
    /// call stops the timer, `false` if it has already expired or
    /// been stopped. Mirrors `Timer.Stop` (sleep.go:107).
    ///
    /// Note: Stop does not close the channel. After Stop, no value
    /// will be sent on C.
    pub fn Stop(&self) -> bool {
        let was = self.stopped.swap(true, Ordering::AcqRel);
        if !was {
            // First Stop: poke the watcher. Cap=1, so the send
            // never blocks — there's always slot for the first
            // Stop, and only the first Stop reaches this branch.
            let stop = self.stop_chan.clone();
            crate::select! {
                stop.Send(()) => {},
                default => {},
            }
        }
        !was
    }
}

/// Internal helper: spawn a fire-and-forget gor that sleeps `d`
/// then signals on the returned chan. Used by both NewTimer and
/// NewTicker watchers as the "timer fired" leg of a select. Lives
/// at the bottom of the timer-call graph so callers can't recurse
/// into `NewTimer`/`After` and explode.
fn spawn_fire(d: Duration) -> chan<()> {
    let fire: chan<()> = crate::make!(chan (), 1);
    let inner = fire.clone();
    crate::go!(stack(64 * crate::KB), move || {
        Sleep(d);
        // Cap=1, fresh chan; first __try_send always slots in.
        let _ = inner.__try_send(());
    });
    fire
}

/// `time.NewTimer(d)` — create a Timer that fires after `d`.
/// Mirrors `NewTimer` (sleep.go:143).
#[allow(non_snake_case)]
pub fn NewTimer(d: Duration) -> Timer {
    let c: chan<Time> = crate::make!(chan Time, 1);
    let stop_chan: chan<()> = crate::make!(chan (), 1);
    let c_inner = c.clone();
    let stop_inner = stop_chan.clone();
    crate::go!(stack(64 * crate::KB), move || {
        // spawn_fire spawns the actual sleeper. Its gor lives ≤ d
        // regardless of Stop. Our outer select races that against
        // the stop chan — when Stop fires, this outer watcher
        // exits IMMEDIATELY, releasing both Arc<chan> handles.
        // Worst-case leak after Stop: the spawn_fire gor's ≤ d.
        let fire = spawn_fire(d);
        crate::select! {
            let _ = fire.Recv() => {
                // Non-blocking — Go's sendTime (sleep.go:179).
                let _ = c_inner.__try_send(Now());
            },
            let _ = stop_inner.Recv() => {
                // Stopped before fire — exit, drop both chans.
            },
        }
    });
    Timer {
        C: c,
        stopped: Arc::new(AtomicBool::new(false)),
        stop_chan,
    }
}

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
    c
}

/// `time.Ticker` — periodic timer. Mirrors `time.Ticker`.
pub struct Ticker {
    /// `<-chan Time` — receives a `Time` value approximately every
    /// `d` duration.
    pub C: chan<Time>,
    /// One-shot stop flag, gates the cap=1 stop_chan send.
    stopped: Arc<AtomicBool>,
    /// Stop poke. The watcher loop selects on this against each
    /// tick's After(d), so Stop exits the OUTER loop on the very
    /// next iteration boundary. Without this, an unstoppable
    /// `loop { Sleep(d); … }` could run forever if the user
    /// dropped the Ticker without calling Stop.
    stop_chan: chan<()>,
}

impl Ticker {
    /// Stop turns off a ticker. After Stop, no more ticks will
    /// be sent on C. Stop does not close the channel.
    pub fn Stop(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            let stop = self.stop_chan.clone();
            crate::select! {
                stop.Send(()) => {},
                default => {},
            }
        }
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
    let stop_chan: chan<()> = crate::make!(chan (), 1);
    let c_inner = c.clone();
    let stop_inner = stop_chan.clone();
    crate::go!(stack(64 * crate::KB), move || {
        loop {
            // Per-tick spawn_fire — its inner gor lives ≤ d. The
            // outer loop's select races against stop_chan: when
            // Stop fires, the loop exits at this scheduling
            // boundary, releasing both Arc<chan> handles. Worst-
            // case leak after Stop: the in-flight spawn_fire gor
            // for ≤ d.
            let fire = spawn_fire(d);
            crate::select! {
                let _ = fire.Recv() => {
                    let _ = c_inner.__try_send(Now());
                },
                let _ = stop_inner.Recv() => {
                    return;
                },
            }
        }
    });
    Ticker {
        C: c,
        stopped: Arc::new(AtomicBool::new(false)),
        stop_chan,
    }
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

/// `time.UnixMilli(msec)` (time.go:1666) — return the Time
/// corresponding to `msec` milliseconds since 1970-01-01 UTC.
pub fn UnixMilli(msec: int) -> Time {
    // Go: return Unix(msec/1e3, (msec%1e3)*1e6)
    Unix(msec / 1_000, (msec % 1_000) * 1_000_000)
}

/// `time.UnixMicro(usec)` (time.go:1672) — return the Time
/// corresponding to `usec` microseconds since 1970-01-01 UTC.
pub fn UnixMicro(usec: int) -> Time {
    // Go: return Unix(usec/1e6, (usec%1e6)*1e3)
    Unix(usec / 1_000_000, (usec % 1_000_000) * 1_000)
}

/// `time.Date(year, month, day, hour, min, sec, nsec)` — construct a
/// UTC Time. Slim port of Go's `time.Date` (time.go:1438) without the
/// `*Location` argument (UTC only, v1). Out-of-range fields normalize
/// the same way Go does (e.g. `Date(2024, 1, 32, …)` ≡ Feb 1).
pub fn Date(year: int, month: int, day: int, hour: int, min: int, sec: int, nsec: int) -> Time {
    let days = days_from_civil(year, month, day);
    let total_sec = days
        .wrapping_mul(86_400)
        .wrapping_add(hour.wrapping_mul(3600))
        .wrapping_add(min.wrapping_mul(60))
        .wrapping_add(sec);
    Unix(total_sec, nsec)
}

/// Inverse of `civil_from_unix` — Howard Hinnant's `days_from_civil`.
/// Returns Unix days (signed, epoch 1970-01-01).
fn days_from_civil(year: int, month: int, day: int) -> int {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
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

// ─── Parse (slim port of time.Parse) ─────────────────────────────────

/// `time.Parse(layout, value)` (format.go:1232) — slim. Recognizes the
/// canonical reference-time layout constants and parses `value`
/// according to the chosen one. Returns `(t, err)` per goish
/// convention; UTC only.
///
/// Recognized layouts: RFC3339, DateTime, DateOnly, TimeOnly,
/// RFC1123 (assumes "GMT" or arbitrary 3-letter zone), ANSIC.
/// Anything else returns an error.
pub fn Parse(
    layout: crate::gostring::string,
    value: crate::gostring::string,
) -> (Time, crate::errors::error) {
    use crate::gostring::string;

    let l = layout.clone();

    // RFC3339: "2006-01-02T15:04:05Z07:00"
    if l == "2006-01-02T15:04:05Z07:00" {
        return parse_rfc3339(value);
    }
    // DateTime: "2006-01-02 15:04:05"
    if l == "2006-01-02 15:04:05" {
        return parse_datetime(value, b' ');
    }
    // DateOnly: "2006-01-02"
    if l == "2006-01-02" {
        return parse_date_only(value);
    }
    // TimeOnly: "15:04:05" (parsed as today's date at the given time;
    // we use 1970-01-01 since there's no Local in goish slim time).
    if l == "15:04:05" {
        return parse_time_only(value);
    }
    // RFC1123: "Mon, 02 Jan 2006 15:04:05 MST"
    if l == "Mon, 02 Jan 2006 15:04:05 MST" {
        return parse_rfc1123(value);
    }
    // ANSIC: "Mon Jan _2 15:04:05 2006"
    if l == "Mon Jan _2 15:04:05 2006" {
        return parse_ansic(value);
    }

    (
        Time::default(),
        crate::errors::New("time: unsupported layout"),
    )
}

fn parse_rfc3339(s: crate::gostring::string) -> (Time, crate::errors::error) {
    use crate::gostring::string;
    let bs = s.as_bytes();
    // "YYYY-MM-DDTHH:MM:SSZ" minimum. Z may be replaced by ±HH:MM, slim port treats only Z.
    if bs.len() < 20 {
        return (Time::default(), crate::errors::New("time: short RFC3339"));
    }
    if bs[4] != b'-' || bs[7] != b'-' || bs[10] != b'T' || bs[13] != b':' || bs[16] != b':' {
        return (
            Time::default(),
            crate::errors::New("time: malformed RFC3339"),
        );
    }
    let y = match parse_int(&bs[0..4]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let m = match parse_int(&bs[5..7]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let d = match parse_int(&bs[8..10]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let hh = match parse_int(&bs[11..13]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let mm = match parse_int(&bs[14..16]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let ss = match parse_int(&bs[17..19]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    // Trailing Z (UTC) or offset — slim accepts only Z.
    if bs[19] != b'Z' {
        return (
            Time::default(),
            crate::errors::New("time: only UTC (Z) supported in slim Parse"),
        );
    }
    (Date(y, m, d, hh, mm, ss, 0), crate::errors::nil)
}

fn parse_datetime(s: crate::gostring::string, sep: u8) -> (Time, crate::errors::error) {
    use crate::gostring::string;
    let bs = s.as_bytes();
    if bs.len() != 19
        || bs[4] != b'-'
        || bs[7] != b'-'
        || bs[10] != sep
        || bs[13] != b':'
        || bs[16] != b':'
    {
        return (
            Time::default(),
            crate::errors::New("time: malformed DateTime"),
        );
    }
    let y = match parse_int(&bs[0..4]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let m = match parse_int(&bs[5..7]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let d = match parse_int(&bs[8..10]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let hh = match parse_int(&bs[11..13]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let mm = match parse_int(&bs[14..16]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let ss = match parse_int(&bs[17..19]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    (Date(y, m, d, hh, mm, ss, 0), crate::errors::nil)
}

fn parse_date_only(s: crate::gostring::string) -> (Time, crate::errors::error) {
    use crate::gostring::string;
    let bs = s.as_bytes();
    if bs.len() != 10 || bs[4] != b'-' || bs[7] != b'-' {
        return (
            Time::default(),
            crate::errors::New("time: malformed DateOnly"),
        );
    }
    let y = match parse_int(&bs[0..4]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let m = match parse_int(&bs[5..7]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let d = match parse_int(&bs[8..10]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    (Date(y, m, d, 0, 0, 0, 0), crate::errors::nil)
}

fn parse_time_only(s: crate::gostring::string) -> (Time, crate::errors::error) {
    use crate::gostring::string;
    let bs = s.as_bytes();
    if bs.len() != 8 || bs[2] != b':' || bs[5] != b':' {
        return (
            Time::default(),
            crate::errors::New("time: malformed TimeOnly"),
        );
    }
    let hh = match parse_int(&bs[0..2]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let mm = match parse_int(&bs[3..5]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let ss = match parse_int(&bs[6..8]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    (Date(1970, 1, 1, hh, mm, ss, 0), crate::errors::nil)
}

fn parse_rfc1123(s: crate::gostring::string) -> (Time, crate::errors::error) {
    use crate::gostring::string;
    let bs = s.as_bytes();
    // "Day, DD Mon YYYY HH:MM:SS GMT" → 29 chars
    if bs.len() != 29 || bs[3] != b',' || bs[4] != b' ' || bs[7] != b' ' || bs[11] != b' '
        || bs[16] != b' ' || bs[19] != b':' || bs[22] != b':' || bs[25] != b' '
    {
        return (
            Time::default(),
            crate::errors::New("time: malformed RFC1123"),
        );
    }
    let d = match parse_int(&bs[5..7]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let mon = match month_short(&bs[8..11]) {
        Some(v) => v,
        None => {
            return (
                Time::default(),
                crate::errors::New("time: bad month in RFC1123"),
            );
        }
    };
    let y = match parse_int(&bs[12..16]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let hh = match parse_int(&bs[17..19]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let mm = match parse_int(&bs[20..22]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let ss = match parse_int(&bs[23..25]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    (Date(y, mon, d, hh, mm, ss, 0), crate::errors::nil)
}

fn parse_ansic(s: crate::gostring::string) -> (Time, crate::errors::error) {
    use crate::gostring::string;
    let bs = s.as_bytes();
    // "Mon Jan _2 15:04:05 2006" → 24 chars
    if bs.len() != 24
        || bs[3] != b' '
        || bs[7] != b' '
        || bs[10] != b' '
        || bs[13] != b':'
        || bs[16] != b':'
        || bs[19] != b' '
    {
        return (
            Time::default(),
            crate::errors::New("time: malformed ANSIC"),
        );
    }
    let mon = match month_short(&bs[4..7]) {
        Some(v) => v,
        None => {
            return (
                Time::default(),
                crate::errors::New("time: bad month in ANSIC"),
            );
        }
    };
    // _2 form: space-padded day in cols 8..10
    let day_bytes = &bs[8..10];
    let d = if day_bytes[0] == b' ' {
        match parse_int(&day_bytes[1..2]) { Ok(v) => v, Err(e) => return (Time::default(), e) }
    } else {
        match parse_int(day_bytes) { Ok(v) => v, Err(e) => return (Time::default(), e) }
    };
    let hh = match parse_int(&bs[11..13]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let mm = match parse_int(&bs[14..16]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let ss = match parse_int(&bs[17..19]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    let y = match parse_int(&bs[20..24]) { Ok(v) => v, Err(e) => return (Time::default(), e) };
    (Date(y, mon, d, hh, mm, ss, 0), crate::errors::nil)
}

fn parse_int(bs: &[u8]) -> Result<int, crate::errors::error> {
    let mut n: int = 0;
    for &c in bs.iter() {
        if !(b'0'..=b'9').contains(&c) {
            return Err(crate::errors::New("time: non-digit in numeric field"));
        }
        n = n * 10 + (c - b'0') as int;
    }
    Ok(n)
}

// ─── ParseDuration (slim port of time/format.go:1621) ────────────────
//
// Reference: Go 1.25 src/time/format.go:1605-1718. Internal helpers
// `leadingInt` and `leadingFraction` are inlined as fns here.

/// `time.ParseDuration(s)` — parse a duration string.
///
/// A duration string is a possibly signed sequence of decimal numbers,
/// each with optional fraction and a unit suffix, such as "300ms",
/// "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"),
/// "ms", "s", "m", "h".
pub fn ParseDuration(s: crate::gostring::string) -> (Duration, crate::errors::error) {
    use crate::gostring::string;
    use crate::strconv;

    // [-+]?([0-9]*(\.[0-9]*)?[a-z]+)+
    let orig = s.clone();
    let mut cur = s.as_bytes().to_vec();
    let mut d: u64 = 0;
    let mut neg = false;

    // Consume [-+]?
    if !cur.is_empty() {
        let c = cur[0];
        if c == b'-' || c == b'+' {
            neg = c == b'-';
            cur = cur[1..].to_vec();
        }
    }
    // Special case: if all that is left is "0", this is zero.
    if cur.as_slice() == b"0" {
        return (Duration(0), crate::errors::nil);
    }
    if cur.is_empty() {
        return (
            Duration(0),
            crate::errors::New(
                string::from("time: invalid duration ") + strconv::Quote(orig.clone()),
            ),
        );
    }
    while !cur.is_empty() {
        let mut v: u64;
        let mut f: u64 = 0;
        let mut scale: f64 = 1.0; // value = v + f/scale

        // The next character must be [0-9.]
        if !(cur[0] == b'.' || (b'0' <= cur[0] && cur[0] <= b'9')) {
            return (
                Duration(0),
                crate::errors::New(
                    string::from("time: invalid duration ") + strconv::Quote(orig.clone()),
                ),
            );
        }
        // Consume [0-9]*
        let pl = cur.len();
        let (vv, rem, err) = leading_int(&cur);
        if !err.IsNil() {
            return (
                Duration(0),
                crate::errors::New(
                    string::from("time: invalid duration ") + strconv::Quote(orig.clone()),
                ),
            );
        }
        v = vv;
        cur = rem;
        let pre = pl != cur.len(); // whether we consumed anything before a period

        // Consume (\.[0-9]*)?
        let mut post = false;
        if !cur.is_empty() && cur[0] == b'.' {
            cur = cur[1..].to_vec();
            let pl = cur.len();
            let (ff, sc, rem) = leading_fraction(&cur);
            f = ff;
            scale = sc;
            cur = rem;
            post = pl != cur.len();
        }
        if !pre && !post {
            // no digits (e.g. ".s" or "-.s")
            return (
                Duration(0),
                crate::errors::New(
                    string::from("time: invalid duration ") + strconv::Quote(orig.clone()),
                ),
            );
        }

        // Consume unit.
        let mut i = 0usize;
        while i < cur.len() {
            let c = cur[i];
            if c == b'.' || (b'0' <= c && c <= b'9') {
                break;
            }
            i += 1;
        }
        if i == 0 {
            return (
                Duration(0),
                crate::errors::New(
                    string::from("time: missing unit in duration ")
                        + strconv::Quote(orig.clone()),
                ),
            );
        }
        let u = &cur[..i];
        let unit = match unit_lookup(u) {
            Some(n) => n,
            None => {
                return (
                    Duration(0),
                    crate::errors::New(
                        string::from("time: unknown unit ")
                            + strconv::Quote(string::from_bytes(u))
                            + string::from(" in duration ")
                            + strconv::Quote(orig.clone()),
                    ),
                );
            }
        };
        cur = cur[i..].to_vec();
        if v > (1u64 << 63) / unit {
            // overflow
            return (
                Duration(0),
                crate::errors::New(
                    string::from("time: invalid duration ") + strconv::Quote(orig.clone()),
                ),
            );
        }
        v = v.wrapping_mul(unit);
        if f > 0 {
            // float64 is needed to be nanosecond accurate for fractions of hours.
            v = v.wrapping_add(((f as f64) * (unit as f64 / scale)) as u64);
            if v > 1u64 << 63 {
                // overflow
                return (
                    Duration(0),
                    crate::errors::New(
                        string::from("time: invalid duration ") + strconv::Quote(orig.clone()),
                    ),
                );
            }
        }
        d = d.wrapping_add(v);
        if d > 1u64 << 63 {
            return (
                Duration(0),
                crate::errors::New(
                    string::from("time: invalid duration ") + strconv::Quote(orig.clone()),
                ),
            );
        }
    }
    if neg {
        return (Duration(-(d as i128) as int), crate::errors::nil);
    }
    if d > (1u64 << 63) - 1 {
        return (
            Duration(0),
            crate::errors::New(
                string::from("time: invalid duration ") + strconv::Quote(orig),
            ),
        );
    }
    (Duration(d as int), crate::errors::nil)
}

/// Mirrors Go's `unitMap` (format.go:1605). Each unit's value is the
/// number of nanoseconds it represents.
fn unit_lookup(u: &[u8]) -> Option<u64> {
    match u {
        b"ns" => Some(1),
        b"us" => Some(1_000),
        // "µs" — U+00B5 (0xC2 0xB5)
        [0xC2, 0xB5, b's'] => Some(1_000),
        // "μs" — U+03BC (0xCE 0xBC)
        [0xCE, 0xBC, b's'] => Some(1_000),
        b"ms" => Some(1_000_000),
        b"s" => Some(1_000_000_000),
        b"m" => Some(60 * 1_000_000_000),
        b"h" => Some(60 * 60 * 1_000_000_000),
        _ => None,
    }
}

/// `leadingInt` — consume the leading [0-9]* from `s`. Returns
/// `(x, rem, err)`.
///
/// Mirrors format.go:1554. Returns error on overflow (caller treats
/// it as "invalid duration"); rem is the unconsumed tail.
fn leading_int(s: &[u8]) -> (u64, alloc::vec::Vec<u8>, crate::errors::error) {
    let mut x: u64 = 0;
    let mut i = 0usize;
    while i < s.len() {
        let c = s[i];
        if c < b'0' || c > b'9' {
            break;
        }
        if x > (1u64 << 63) / 10 {
            // overflow
            return (
                0,
                s.to_vec(),
                crate::errors::New(crate::gostring::string::from("time: bad [0-9]*")),
            );
        }
        x = x * 10 + (c - b'0') as u64;
        if x > 1u64 << 63 {
            // overflow
            return (
                0,
                s.to_vec(),
                crate::errors::New(crate::gostring::string::from("time: bad [0-9]*")),
            );
        }
        i += 1;
    }
    (x, s[i..].to_vec(), crate::errors::nil)
}

/// `leadingFraction` — consume the leading [0-9]* from `s` as a
/// fraction. Mirrors format.go:1577. No error on overflow; precision
/// just stops accumulating.
fn leading_fraction(s: &[u8]) -> (u64, f64, alloc::vec::Vec<u8>) {
    let mut x: u64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    let mut i = 0usize;
    while i < s.len() {
        let c = s[i];
        if c < b'0' || c > b'9' {
            break;
        }
        if !overflow {
            if x > ((1u64 << 63) - 1) / 10 {
                // It's possible for overflow to give a positive number,
                // so take care.
                overflow = true;
            } else {
                let y = x * 10 + (c - b'0') as u64;
                if y > 1u64 << 63 {
                    overflow = true;
                } else {
                    x = y;
                    scale *= 10.0;
                }
            }
        }
        i += 1;
    }
    (x, scale, s[i..].to_vec())
}

fn month_short(bs: &[u8]) -> Option<int> {
    match bs {
        b"Jan" => Some(1),
        b"Feb" => Some(2),
        b"Mar" => Some(3),
        b"Apr" => Some(4),
        b"May" => Some(5),
        b"Jun" => Some(6),
        b"Jul" => Some(7),
        b"Aug" => Some(8),
        b"Sep" => Some(9),
        b"Oct" => Some(10),
        b"Nov" => Some(11),
        b"Dec" => Some(12),
        _ => None,
    }
}
