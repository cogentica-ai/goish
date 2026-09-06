// go: file time/format.go decls: startsWithLowerCase, nextStdChunk, ParseError.Error, newParseError, quote, atoi, getnum, getnum3, cutspace, skip, commaOrPeriod, parseNanoseconds, parseTimeZone, parseGMT, parseSignedOffset, Parse, ParseInLocation, parse, match, lookup, appendInt, stdFracSecond, digitsLen, separator, appendNano, Time.String, Time.Format, Time.AppendFormat, Time.appendFormat, ParseDuration, unitMap, leadingInt, leadingFraction
// goishlint:ignore GOISH018 errBad — Go's `errBad` is a sentinel
// error returned by the parse helpers and compared by identity; it is
// never shown to a caller. goish's helpers return a bool for the same
// signal, so there is nothing to construct.
//
// format.go — the reference-time layout constants, the name tables,
// Format/AppendFormat, Parse, Duration.String and ParseDuration.

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
use super::time_go::civil_from_unix;
#[allow(unused_imports)]
use super::*;

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

// Long-name lookup tables used by Month::String / Weekday::String.
// Mirrors Go's longMonthNames + longDayNames in time/format.go.
// go: sdk 1.25.5 time/format.go:372-385 longMonthNames
pub(crate) const longMonthNames: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

// go: sdk 1.25.5 time/format.go:357-370 shortMonthNames
pub(crate) const shortMonthNames: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
// go: sdk 1.25.5 time/format.go:347-355 shortDayNames
pub(crate) const shortDayNames: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
// go: sdk 1.25.5 time/format.go:337-345 longDayNames
pub(crate) const longDayNames: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

// go: none — goish idiom: Go emits a fixed-width number with
//     `appendInt(b, x, width)` straight into the output buffer; goish's
//     formatter builds small fixed arrays instead, so the two widths it
//     ever needs are their own functions.
// ─── The std chunk vocabulary ─────────────────────────────────────────
//
// Go encodes each layout element as an `int` whose low bits name the
// element and whose high bits carry two extra fields for fractional
// seconds. goish keeps the same encoding so the two files compare line
// for line.

// go: sdk 1.25.5 time/format.go:132-176 stdNeedDate
pub(crate) const stdNeedDate: int = 1 << 8; // need month, day, year
                                            // go: sdk 1.25.5 time/format.go:132-176 stdNeedYday
pub(crate) const stdNeedYday: int = 1 << 9; // need yday
                                            // go: sdk 1.25.5 time/format.go:132-176 stdNeedClock
pub(crate) const stdNeedClock: int = 1 << 10; // need hour, minute, second
                                              // go: sdk 1.25.5 time/format.go:132-176 stdArgShift
pub(crate) const stdArgShift: int = 16; // extra argument in high bits
                                        // go: sdk 1.25.5 time/format.go:132-176 stdSeparatorShift
pub(crate) const stdSeparatorShift: int = 28; // fractional-second separator
                                              // go: sdk 1.25.5 time/format.go:132-176 stdMask
pub(crate) const stdMask: int = (1 << stdArgShift) - 1; // mask out argument

// go: sdk 1.25.5 time/format.go:132-176 stdLongMonth
pub(crate) const stdLongMonth: int = 1 + stdNeedDate; // "January"
                                                      // go: sdk 1.25.5 time/format.go:132-176 stdMonth
pub(crate) const stdMonth: int = 2 + stdNeedDate; // "Jan"
                                                  // go: sdk 1.25.5 time/format.go:132-176 stdNumMonth
pub(crate) const stdNumMonth: int = 3 + stdNeedDate; // "1"
                                                     // go: sdk 1.25.5 time/format.go:132-176 stdZeroMonth
pub(crate) const stdZeroMonth: int = 4 + stdNeedDate; // "01"
                                                      // go: sdk 1.25.5 time/format.go:132-176 stdLongWeekDay
pub(crate) const stdLongWeekDay: int = 5 + stdNeedDate; // "Monday"
                                                        // go: sdk 1.25.5 time/format.go:132-176 stdWeekDay
pub(crate) const stdWeekDay: int = 6 + stdNeedDate; // "Mon"
                                                    // go: sdk 1.25.5 time/format.go:132-176 stdDay
pub(crate) const stdDay: int = 7 + stdNeedDate; // "2"
                                                // go: sdk 1.25.5 time/format.go:132-176 stdUnderDay
pub(crate) const stdUnderDay: int = 8 + stdNeedDate; // "_2"
                                                     // go: sdk 1.25.5 time/format.go:132-176 stdZeroDay
pub(crate) const stdZeroDay: int = 9 + stdNeedDate; // "02"
                                                    // go: sdk 1.25.5 time/format.go:132-176 stdUnderYearDay
pub(crate) const stdUnderYearDay: int = 10 + stdNeedYday; // "__2"
                                                          // go: sdk 1.25.5 time/format.go:132-176 stdZeroYearDay
pub(crate) const stdZeroYearDay: int = 11 + stdNeedYday; // "002"
                                                         // go: sdk 1.25.5 time/format.go:132-176 stdHour
pub(crate) const stdHour: int = 12 + stdNeedClock; // "15"
                                                   // go: sdk 1.25.5 time/format.go:132-176 stdHour12
pub(crate) const stdHour12: int = 13 + stdNeedClock; // "3"
                                                     // go: sdk 1.25.5 time/format.go:132-176 stdZeroHour12
pub(crate) const stdZeroHour12: int = 14 + stdNeedClock; // "03"
                                                         // go: sdk 1.25.5 time/format.go:132-176 stdMinute
pub(crate) const stdMinute: int = 15 + stdNeedClock; // "4"
                                                     // go: sdk 1.25.5 time/format.go:132-176 stdZeroMinute
pub(crate) const stdZeroMinute: int = 16 + stdNeedClock; // "04"
                                                         // go: sdk 1.25.5 time/format.go:132-176 stdSecond
pub(crate) const stdSecond: int = 17 + stdNeedClock; // "5"
                                                     // go: sdk 1.25.5 time/format.go:132-176 stdZeroSecond
pub(crate) const stdZeroSecond: int = 18 + stdNeedClock; // "05"
                                                         // go: sdk 1.25.5 time/format.go:132-176 stdLongYear
pub(crate) const stdLongYear: int = 19 + stdNeedDate; // "2006"
                                                      // go: sdk 1.25.5 time/format.go:132-176 stdYear
pub(crate) const stdYear: int = 20 + stdNeedDate; // "06"
                                                  // go: sdk 1.25.5 time/format.go:132-176 stdPM
pub(crate) const stdPM: int = 21 + stdNeedClock; // "PM"
                                                 // go: sdk 1.25.5 time/format.go:132-176 stdpm
pub(crate) const stdpm: int = 22 + stdNeedClock; // "pm"
                                                 // go: sdk 1.25.5 time/format.go:132-176 stdTZ
pub(crate) const stdTZ: int = 23; // "MST"
                                  // go: sdk 1.25.5 time/format.go:132-176 stdISO8601TZ
pub(crate) const stdISO8601TZ: int = 24; // "Z0700"  — prints Z for UTC
                                         // go: sdk 1.25.5 time/format.go:132-176 stdISO8601SecondsTZ
pub(crate) const stdISO8601SecondsTZ: int = 25; // "Z070000"
                                                // go: sdk 1.25.5 time/format.go:132-176 stdISO8601ShortTZ
pub(crate) const stdISO8601ShortTZ: int = 26; // "Z07"
                                              // go: sdk 1.25.5 time/format.go:132-176 stdISO8601ColonTZ
pub(crate) const stdISO8601ColonTZ: int = 27; // "Z07:00" — prints Z for UTC
                                              // go: sdk 1.25.5 time/format.go:132-176 stdISO8601ColonSecondsTZ
pub(crate) const stdISO8601ColonSecondsTZ: int = 28; // "Z07:00:00"
                                                     // go: sdk 1.25.5 time/format.go:132-176 stdNumTZ
pub(crate) const stdNumTZ: int = 29; // "-0700"  — always numeric
                                     // go: sdk 1.25.5 time/format.go:132-176 stdNumSecondsTz
pub(crate) const stdNumSecondsTz: int = 30; // "-070000"
                                            // go: sdk 1.25.5 time/format.go:132-176 stdNumShortTZ
pub(crate) const stdNumShortTZ: int = 31; // "-07"    — always numeric
                                          // go: sdk 1.25.5 time/format.go:132-176 stdNumColonTZ
pub(crate) const stdNumColonTZ: int = 32; // "-07:00" — always numeric
                                          // go: sdk 1.25.5 time/format.go:132-176 stdNumColonSecondsTZ
pub(crate) const stdNumColonSecondsTZ: int = 33; // "-07:00:00"
                                                 // go: sdk 1.25.5 time/format.go:132-176 stdFracSecond0
pub(crate) const stdFracSecond0: int = 34; // ".0", ".00" — trailing zeros kept
                                           // go: sdk 1.25.5 time/format.go:132-176 stdFracSecond9
pub(crate) const stdFracSecond9: int = 35; // ".9", ".99" — trailing zeros dropped

// go: sdk 1.25.5 time/format.go:179-179 std0x
/// The std values for "01", "02", ..., "06".
const std0x: [int; 6] = [
    stdZeroMonth,
    stdZeroDay,
    stdZeroHour12,
    stdZeroMinute,
    stdZeroSecond,
    stdYear,
];

// go: sdk 1.25.5 time/format.go:183-189 startsWithLowerCase
/// Reports whether the string has a lower-case letter at the beginning.
/// Its purpose is to prevent matching strings like "Month" when looking
/// for "Mon".
fn startsWithLowerCase(str: &[u8]) -> bool {
    if str.is_empty() {
        return false;
    }
    let c = str[0];
    return b'a' <= c && c <= b'z';
}

// go: none — goish idiom: Go slices a `string` for free; goish's
//     `nextStdChunk` walks a `&[u8]` and this is the `layout[i:i+n] ==
//     lit` comparison spelled once.
fn has(layout: &[u8], i: usize, lit: &[u8]) -> bool {
    return layout.len() >= i + lit.len() && &layout[i..i + lit.len()] == lit;
}

// go: sdk 1.25.5 time/format.go:203-336 nextStdChunk
/// Finds the first occurrence of a std string in `layout` and returns
/// the text before, the std value, and the text after.
pub(crate) fn nextStdChunk(layout: &[u8]) -> (usize, int, usize) {
    // Go returns three strings; goish returns the two split indices —
    // prefix is layout[..p], suffix is layout[s..] — because a Rust
    // slice cannot outlive the borrow the caller already holds.
    let mut i: usize = 0;
    while i < layout.len() {
        let c = layout[i];
        match c {
            // January, Jan
            b'J' => {
                if has(layout, i, b"Jan") {
                    if has(layout, i, b"January") {
                        return (i, stdLongMonth, i + 7);
                    }
                    if !startsWithLowerCase(&layout[i + 3..]) {
                        return (i, stdMonth, i + 3);
                    }
                }
            }
            // Monday, Mon, MST
            b'M' => {
                if layout.len() >= i + 3 {
                    if has(layout, i, b"Mon") {
                        if has(layout, i, b"Monday") {
                            return (i, stdLongWeekDay, i + 6);
                        }
                        if !startsWithLowerCase(&layout[i + 3..]) {
                            return (i, stdWeekDay, i + 3);
                        }
                    }
                    if has(layout, i, b"MST") {
                        return (i, stdTZ, i + 3);
                    }
                }
            }
            // 01, 02, 03, 04, 05, 06, 002
            b'0' => {
                if layout.len() >= i + 2 && b'1' <= layout[i + 1] && layout[i + 1] <= b'6' {
                    return (i, std0x[(layout[i + 1] - b'1') as usize], i + 2);
                }
                if layout.len() >= i + 3 && layout[i + 1] == b'0' && layout[i + 2] == b'2' {
                    return (i, stdZeroYearDay, i + 3);
                }
            }
            // 15, 1
            b'1' => {
                if layout.len() >= i + 2 && layout[i + 1] == b'5' {
                    return (i, stdHour, i + 2);
                }
                return (i, stdNumMonth, i + 1);
            }
            // 2006, 2
            b'2' => {
                if has(layout, i, b"2006") {
                    return (i, stdLongYear, i + 4);
                }
                return (i, stdDay, i + 1);
            }
            // _2, _2006, __2
            b'_' => {
                if layout.len() >= i + 2 && layout[i + 1] == b'2' {
                    // _2006 is really a literal _, followed by stdLongYear
                    if has(layout, i + 1, b"2006") {
                        return (i + 1, stdLongYear, i + 5);
                    }
                    return (i, stdUnderDay, i + 2);
                }
                if layout.len() >= i + 3 && layout[i + 1] == b'_' && layout[i + 2] == b'2' {
                    return (i, stdUnderYearDay, i + 3);
                }
            }
            b'3' => return (i, stdHour12, i + 1),
            b'4' => return (i, stdMinute, i + 1),
            b'5' => return (i, stdSecond, i + 1),
            // PM
            b'P' => {
                if layout.len() >= i + 2 && layout[i + 1] == b'M' {
                    return (i, stdPM, i + 2);
                }
            }
            // pm
            b'p' => {
                if layout.len() >= i + 2 && layout[i + 1] == b'm' {
                    return (i, stdpm, i + 2);
                }
            }
            // -070000, -07:00:00, -0700, -07:00, -07
            b'-' => {
                if has(layout, i, b"-070000") {
                    return (i, stdNumSecondsTz, i + 7);
                }
                if has(layout, i, b"-07:00:00") {
                    return (i, stdNumColonSecondsTZ, i + 9);
                }
                if has(layout, i, b"-0700") {
                    return (i, stdNumTZ, i + 5);
                }
                if has(layout, i, b"-07:00") {
                    return (i, stdNumColonTZ, i + 6);
                }
                if has(layout, i, b"-07") {
                    return (i, stdNumShortTZ, i + 3);
                }
            }
            // Z070000, Z07:00:00, Z0700, Z07:00, Z07
            b'Z' => {
                if has(layout, i, b"Z070000") {
                    return (i, stdISO8601SecondsTZ, i + 7);
                }
                if has(layout, i, b"Z07:00:00") {
                    return (i, stdISO8601ColonSecondsTZ, i + 9);
                }
                if has(layout, i, b"Z0700") {
                    return (i, stdISO8601TZ, i + 5);
                }
                if has(layout, i, b"Z07:00") {
                    return (i, stdISO8601ColonTZ, i + 6);
                }
                if has(layout, i, b"Z07") {
                    return (i, stdISO8601ShortTZ, i + 3);
                }
            }
            // ,000 or .000 or ,999 or .999 — repeated digits for
            // fractional seconds.
            b'.' | b',' => {
                if i + 1 < layout.len() && (layout[i + 1] == b'0' || layout[i + 1] == b'9') {
                    let ch = layout[i + 1];
                    let mut j = i + 1;
                    while j < layout.len() && layout[j] == ch {
                        j += 1;
                    }
                    // The string of digits must end here — only a
                    // fractional second is all digits.
                    if !isDigit(layout, j) {
                        let mut code = stdFracSecond0;
                        if layout[i + 1] == b'9' {
                            code = stdFracSecond9;
                        }
                        let std = stdFracSecond(code, toint(j - (i + 1)), toint(c));
                        return (i, std, j);
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    return (layout.len(), 0, layout.len());
}

// go: sdk 1.25.5 time/format.go:390-404 match
/// Reports whether `s1` and `s2` match ignoring case. It is assumed
/// they are the same length.
fn match_(s1: &[u8], s2: &[u8]) -> bool {
    let mut i = 0;
    while i < s1.len() {
        let mut c1 = s1[i];
        let mut c2 = s2[i];
        if c1 != c2 {
            // Switch to lower-case; 'a'-'A' is known to be a single bit.
            c1 |= b'a' - b'A';
            c2 |= b'a' - b'A';
            if c1 != c2 || c1 < b'a' || c1 > b'z' {
                return false;
            }
        }
        i += 1;
    }
    return true;
}

// go: sdk 1.25.5 time/format.go:406-413 lookup
/// Finds the first entry of `tab` that prefixes `val`, case-insensitively.
/// Returns its index and the number of bytes consumed, or `None`.
pub(crate) fn lookup(tab: &[&str], val: &[u8]) -> Option<(int, usize)> {
    let mut i = 0;
    while i < tab.len() {
        let v = tab[i].as_bytes();
        if val.len() >= v.len() && match_(&val[..v.len()], v) {
            return Some((toint(i), v.len()));
        }
        i += 1;
    }
    return None;
}

// go: sdk 1.25.5 time/format.go:412-465 appendInt
/// Appends the decimal form of `x` to `b`. If the decimal form
/// (excluding sign) is shorter than `width`, it is padded with leading
/// zeros. Go notes this duplicates strconv to avoid the dependency;
/// goish keeps the duplicate so the two files compare line for line.
pub(crate) fn appendInt(b: &mut alloc::vec::Vec<crate::types::byte>, x: int, width: usize) {
    let mut u = touint64(x);
    if x < 0 {
        b.push(b'-');
        u = touint64(x).wrapping_neg();
    }

    // Compute the number of decimal digits.
    let mut n = 0usize;
    if u == 0 {
        n = 1;
    }
    let mut u2 = u;
    while u2 > 0 {
        n += 1;
        u2 /= 10;
    }

    // Add 0-padding.
    let mut pad = width;
    while pad > n {
        b.push(b'0');
        pad -= 1;
    }

    // Assemble the decimal in reverse order.
    let start = b.len();
    b.resize(start + n, b'0');
    let mut i = start + n - 1;
    while u >= 10 {
        let q = u / 10;
        b[i] = b'0' + tobyte(u - q * 10);
        u = q;
        i -= 1;
    }
    b[i] = b'0' + tobyte(u);
}

// go: sdk 1.25.5 time/format.go:491-497 stdFracSecond
/// The `std` value for a fractional second packs two extra fields
/// above `stdArgShift`: the number of digits after the decimal, and
/// which separator (period or comma) introduced it.
pub(crate) fn stdFracSecond(code: int, n: int, c: int) -> int {
    // Use 0xfff to make the failure case even more absurd.
    if c == toint(b'.') {
        return code | ((n & 0xfff) << stdArgShift);
    }
    return code | ((n & 0xfff) << stdArgShift) | (1 << stdSeparatorShift);
}

// go: sdk 1.25.5 time/format.go:499-501 digitsLen
pub(crate) fn digitsLen(std: int) -> int {
    return (std >> stdArgShift) & 0xfff;
}

// go: sdk 1.25.5 time/format.go:503-508 separator
pub(crate) fn separator(std: int) -> crate::types::byte {
    if (std >> stdSeparatorShift) == 0 {
        return b'.';
    }
    return b',';
}

// go: sdk 1.25.5 time/format.go:512-533 appendNano
/// Appends a fractional second, as nanoseconds, to `b`. The nanosecond
/// value must be within [0, 999999999].
fn appendNano(b: &mut Vec<crate::types::byte>, nanosec: int, std: int) {
    let trim = std & stdMask == stdFracSecond9;
    let n = digitsLen(std);
    if trim && (n == 0 || nanosec == 0) {
        return;
    }
    let dot = separator(std);
    b.push(dot);
    appendInt(b, nanosec, 9);
    if n < 9 {
        let keep = b.len() - 9 + (n as usize);
        b.truncate(keep);
    }
    if trim {
        while !b.is_empty() && b[b.len() - 1] == b'0' {
            b.pop();
        }
        if !b.is_empty() && b[b.len() - 1] == dot {
            b.pop();
        }
    }
}

// go: none — goish idiom: Go asks the layout scanner whether the run of
//     digits it just walked ends there, using `isDigit(layout, j)` over
//     the generic `[]byte | string`. goish's scanner is byte-only.
fn isDigit(s: &[u8], i: usize) -> bool {
    if s.len() <= i {
        return false;
    }
    let c = s[i];
    return b'0' <= c && c <= b'9';
}

// ─── Format ───────────────────────────────────────────────────────────

impl Time {
    // go: sdk 1.25.5 time/format.go:546-573 Time.String
    /// `t.String()` — the default rendering, and the one every
    /// `fmt.Println(t)` reaches. Not a separate renderer: Go calls
    /// `Format` with one fixed layout and appends the monotonic
    /// reading when there is one.
    pub fn String(self) -> crate::gostring::string {
        // Go: s := t.Format("2006-01-02 15:04:05.999999999 -0700 MST")
        let s = self.Format("2006-01-02 15:04:05.999999999 -0700 MST");

        // Go: format the monotonic clock reading as m=±ddd.nnnnnnnnn.
        if self.__mono() == 0 {
            return s;
        }
        let m = self.__mono();
        let sign: crate::types::byte = if m < 0 { b'-' } else { b'+' };
        let mut m2 = if m < 0 {
            touint64(m).wrapping_neg()
        } else {
            touint64(m)
        };
        let mut m1 = m2 / 1_000_000_000;
        m2 %= 1_000_000_000;
        let m0 = m1 / 1_000_000_000;
        m1 %= 1_000_000_000;
        let mut buf: alloc::vec::Vec<crate::types::byte> = alloc::vec::Vec::with_capacity(24);
        buf.extend_from_slice(b" m=");
        buf.push(sign);
        let mut wid = 0usize;
        if m0 != 0 {
            appendInt(&mut buf, toint(m0), 0);
            wid = 9;
        }
        appendInt(&mut buf, toint(m1), wid);
        buf.push(b'.');
        appendInt(&mut buf, toint(m2), 9);
        return s + crate::gostring::string::__from_vec(buf);
    }

    // go: sdk 1.25.5 time/format.go:639-651 Time.Format
    /// `t.Format(layout)` — render `t` in the given layout. The layout
    /// is any reference-time layout, scanned chunk by chunk by
    /// `nextStdChunk`, exactly as Go does.
    pub fn Format<S: Into<crate::gostring::string>>(self, layout: S) -> crate::gostring::string {
        let layout: crate::gostring::string = layout.into();
        // Go sizes the buffer with `len(layout) + 10`.
        let mut b: Vec<crate::types::byte> = Vec::with_capacity(layout.as_bytes().len() + 10);
        self.appendFormat(&mut b, layout.as_bytes());
        return crate::gostring::string::__from_vec(b);
    }

    // go: sdk 1.25.5 time/format.go:655-664 Time.AppendFormat
    /// `t.AppendFormat(b, layout)` — append the formatted time to `b`
    /// and return the extended buffer.
    pub fn AppendFormat<L: Into<crate::gostring::string>>(
        self,
        b: crate::goslice::slice<crate::types::byte>,
        layout: L,
    ) -> crate::goslice::slice<crate::types::byte> {
        let layout: crate::gostring::string = layout.into();
        let mut v = b.__into_vec();
        self.appendFormat(&mut v, layout.as_bytes());
        return crate::goslice::slice::__from_vec(v);
    }

    // go: sdk 1.25.5 time/format.go:667-836 Time.appendFormat
    /// The layout walk itself. Go reads the zone name and offset from
    /// `t.locabs()`; goish reads them from the Time's own `Location`,
    /// which is what makes `-0700` render the real offset and the `Z…`
    /// forms render "Z" only when that offset is zero.
    ///
    /// Both were hardcoded to ("UTC", 0) before, so a Time carrying an
    /// offset — one parsed out of an RFC 3339 string, say — rendered as
    /// if it were UTC.
    fn appendFormat(self, b: &mut Vec<crate::types::byte>, layout: &[u8]) {
        // Go: name, offset, abs := t.locabs()
        let loc = self.Location();
        let name: &[u8] = loc.__abbrev();
        let offset: int = loc.__offset();

        let mut year: int = -1;
        let mut month: int = 0;
        let mut day: int = 0;
        let mut yday: int = -1;
        let mut hour: int = -1;
        let mut min: int = 0;
        let mut sec: int = 0;

        let mut layout = layout;
        // Each iteration generates one std value.
        while !layout.is_empty() {
            let (p, std, s) = nextStdChunk(layout);
            if p > 0 {
                b.extend_from_slice(&layout[..p]);
            }
            if std == 0 {
                break;
            }
            layout = &layout[s..];

            // Compute year, month, day if needed.
            if year < 0 && std & stdNeedDate != 0 {
                let (y, m, d, _, _, _) = civil_from_unix(self.locSec());
                year = y;
                month = m;
                day = d;
            }
            if yday < 0 && std & stdNeedYday != 0 {
                yday = self.YearDay();
            }
            // Compute hour, minute, second if needed.
            if hour < 0 && std & stdNeedClock != 0 {
                let (_, _, _, hh, mm, ss) = civil_from_unix(self.locSec());
                hour = hh;
                min = mm;
                sec = ss;
            }

            match std & stdMask {
                x if x == stdYear => {
                    let mut y = year;
                    if y < 0 {
                        y = -y;
                    }
                    appendInt(b, y % 100, 2);
                }
                x if x == stdLongYear => appendInt(b, year, 4),
                x if x == stdMonth => {
                    b.extend_from_slice(&longMonthNames[(month - 1) as usize].as_bytes()[..3])
                }
                x if x == stdLongMonth => {
                    b.extend_from_slice(longMonthNames[(month - 1) as usize].as_bytes())
                }
                x if x == stdNumMonth => appendInt(b, month, 0),
                x if x == stdZeroMonth => appendInt(b, month, 2),
                x if x == stdWeekDay => b.extend_from_slice(
                    &longDayNames[self.Weekday().Int() as usize].as_bytes()[..3],
                ),
                x if x == stdLongWeekDay => {
                    b.extend_from_slice(longDayNames[self.Weekday().Int() as usize].as_bytes())
                }
                x if x == stdDay => appendInt(b, day, 0),
                x if x == stdUnderDay => {
                    if day < 10 {
                        b.push(b' ');
                    }
                    appendInt(b, day, 0);
                }
                x if x == stdZeroDay => appendInt(b, day, 2),
                x if x == stdUnderYearDay => {
                    if yday < 100 {
                        b.push(b' ');
                        if yday < 10 {
                            b.push(b' ');
                        }
                    }
                    appendInt(b, yday, 0);
                }
                x if x == stdZeroYearDay => appendInt(b, yday, 3),
                x if x == stdHour => appendInt(b, hour, 2),
                x if x == stdHour12 => {
                    // Noon is 12PM, midnight is 12AM.
                    let mut hr = hour % 12;
                    if hr == 0 {
                        hr = 12;
                    }
                    appendInt(b, hr, 0);
                }
                x if x == stdZeroHour12 => {
                    let mut hr = hour % 12;
                    if hr == 0 {
                        hr = 12;
                    }
                    appendInt(b, hr, 2);
                }
                x if x == stdMinute => appendInt(b, min, 0),
                x if x == stdZeroMinute => appendInt(b, min, 2),
                x if x == stdSecond => appendInt(b, sec, 0),
                x if x == stdZeroSecond => appendInt(b, sec, 2),
                x if x == stdPM => {
                    if hour >= 12 {
                        b.extend_from_slice(b"PM");
                    } else {
                        b.extend_from_slice(b"AM");
                    }
                }
                x if x == stdpm => {
                    if hour >= 12 {
                        b.extend_from_slice(b"pm");
                    } else {
                        b.extend_from_slice(b"am");
                    }
                }
                x if x == stdISO8601TZ
                    || x == stdISO8601ColonTZ
                    || x == stdISO8601SecondsTZ
                    || x == stdISO8601ShortTZ
                    || x == stdISO8601ColonSecondsTZ
                    || x == stdNumTZ
                    || x == stdNumColonTZ
                    || x == stdNumSecondsTz
                    || x == stdNumShortTZ
                    || x == stdNumColonSecondsTZ =>
                {
                    // Ugly special case. We cheat and take the "Z"
                    // variants to mean "the time zone as formatted for
                    // ISO 8601".
                    if offset == 0
                        && (std == stdISO8601TZ
                            || std == stdISO8601ColonTZ
                            || std == stdISO8601SecondsTZ
                            || std == stdISO8601ShortTZ
                            || std == stdISO8601ColonSecondsTZ)
                    {
                        b.push(b'Z');
                    } else {
                        let mut zone = offset / 60; // convert to minutes
                        let mut absoffset = offset;
                        if zone < 0 {
                            b.push(b'-');
                            zone = -zone;
                            absoffset = -absoffset;
                        } else {
                            b.push(b'+');
                        }
                        appendInt(b, zone / 60, 2);
                        if std == stdISO8601ColonTZ
                            || std == stdNumColonTZ
                            || std == stdISO8601ColonSecondsTZ
                            || std == stdNumColonSecondsTZ
                        {
                            b.push(b':');
                        }
                        if std != stdNumShortTZ && std != stdISO8601ShortTZ {
                            appendInt(b, zone % 60, 2);
                        }
                        // Append seconds if appropriate.
                        if std == stdISO8601SecondsTZ
                            || std == stdNumSecondsTz
                            || std == stdNumColonSecondsTZ
                            || std == stdISO8601ColonSecondsTZ
                        {
                            if std == stdNumColonSecondsTZ || std == stdISO8601ColonSecondsTZ {
                                b.push(b':');
                            }
                            appendInt(b, absoffset % 60, 2);
                        }
                    }
                }
                x if x == stdTZ => {
                    if !name.is_empty() {
                        b.extend_from_slice(name);
                    } else {
                        // No time zone known for this time, but we must
                        // print one. Use the -0700 format.
                        let mut zone = offset / 60;
                        if zone < 0 {
                            b.push(b'-');
                            zone = -zone;
                        } else {
                            b.push(b'+');
                        }
                        appendInt(b, zone / 60, 2);
                        appendInt(b, zone % 60, 2);
                    }
                }
                x if x == stdFracSecond0 || x == stdFracSecond9 => {
                    appendNano(b, self.Nanosecond(), std)
                }
                _ => {}
            }
        }
    }
}

// ─── Parse ────────────────────────────────────────────────────────────

// go: sdk 1.25.5 time/format.go:840-848 ParseError
/// Describes a problem parsing a time string.
pub struct ParseError {
    pub Layout: crate::gostring::string,
    pub Value: crate::gostring::string,
    pub LayoutElem: crate::gostring::string,
    pub ValueElem: crate::gostring::string,
    pub Message: crate::gostring::string,
}

// go: sdk 1.25.5 time/format.go:850-855 newParseError
fn newParseError(
    layout: &[u8],
    value: &[u8],
    layoutElem: &[u8],
    valueElem: &[u8],
    message: &str,
) -> crate::error {
    return crate::errors::Wrap(ParseError {
        Layout: crate::gostring::string::from_bytes(layout),
        Value: crate::gostring::string::from_bytes(value),
        LayoutElem: crate::gostring::string::from_bytes(layoutElem),
        ValueElem: crate::gostring::string::from_bytes(valueElem),
        Message: crate::gostring::string::from_bytes(message.as_bytes()),
    });
}

impl crate::errors::ErrorTrait for ParseError {
    // go: sdk 1.25.5 time/format.go:902-912 ParseError.Error
    fn Error(&self) -> crate::gostring::string {
        if self.Message.as_bytes().is_empty() {
            return crate::gostring::string::from("parsing time ")
                + quote(self.Value.as_bytes())
                + crate::gostring::string::from(" as ")
                + quote(self.Layout.as_bytes())
                + crate::gostring::string::from(": cannot parse ")
                + quote(self.ValueElem.as_bytes())
                + crate::gostring::string::from(" as ")
                + quote(self.LayoutElem.as_bytes());
        }
        return crate::gostring::string::from("parsing time ")
            + quote(self.Value.as_bytes())
            + self.Message.clone();
    }
}

// go: sdk 1.25.5 time/format.go:865-899 quote
/// Go's own quoting, which duplicates strconv to avoid the dependency.
/// Anything below a space or at or above 0x80 becomes `\xHH`.
fn quote(s: &[u8]) -> crate::gostring::string {
    let mut buf: Vec<crate::types::byte> = Vec::with_capacity(s.len() + 2);
    buf.push(b'"');
    let mut i = 0usize;
    while i < s.len() {
        let c = s[i];
        if c >= 0x80 || c < b' ' {
            buf.extend_from_slice(b"\\x");
            buf.push(lowerhex[(c >> 4) as usize]);
            buf.push(lowerhex[(c & 0xF) as usize]);
        } else {
            if c == b'"' || c == b'\\' {
                buf.push(b'\\');
            }
            buf.push(c);
        }
        i += 1;
    }
    buf.push(b'"');
    return crate::gostring::string::__from_vec(buf);
}

// go: sdk 1.25.5 time/format.go:858-860 lowerhex
const lowerhex: &[crate::types::byte] = b"0123456789abcdef";

// go: sdk 1.25.5 time/format.go:471-486 atoi
/// Duplicates functionality in strconv, but avoids the dependency.
fn atoi(s: &[u8]) -> (int, bool) {
    let mut s = s;
    let mut neg = false;
    if !s.is_empty() && (s[0] == b'-' || s[0] == b'+') {
        neg = s[0] == b'-';
        s = &s[1..];
    }
    let (q, rem, err) = leadingInt(s);
    let mut x = toint(q);
    if err != crate::errors::nil || !rem.is_empty() {
        return (0, false);
    }
    if neg {
        x = -x;
    }
    return (x, true);
}

// go: sdk 1.25.5 time/format.go:924-936 getnum
/// Parses `s[0:1]` or `s[0:2]` (`fixed` forces `s[0:2]`) as a decimal
/// integer, returning the integer and how many bytes it consumed.
fn getnum(s: &[u8], fixed: bool) -> (int, usize, bool) {
    if !isDigit(s, 0) {
        return (0, 0, false);
    }
    if !isDigit(s, 1) {
        if fixed {
            return (0, 0, false);
        }
        return (toint(s[0] - b'0'), 1, true);
    }
    return (toint(s[0] - b'0') * 10 + toint(s[1] - b'0'), 2, true);
}

// go: sdk 1.25.5 time/format.go:938-950 getnum3
/// Parses `s[0:1]`, `s[0:2]` or `s[0:3]` (`fixed` forces `s[0:3]`).
fn getnum3(s: &[u8], fixed: bool) -> (int, usize, bool) {
    let mut n: int = 0;
    let mut i = 0usize;
    while i < 3 && isDigit(s, i) {
        n = n * 10 + toint(s[i] - b'0');
        i += 1;
    }
    if i == 0 || (fixed && i != 3) {
        return (0, 0, false);
    }
    return (n, i, true);
}

// go: sdk 1.25.5 time/format.go:952-958 cutspace
fn cutspace(s: &[u8]) -> &[u8] {
    let mut s = s;
    while !s.is_empty() && s[0] == b' ' {
        s = &s[1..];
    }
    return s;
}

// go: sdk 1.25.5 time/format.go:960-978 skip
/// Removes the given prefix from `value`, treating runs of spaces as
/// equivalent.
fn skip<'a>(value: &'a [u8], prefix: &[u8]) -> (&'a [u8], bool) {
    let mut value = value;
    let mut prefix = prefix;
    while !prefix.is_empty() {
        if prefix[0] == b' ' {
            if !value.is_empty() && value[0] != b' ' {
                return (value, false);
            }
            prefix = cutspace(prefix);
            value = cutspace(value);
            continue;
        }
        if value.is_empty() || value[0] != prefix[0] {
            return (value, false);
        }
        prefix = &prefix[1..];
        value = &value[1..];
    }
    return (value, true);
}

// go: sdk 1.25.5 time/format.go:1522-1524 commaOrPeriod
fn commaOrPeriod(b: crate::types::byte) -> bool {
    return b == b'.' || b == b',';
}

// go: sdk 1.25.5 time/format.go:1526-1549 parseNanoseconds
/// Returns `(ns, rangeErrString, ok)`.
fn parseNanoseconds(value: &[u8], nbytes: usize) -> (int, &'static str, bool) {
    if !commaOrPeriod(value[0]) {
        return (0, "", false);
    }
    let mut value = value;
    let mut nbytes = nbytes;
    if nbytes > 10 {
        value = &value[..10];
        nbytes = 10;
    }
    let (mut ns, ok) = atoi(&value[1..nbytes]);
    if !ok {
        return (0, "", false);
    }
    if ns < 0 {
        return (0, "fractional second", true);
    }
    // Scale by the number of digits missing from the format, maximum
    // length 10.
    let scaleDigits = 10 - nbytes;
    let mut i = 0;
    while i < scaleDigits {
        ns *= 10;
        i += 1;
    }
    return (ns, "", true);
}

// go: sdk 1.25.5 time/format.go:1436-1487 parseTimeZone
/// Parses a time-zone string and returns its length. Time zones are
/// human-generated and unpredictable, so this cannot check precisely:
/// it looks for a run of upper-case letters at the start.
fn parseTimeZone(value: &[u8]) -> (usize, bool) {
    if value.len() < 3 {
        return (0, false);
    }
    // Special case 1: ChST and MeST are the only zones with a
    // lower-case letter.
    if value.len() >= 4 && (&value[..4] == b"ChST" || &value[..4] == b"MeST") {
        return (4, true);
    }
    // Special case 2: GMT may have an hour offset; treat it specially.
    if &value[..3] == b"GMT" {
        return (parseGMT(value), true);
    }
    // Special case 3: some time zones are not named, but have a +/-00
    // form.
    if value[0] == b'+' || value[0] == b'-' {
        let length = parseSignedOffset(value);
        // parseSignedOffset returns 0 on bad input.
        return (length, length > 0);
    }
    // How many upper-case letters are there? Need at least three, at
    // most five.
    let mut nUpper = 0usize;
    while nUpper < 6 {
        if nUpper >= value.len() {
            break;
        }
        let c = value[nUpper];
        if c < b'A' || b'Z' < c {
            break;
        }
        nUpper += 1;
    }
    match nUpper {
        0 | 1 | 2 | 6 => return (0, false),
        5 => {
            // Must end in T to match.
            if value[4] == b'T' {
                return (5, true);
            }
        }
        4 => {
            // Must end in T, except one special case.
            if value[3] == b'T' || &value[..4] == b"WITA" {
                return (4, true);
            }
        }
        3 => return (3, true),
        _ => {}
    }
    return (0, false);
}

// go: sdk 1.25.5 time/format.go:1489-1499 parseGMT
/// Parses a GMT time zone. The input is known to start "GMT". Checks
/// whether that is followed by a sign and a number in -23..+23,
/// excluding zero.
fn parseGMT(value: &[u8]) -> usize {
    let value = &value[3..];
    if value.is_empty() {
        return 3;
    }
    return 3 + parseSignedOffset(value);
}

// go: sdk 1.25.5 time/format.go:1505-1520 parseSignedOffset
/// Parses a signed time-zone offset (e.g. "+03" or "-04"). Returns the
/// length of the offset string found, or 0.
fn parseSignedOffset(value: &[u8]) -> usize {
    let sign = value[0];
    if sign != b'-' && sign != b'+' {
        return 0;
    }
    let (x, rem, err) = leadingInt(&value[1..]);
    // Fail if leadingInt consumed nothing.
    if err != crate::errors::nil || rem.len() == value.len() - 1 {
        return 0;
    }
    if x > 23 {
        return 0;
    }
    return value.len() - rem.len();
}

// go: sdk 1.25.5 time/format.go:1013-1030 Parse
/// `time.Parse(layout, value)` — parse `value` according to `layout`.
/// Any reference-time layout works, not a fixed list: `nextStdChunk`
/// walks the layout and each chunk consumes its part of the value.
///
/// goish has no zone database, so a parsed zone OFFSET is applied to
/// the instant and the result is UTC, and a parsed zone NAME other
/// than "UTC" or "GMT±h" is accepted for syntax and contributes a zero
/// offset — which is what Go does for an unknown abbreviation too.
pub fn Parse<L: Into<crate::gostring::string>, V: Into<crate::gostring::string>>(
    layout: L,
    value: V,
) -> (Time, crate::error) {
    let layout: crate::gostring::string = layout.into();
    let value: crate::gostring::string = value.into();
    // Go: `parse(layout, value, UTC, Local)` — the third argument is
    // the location a zone-less value lands in, and for `Parse` it is
    // UTC.
    return parse(layout.as_bytes(), value.as_bytes(), UTC);
}

// go: sdk 1.25.5 time/format.go:1032-1046 ParseInLocation
/// `time.ParseInLocation(layout, value, loc)` — like `Parse`, but a
/// value with no zone information is interpreted in `loc`. goish's
/// only Location is UTC, so this is `Parse`.
pub fn ParseInLocation<L: Into<crate::gostring::string>, V: Into<crate::gostring::string>>(
    layout: L,
    value: V,
    loc: Location,
) -> (Time, crate::error) {
    // Go: "ParseInLocation is like Parse but differs in two important
    // ways. First, in the absence of time zone information, Parse
    // interprets a time as UTC; ParseInLocation interprets the time as
    // in the given location."
    //
    // goish forwarded to `Parse` and ignored the location entirely, so
    // a zone-less value read in a +02:00 zone named an instant two
    // hours later than Go's.
    let layout: crate::gostring::string = layout.into();
    let value: crate::gostring::string = value.into();
    return parse(layout.as_bytes(), value.as_bytes(), loc);
}

// go: sdk 1.25.5 time/format.go:1048-1431 parse
fn parse(layout0: &[u8], value0: &[u8], defaultLocation: Location) -> (Time, crate::error) {
    let alayout = layout0;
    let avalue = value0;
    let mut layout = layout0;
    let mut value = value0;
    let mut rangeErrString: &str = ""; // set if a value is out of range
    let mut amSet = false; // do we need to subtract 12 from the hour for midnight?
    let mut pmSet = false; // do we need to add 12 to the hour?

    // Time being constructed.
    let mut year: int = 0;
    let mut month: int = -1;
    let mut day: int = -1;
    let mut yday: int = -1;
    let mut hour: int = 0;
    let mut min: int = 0;
    let mut sec: int = 0;
    let mut nsec: int = 0;
    let mut z_utc = false;
    let mut zoneOffset: int = -1;
    let mut zoneName: &[u8] = b"";

    // Each iteration processes one std value.
    loop {
        let mut err = false;
        let (p, std, sfx) = nextStdChunk(layout);
        let prefix = &layout[..p];
        let stdstr = &layout[p..sfx];
        let (v, ok) = skip(value, prefix);
        value = v;
        if !ok {
            return (
                Time::default(),
                newParseError(alayout, avalue, prefix, value, ""),
            );
        }
        if std == 0 {
            if !value.is_empty() {
                let msg = crate::gostring::string::from(": extra text: ") + quote(value);
                return (
                    Time::default(),
                    crate::errors::Wrap(ParseError {
                        Layout: crate::gostring::string::from_bytes(alayout),
                        Value: crate::gostring::string::from_bytes(avalue),
                        LayoutElem: crate::gostring::string::new(),
                        ValueElem: crate::gostring::string::from_bytes(value),
                        Message: msg,
                    }),
                );
            }
            break;
        }
        layout = &layout[sfx..];
        let hold = value;
        match std & stdMask {
            x if x == stdYear => {
                if value.len() < 2 {
                    err = true;
                } else {
                    let (y, yok) = atoi(&value[..2]);
                    value = &value[2..];
                    if !yok {
                        err = true;
                    } else if y >= 69 {
                        // Unix time starts Dec 31 1969 in some zones.
                        year = y + 1900;
                    } else {
                        year = y + 2000;
                    }
                }
            }
            x if x == stdLongYear => {
                if value.len() < 4 || !isDigit(value, 0) {
                    err = true;
                } else {
                    let (y, yok) = atoi(&value[..4]);
                    value = &value[4..];
                    year = y;
                    err = !yok;
                }
            }
            x if x == stdMonth => match lookup(&shortMonthNames, value) {
                Some((i, n)) => {
                    month = i + 1;
                    value = &value[n..];
                }
                None => err = true,
            },
            x if x == stdLongMonth => match lookup(&longMonthNames, value) {
                Some((i, n)) => {
                    month = i + 1;
                    value = &value[n..];
                }
                None => err = true,
            },
            x if x == stdNumMonth || x == stdZeroMonth => {
                let (m, n, ok2) = getnum(value, std == stdZeroMonth);
                month = m;
                value = &value[n..];
                err = !ok2;
                if !err && (month <= 0 || 12 < month) {
                    rangeErrString = "month";
                }
            }
            x if x == stdWeekDay => {
                // Ignore the weekday except for error checking.
                match lookup(&shortDayNames, value) {
                    Some((_, n)) => value = &value[n..],
                    None => err = true,
                }
            }
            x if x == stdLongWeekDay => match lookup(&longDayNames, value) {
                Some((_, n)) => value = &value[n..],
                None => err = true,
            },
            x if x == stdDay || x == stdUnderDay || x == stdZeroDay => {
                if std == stdUnderDay && !value.is_empty() && value[0] == b' ' {
                    value = &value[1..];
                }
                let (d, n, ok2) = getnum(value, std == stdZeroDay);
                day = d;
                value = &value[n..];
                err = !ok2;
                // Any one- or two-digit day is allowed here; the
                // month/day/year combination is validated at the end.
            }
            x if x == stdUnderYearDay || x == stdZeroYearDay => {
                let mut i = 0;
                while i < 2 {
                    if std == stdUnderYearDay && !value.is_empty() && value[0] == b' ' {
                        value = &value[1..];
                    }
                    i += 1;
                }
                let (yd, n, ok2) = getnum3(value, std == stdZeroYearDay);
                yday = yd;
                value = &value[n..];
                err = !ok2;
            }
            x if x == stdHour => {
                let (h, n, ok2) = getnum(value, false);
                hour = h;
                value = &value[n..];
                err = !ok2;
                if hour < 0 || 24 <= hour {
                    rangeErrString = "hour";
                }
            }
            x if x == stdHour12 || x == stdZeroHour12 => {
                let (h, n, ok2) = getnum(value, std == stdZeroHour12);
                hour = h;
                value = &value[n..];
                err = !ok2;
                if hour < 0 || 12 < hour {
                    rangeErrString = "hour";
                }
            }
            x if x == stdMinute || x == stdZeroMinute => {
                let (m, n, ok2) = getnum(value, std == stdZeroMinute);
                min = m;
                value = &value[n..];
                err = !ok2;
                if min < 0 || 60 <= min {
                    rangeErrString = "minute";
                }
            }
            x if x == stdSecond || x == stdZeroSecond => {
                let (sv, n, ok2) = getnum(value, std == stdZeroSecond);
                sec = sv;
                value = &value[n..];
                if !ok2 {
                    err = true;
                } else if sec < 0 || 60 <= sec {
                    rangeErrString = "second";
                } else if value.len() >= 2 && commaOrPeriod(value[0]) && isDigit(value, 1) {
                    // Special case: a fractional second in the input
                    // but not in the layout.
                    let (_, nstd, _) = nextStdChunk(layout);
                    let nstd = nstd & stdMask;
                    if nstd != stdFracSecond0 && nstd != stdFracSecond9 {
                        let mut n2 = 2usize;
                        while n2 < value.len() && isDigit(value, n2) {
                            n2 += 1;
                        }
                        let (ns, res, ok3) = parseNanoseconds(value, n2);
                        nsec = ns;
                        rangeErrString = res;
                        err = !ok3;
                        value = &value[n2..];
                    }
                }
            }
            x if x == stdPM => {
                if value.len() < 2 {
                    err = true;
                } else {
                    let p2 = &value[..2];
                    value = &value[2..];
                    if p2 == b"PM" {
                        pmSet = true;
                    } else if p2 == b"AM" {
                        amSet = true;
                    } else {
                        err = true;
                    }
                }
            }
            x if x == stdpm => {
                if value.len() < 2 {
                    err = true;
                } else {
                    let p2 = &value[..2];
                    value = &value[2..];
                    if p2 == b"pm" {
                        pmSet = true;
                    } else if p2 == b"am" {
                        amSet = true;
                    } else {
                        err = true;
                    }
                }
            }
            x if x == stdISO8601TZ
                || x == stdISO8601ShortTZ
                || x == stdISO8601ColonTZ
                || x == stdISO8601SecondsTZ
                || x == stdISO8601ColonSecondsTZ
                || x == stdNumTZ
                || x == stdNumShortTZ
                || x == stdNumColonTZ
                || x == stdNumSecondsTz
                || x == stdNumColonSecondsTZ =>
            {
                let iso = std == stdISO8601TZ
                    || std == stdISO8601ShortTZ
                    || std == stdISO8601ColonTZ
                    || std == stdISO8601SecondsTZ
                    || std == stdISO8601ColonSecondsTZ;
                if iso && !value.is_empty() && value[0] == b'Z' {
                    value = &value[1..];
                    z_utc = true;
                } else {
                    // Go falls through from the ISO case into the
                    // numeric one; goish spells the shared body once.
                    let sign: &[u8];
                    let hh: &[u8];
                    let mm: &[u8];
                    let ss: &[u8];
                    if std == stdISO8601ColonTZ || std == stdNumColonTZ {
                        if value.len() < 6 || value[3] != b':' {
                            err = true;
                            sign = b"";
                            hh = b"";
                            mm = b"";
                            ss = b"";
                        } else {
                            sign = &value[0..1];
                            hh = &value[1..3];
                            mm = &value[4..6];
                            ss = b"00";
                            value = &value[6..];
                        }
                    } else if std == stdNumShortTZ || std == stdISO8601ShortTZ {
                        if value.len() < 3 {
                            err = true;
                            sign = b"";
                            hh = b"";
                            mm = b"";
                            ss = b"";
                        } else {
                            sign = &value[0..1];
                            hh = &value[1..3];
                            mm = b"00";
                            ss = b"00";
                            value = &value[3..];
                        }
                    } else if std == stdISO8601ColonSecondsTZ || std == stdNumColonSecondsTZ {
                        if value.len() < 9 || value[3] != b':' || value[6] != b':' {
                            err = true;
                            sign = b"";
                            hh = b"";
                            mm = b"";
                            ss = b"";
                        } else {
                            sign = &value[0..1];
                            hh = &value[1..3];
                            mm = &value[4..6];
                            ss = &value[7..9];
                            value = &value[9..];
                        }
                    } else if std == stdISO8601SecondsTZ || std == stdNumSecondsTz {
                        if value.len() < 7 {
                            err = true;
                            sign = b"";
                            hh = b"";
                            mm = b"";
                            ss = b"";
                        } else {
                            sign = &value[0..1];
                            hh = &value[1..3];
                            mm = &value[3..5];
                            ss = &value[5..7];
                            value = &value[7..];
                        }
                    } else if value.len() < 5 {
                        err = true;
                        sign = b"";
                        hh = b"";
                        mm = b"";
                        ss = b"";
                    } else {
                        sign = &value[0..1];
                        hh = &value[1..3];
                        mm = &value[3..5];
                        ss = b"00";
                        value = &value[5..];
                    }
                    if !err {
                        let (hr, _, ok1) = getnum(hh, true);
                        let (mn, _, ok2) = getnum(mm, true);
                        let (sc, _, ok3) = getnum(ss, true);
                        err = !(ok1 && ok2 && ok3);
                        // The range tests use > rather than >=, as some
                        // people do write offsets of 24 hours or 60
                        // minutes or 60 seconds.
                        if hr > 24 {
                            rangeErrString = "time zone offset hour";
                        }
                        if mn > 60 {
                            rangeErrString = "time zone offset minute";
                        }
                        if sc > 60 {
                            rangeErrString = "time zone offset second";
                        }
                        zoneOffset = (hr * 60 + mn) * 60 + sc; // offset in seconds
                        if sign[0] == b'+' {
                        } else if sign[0] == b'-' {
                            zoneOffset = -zoneOffset;
                        } else {
                            err = true;
                        }
                    }
                }
            }
            x if x == stdTZ => {
                // Does it look like a time zone?
                if value.len() >= 3 && &value[..3] == b"UTC" {
                    z_utc = true;
                    value = &value[3..];
                } else {
                    let (n, ok2) = parseTimeZone(value);
                    if !ok2 {
                        err = true;
                    } else {
                        zoneName = &value[..n];
                        value = &value[n..];
                    }
                }
            }
            x if x == stdFracSecond0 => {
                // Requires exactly the number of digits the layout gave.
                let ndigit = 1 + (digitsLen(std) as usize);
                if value.len() < ndigit {
                    err = true;
                } else {
                    let (ns, res, ok2) = parseNanoseconds(value, ndigit);
                    nsec = ns;
                    rangeErrString = res;
                    err = !ok2;
                    value = &value[ndigit..];
                }
            }
            x if x == stdFracSecond9 => {
                if value.len() < 2 || !commaOrPeriod(value[0]) || value[1] < b'0' || b'9' < value[1]
                {
                    // Fractional second omitted.
                } else {
                    // Take any number of digits, even more than asked
                    // for, because it is what the stdSecond case does.
                    let mut i = 0usize;
                    while i + 1 < value.len() && b'0' <= value[i + 1] && value[i + 1] <= b'9' {
                        i += 1;
                    }
                    let (ns, res, ok2) = parseNanoseconds(value, 1 + i);
                    nsec = ns;
                    rangeErrString = res;
                    err = !ok2;
                    value = &value[1 + i..];
                }
            }
            _ => {}
        }
        if !rangeErrString.is_empty() {
            let msg = crate::gostring::string::from(": ") + rangeErrString + " out of range";
            return (
                Time::default(),
                crate::errors::Wrap(ParseError {
                    Layout: crate::gostring::string::from_bytes(alayout),
                    Value: crate::gostring::string::from_bytes(avalue),
                    LayoutElem: crate::gostring::string::from_bytes(stdstr),
                    ValueElem: crate::gostring::string::from_bytes(value),
                    Message: msg,
                }),
            );
        }
        if err {
            return (
                Time::default(),
                newParseError(alayout, avalue, stdstr, hold, ""),
            );
        }
    }
    if pmSet && hour < 12 {
        hour += 12;
    } else if amSet && hour == 12 {
        hour = 0;
    }

    // Convert yday to day, month.
    if yday >= 0 {
        let mut d: int = 0;
        let mut m: int = 0;
        let mut yday = yday;
        if isLeap(year) {
            if yday == 31 + 29 {
                m = 2;
                d = 29;
            } else if yday > 31 + 29 {
                yday -= 1;
            }
        }
        if yday < 1 || yday > 365 {
            return (
                Time::default(),
                parseErrMsg(alayout, avalue, value, ": day-of-year out of range"),
            );
        }
        if m == 0 {
            m = (yday - 1) / 31 + 1;
            if daysBefore(m + 1) < yday {
                m += 1;
            }
            d = yday - daysBefore(m);
        }
        // If month, day already seen, yday's m, d must match.
        if month >= 0 && month != m {
            return (
                Time::default(),
                parseErrMsg(alayout, avalue, value, ": day-of-year does not match month"),
            );
        }
        month = m;
        if day >= 0 && day != d {
            return (
                Time::default(),
                parseErrMsg(alayout, avalue, value, ": day-of-year does not match day"),
            );
        }
        day = d;
    } else {
        if month < 0 {
            month = 1;
        }
        if day < 0 {
            day = 1;
        }
    }

    // Validate the day of the month.
    if day < 1 || day > daysIn(month, year) {
        return (
            Time::default(),
            parseErrMsg(alayout, avalue, value, ": day out of range"),
        );
    }

    if z_utc {
        return (
            Date(year, month, day, hour, min, sec, nsec, UTC),
            crate::errors::nil,
        );
    }

    if zoneOffset != -1 {
        let mut t = Date(year, month, day, hour, min, sec, nsec, UTC);
        t.addSec(-zoneOffset);
        // Go: "Look for local zone with the given offset. If that zone
        // was in effect at the given time, use it." With no zone
        // database there is nothing to look up, so this is Go's
        // fall-back: `t.setLoc(FixedZone(zoneName, zoneOffset))`, and
        // the zone has no NAME unless the layout carried one.
        //
        // goish used to stop at the instant and leave the location UTC,
        // so `Parse` of "2024-01-02T03:04:05+02:00" followed by
        // `Format` gave back "2024-01-02T01:04:05Z" — the right instant
        // rendered as the wrong wall clock, which is the difference
        // every RFC 3339 round trip through a JSON API would show.
        // Go: "Look for local zone with the given offset. If that zone
        // was in effect at the given time, use it."
        //
        // goish has no zone database, so `Local` IS the whole of it —
        // one entry, UTC, offset zero. That is still a lookup Go
        // performs and goish must, because it decides the NAME the
        // parsed Time reports, not just its offset. Skipping it made
        // `Parse` of "Fri, 21 Nov 1997 09:55:06 +0000" answer an
        // anonymous zone where Go answers the local one: the offset
        // agreed and the name did not, which net/mail's ParseDate is
        // what surfaced.
        //
        // Go's answer here depends on the machine's TZ; goish's Local
        // is UTC because there is no database to say otherwise, so this
        // matches Go on a UTC machine and is stated rather than
        // implied.
        let local = crate::time::Local;
        if local.__offset() == zoneOffset && (zoneName.is_empty() || local.__abbrev() == zoneName) {
            return (t.In(local), crate::errors::nil);
        }

        // Go: "Otherwise create fake zone to record offset."
        return (
            t.In(crate::time::FixedZone(
                crate::gostring::string::from_bytes(zoneName),
                zoneOffset,
            )),
            crate::errors::nil,
        );
    }

    if !zoneName.is_empty() {
        // Go looks the abbreviation up in the local zone and, failing
        // that, "Otherwise create fake zone to record offset."
        // goish has no database, so the abbreviation is recorded with a
        // zero offset — the instant computed above is already correct,
        // and this is what lets `Zone()` read the name back.
        return (
            Date(year, month, day, hour, min, sec, nsec, UTC).In(crate::time::FixedZone(
                crate::gostring::string::from_bytes(zoneName),
                0,
            )),
            crate::errors::nil,
        );
    }

    // Go: `Date(…, defaultLocation)` — for `Parse` that is UTC, and for
    // `ParseInLocation` the caller's zone, which is why the two differ
    // only for a layout that carries no zone at all.
    return (
        Date(year, month, day, hour, min, sec, nsec, defaultLocation),
        crate::errors::nil,
    );
}

// go: none — goish idiom: Go builds these five ParseErrors inline with
//     a composite literal; this is the shape they share.
fn parseErrMsg(alayout: &[u8], avalue: &[u8], value: &[u8], message: &str) -> crate::error {
    return crate::errors::Wrap(ParseError {
        Layout: crate::gostring::string::from_bytes(alayout),
        Value: crate::gostring::string::from_bytes(avalue),
        LayoutElem: crate::gostring::string::new(),
        ValueElem: crate::gostring::string::from_bytes(value),
        Message: crate::gostring::string::from_bytes(message.as_bytes()),
    });
}

// ─── ParseDuration (slim port of time/format.go:1621) ────────────────
//
// Reference: Go 1.25 src/time/format.go:1605-1718. Internal helpers
// `leadingInt` and `leadingFraction` are inlined as fns here.

// go: sdk 1.25.5 time/format.go:1621-1718 ParseDuration
/// `time.ParseDuration(s)` — parse a duration string.
///
/// A duration string is a possibly signed sequence of decimal numbers,
/// each with optional fraction and a unit suffix, such as "300ms",
/// "-1.5h" or "2h45m". Valid time units are "ns", "us" (or "µs"),
/// "ms", "s", "m", "h".
pub fn ParseDuration<S: Into<crate::gostring::string>>(s: S) -> (Duration, crate::error) {
    use crate::gostring::string;
    use crate::strconv;
    let s: crate::gostring::string = s.into();

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
        let (vv, rem, err) = leadingInt(&cur);
        let rem = rem.to_vec();
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
            let (ff, sc, rem) = leadingFraction(&cur);
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
                    string::from("time: missing unit in duration ") + strconv::Quote(orig.clone()),
                ),
            );
        }
        let u = &cur[..i];
        let unit = match unitMap(u) {
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
            v = v.wrapping_add(touint64((f as f64) * (unit as f64 / scale)));
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
        // Go: return -Duration(d), nil
        return (Duration(toint(d).wrapping_neg()), crate::errors::nil);
    }
    if d > (1u64 << 63) - 1 {
        return (
            Duration(0),
            crate::errors::New(string::from("time: invalid duration ") + strconv::Quote(orig)),
        );
    }
    return (Duration(toint(d)), crate::errors::nil);
}

// go: sdk 1.25.5 time/format.go:1605-1614 unitMap
/// Each unit's value is the
/// number of nanoseconds it represents.
fn unitMap(u: &[u8]) -> Option<u64> {
    return match u {
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
    };
}

// go: sdk 1.25.5 time/format.go:1554-1572 leadingInt
/// Consume the leading [0-9]* from `s`. Returns
/// `(x, rem, err)`.
///
/// Mirrors format.go:1554. Returns error on overflow (caller treats
/// it as "invalid duration"); rem is the unconsumed tail.
fn leadingInt(s: &[u8]) -> (u64, &[u8], crate::error) {
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
                s,
                crate::errors::New(crate::gostring::string::from("time: bad [0-9]*")),
            );
        }
        x = x * 10 + touint64(c - b'0');
        if x > 1u64 << 63 {
            // overflow
            return (
                0,
                s,
                crate::errors::New(crate::gostring::string::from("time: bad [0-9]*")),
            );
        }
        i += 1;
    }
    return (x, &s[i..], crate::errors::nil);
}

// go: sdk 1.25.5 time/format.go:1574-1602 leadingFraction
/// Consume the leading [0-9]* from `s` as a
/// fraction. Mirrors format.go:1577. No error on overflow; precision
/// just stops accumulating.
fn leadingFraction(s: &[u8]) -> (u64, f64, alloc::vec::Vec<u8>) {
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
                let y = x * 10 + touint64(c - b'0');
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
    return (x, scale, s[i..].to_vec());
}

// go: none — goish idiom: Go's `Time` satisfies `Stringer` and the
//     printer finds it through the interface; goish's fmt dispatches on
//     a trait, so the bridge is written out. Without it a `Time` could
//     not be handed to `Println!` at all — the macro failed to compile.
impl crate::fmt::Format for Time {
    // go: none — goish idiom: see the note on the impl above.
    fn fmt(&self, _verb: crate::types::byte, f: &mut crate::fmt::FmtBuf) {
        f.extend(self.String().as_bytes());
    }
}
