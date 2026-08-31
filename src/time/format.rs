// go: file time/format.go decls: String, appendInt, format_layout_scan, Time.Format, Time.AppendFormat, Parse, ParseDuration, unitMap, leadingInt, leadingFraction
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
pub(crate) const MONTH_LONG: [&str; 12] = [
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

pub(crate) const MONTH_SHORT: [&str; 13] = [
    "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
pub(crate) const DAY_SHORT: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
pub(crate) const DAY_LONG: [&str; 7] = [
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
pub(crate) fn pad2(n: int) -> [u8; 2] {
    let n = toint64(n);
    return [b'0' + tobyte((n / 10) % 10), b'0' + tobyte(n % 10)];
}

// go: none — goish idiom: see the note on `pad2`.
pub(crate) fn pad4(n: int) -> [u8; 4] {
    let n = toint64(n);
    return [
        b'0' + tobyte((n / 1000) % 10),
        b'0' + tobyte((n / 100) % 10),
        b'0' + tobyte((n / 10) % 10),
        b'0' + tobyte(n % 10),
    ];
}

// go: none — goish idiom: the named-layout fast paths. Go has no
//     equivalent: it runs every layout through `format_layout_scan`. This
//     dispatches the handful of constants the tree uses and falls
//     through to `format_layout_scan`, which is the real scanner.
pub(crate) fn format_layout(
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
            let mut n = touint64(_nano);
            let mut i = 9;
            while i > 0 {
                i -= 1;
                frac[i] = b'0' + tobyte(n % 10);
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
            out.push(b'0' + tobyte(d));
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
            out.push(b'0' + tobyte(d));
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
        let h12 = if hh == 0 {
            12
        } else if hh > 12 {
            hh - 12
        } else {
            hh
        };
        let pm = hh >= 12;
        let mut out = alloc::vec::Vec::with_capacity(7);
        if h12 < 10 {
            out.push(b'0' + tobyte(h12));
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
    // Fixed-width fractional seconds: "2006-01-02T15:04:05.0000000Z07:00"
    // (7 digits, zero-padded, always emitted including the dot).
    if l == "2006-01-02T15:04:05.0000000Z07:00" {
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
        out.push(b'.');
        // 7 digits from nanoseconds (0..999999999) — pad to 7, truncate if > 7.
        let mut frac: [u8; 7] = [b'0'; 7];
        let mut n = touint64(_nano);
        let mut i = 7;
        while i > 0 {
            i -= 1;
            frac[i] = b'0' + tobyte(n % 10);
            n /= 10;
        }
        out.extend_from_slice(&frac);
        out.push(b'Z');
        return string::from_bytes(&out);
    }
    // General layout: token-scan port of Go's `format_layout_scan`
    // (format.go:190). The named-layout arms above stay as fast
    // paths; anything else — custom layouts like the nginx access-log
    // `02/Jan/2006:15:04:05` — is emitted chunk by chunk here.
    return format_layout_scan(&l, y, m, d, hh, mm, ss, wd, _nano);
}

// go: none — goish idiom: Go splits layout handling in two —
//     `nextStdChunk` (format.go:186) walks the layout and hands back
//     one chunk at a time, and `Time.appendFormat` (format.go:660)
//     emits it. goish fuses the two into a single pass, so it matches
//     neither signature. The chunk vocabulary below is Go's, chunk for
//     chunk.
/// Go's layout scanner and emit loop, collapsed into one pass. Slim
/// deviations (v1 is UTC-only, no year-day):
///   - zone chunks render the UTC fixed forms: `MST` → "UTC",
///     `-0700`/`-07:00`/`-07` → "+0000"/"+00:00"/"+00", `Z0700`/
///     `Z07:00` → "Z" (Go emits "Z" for zero offset too);
///   - year-day chunks (`002`, `__2`) are not recognized.
pub(crate) fn format_layout_scan(
    layout: &crate::gostring::string,
    y: int,
    m: int,
    d: int,
    hh: int,
    mm: int,
    ss: int,
    wd: int,
    nano: int,
) -> crate::gostring::string {
    use crate::gostring::string;
    let lb = layout.as_bytes();
    let n = lb.len();
    let mut out: Vec<u8> = Vec::with_capacity(n + 8);

    // hour-12 with Go's 0→12 mapping (format.go stdHour12 emit).
    let h12 = {
        let h = hh % 12;
        if h == 0 {
            12
        } else {
            h
        }
    };
    let starts = |i: usize, pat: &[u8]| -> bool { lb[i..].starts_with(pat) };
    // push a value without zero padding (Go appendInt(b, v, 0)).
    let push_num = |out: &mut Vec<u8>, v: int| {
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        let mut x = if v < 0 { -v } else { v };
        if x == 0 {
            i -= 1;
            buf[i] = b'0';
        }
        while x > 0 {
            i -= 1;
            buf[i] = b'0' + tobyte(x % 10);
            x /= 10;
        }
        if v < 0 {
            i -= 1;
            buf[i] = b'-';
        }
        out.extend_from_slice(&buf[i..]);
    };

    let mut i = 0usize;
    while i < n {
        let c = lb[i];
        match c {
            b'J' if starts(i, b"January") => {
                // MONTH_LONG is 0-based; MONTH_SHORT carries a dummy
                // slot 0 and is 1-based.
                out.extend_from_slice(MONTH_LONG[m as usize - 1].as_bytes());
                i += 7;
            }
            b'J' if starts(i, b"Jan") => {
                out.extend_from_slice(MONTH_SHORT[m as usize].as_bytes());
                i += 3;
            }
            b'M' if starts(i, b"Monday") => {
                out.extend_from_slice(DAY_LONG[wd as usize].as_bytes());
                i += 6;
            }
            b'M' if starts(i, b"Mon") => {
                out.extend_from_slice(DAY_SHORT[wd as usize].as_bytes());
                i += 3;
            }
            b'M' if starts(i, b"MST") => {
                out.extend_from_slice(b"UTC");
                i += 3;
            }
            b'2' if starts(i, b"2006") => {
                out.extend_from_slice(&pad4(y));
                i += 4;
            }
            b'2' => {
                push_num(&mut out, d);
                i += 1;
            }
            b'1' if starts(i, b"15") => {
                out.extend_from_slice(&pad2(hh));
                i += 2;
            }
            b'1' => {
                push_num(&mut out, m);
                i += 1;
            }
            b'0' if i + 1 < n && lb[i + 1] >= b'1' && lb[i + 1] <= b'6' => {
                match lb[i + 1] {
                    b'1' => out.extend_from_slice(&pad2(m)),
                    b'2' => out.extend_from_slice(&pad2(d)),
                    b'3' => out.extend_from_slice(&pad2(h12)),
                    b'4' => out.extend_from_slice(&pad2(mm)),
                    b'5' => out.extend_from_slice(&pad2(ss)),
                    // "06" — two-digit year.
                    _ => out.extend_from_slice(&pad2(y % 100)),
                }
                i += 2;
            }
            b'_' if starts(i, b"_2") => {
                // stdUnderDay: space-padded day, width 2.
                if d < 10 {
                    out.push(b' ');
                }
                push_num(&mut out, d);
                i += 2;
            }
            b'3' => {
                push_num(&mut out, h12);
                i += 1;
            }
            b'4' => {
                push_num(&mut out, mm);
                i += 1;
            }
            b'5' => {
                push_num(&mut out, ss);
                i += 1;
            }
            b'P' if starts(i, b"PM") => {
                out.extend_from_slice(if hh < 12 { b"AM" } else { b"PM" });
                i += 2;
            }
            b'p' if starts(i, b"pm") => {
                out.extend_from_slice(if hh < 12 { b"am" } else { b"pm" });
                i += 2;
            }
            b'-' if starts(i, b"-07:00") => {
                out.extend_from_slice(b"+00:00");
                i += 6;
            }
            b'-' if starts(i, b"-0700") => {
                out.extend_from_slice(b"+0000");
                i += 5;
            }
            b'-' if starts(i, b"-07") => {
                out.extend_from_slice(b"+00");
                i += 3;
            }
            b'Z' if starts(i, b"Z07:00") => {
                out.push(b'Z');
                i += 6;
            }
            b'Z' if starts(i, b"Z0700") => {
                out.push(b'Z');
                i += 5;
            }
            b'.' | b',' if i + 1 < n && (lb[i + 1] == b'0' || lb[i + 1] == b'9') => {
                // Fractional seconds (Go stdFrac0 / stdFrac9): count
                // the digit run, emit that many nanosecond digits;
                // the 9-form trims trailing zeros (and the separator
                // when all zero).
                let digit = lb[i + 1];
                let mut w = 0usize;
                while i + 1 + w < n && lb[i + 1 + w] == digit {
                    w += 1;
                }
                let mut frac: [u8; 9] = [b'0'; 9];
                let mut v = touint64(nano);
                let mut j = 9;
                while j > 0 {
                    j -= 1;
                    frac[j] = b'0' + tobyte(v % 10);
                    v /= 10;
                }
                let take = if w > 9 { 9 } else { w };
                if digit == b'0' {
                    out.push(c);
                    out.extend_from_slice(&frac[..take]);
                } else {
                    let mut len = take;
                    while len > 0 && frac[len - 1] == b'0' {
                        len -= 1;
                    }
                    if len > 0 {
                        out.push(c);
                        out.extend_from_slice(&frac[..len]);
                    }
                }
                i += 1 + w;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    return string::from_bytes(&out);
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
            buf.extend_from_slice(crate::strconv::FormatUint(m0, 10).as_bytes());
            wid = 9;
        }
        appendInt(&mut buf, m1, wid);
        buf.push(b'.');
        appendInt(&mut buf, m2, 9);
        return s + crate::gostring::string::__from_vec(buf);
    }

    // go: sdk 1.25.5 time/format.go:639-651 Time.Format
    /// `t.Format(layout)` — slim port. Recognizes the
    /// canonical layout constants (RFC3339, RFC1123, RFC1123Z,
    /// DateTime, DateOnly, TimeOnly, Stamp, Kitchen, ANSIC) and
    /// renders the time directly. Does NOT support arbitrary
    /// reference-time layouts (porting Go's format_layout_scan machinery
    /// is ~1500 LOC).
    ///
    /// Pass the constant via `string(time::RFC3339)`.
    pub fn Format<S: Into<crate::gostring::string>>(self, layout: S) -> crate::gostring::string {
        let layout = layout.into();
        let (y, m, d, hh, mm, ss) = civil_from_unix(self.unixSec());
        let wd = self.Weekday().Int();
        let nano = self.nsec;
        return format_layout(&layout, y, m, d, hh, mm, ss, wd, toint(nano));
    }

    // go: sdk 1.25.5 time/format.go:655-665 Time.AppendFormat
    /// `t.AppendFormat(b, layout)` — append the formatted
    /// time to `b` and return the extended buffer. Slim port: delegates
    /// to `Format` then appends the byte representation.
    pub fn AppendFormat<L: Into<crate::gostring::string>>(
        self,
        b: crate::goslice::slice<crate::types::byte>,
        layout: L,
    ) -> crate::goslice::slice<crate::types::byte> {
        let layout: crate::gostring::string = layout.into();
        let s = self.Format(layout);
        let extra = crate::convert::bytes(s);
        // Go: return append(b, formatted...). Use range! to mirror.
        let mut out = b;
        for (_, byte_ref) in crate::range!(extra) {
            out = crate::append!(out, *byte_ref);
        }
        return out;
    }
}

// ─── Parse (slim port of time.Parse) ─────────────────────────────────

// go: sdk 1.25.5 time/format.go:1023-1031 Parse
/// `time.Parse(layout, value)` (format.go:1232) — slim. Recognizes the
/// canonical reference-time layout constants and parses `value`
/// according to the chosen one. Returns `(t, err)` per goish
/// convention; UTC only.
///
/// Recognized layouts: RFC3339, DateTime, DateOnly, TimeOnly,
/// RFC1123 (assumes "GMT" or arbitrary 3-letter zone), ANSIC.
/// Anything else returns an error.
pub fn Parse<L: Into<crate::gostring::string>, V: Into<crate::gostring::string>>(
    layout: L,
    value: V,
) -> (Time, crate::error) {
    let layout: crate::gostring::string = layout.into();
    let value: crate::gostring::string = value.into();

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
    // ASN.1 UTCTime, second precision: "060102150405Z0700"
    // (cryptobyte's defaultUTCTimeFormatStr).
    if l == "060102150405Z0700" {
        return parse_asn1_utc(value, true);
    }
    // ASN.1 UTCTime, minute precision: "0601021504Z0700" — the fallback
    // cryptobyte's ReadASN1UTCTime tries when second precision fails.
    if l == "0601021504Z0700" {
        return parse_asn1_utc(value, false);
    }
    // ASN.1 GeneralizedTime: "20060102150405Z0700"
    // (cryptobyte's generalizedTimeFormatStr).
    if l == "20060102150405Z0700" {
        return parse_asn1_generalized(value);
    }
    // ASN.1 GeneralizedTime with optional fractional seconds:
    // "20060102150405.999999999Z0700" — encoding/asn1's own
    // `parseGeneralizedTime` layout. The `.999999999` chunk is Go's
    // stdFrac9: the fraction and its separator are both optional, and
    // trailing zeros are trimmed. `format_layout_scan` already emits
    // this form; this is the reading half.
    if l == "20060102150405.999999999Z0700" {
        return parse_asn1_generalized_frac(value);
    }

    return (
        Time::default(),
        crate::errors::New("time: unsupported layout"),
    );
}

// go: none - goish idiom: `time.Parse` in this file is a layout switch,
// not a port of Go's scanner; this is the ASN.1 UTCTime arm.
/// ASN.1 UTCTime — `YYMMDDhhmm[ss]Z`. Slim deviation, matching the rest
/// of this file: only the `Z` (UTC) zone form is accepted, never a
/// numeric `±hhmm` offset. Callers in cryptobyte re-`Format` the result
/// and compare it to the input, so an offset form would be rejected
/// there anyway; RFC 5280 §4.1.2.5.1 requires `Z` in certificates.
///
/// The two-digit year uses Go's `stdYear` rule verbatim (format.go: `if
/// year >= 69 { year += 1900 } else { year += 2000 }`). The further
/// RFC 5280 §4.1.2.5.1 pivot — subtract a century when the result is
/// >= 2050 — belongs to cryptobyte's `ReadASN1UTCTime`, which applies it
/// *after* its round-trip `Format` check; doing it here would make that
/// check compare a 19xx year against a 50-68 input and fail.
fn parse_asn1_utc(s: crate::gostring::string, seconds: bool) -> (Time, crate::error) {
    let bs = s.as_bytes();
    let want = if seconds { 13 } else { 11 };
    if bs.len() != want || bs[want - 1] != b'Z' {
        return (
            Time::default(),
            crate::errors::New("time: malformed ASN.1 UTCTime"),
        );
    }
    let yy = match parse_int(&bs[0..2]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let m = match parse_int(&bs[2..4]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let d = match parse_int(&bs[4..6]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let hh = match parse_int(&bs[6..8]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let mm = match parse_int(&bs[8..10]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let ss = if seconds {
        match parse_int(&bs[10..12]) {
            Ok(v) => v,
            Err(e) => return (Time::default(), e),
        }
    } else {
        0
    };
    let y = if yy >= 69 { 1900 + yy } else { 2000 + yy };
    return (Date(y, m, d, hh, mm, ss, 0, UTC), crate::errors::nil);
}

// go: none - goish idiom: the ASN.1 GeneralizedTime arm of the layout
// switch above.
/// ASN.1 GeneralizedTime — `YYYYMMDDhhmmssZ`. Same `Z`-only deviation as
/// `parse_asn1_utc`.
fn parse_asn1_generalized(s: crate::gostring::string) -> (Time, crate::error) {
    let bs = s.as_bytes();
    if bs.len() != 15 || bs[14] != b'Z' {
        return (
            Time::default(),
            crate::errors::New("time: malformed ASN.1 GeneralizedTime"),
        );
    }
    let y = match parse_int(&bs[0..4]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let m = match parse_int(&bs[4..6]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let d = match parse_int(&bs[6..8]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let hh = match parse_int(&bs[8..10]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let mm = match parse_int(&bs[10..12]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let ss = match parse_int(&bs[12..14]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    return (Date(y, m, d, hh, mm, ss, 0, UTC), crate::errors::nil);
}

// go: none - goish idiom: the fractional-seconds ASN.1 GeneralizedTime
// arm of the layout switch above.
/// ASN.1 GeneralizedTime — `YYYYMMDDhhmmss[.f{1,9}]Z`.
///
/// Same `Z`-only deviation as [`parse_asn1_utc`]: this file's `Time` has
/// no `Location` (`Zone()` is hard-wired to `("UTC", 0)`), so a numeric
/// `±hhmm` offset cannot be retained, and `encoding/asn1`'s
/// `parseGeneralizedTime` re-`Format`s the result and compares it to the
/// input — which an offset could never satisfy. KNOWN DIVERGENCE: Go
/// accepts `20100102030405+0607`; goish rejects it. RFC 5280 §4.1.2.5.2
/// requires `Z` in certificates, so no conforming certificate reaches it.
///
/// The fraction is truncated at nanosecond precision, as Go's stdFrac9
/// scanner does.
fn parse_asn1_generalized_frac(s: crate::gostring::string) -> (Time, crate::error) {
    let bs = s.as_bytes();
    let bad = || -> (Time, crate::error) {
        return (
            Time::default(),
            crate::errors::New("time: malformed ASN.1 GeneralizedTime"),
        );
    };
    // Shortest accepted form is "YYYYMMDDhhmmssZ".
    if bs.len() < 15 || bs[bs.len() - 1] != b'Z' {
        return bad();
    }
    let y = match parse_int(&bs[0..4]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let m = match parse_int(&bs[4..6]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let d = match parse_int(&bs[6..8]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let hh = match parse_int(&bs[8..10]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let mm = match parse_int(&bs[10..12]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let ss = match parse_int(&bs[12..14]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };

    // Everything between the seconds and the trailing 'Z' is the
    // optional ".fraction".
    let tail = &bs[14..bs.len() - 1];
    let mut nsec: int = 0;
    if !tail.is_empty() {
        if tail[0] != b'.' || tail.len() < 2 {
            return bad();
        }
        let digits = &tail[1..];
        let mut scale: int = 100_000_000;
        let mut i = 0usize;
        while i < digits.len() {
            let c = digits[i];
            if c < b'0' || c > b'9' {
                return bad();
            }
            // Beyond nanosecond precision the digits are dropped, which
            // is what Go's scanner does once its 9-digit window fills.
            if scale > 0 {
                nsec += crate::int(c - b'0') * scale;
                scale /= 10;
            }
            i += 1;
        }
    }
    return (Date(y, m, d, hh, mm, ss, nsec, UTC), crate::errors::nil);
}

// go: none — goish idiom: `Parse` in this file is a layout switch
//     rather than a port of Go's scanner; this is the RFC3339 arm.
fn parse_rfc3339(s: crate::gostring::string) -> (Time, crate::error) {
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
    return (Date(y, m, d, hh, mm, ss, 0, UTC), crate::errors::nil);
}

// go: none — goish idiom: see the note on `parse_rfc3339`.
fn parse_datetime(s: crate::gostring::string, sep: u8) -> (Time, crate::error) {
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
    return (Date(y, m, d, hh, mm, ss, 0, UTC), crate::errors::nil);
}

// go: none — goish idiom: see the note on `parse_rfc3339`.
fn parse_date_only(s: crate::gostring::string) -> (Time, crate::error) {
    let bs = s.as_bytes();
    if bs.len() != 10 || bs[4] != b'-' || bs[7] != b'-' {
        return (
            Time::default(),
            crate::errors::New("time: malformed DateOnly"),
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
    return (Date(y, m, d, 0, 0, 0, 0, UTC), crate::errors::nil);
}

// go: none — goish idiom: see the note on `parse_rfc3339`.
fn parse_time_only(s: crate::gostring::string) -> (Time, crate::error) {
    let bs = s.as_bytes();
    if bs.len() != 8 || bs[2] != b':' || bs[5] != b':' {
        return (
            Time::default(),
            crate::errors::New("time: malformed TimeOnly"),
        );
    }
    let hh = match parse_int(&bs[0..2]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let mm = match parse_int(&bs[3..5]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let ss = match parse_int(&bs[6..8]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    return (Date(1970, 1, 1, hh, mm, ss, 0, UTC), crate::errors::nil);
}

// go: none — goish idiom: see the note on `parse_rfc3339`.
fn parse_rfc1123(s: crate::gostring::string) -> (Time, crate::error) {
    let bs = s.as_bytes();
    // "Day, DD Mon YYYY HH:MM:SS GMT" → 29 chars
    if bs.len() != 29
        || bs[3] != b','
        || bs[4] != b' '
        || bs[7] != b' '
        || bs[11] != b' '
        || bs[16] != b' '
        || bs[19] != b':'
        || bs[22] != b':'
        || bs[25] != b' '
    {
        return (
            Time::default(),
            crate::errors::New("time: malformed RFC1123"),
        );
    }
    let d = match parse_int(&bs[5..7]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let mon = match month_short(&bs[8..11]) {
        Some(v) => v,
        None => {
            return (
                Time::default(),
                crate::errors::New("time: bad month in RFC1123"),
            );
        }
    };
    let y = match parse_int(&bs[12..16]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let hh = match parse_int(&bs[17..19]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let mm = match parse_int(&bs[20..22]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let ss = match parse_int(&bs[23..25]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    return (Date(y, mon, d, hh, mm, ss, 0, UTC), crate::errors::nil);
}

// go: none — goish idiom: see the note on `parse_rfc3339`.
fn parse_ansic(s: crate::gostring::string) -> (Time, crate::error) {
    let bs = s.as_bytes();
    let bad = || (Time::default(), crate::errors::New("time: malformed ANSIC"));
    // "Mon Jan _2 15:04:05 2006". The `_2` day is space-padded, and Go
    // accepts all three renderings of it: " 6", "6" and "06". The
    // unpadded single digit makes the string 23 bytes instead of 24,
    // which is why the length is not a constant.
    if bs.len() < 23 || bs.len() > 24 || bs[3] != b' ' || bs[7] != b' ' {
        return bad();
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
    // Day occupies cols 8..day_end; the separator space follows it.
    let day_end = if bs.len() == 24 { 10 } else { 9 };
    let day_bytes = &bs[8..day_end];
    let d = if day_bytes[0] == b' ' {
        match parse_int(&day_bytes[1..]) {
            Ok(v) => v,
            Err(e) => return (Time::default(), e),
        }
    } else {
        match parse_int(day_bytes) {
            Ok(v) => v,
            Err(e) => return (Time::default(), e),
        }
    };
    // Everything after the day sits at a fixed offset from day_end.
    let t = day_end + 1;
    if bs[day_end] != b' ' || bs[t + 2] != b':' || bs[t + 5] != b':' || bs[t + 8] != b' ' {
        return bad();
    }
    let hh = match parse_int(&bs[t..t + 2]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let mm = match parse_int(&bs[t + 3..t + 5]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let ss = match parse_int(&bs[t + 6..t + 8]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    let y = match parse_int(&bs[t + 9..t + 13]) {
        Ok(v) => v,
        Err(e) => return (Time::default(), e),
    };
    return (Date(y, mon, d, hh, mm, ss, 0, UTC), crate::errors::nil);
}

// go: none — goish idiom: the layout-switch parsers' shared digit
//     reader. Go's scanner uses `getnum`, which is tied to its chunk
//     representation.
fn parse_int(bs: &[u8]) -> Result<int, crate::error> {
    let mut n: int = 0;
    for &c in bs.iter() {
        if !(b'0'..=b'9').contains(&c) {
            return Err(crate::errors::New("time: non-digit in numeric field"));
        }
        n = n * 10 + toint(c - b'0');
    }
    return Ok(n);
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
fn leading_int(s: &[u8]) -> (u64, alloc::vec::Vec<u8>, crate::error) {
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
        x = x * 10 + touint64(c - b'0');
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
    return (x, s[i..].to_vec(), crate::errors::nil);
}

// go: sdk 1.25.5 time/format.go:1574-1602 leadingFraction
/// Consume the leading [0-9]* from `s` as a
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

// go: none — goish idiom: the layout-switch parsers' three-letter
//     month lookup. Go's scanner resolves it through `lookup(shortMonthNames, value)`.
pub(crate) fn month_short(bs: &[u8]) -> Option<int> {
    return match bs {
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
    };
}

// go: sdk 1.25.5 time/format.go:418-465 appendInt
/// `appendInt` — append `x` in decimal, zero-padded to `width`.
/// goish's callers only ever pass a non-negative value, so the sign
/// handling Go's has is not reachable here.
fn appendInt(b: &mut alloc::vec::Vec<crate::types::byte>, x: u64, width: usize) {
    let s = crate::strconv::FormatUint(x, 10);
    let d = s.as_bytes();
    let mut i = d.len();
    while i < width {
        b.push(b'0');
        i += 1;
    }
    b.extend_from_slice(d);
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
