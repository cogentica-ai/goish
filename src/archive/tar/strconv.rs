// go: file archive/tar/strconv.go decls: parsePAXRecord, validPAXRecord, parsePAXTime, parser.parseString, parser.parseNumeric, parser.parseOctal, isASCII, hasNUL, toASCII, formatter.formatString, formatter.formatNumeric, formatter.formatOctal, fitsInBase256, fitsInOctal, formatPAXTime, formatPAXRecord
//
// strconv.go — the numeric and string codecs both sides share.

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{
    int as toint, int64 as toint64, uint32 as touint32, uint64 as touint64, uint8 as touint8,
};
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strconv;
use crate::strings;
use crate::time::Time;
use crate::types::{byte, int};

use super::*;

// go: sdk 1.25.5 archive/tar/strconv.go:252-285 parsePAXRecord
pub(crate) fn parsePAXRecord(s: string) -> (string, string, string, error) {
    let s_bytes = s.as_bytes();
    let mut space_idx = -1;
    for i in 0..s.Len() {
        if s_bytes[i as usize] == b' ' {
            space_idx = i;
            break;
        }
    }
    if space_idx < 0 {
        return (string::new(), string::new(), s, ErrHeader.into());
    }
    let n_str = s.slice(0, space_idx);
    let rest = s.slice(space_idx + 1, s.Len());
    let (n, err) = strconv::ParseInt(n_str, 10, 0);
    if !err.IsNil() || n < 5 || n > s.Len() {
        return (string::new(), string::new(), s, ErrHeader.into());
    }
    let rec_len = n - (space_idx + 1);
    if rec_len <= 0 {
        return (string::new(), string::new(), s, ErrHeader.into());
    }
    let rec = rest.slice(0, rec_len - 1);
    let nl = rest.slice(rec_len - 1, rec_len);
    let rem = rest.slice(rec_len, rest.Len());
    if nl != "\n" {
        return (string::new(), string::new(), s, ErrHeader.into());
    }

    let rec_bytes = rec.as_bytes();
    let mut eq_idx = -1;
    for i in 0..rec.Len() {
        if rec_bytes[i as usize] == b'=' {
            eq_idx = i;
            break;
        }
    }
    if eq_idx < 0 {
        return (string::new(), string::new(), s, ErrHeader.into());
    }
    let key = rec.slice(0, eq_idx);
    let val = rec.slice(eq_idx + 1, rec.Len());
    if !validPAXRecord(key.clone(), val.clone()) {
        return (string::new(), string::new(), s, ErrHeader.into());
    }
    return (key, val, rem, nil);
}

// go: sdk 1.25.5 archive/tar/strconv.go:317-327 validPAXRecord
pub(crate) fn validPAXRecord(k: string, v: string) -> bool {
    if k == "" || strings::Contains(k.clone(), "=") {
        return false;
    }
    let k_bytes = k.as_bytes();
    return if k_bytes == paxPath.as_bytes()
        || k_bytes == paxLinkpath.as_bytes()
        || k_bytes == paxUname.as_bytes()
        || k_bytes == paxGname.as_bytes()
    {
        !strings::Contains(v.clone(), "\x00")
    } else {
        !strings::Contains(k.clone(), "\x00")
    };
}

// go: sdk 1.25.5 archive/tar/strconv.go:200-229 parsePAXTime
pub(crate) fn parsePAXTime(s: string) -> (Time, error) {
    const maxNanoSecondDigits: int = 9;
    let parts = strings::SplitN(s, ".", 2);
    let ss = if parts.Len() > 0 {
        parts[0].clone()
    } else {
        string::new()
    };
    let has_dot = parts.Len() > 1;
    let mut sn = if has_dot {
        parts[1].clone()
    } else {
        string::new()
    };

    let ss_bytes = ss.as_bytes();
    let (secs, err) = strconv::ParseInt(&ss, 10, 64);
    if !err.IsNil() {
        return (crate::time::Unix(0, 0), ErrHeader.into());
    }
    if !has_dot {
        return (crate::time::Unix(secs, 0), nil);
    }

    let sn_bytes = sn.as_bytes();
    for &c in sn_bytes {
        if c < b'0' || c > b'9' {
            return (crate::time::Unix(0, 0), ErrHeader.into());
        }
    }

    let sn_len = sn.Len();
    if sn_len < maxNanoSecondDigits {
        sn = sn + strings::Repeat("0", toint(maxNanoSecondDigits - sn_len));
    } else if sn_len > maxNanoSecondDigits {
        sn = sn.slice(0, maxNanoSecondDigits);
    }

    let (nsecs, _) = strconv::ParseInt(&sn, 10, 64);
    return if !ss_bytes.is_empty() && ss_bytes[0] == b'-' {
        (crate::time::Unix(secs, -nsecs), nil)
    } else {
        (crate::time::Unix(secs, nsecs), nil)
    };
}

// ─── parser ──────────────────────────────────────────────────────────

pub(crate) struct parser {
    pub(crate) err: error,
}

impl parser {
    // go: none — goish idiom: Go's `var p parser` / `var f formatter`
    //     is a usable zero value. Rust needs the constructor spelled.
    pub(crate) fn new() -> Self {
        return Self { err: nil };
    }

    // go: sdk 1.25.5 archive/tar/strconv.go:55-61 parser.parseString
    pub(crate) fn parseString(&mut self, b: slice<byte>) -> string {
        let bytes: &[u8] = &b;
        return if let Some(i) = bytes.iter().position(|&c| c == 0) {
            string::from_bytes(&bytes[..i])
        } else {
            string::from_bytes(bytes)
        };
    }

    // go: sdk 1.25.5 archive/tar/strconv.go:96-135 parser.parseNumeric
    pub(crate) fn parseNumeric(&mut self, b: slice<byte>) -> i64 {
        let bytes: &[u8] = &b;
        if !bytes.is_empty() && bytes[0] & 0x80 != 0 {
            let inv = if bytes[0] & 0x40 != 0 { 0xff } else { 0x00 };
            let mut x: u64 = 0;
            for (i, &c) in bytes.iter().enumerate() {
                let mut c = c ^ inv;
                if i == 0 {
                    c &= 0x7f;
                }
                if (x >> 56) > 0 {
                    self.err = ErrHeader.into();
                    return 0;
                }
                x = (x << 8) | touint64(c);
            }
            if (x >> 63) > 0 {
                self.err = ErrHeader.into();
                return 0;
            }
            if inv == 0xff {
                return !toint64(x);
            }
            return toint64(x);
        }
        return self.parseOctal(b);
    }

    // go: sdk 1.25.5 archive/tar/strconv.go:158-174 parser.parseOctal
    pub(crate) fn parseOctal(&mut self, b: slice<byte>) -> i64 {
        let bytes: &[u8] = &b;
        let mut start = 0usize;
        let mut end = bytes.len();
        while start < end && (bytes[start] == b' ' || bytes[start] == 0) {
            start += 1;
        }
        while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == 0) {
            end -= 1;
        }
        if start == end {
            return 0;
        }
        let trimmed = slice::__from_vec(bytes[start..end].to_vec());
        let s = self.parseString(trimmed);
        let (x, err) = strconv::ParseUint(s, 8, 64);
        if !err.IsNil() {
            self.err = ErrHeader.into();
        }
        return toint64(x);
    }
}

// go: sdk 1.25.5 archive/tar/strconv.go:21-28 isASCII
pub(crate) fn isASCII(s: &string) -> bool {
    let bytes = s.as_bytes();
    for &c in bytes {
        if c >= 0x80 || c == 0x00 {
            return false;
        }
    }
    return true;
}

// ─── toASCII / hasNUL (strconv.go) ───────────────────────────────────

// go: sdk 1.25.5 archive/tar/strconv.go:16-18 hasNUL
pub(crate) fn hasNUL(s: &string) -> bool {
    return strings::Contains(s.clone(), "\x00");
}

// go: sdk 1.25.5 archive/tar/strconv.go:32-43 toASCII
/// `toASCII` — best-effort conversion to an ASCII C-style string.
pub(crate) fn toASCII(s: &string) -> string {
    if isASCII(s) {
        return s.clone();
    }
    let mut b: Vec<u8> = Vec::with_capacity(s.Len() as usize);
    for &c in s.as_bytes() {
        if c < 0x80 && c != 0x00 {
            b.push(c);
        }
    }
    return string::from_bytes(&b);
}

// ─── formatter — write-side numeric/string encoders (strconv.go) ─────

pub(crate) struct formatter {
    pub(crate) err: error,
}

impl formatter {
    // go: none — goish idiom: Go's `var p parser` / `var f formatter`
    //     is a usable zero value. Rust needs the constructor spelled.
    pub(crate) fn new() -> Self {
        return Self { err: nil };
    }

    // go: sdk 1.25.5 archive/tar/strconv.go:63-79 formatter.formatString
    /// `formatString` — copy `s` into `b`, NUL-terminating if possible.
    pub(crate) fn formatString(&mut self, b: &mut [u8], s: &string) {
        let sb = s.as_bytes();
        if sb.len() > b.len() {
            self.err = ErrFieldTooLong.into();
        }
        copyBytes(b, sb);
        if sb.len() < b.len() {
            b[sb.len()] = 0;
        }
        // Buggy-reader workaround: a regular file with a trailing slash
        // in the V7 path field looks like a directory.
        if sb.len() > b.len() && b[b.len() - 1] == b'/' {
            let blen = b.len();
            let trimmed = strings::TrimRight(string::from_bytes(&sb[..blen - 1]), "/");
            let n = trimmed.Len() as usize;
            b[n] = 0;
        }
    }

    // go: sdk 1.25.5 archive/tar/strconv.go:139-156 formatter.formatNumeric
    /// `formatNumeric` — octal if it fits, else base-256 binary.
    pub(crate) fn formatNumeric(&mut self, b: &mut [u8], mut x: i64) {
        if fitsInOctal(toint(b.len()), x) {
            self.formatOctal(b, x);
            return;
        }
        if fitsInBase256(toint(b.len()), x) {
            let mut i = b.len();
            while i > 0 {
                i -= 1;
                b[i] = touint8(x & 0xff);
                x >>= 8;
            }
            b[0] |= 0x80; // Highest bit indicates binary format
            return;
        }
        self.formatOctal(b, 0); // Last resort
        self.err = ErrFieldTooLong.into();
    }

    // go: sdk 1.25.5 archive/tar/strconv.go:176-188 formatter.formatOctal
    /// `formatOctal` — base-8 with leading zeros and a NUL terminator.
    pub(crate) fn formatOctal(&mut self, b: &mut [u8], mut x: i64) {
        if !fitsInOctal(toint(b.len()), x) {
            x = 0;
            self.err = ErrFieldTooLong.into();
        }
        let mut s = strconv::FormatInt(x, 8);
        // Add leading zeros, but leave room for a NUL.
        let n = toint(b.len()) - toint(s.Len()) - 1;
        if n > 0 {
            s = strings::Repeat("0", n) + s;
        }
        self.formatString(b, &s);
    }
}

// go: sdk 1.25.5 archive/tar/strconv.go:88-91 fitsInBase256
/// `fitsInBase256` — reports whether `x` fits in `n` base-256 bytes.
pub(crate) fn fitsInBase256(n: int, x: i64) -> bool {
    let bin_bits: u32 = touint32(n - 1) * 8;
    return n >= 9 || (x >= -(1_i64 << bin_bits) && x < (1_i64 << bin_bits));
}

// go: sdk 1.25.5 archive/tar/strconv.go:192-195 fitsInOctal
/// `fitsInOctal` — reports whether `x` fits in `n` octal bytes.
pub(crate) fn fitsInOctal(n: int, x: i64) -> bool {
    let oct_bits: u32 = touint32(n - 1) * 3;
    return x >= 0 && (n >= 22 || x < (1_i64 << oct_bits));
}

// go: sdk 1.25.5 archive/tar/strconv.go:233-247 formatPAXTime
/// `formatPAXTime` — convert `ts` into a `%d.%d` PAX time string.
pub(crate) fn formatPAXTime(ts: Time) -> string {
    let secs = ts.Unix();
    let nsecs = ts.Nanosecond();
    if nsecs == 0 {
        return strconv::FormatInt(secs, 10);
    }
    let mut sign = string::new();
    let mut secs = secs;
    let mut nsecs = nsecs;
    if secs < 0 {
        sign = crate::string("-");
        secs = -(secs + 1);
        nsecs = -(nsecs - 1_000_000_000);
    }
    // "%s%d.%09d" then strip trailing zeros.
    let mut ns = strconv::FormatInt(nsecs, 10);
    while toint(ns.Len()) < 9 {
        ns = crate::string("0") + ns;
    }
    let composed = sign + strconv::FormatInt(secs, 10) + "." + ns;
    return strings::TrimRight(composed, "0");
}

// go: sdk 1.25.5 archive/tar/strconv.go:289-305 formatPAXRecord
/// `formatPAXRecord` — format one PAX record with its length prefix.
pub(crate) fn formatPAXRecord(k: &string, v: &string) -> (string, error) {
    if !validPAXRecord(k.clone(), v.clone()) {
        return (string::new(), ErrHeader.into());
    }
    const padding: int = 3; // ' ', '=', '\n'
    let mut size = toint(k.Len()) + toint(v.Len()) + padding;
    size += toint(strconv::Itoa(size).Len());
    let build =
        |sz: int| -> string { strconv::Itoa(sz) + " " + k.clone() + "=" + v.clone() + "\n" };
    let mut record = build(size);
    // Final adjustment if the size field grew the record.
    if toint(record.Len()) != size {
        size = toint(record.Len());
        record = build(size);
    }
    return (record, nil);
}
