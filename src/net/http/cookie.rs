// net/http/cookie — Go's `http.Cookie`, ported.
//
//   Go                                      goish
//   ─────────────────────────────────────   ──────────────────────────────────
//   c := &http.Cookie{Name: "k", Value: "v"} let c = http::Cookie::new(string("k"), string("v"));
//   http.SetCookie(w, c)                     http::SetCookie(w, &c);
//   r.Cookies()                              r.Cookies()
//   r.Cookie("session")                      r.Cookie(string("session"))
//   c.String()                               c.String()
//
// Faithful port of Go 1.25 src/net/http/cookie.go (577 LOC). Notable
// deviations from Go:
//
//   * Cookie limit (`defaultCookieMaxNum=3000`) honored as a hard cap;
//     Go's GODEBUG override is dropped (no godebug yet).
//   * `validCookieDomain` accepts only IPv4 literals as IPs (no IPv6
//     since `net::ParseIP` isn't ported yet). RFC 6265 only requires
//     IPv4; IPv6 literals must be bracketed and aren't valid cookie
//     domains anyway.
//   * Time parse/format for the `Expires` attribute uses an inline
//     IMF-fixdate parser (`Mon, 02 Jan 2006 15:04:05 GMT`) instead of
//     `time::Parse`/`time::Format` since those aren't ported yet. The
//     legacy `Mon, 02-Jan-2006 15:04:05 MST` form is also accepted on
//     read.
//
// Reference: /nix/store/.../net/http/cookie.go.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::strings;
use crate::time;
use crate::types::{byte, int};

use super::header::Header;

// ─── Cookie struct ───────────────────────────────────────────────────

/// `http.Cookie` (cookie.go:26). All fields public to match Go's
/// struct literal idiom: `Cookie{Name: ..., Value: ..., ...}`.
#[derive(Clone)]
pub struct Cookie {
    pub Name: string,
    pub Value: string,
    /// Whether the value was originally double-quoted.
    pub Quoted: bool,
    pub Path: string,
    pub Domain: string,
    pub Expires: time::Time,
    /// Raw `Expires` string (read-only; populated by `ParseSetCookie`).
    pub RawExpires: string,
    /// `MaxAge=0` ⇒ no Max-Age attribute. `MaxAge<0` ⇒ delete now
    /// (`Max-Age=0` on the wire). `MaxAge>0` ⇒ that many seconds.
    pub MaxAge: int,
    pub Secure: bool,
    pub HttpOnly: bool,
    pub SameSite: SameSite,
    pub Partitioned: bool,
    /// Original Set-Cookie line (populated by `ParseSetCookie`).
    pub Raw: string,
    /// Attribute-value pairs the parser couldn't recognize.
    pub Unparsed: slice<string>,
}

impl Default for Cookie {
    fn default() -> Self {
        Cookie {
            Name: string::new(),
            Value: string::new(),
            Quoted: false,
            Path: string::new(),
            Domain: string::new(),
            Expires: time::Time::default(),
            RawExpires: string::new(),
            MaxAge: 0,
            Secure: false,
            HttpOnly: false,
            SameSite: SameSite::DefaultMode,
            Partitioned: false,
            Raw: string::new(),
            Unparsed: slice::<string>::__from_vec(Vec::new()),
        }
    }
}

impl Cookie {
    /// Convenience constructor: a Cookie with `Name`/`Value` set and
    /// every other field at its zero value. The Go-idiomatic way is
    /// the struct literal, but this is handier for the common case.
    pub fn new(name: string, value: string) -> Self {
        let mut c = Cookie::default();
        c.Name = name;
        c.Value = value;
        c
    }
}

/// `http.SameSite` (cookie.go:54). Default mode = no attribute on the
/// wire; the four named modes map to the SameSite= attribute values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum SameSite {
    DefaultMode = 1,
    LaxMode = 2,
    StrictMode = 3,
    NoneMode = 4,
}

// ─── Errors (lazy-init for stable identity) ──────────────────────────

fn err_blank_cookie() -> error {
    errors::New(string("http: blank cookie"))
}
fn err_equal_not_found() -> error {
    errors::New(string("http: '=' not found in cookie"))
}
fn err_invalid_name() -> error {
    errors::New(string("http: invalid cookie name"))
}
fn err_invalid_value() -> error {
    errors::New(string("http: invalid cookie value"))
}
fn err_num_limit() -> error {
    errors::New(string("http: number of cookies exceeded limit"))
}

const DEFAULT_COOKIE_MAX_NUM: usize = 3000;

#[inline]
fn cookie_num_within_max(n: usize) -> bool {
    n <= DEFAULT_COOKIE_MAX_NUM
}

// ─── ParseCookie / ParseSetCookie ────────────────────────────────────

/// `http.ParseCookie(line)` — parse a `Cookie:` header value into the
/// list of cookies it carries (cookie.go:91). Same name may appear
/// multiple times.
pub fn ParseCookie(line: string) -> (slice<Cookie>, error) {
    let semi_count = strings::Count(line.clone(), string(";")) as usize;
    if !cookie_num_within_max(semi_count + 1) {
        return (slice::<Cookie>::__from_vec(Vec::new()), err_num_limit());
    }
    let trimmed = strings::TrimSpace(line);
    let parts = strings::Split(trimmed.clone(), string(";"));
    if parts.Len() == 1 && parts[0].Len() == 0 {
        return (slice::<Cookie>::__from_vec(Vec::new()), err_blank_cookie());
    }
    let mut out: Vec<Cookie> = Vec::with_capacity(parts.Len() as usize);
    for i in 0..parts.Len() {
        let s = strings::TrimSpace(parts[i].clone());
        let (name, value, found) = strings::Cut(s, string("="));
        if !found {
            return (slice::<Cookie>::__from_vec(Vec::new()), err_equal_not_found());
        }
        if !is_token(&name) {
            return (slice::<Cookie>::__from_vec(Vec::new()), err_invalid_name());
        }
        let (val, quoted, ok) = parse_cookie_value(&value, true);
        if !ok {
            return (slice::<Cookie>::__from_vec(Vec::new()), err_invalid_value());
        }
        let mut c = Cookie::default();
        c.Name = name;
        c.Value = val;
        c.Quoted = quoted;
        out.push(c);
    }
    (slice::<Cookie>::__from_vec(out), errors::nil)
}

/// `http.ParseSetCookie(line)` — parse a `Set-Cookie:` header value
/// (cookie.go:120).
pub fn ParseSetCookie(line: string) -> (Cookie, error) {
    let trimmed = strings::TrimSpace(line.clone());
    let parts = strings::Split(trimmed, string(";"));
    if parts.Len() == 1 && parts[0].Len() == 0 {
        return (Cookie::default(), err_blank_cookie());
    }
    let head = strings::TrimSpace(parts[0].clone());
    let (name_raw, value_raw, ok) = strings::Cut(head, string("="));
    if !ok {
        return (Cookie::default(), err_equal_not_found());
    }
    let name = strings::TrimSpace(name_raw);
    if !is_token(&name) {
        return (Cookie::default(), err_invalid_name());
    }
    let (val, quoted, ok) = parse_cookie_value(&value_raw, true);
    if !ok {
        return (Cookie::default(), err_invalid_value());
    }
    let mut c = Cookie::default();
    c.Name = name;
    c.Value = val;
    c.Quoted = quoted;
    c.Raw = line;

    let mut unparsed: Vec<string> = Vec::new();
    for i in 1..parts.Len() {
        let part = strings::TrimSpace(parts[i].clone());
        if part.Len() == 0 {
            continue;
        }
        let (attr, raw_val, _) = strings::Cut(part.clone(), string("="));
        let lower_attr = ascii_to_lower_string(&attr);
        let (vv, _, vok) = parse_cookie_value(&raw_val, false);
        if !vok {
            unparsed.push(part);
            continue;
        }
        match lower_attr.as_bytes() {
            b"samesite" => {
                let lower_val = ascii_to_lower_string(&vv);
                c.SameSite = match lower_val.as_bytes() {
                    b"lax" => SameSite::LaxMode,
                    b"strict" => SameSite::StrictMode,
                    b"none" => SameSite::NoneMode,
                    _ => SameSite::DefaultMode,
                };
            }
            b"secure" => c.Secure = true,
            b"httponly" => c.HttpOnly = true,
            b"domain" => c.Domain = vv,
            b"max-age" => {
                let (secs, perr) = crate::strconv::Atoi(vv.clone());
                let bad_zero = vv.Len() > 0 && vv.as_bytes()[0] == b'0' && secs != 0;
                if !perr.IsNil() || bad_zero {
                    unparsed.push(part);
                    continue;
                }
                c.MaxAge = if secs <= 0 { -1 } else { secs };
            }
            b"expires" => {
                c.RawExpires = vv.clone();
                if let Some(t) = parse_imf_fixdate(&vv).or_else(|| parse_legacy_cookie_date(&vv)) {
                    c.Expires = t;
                } else {
                    c.Expires = time::Time::default();
                }
            }
            b"path" => c.Path = vv,
            b"partitioned" => c.Partitioned = true,
            _ => unparsed.push(part),
        }
    }
    c.Unparsed = slice::<string>::__from_vec(unparsed);
    (c, errors::nil)
}

// ─── Cookie::String / Valid ──────────────────────────────────────────

impl Cookie {
    /// Serialize the cookie for use in a `Cookie:` header (when only
    /// `Name`+`Value` are set) or `Set-Cookie:` response header (when
    /// any other field is set). Returns `""` if `Name` is invalid.
    /// Mirrors `(*Cookie).String()` (cookie.go:261).
    pub fn String(&self) -> string {
        if !is_token(&self.Name) {
            return string::new();
        }
        let cap = (self.Name.Len() + self.Value.Len() + self.Domain.Len() + self.Path.Len()) as usize + 110;
        let mut out: Vec<u8> = Vec::with_capacity(cap);
        out.extend_from_slice(self.Name.as_bytes());
        out.push(b'=');
        let sanitized = sanitize_cookie_value(&self.Value, self.Quoted);
        out.extend_from_slice(sanitized.as_bytes());

        if self.Path.Len() > 0 {
            out.extend_from_slice(b"; Path=");
            let p = sanitize_cookie_path(&self.Path);
            out.extend_from_slice(p.as_bytes());
        }
        if self.Domain.Len() > 0 && valid_cookie_domain(&self.Domain) {
            // Strip leading dot per RFC 6265.
            let d = self.Domain.as_bytes();
            let dd = if !d.is_empty() && d[0] == b'.' { &d[1..] } else { d };
            out.extend_from_slice(b"; Domain=");
            out.extend_from_slice(dd);
        }
        if valid_cookie_expires(&self.Expires) {
            out.extend_from_slice(b"; Expires=");
            append_imf_fixdate(&mut out, &self.Expires);
        }
        if self.MaxAge > 0 {
            out.extend_from_slice(b"; Max-Age=");
            append_int(&mut out, self.MaxAge);
        } else if self.MaxAge < 0 {
            out.extend_from_slice(b"; Max-Age=0");
        }
        if self.HttpOnly {
            out.extend_from_slice(b"; HttpOnly");
        }
        if self.Secure {
            out.extend_from_slice(b"; Secure");
        }
        match self.SameSite {
            SameSite::DefaultMode => {} // skip
            SameSite::NoneMode => out.extend_from_slice(b"; SameSite=None"),
            SameSite::LaxMode => out.extend_from_slice(b"; SameSite=Lax"),
            SameSite::StrictMode => out.extend_from_slice(b"; SameSite=Strict"),
        }
        if self.Partitioned {
            out.extend_from_slice(b"; Partitioned");
        }
        string::from_bytes(&out)
    }

    /// Reports whether the cookie is valid. Returns `errors::nil` if so,
    /// else an error describing the first problem. Mirrors
    /// `(*Cookie).Valid()` (cookie.go:328).
    pub fn Valid(&self) -> error {
        if !is_token(&self.Name) {
            return errors::New(string("http: invalid Cookie.Name"));
        }
        if !self.Expires.IsZero() && !valid_cookie_expires(&self.Expires) {
            return errors::New(string("http: invalid Cookie.Expires"));
        }
        for &b in self.Value.as_bytes() {
            if !valid_cookie_value_byte(b) {
                return errors::New(string("http: invalid byte in Cookie.Value"));
            }
        }
        if self.Path.Len() > 0 {
            for &b in self.Path.as_bytes() {
                if !valid_cookie_path_byte(b) {
                    return errors::New(string("http: invalid byte in Cookie.Path"));
                }
            }
        }
        if self.Domain.Len() > 0 && !valid_cookie_domain(&self.Domain) {
            return errors::New(string("http: invalid Cookie.Domain"));
        }
        if self.Partitioned && !self.Secure {
            return errors::New(string("http: partitioned cookies must be set with Secure"));
        }
        errors::nil
    }
}

// ─── readCookies / readSetCookies — used by Request / Response ───────

/// Parse all "Cookie" header lines from `h`. If `filter` is non-empty,
/// only cookies named `filter` are returned. Mirrors `readCookies`
/// (cookie.go:371).
pub(crate) fn read_cookies(h: &Header, filter: &string) -> slice<Cookie> {
    let lines = h.Values(string("Cookie"));
    if lines.Len() == 0 {
        return slice::<Cookie>::__from_vec(Vec::new());
    }
    let mut total_segments: usize = 0;
    for i in 0..lines.Len() {
        total_segments += strings::Count(lines[i].clone(), string(";")) as usize + 1;
    }
    if !cookie_num_within_max(total_segments) {
        return slice::<Cookie>::__from_vec(Vec::new());
    }
    let mut out: Vec<Cookie> = Vec::with_capacity(total_segments);
    for i in 0..lines.Len() {
        let mut line = strings::TrimSpace(lines[i].clone());
        while line.Len() > 0 {
            let (part, rest, _) = strings::Cut(line.clone(), string(";"));
            line = rest;
            let part = strings::TrimSpace(part);
            if part.Len() == 0 {
                continue;
            }
            let (name_raw, val_raw, _) = strings::Cut(part, string("="));
            let name = strings::TrimSpace(name_raw);
            if !is_token(&name) {
                continue;
            }
            if filter.Len() > 0 && *filter != name {
                continue;
            }
            let (val, quoted, ok) = parse_cookie_value(&val_raw, true);
            if !ok {
                continue;
            }
            let mut c = Cookie::default();
            c.Name = name;
            c.Value = val;
            c.Quoted = quoted;
            out.push(c);
        }
    }
    slice::<Cookie>::__from_vec(out)
}

/// Parse all "Set-Cookie" headers from `h`. Mirrors `readSetCookies`
/// (cookie.go:228). Used by the (future) `Response` type.
pub(crate) fn read_set_cookies(h: &Header) -> slice<Cookie> {
    let lines = h.Values(string("Set-Cookie"));
    if lines.Len() == 0 || !cookie_num_within_max(lines.Len() as usize) {
        return slice::<Cookie>::__from_vec(Vec::new());
    }
    let mut out: Vec<Cookie> = Vec::with_capacity(lines.Len() as usize);
    for i in 0..lines.Len() {
        let (c, err) = ParseSetCookie(lines[i].clone());
        if err.IsNil() {
            out.push(c);
        }
    }
    slice::<Cookie>::__from_vec(out)
}

// ─── SetCookie ───────────────────────────────────────────────────────

/// `http.SetCookie(w, c)` — appends `Set-Cookie: c.String()` to the
/// response header. Drops cookies with invalid names. Mirrors
/// `SetCookie` (cookie.go:251).
pub fn SetCookie(w: &mut super::ResponseWriter, c: &Cookie) {
    let v = c.String();
    if v.Len() == 0 {
        return;
    }
    w.Header().Add(string("Set-Cookie"), v);
}

// ─── helpers — RFC 6265 byte classes, sanitizers, parser ─────────────

/// `validCookieValueByte` — RFC 6265 cookie-octet (loosened to allow
/// space/comma; emitted quoted by `sanitize_cookie_value`).
fn valid_cookie_value_byte(b: byte) -> bool {
    0x20 <= b && b < 0x7f && b != b'"' && b != b';' && b != b'\\'
}

fn valid_cookie_path_byte(b: byte) -> bool {
    0x20 <= b && b < 0x7f && b != b';'
}

/// RFC 7230 token char — used for cookie *names*. Allows alnum and
/// `!#$%&'*+-.^_` `\`` `|~`.
fn is_token_byte(b: byte) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
        b'^' | b'_' | b'`' | b'|' | b'~' |
        b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')
}

fn is_token(s: &string) -> bool {
    let b = s.as_bytes();
    if b.is_empty() {
        return false;
    }
    for &c in b {
        if !is_token_byte(c) {
            return false;
        }
    }
    true
}

fn sanitize_cookie_value(v: &string, quoted: bool) -> string {
    let cleaned = sanitize_or_drop(v.as_bytes(), valid_cookie_value_byte);
    if cleaned.is_empty() {
        return string::from_bytes(&cleaned);
    }
    let needs_quotes =
        quoted || cleaned.iter().any(|&b| b == b' ' || b == b',');
    if needs_quotes {
        let mut out = Vec::with_capacity(cleaned.len() + 2);
        out.push(b'"');
        out.extend_from_slice(&cleaned);
        out.push(b'"');
        string::from_bytes(&out)
    } else {
        string::from_bytes(&cleaned)
    }
}

fn sanitize_cookie_path(v: &string) -> string {
    let cleaned = sanitize_or_drop(v.as_bytes(), valid_cookie_path_byte);
    string::from_bytes(&cleaned)
}

/// `sanitizeOrWarn` (cookie.go:534). The Go version logs a warning;
/// we silently drop. Returns a fresh byte vec whether or not anything
/// was filtered.
fn sanitize_or_drop(v: &[u8], valid: fn(byte) -> bool) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(v.len());
    for &b in v {
        if valid(b) {
            out.push(b);
        }
    }
    out
}

/// `parseCookieValue` (cookie.go:565). Strips matching outer quotes
/// when `allow_double_quote` is set; rejects invalid bytes.
fn parse_cookie_value(raw: &string, allow_double_quote: bool) -> (string, bool, bool) {
    let mut bytes = raw.as_bytes();
    let mut quoted = false;
    if allow_double_quote && bytes.len() > 1 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        bytes = &bytes[1..bytes.len() - 1];
        quoted = true;
    }
    for &b in bytes {
        if !valid_cookie_value_byte(b) {
            return (string::new(), quoted, false);
        }
    }
    (string::from_bytes(bytes), quoted, true)
}

fn valid_cookie_domain(v: &string) -> bool {
    if is_cookie_domain_name(v) {
        return true;
    }
    is_ipv4_literal(v.as_bytes())
}

fn valid_cookie_expires(t: &time::Time) -> bool {
    // RFC 6265 §5.1.1.5 — year >= 1601.
    !t.IsZero() && t.Year() >= 1601
}

/// Mirrors `isCookieDomainName` (cookie.go:437). Almost a direct copy
/// of net's `isDomainName`, but disallows underscore.
fn is_cookie_domain_name(s: &string) -> bool {
    let mut bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 {
        return false;
    }
    if bytes[0] == b'.' {
        bytes = &bytes[1..];
    }
    let mut last: u8 = b'.';
    let mut ok = false;
    let mut partlen: usize = 0;
    for &c in bytes {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' => {
                ok = true;
                partlen += 1;
            }
            b'0'..=b'9' => partlen += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                partlen += 1;
            }
            b'.' => {
                if last == b'.' || last == b'-' {
                    return false;
                }
                if partlen > 63 || partlen == 0 {
                    return false;
                }
                partlen = 0;
            }
            _ => return false,
        }
        last = c;
    }
    !(last == b'-' || partlen > 63) && ok
}

/// Tiny IPv4-literal check — `D.D.D.D` where each D is 0..255 with
/// no leading-zero shenanigans. Used in place of `net::ParseIP`.
fn is_ipv4_literal(s: &[u8]) -> bool {
    let mut octets = 0;
    let mut digits: u32 = 0;
    let mut acc: u32 = 0;
    for &b in s {
        if b == b'.' {
            if digits == 0 || acc > 255 {
                return false;
            }
            octets += 1;
            digits = 0;
            acc = 0;
        } else if b.is_ascii_digit() {
            acc = acc * 10 + (b - b'0') as u32;
            digits += 1;
            if digits > 3 || acc > 255 {
                return false;
            }
        } else {
            return false;
        }
    }
    octets == 3 && digits > 0 && acc <= 255
}

#[inline]
fn ascii_to_lower_string(s: &string) -> string {
    let mut out = Vec::with_capacity(s.Len() as usize);
    for &b in s.as_bytes() {
        out.push(if (b'A'..=b'Z').contains(&b) { b + 32 } else { b });
    }
    string::from_bytes(&out)
}

fn append_int(out: &mut Vec<u8>, mut n: int) {
    if n == 0 {
        out.push(b'0');
        return;
    }
    let neg = n < 0;
    if neg {
        n = -n;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    if neg {
        out.push(b'-');
    }
    out.extend_from_slice(&buf[i..]);
}

// ─── inline IMF-fixdate (RFC 7231 §7.1.1.1): "Mon, 02 Jan 2006 15:04:05 GMT"

const DAY_NAMES: [&[u8]; 7] = [
    b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat",
];
const MONTH_NAMES: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun",
    b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

fn append_imf_fixdate(out: &mut Vec<u8>, t: &time::Time) {
    let weekday = t.Weekday() as usize % 7;
    let (year, month, day) = t.Date();
    let (hh, mm, ss) = t.Clock();
    out.extend_from_slice(DAY_NAMES[weekday]);
    out.extend_from_slice(b", ");
    push_2(out, day as u32);
    out.push(b' ');
    out.extend_from_slice(MONTH_NAMES[(month - 1) as usize % 12]);
    out.push(b' ');
    push_4(out, year as u32);
    out.push(b' ');
    push_2(out, hh as u32);
    out.push(b':');
    push_2(out, mm as u32);
    out.push(b':');
    push_2(out, ss as u32);
    out.extend_from_slice(b" GMT");
}

fn push_2(out: &mut Vec<u8>, n: u32) {
    out.push(b'0' + ((n / 10) % 10) as u8);
    out.push(b'0' + (n % 10) as u8);
}
fn push_4(out: &mut Vec<u8>, n: u32) {
    out.push(b'0' + ((n / 1000) % 10) as u8);
    out.push(b'0' + ((n / 100) % 10) as u8);
    out.push(b'0' + ((n / 10) % 10) as u8);
    out.push(b'0' + (n % 10) as u8);
}

/// Parse `"Mon, 02 Jan 2006 15:04:05 GMT"`. Returns `None` on any
/// shape mismatch — the caller falls through to the legacy form.
fn parse_imf_fixdate(s: &string) -> Option<time::Time> {
    parse_cookie_date(s.as_bytes(), b' ')
}

/// Parse `"Mon, 02-Jan-2006 15:04:05 MST"` — dash-separated d-M-y.
fn parse_legacy_cookie_date(s: &string) -> Option<time::Time> {
    parse_cookie_date(s.as_bytes(), b'-')
}

fn parse_cookie_date(b: &[u8], sep: u8) -> Option<time::Time> {
    // "Mon, 02 Jan 2006 15:04:05 GMT" = 29 bytes; legacy = 29.
    if b.len() < 25 {
        return None;
    }
    // Skip the day-of-week + ", ".
    let comma = b.iter().position(|&c| c == b',')?;
    let after = &b[comma + 1..];
    let after = if !after.is_empty() && after[0] == b' ' {
        &after[1..]
    } else {
        after
    };
    if after.len() < 20 {
        return None;
    }
    let day = read_2(&after[0..2])?;
    if after[2] != sep {
        return None;
    }
    let month = month_index(&after[3..6])?;
    if after[6] != sep {
        return None;
    }
    let year = read_4(&after[7..11])?;
    if after[11] != b' ' {
        return None;
    }
    let hh = read_2(&after[12..14])?;
    if after[14] != b':' {
        return None;
    }
    let mm = read_2(&after[15..17])?;
    if after[17] != b':' {
        return None;
    }
    let ss = read_2(&after[18..20])?;
    // Reject obviously bad dates.
    if day == 0 || day > 31 || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    Some(time::Date(
        year as int,
        month as int + 1,
        day as int,
        hh as int,
        mm as int,
        ss as int,
        0,
    ))
}

fn read_2(b: &[u8]) -> Option<u32> {
    if !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
        return None;
    }
    Some(((b[0] - b'0') as u32) * 10 + (b[1] - b'0') as u32)
}

fn read_4(b: &[u8]) -> Option<u32> {
    let mut acc: u32 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc * 10 + (c - b'0') as u32;
    }
    Some(acc)
}

fn month_index(b: &[u8]) -> Option<u32> {
    for (i, m) in MONTH_NAMES.iter().enumerate() {
        if eq_case_insensitive(b, m) {
            return Some(i as u32);
        }
    }
    None
}

fn eq_case_insensitive(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if (a[i] | 0x20) != (b[i] | 0x20) {
            return false;
        }
    }
    true
}
