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
        // Go: attr, val, _ := strings.Cut(parts[i], "=")
        let (attr, raw_val, _) = strings::Cut(part.clone(), string("="));
        // Go: lowerAttr, isASCII := ascii.ToLower(attr); if !isASCII { continue }
        // goish: use strings::EqualFold for each known attribute name —
        // skips the lowering allocation and matches case-insensitively.
        let (vv, _, vok) = parse_cookie_value(&raw_val, false);
        if !vok {
            unparsed.push(part);
            continue;
        }
        if strings::EqualFold(attr.clone(), string("samesite")) {
            // Go: switch lowerVal { case "lax": ...; "strict": ...; "none": ...; default: ... }
            if strings::EqualFold(vv.clone(), string("lax")) {
                c.SameSite = SameSite::LaxMode;
            } else if strings::EqualFold(vv.clone(), string("strict")) {
                c.SameSite = SameSite::StrictMode;
            } else if strings::EqualFold(vv.clone(), string("none")) {
                c.SameSite = SameSite::NoneMode;
            } else {
                c.SameSite = SameSite::DefaultMode;
            }
        } else if strings::EqualFold(attr.clone(), string("secure")) {
            c.Secure = true;
        } else if strings::EqualFold(attr.clone(), string("httponly")) {
            c.HttpOnly = true;
        } else if strings::EqualFold(attr.clone(), string("domain")) {
            c.Domain = vv;
        } else if strings::EqualFold(attr.clone(), string("max-age")) {
            // Go: secs, err := strconv.Atoi(val); if err != nil || secs != 0 && val[0] == '0' { break }
            let (secs, perr) = crate::strconv::Atoi(vv.clone());
            let bad_zero = vv.Len() > 0 && vv[0] == b'0' && secs != 0;
            if !perr.IsNil() || bad_zero {
                unparsed.push(part);
                continue;
            }
            // Go: if secs <= 0 { secs = -1 }; c.MaxAge = secs
            c.MaxAge = if secs <= 0 { -1 } else { secs };
        } else if strings::EqualFold(attr.clone(), string("expires")) {
            // Go: c.RawExpires = val; exptime, err := time.Parse(time.RFC1123, val); …
            c.RawExpires = vv.clone();
            if let Some(t) = parse_imf_fixdate(&vv).or_else(|| parse_legacy_cookie_date(&vv)) {
                c.Expires = t;
            } else {
                c.Expires = time::Time::default();
            }
        } else if strings::EqualFold(attr.clone(), string("path")) {
            c.Path = vv;
        } else if strings::EqualFold(attr.clone(), string("partitioned")) {
            c.Partitioned = true;
        } else {
            unparsed.push(part);
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
    ///
    /// Line-by-line port of `(*Cookie).String()` (cookie.go:261). Uses
    /// `strings::Builder` and `strconv::AppendInt` so the body matches
    /// Go's `var b strings.Builder` flow one statement to one
    /// statement.
    pub fn String(&self) -> string {
        // Go: if c == nil || !isToken(c.Name) { return "" }
        if !is_token(&self.Name) {
            return string("");
        }
        // Go: const extraCookieLength = 110
        const EXTRA_COOKIE_LENGTH: int = 110;
        // Go: var b strings.Builder
        let mut b = strings::Builder::new();
        // Go: b.Grow(len(c.Name) + len(c.Value) + len(c.Domain) + len(c.Path) + extraCookieLength)
        b.Grow(
            self.Name.Len()
                + self.Value.Len()
                + self.Domain.Len()
                + self.Path.Len()
                + EXTRA_COOKIE_LENGTH,
        );
        // Go: b.WriteString(c.Name)
        let _ = b.WriteString(self.Name.clone());
        // Go: b.WriteRune('=')
        let _ = b.WriteByte(b'=');
        // Go: b.WriteString(sanitizeCookieValue(c.Value, c.Quoted))
        let _ = b.WriteString(sanitize_cookie_value(self.Value.clone(), self.Quoted));

        // Go: if len(c.Path) > 0 { b.WriteString("; Path="); b.WriteString(sanitizeCookiePath(c.Path)) }
        if self.Path.Len() > 0 {
            let _ = b.WriteString("; Path=");
            let _ = b.WriteString(sanitize_cookie_path(self.Path.clone()));
        }
        // Go: if len(c.Domain) > 0 { if validCookieDomain(c.Domain) { ... } else { log.Printf("…") } }
        if self.Domain.Len() > 0 {
            if valid_cookie_domain(&self.Domain) {
                // Go: d := c.Domain; if d[0] == '.' { d = d[1:] }
                let d = self.Domain.clone();
                let d = if d.Len() > 0 && d[0] == b'.' {
                    string::from_bytes(&d.as_bytes()[1..])
                } else {
                    d
                };
                let _ = b.WriteString("; Domain=");
                let _ = b.WriteString(d);
            }
            // Go's else branch logs and drops the attribute; we silently drop (no log pkg yet).
        }
        // Go: var buf [len(TimeFormat)]byte
        // Go: if validCookieExpires(c.Expires) { b.WriteString("; Expires="); b.Write(c.Expires.UTC().AppendFormat(buf[:0], TimeFormat)) }
        let mut time_buf: [byte; 29] = [0; 29];
        if valid_cookie_expires(&self.Expires) {
            let _ = b.WriteString("; Expires=");
            let appended = append_imf_fixdate_into(&mut time_buf, &self.Expires);
            let _ = b.WriteString(string::from_bytes(appended));
        }
        // Go: if c.MaxAge > 0 { b.WriteString("; Max-Age="); b.Write(strconv.AppendInt(buf[:0], int64(c.MaxAge), 10)) }
        // Go: else if c.MaxAge < 0 { b.WriteString("; Max-Age=0") }
        if self.MaxAge > 0 {
            let _ = b.WriteString("; Max-Age=");
            let dst = slice::<byte>::__from_vec(Vec::new());
            let appended = crate::strconv::AppendInt(dst, self.MaxAge, 10);
            let _ = b.WriteString(string::from_bytes(&appended));
        } else if self.MaxAge < 0 {
            let _ = b.WriteString("; Max-Age=0");
        }
        // Go: if c.HttpOnly { b.WriteString("; HttpOnly") }
        if self.HttpOnly {
            let _ = b.WriteString("; HttpOnly");
        }
        // Go: if c.Secure { b.WriteString("; Secure") }
        if self.Secure {
            let _ = b.WriteString("; Secure");
        }
        // Go: switch c.SameSite { case SameSiteDefaultMode: ... }
        match self.SameSite {
            SameSite::DefaultMode => {} // Go: skip — default mode = no attribute
            SameSite::NoneMode => {
                let _ = b.WriteString("; SameSite=None");
            }
            SameSite::LaxMode => {
                let _ = b.WriteString("; SameSite=Lax");
            }
            SameSite::StrictMode => {
                let _ = b.WriteString("; SameSite=Strict");
            }
        }
        // Go: if c.Partitioned { b.WriteString("; Partitioned") }
        if self.Partitioned {
            let _ = b.WriteString("; Partitioned");
        }
        // Go: return b.String()
        b.String()
    }

    /// Reports whether the cookie is valid. Returns `errors::nil` if so,
    /// else an error describing the first problem.
    ///
    /// Line-by-line port of `(*Cookie).Valid()` (cookie.go:328).
    pub fn Valid(&self) -> error {
        // Go: if c == nil { return errors.New("http: nil Cookie") }   — we have &self, so always non-nil
        // Go: if !isToken(c.Name) { ... }
        if !is_token(&self.Name) {
            return errors::New(string("http: invalid Cookie.Name"));
        }
        // Go: if !c.Expires.IsZero() && !validCookieExpires(c.Expires) { ... }
        if !self.Expires.IsZero() && !valid_cookie_expires(&self.Expires) {
            return errors::New(string("http: invalid Cookie.Expires"));
        }
        // Go: for i := 0; i < len(c.Value); i++ { if !validCookieValueByte(c.Value[i]) { … } }
        for i in 0..self.Value.Len() {
            if !valid_cookie_value_byte(self.Value[i]) {
                return errors::New(string("http: invalid byte in Cookie.Value"));
            }
        }
        // Go: if len(c.Path) > 0 { for i ... validCookiePathByte ... }
        if self.Path.Len() > 0 {
            for i in 0..self.Path.Len() {
                if !valid_cookie_path_byte(self.Path[i]) {
                    return errors::New(string("http: invalid byte in Cookie.Path"));
                }
            }
        }
        // Go: if len(c.Domain) > 0 { if !validCookieDomain(c.Domain) { … } }
        if self.Domain.Len() > 0 && !valid_cookie_domain(&self.Domain) {
            return errors::New(string("http: invalid Cookie.Domain"));
        }
        // Go: if c.Partitioned { if !c.Secure { return errors.New(...) } }
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

/// Line-by-line port of Go's `isToken` (mime header / RFC 7230 token).
/// Used for cookie-name validation.
fn is_token(s: &string) -> bool {
    // Go: if len(s) == 0 { return false }
    if s.Len() == 0 {
        return false;
    }
    // Go: for i := 0; i < len(s); i++ { if !isTokenByte(s[i]) { return false } }
    for i in 0..s.Len() {
        if !is_token_byte(s[i]) {
            return false;
        }
    }
    true
}

/// Line-by-line port of `sanitizeCookieValue` (cookie.go:509).
fn sanitize_cookie_value(v: string, quoted: bool) -> string {
    // Go: v = sanitizeOrWarn("Cookie.Value", validCookieValueByte, v)
    let v = sanitize_or_warn(string("Cookie.Value"), valid_cookie_value_byte, v);
    // Go: if len(v) == 0 { return v }
    if v.Len() == 0 {
        return v;
    }
    // Go: if strings.ContainsAny(v, " ,") || quoted { return `"` + v + `"` }
    if strings::ContainsAny(v.clone(), string(" ,")) || quoted {
        let mut b = strings::Builder::new();
        b.Grow(v.Len() + 2);
        let _ = b.WriteByte(b'"');
        let _ = b.WriteString(v);
        let _ = b.WriteByte(b'"');
        return b.String();
    }
    // Go: return v
    v
}

/// Line-by-line port of `sanitizeCookiePath` (cookie.go:526).
fn sanitize_cookie_path(v: string) -> string {
    sanitize_or_warn(string("Cookie.Path"), valid_cookie_path_byte, v)
}

/// Line-by-line port of `sanitizeOrWarn` (cookie.go:534). Go's version
/// logs the offending byte via `log.Printf`; goish silently drops
/// since `log` isn't ported. Behavior on the wire is identical.
fn sanitize_or_warn(_field_name: string, valid: fn(byte) -> bool, v: string) -> string {
    // Go: ok := true; for i := 0; i < len(v); i++ { if valid(v[i]) { continue }; … ok = false; break }
    let mut ok = true;
    for i in 0..v.Len() {
        if valid(v[i]) {
            continue;
        }
        // Go logs here; we drop silently.
        ok = false;
        break;
    }
    // Go: if ok { return v }
    if ok {
        return v;
    }
    // Go: buf := make([]byte, 0, len(v))
    let mut buf = crate::make!([]byte, 0, v.Len());
    // Go: for i := 0; i < len(v); i++ { if b := v[i]; valid(b) { buf = append(buf, b) } }
    for i in 0..v.Len() {
        let b = v[i];
        if valid(b) {
            buf = crate::append!(buf, b);
        }
    }
    // Go: return string(buf)
    crate::convert::string(buf)
}

/// Line-by-line port of `parseCookieValue` (cookie.go:565).
/// Strips matching outer quotes when `allow_double_quote` is set;
/// rejects invalid bytes.
fn parse_cookie_value(raw: &string, allow_double_quote: bool) -> (string, bool, bool) {
    // Go: var quoted bool
    let mut quoted = false;
    // Go: if allowDoubleQuote && len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
    //         raw = raw[1 : len(raw)-1]; quoted = true
    //     }
    let raw = if allow_double_quote
        && raw.Len() > 1
        && raw[0] == b'"'
        && raw[raw.Len() - 1] == b'"'
    {
        quoted = true;
        string::from_bytes(&raw.as_bytes()[1..(raw.Len() - 1) as usize])
    } else {
        raw.clone()
    };
    // Go: for i := 0; i < len(raw); i++ { if !validCookieValueByte(raw[i]) { return "", quoted, false } }
    for i in 0..raw.Len() {
        if !valid_cookie_value_byte(raw[i]) {
            return (string(""), quoted, false);
        }
    }
    // Go: return raw, quoted, true
    (raw, quoted, true)
}

/// Line-by-line port of `validCookieDomain` (cookie.go:418). Goish
/// drops the IPv6 path since `net::ParseIP` isn't ported.
fn valid_cookie_domain(v: &string) -> bool {
    // Go: if isCookieDomainName(v) { return true }
    if is_cookie_domain_name(v) {
        return true;
    }
    // Go: if net.ParseIP(v) != nil && !strings.Contains(v, ":") { return true }
    is_ipv4_literal(v)
}

fn valid_cookie_expires(t: &time::Time) -> bool {
    // Go: t.Year() >= 1601 (with goish's IsZero guard for safety)
    !t.IsZero() && t.Year() >= 1601
}

/// Line-by-line port of `isCookieDomainName` (cookie.go:437). Direct
/// copy of net's `isDomainName` with underscore disallowed.
fn is_cookie_domain_name(s: &string) -> bool {
    // Go: if len(s) == 0 { return false }; if len(s) > 255 { return false }
    if s.Len() == 0 || s.Len() > 255 {
        return false;
    }
    // Go: if s[0] == '.' { s = s[1:] }
    let s = if s[0] == b'.' {
        string::from_bytes(&s.as_bytes()[1..])
    } else {
        s.clone()
    };
    // Go: last := byte('.'); ok := false; partlen := 0
    let mut last: byte = b'.';
    let mut ok = false;
    let mut partlen: int = 0;
    // Go: for i := 0; i < len(s); i++ { c := s[i]; switch { ... } }
    for i in 0..s.Len() {
        let c: byte = s[i];
        if (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z') {
            ok = true;
            partlen += 1;
        } else if c >= b'0' && c <= b'9' {
            partlen += 1;
        } else if c == b'-' {
            if last == b'.' {
                return false;
            }
            partlen += 1;
        } else if c == b'.' {
            if last == b'.' || last == b'-' {
                return false;
            }
            if partlen > 63 || partlen == 0 {
                return false;
            }
            partlen = 0;
        } else {
            return false;
        }
        last = c;
    }
    // Go: if last == '-' || partlen > 63 { return false }
    if last == b'-' || partlen > 63 {
        return false;
    }
    ok
}

/// IPv4 dotted-decimal literal check (4 octets 0..=255). Stand-in for
/// `net.ParseIP(v) != nil && !strings.Contains(v, ":")` until net.ParseIP
/// is ported.
fn is_ipv4_literal(s: &string) -> bool {
    // Go (paraphrased): split on '.'; need exactly 4 numeric groups.
    let parts = strings::Split(s.clone(), string("."));
    if parts.Len() != 4 {
        return false;
    }
    for i in 0..parts.Len() {
        let p = parts[i].clone();
        if p.Len() == 0 || p.Len() > 3 {
            return false;
        }
        let (n, err) = crate::strconv::Atoi(p);
        if !err.IsNil() || n < 0 || n > 255 {
            return false;
        }
    }
    true
}

// ─── inline IMF-fixdate (RFC 7231 §7.1.1.1): "Mon, 02 Jan 2006 15:04:05 GMT"
//
// Matches Go's `TimeFormat` constant from net/http/server.go:
//   "Mon, 02 Jan 2006 15:04:05 GMT" — 29 bytes, fixed.
// Used in place of `time.Time.Format(TimeFormat)` until time::Format is
// ported.

const DAY_NAMES: [&[byte; 3]; 7] = [
    b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat",
];
const MONTH_NAMES: [&[byte; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun",
    b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Fill `buf` (must be ≥ 29 bytes) with the IMF-fixdate rendering of
/// `t`, returning a slice covering exactly the 29 bytes written.
/// Mirrors Go's `t.UTC().AppendFormat(buf[:0], TimeFormat)` flow.
fn append_imf_fixdate_into<'a>(buf: &'a mut [byte; 29], t: &time::Time) -> &'a [byte] {
    let weekday = (t.Weekday() as usize) % 7;
    let (year, month, day) = t.Date();
    let (hh, mm, ss) = t.Clock();
    let dn = DAY_NAMES[weekday];
    buf[0] = dn[0];
    buf[1] = dn[1];
    buf[2] = dn[2];
    buf[3] = b',';
    buf[4] = b' ';
    write_2(&mut buf[5..7], day as u32);
    buf[7] = b' ';
    let mn = MONTH_NAMES[((month - 1) as usize) % 12];
    buf[8] = mn[0];
    buf[9] = mn[1];
    buf[10] = mn[2];
    buf[11] = b' ';
    write_4(&mut buf[12..16], year as u32);
    buf[16] = b' ';
    write_2(&mut buf[17..19], hh as u32);
    buf[19] = b':';
    write_2(&mut buf[20..22], mm as u32);
    buf[22] = b':';
    write_2(&mut buf[23..25], ss as u32);
    buf[25] = b' ';
    buf[26] = b'G';
    buf[27] = b'M';
    buf[28] = b'T';
    &buf[..]
}

fn write_2(dst: &mut [byte], n: u32) {
    dst[0] = b'0' + ((n / 10) % 10) as byte;
    dst[1] = b'0' + (n % 10) as byte;
}
fn write_4(dst: &mut [byte], n: u32) {
    dst[0] = b'0' + ((n / 1000) % 10) as byte;
    dst[1] = b'0' + ((n / 100) % 10) as byte;
    dst[2] = b'0' + ((n / 10) % 10) as byte;
    dst[3] = b'0' + (n % 10) as byte;
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
        if eq_case_insensitive(b, &m[..]) {
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
