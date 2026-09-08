// go: package net/http
//
// go: file net/http/cookie.go decls: cookieNumWithinMax, ParseCookie, ParseSetCookie, readSetCookies, SetCookie, Cookie.String, Cookie.Valid, readCookies, validCookieDomain, validCookieExpires, isCookieDomainName, sanitizeCookieName, sanitizeCookieValue, validCookieValueByte, sanitizeCookiePath, validCookiePathByte, sanitizeOrWarn, parseCookieValue, cookieNameSanitizer
//
// Go: "http.Cookie represents an HTTP cookie as sent in the Set-Cookie
// header of an HTTP response or the Cookie header of an HTTP request."
//
//   Go                                       goish
//   ──────────────────────────────────────   ─────────────────────────────────
//   c := &http.Cookie{Name: "k", Value: "v"} let c = http::Cookie::new(string("k"), string("v"));
//   http.SetCookie(w, c)                     http::SetCookie(w, &c);
//   r.Cookies()                              r.Cookies()
//   c.String()                               c.String()
//
// Three divergences, all deliberate and all narrower than the notes
// that used to sit here claimed:
//
//   * `defaultCookieMaxNum` (3000) is a hard cap. Go lets the
//     httpcookiemaxnum GODEBUG raise or disable it; goish has no
//     godebug, so `cookieNumWithinMax` is the default branch only.
// ─── What has been diffed against Go, 2026-09-06 ─────────────────────
//
//   clean  sanitizeCookieValue and its predicate. validCookieValueByte
//          is byte-for-byte Go's — `0x20 <= b && b < 0x7f && b != '"'
//          && b != ';' && b != '\\'` — which is what keeps a quote,
//          semicolon, backslash or control byte out of a Set-Cookie
//          header. The quoting rule (` ,` or an already-quoted value)
//          matches too.
//   clean  sanitizeCookieName rewrites CR and LF to '-' through the
//          same Replacer pair Go uses. It does not REJECT a bad name,
//          which the note at its definition already explains; that is
//          Go's behaviour, not a slim.
//   clean  the 3000-cookie cap is enforced at THREE call sites, the
//          same three Go enforces it at (cookie.go:92, 236, 384). A
//          limit that is defined and never consulted is a shape this
//          tree has produced before, so the call sites were counted
//          rather than assumed.
//
//   * Expires is rendered and parsed by hand rather than through
//     time::Format / time::Parse — see the note above DAY_NAMES. The
//     old note blamed those functions being unported; they are ported.
//   * `Cookie::new` and `impl Default for Cookie` have no Go
//     counterpart: they stand in for a composite literal with the rest
//     of the fields zeroed.
//
// goishlint:ignore GOISH021 httpcookiemaxnum — a godebug.Setting, and
// goish has no godebug package for it to be one of.

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
    // go: none — goish-only: Go's zero value. `SameSiteDefaultMode` is
    // `iota + 1`, so the zero value of the field is 0 and NOT
    // DefaultMode; `readSetCookies` only assigns when the attribute is
    // present. Defaulting to DefaultMode here made every cookie look as
    // though it had asked for it.
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
            SameSite: SameSite::Unset,
            Partitioned: false,
            Raw: string::new(),
            Unparsed: slice::<string>::__from_vec(Vec::new()),
        }
    }
}

impl Cookie {
    // go: none — goish-only: Go writes `&Cookie{Name: n, Value: v}`,
    // a composite literal with the rest zeroed. Rust has no partial
    // struct literal, so the two-field case gets a constructor.
    pub fn new<N: Into<string>, V: Into<string>>(name: N, value: V) -> Self {
        let name: string = name.into();
        let value: string = value.into();
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
    /// Go's ZERO value. `SameSiteDefaultMode` is `iota + 1`, so a
    /// `Cookie` that never mentioned SameSite carries 0 — which is not
    /// DefaultMode, and is how a caller tells "the attribute was
    /// absent" from "the attribute said default". goish had no way to
    /// represent it, so every parsed cookie claimed DefaultMode.
    Unset = 0,
    DefaultMode = 1,
    LaxMode = 2,
    StrictMode = 3,
    NoneMode = 4,
}

/// Go-style constants matching `http.SameSiteDefaultMode` etc. — same
/// values as the enum variants, exposed at module scope so call sites
/// can write `http::SameSiteLaxMode` instead of
/// `http::SameSite::LaxMode`.
pub const SameSiteDefaultMode: SameSite = SameSite::DefaultMode;
pub const SameSiteLaxMode: SameSite = SameSite::LaxMode;
pub const SameSiteStrictMode: SameSite = SameSite::StrictMode;
pub const SameSiteNoneMode: SameSite = SameSite::NoneMode;

// ─── Errors ──────────────────────────────────────────────────────────
//
// A `var (...)` block in Go, so each of these is ONE pointer-stable
// value. The five functions that stood here minted a fresh error per
// call under a comment claiming "lazy-init for stable identity" — goish
// errors compare by Arc identity, so identity was exactly what they did
// not have, and errors::Is against any of them was always false.

crate::var! {
    // go: sdk 1.25.5 net/http/cookie.go:63-69 errBlankCookie
    errBlankCookie: error = "http: blank cookie";
    // go: sdk 1.25.5 net/http/cookie.go:63-69 errEqualNotFoundInCookie
    errEqualNotFoundInCookie: error = "http: '=' not found in cookie";
    // go: sdk 1.25.5 net/http/cookie.go:63-69 errInvalidCookieName
    errInvalidCookieName: error = "http: invalid cookie name";
    // go: sdk 1.25.5 net/http/cookie.go:63-69 errInvalidCookieValue
    errInvalidCookieValue: error = "http: invalid cookie value";
    // go: sdk 1.25.5 net/http/cookie.go:63-69 errCookieNumLimitExceeded
    errCookieNumLimitExceeded: error = "http: number of cookies exceeded limit";
}

const defaultCookieMaxNum: usize = 3000;

// go: sdk 1.25.5 net/http/cookie.go:73-86 cookieNumWithinMax
#[inline]
fn cookieNumWithinMax(n: usize) -> bool {
    n <= defaultCookieMaxNum
}

// ─── ParseCookie / ParseSetCookie ────────────────────────────────────

// go: sdk 1.25.5 net/http/cookie.go:91-116 ParseCookie
/// `http.ParseCookie(line)` — parse a `Cookie:` header value into the
/// list of cookies it carries (cookie.go:91). Same name may appear
/// multiple times.
pub fn ParseCookie<L: Into<string>>(line: L) -> (slice<Cookie>, error) {
    let line: string = line.into();
    let semi_count = strings::Count(line.clone(), string(";")) as usize;
    if !cookieNumWithinMax(semi_count + 1) {
        return (
            slice::<Cookie>::__from_vec(Vec::new()),
            errCookieNumLimitExceeded.into(),
        );
    }
    let trimmed = strings::TrimSpace(line);
    let parts = strings::Split(trimmed.clone(), string(";"));
    if parts.Len() == 1 && parts[0].Len() == 0 {
        return (
            slice::<Cookie>::__from_vec(Vec::new()),
            errBlankCookie.into(),
        );
    }
    let mut out: Vec<Cookie> = Vec::with_capacity(parts.Len() as usize);
    for i in 0..parts.Len() {
        let s = strings::TrimSpace(parts[i].clone());
        let (name, value, found) = strings::Cut(s, string("="));
        if !found {
            return (
                slice::<Cookie>::__from_vec(Vec::new()),
                errEqualNotFoundInCookie.into(),
            );
        }
        if !super::http::isToken(&name) {
            return (
                slice::<Cookie>::__from_vec(Vec::new()),
                errInvalidCookieName.into(),
            );
        }
        let (val, quoted, ok) = parseCookieValue(&value, true);
        if !ok {
            return (
                slice::<Cookie>::__from_vec(Vec::new()),
                errInvalidCookieValue.into(),
            );
        }
        let mut c = Cookie::default();
        c.Name = name;
        c.Value = val;
        c.Quoted = quoted;
        out.push(c);
    }
    (slice::<Cookie>::__from_vec(out), errors::nil)
}

// go: sdk 1.25.5 net/http/cookie.go:120-220 ParseSetCookie
/// `http.ParseSetCookie(line)` — parse a `Set-Cookie:` header value
/// (cookie.go:120).
pub fn ParseSetCookie<L: Into<string>>(line: L) -> (Cookie, error) {
    let line: string = line.into();
    let trimmed = strings::TrimSpace(line.clone());
    let parts = strings::Split(trimmed, string(";"));
    if parts.Len() == 1 && parts[0].Len() == 0 {
        return (Cookie::default(), errBlankCookie.into());
    }
    let head = strings::TrimSpace(parts[0].clone());
    let (name_raw, value_raw, ok) = strings::Cut(head, string("="));
    if !ok {
        return (Cookie::default(), errEqualNotFoundInCookie.into());
    }
    let name = strings::TrimSpace(name_raw);
    if !super::http::isToken(&name) {
        return (Cookie::default(), errInvalidCookieName.into());
    }
    let (val, quoted, ok) = parseCookieValue(&value_raw, true);
    if !ok {
        return (Cookie::default(), errInvalidCookieValue.into());
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
        let (vv, _, vok) = parseCookieValue(&raw_val, false);
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
                // Go zeroes Expires and then `break`s out of the
                // switch, which falls into the append that every
                // UNRECOGNISED attribute takes (cookie.go:204-205 —
                // the successful path `continue`s past it instead).
                // So an Expires that neither layout parses is reported
                // in Unparsed, and a caller checking that slice can
                // tell "no Expires was sent" from "one was sent and I
                // could not read it". goish dropped it silently, which
                // reads to such a caller as a cookie with no expiry.
                c.Expires = time::Time::default();
                unparsed.push(part);
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
    // go: sdk 1.25.5 net/http/cookie.go:261-325 Cookie.String
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
        if !super::http::isToken(&self.Name) {
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
        let _ = b.WriteString(sanitizeCookieValue(self.Value.clone(), self.Quoted));

        // Go: if len(c.Path) > 0 { b.WriteString("; Path="); b.WriteString(sanitizeCookiePath(c.Path)) }
        if self.Path.Len() > 0 {
            let _ = b.WriteString("; Path=");
            let _ = b.WriteString(sanitizeCookiePath(self.Path.clone()));
        }
        // Go: if len(c.Domain) > 0 { if validCookieDomain(c.Domain) { ... } else { log.Printf("…") } }
        if self.Domain.Len() > 0 {
            if validCookieDomain(&self.Domain) {
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
        if validCookieExpires(&self.Expires) {
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
            // Go: `case SameSiteDefaultMode:` — "Skip, default mode is
            // obtained by not emitting the attribute." The zero value
            // falls through Go's switch untouched and emits nothing
            // either, so both are silent here.
            SameSite::Unset | SameSite::DefaultMode => {}
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

    // go: sdk 1.25.5 net/http/cookie.go:328-361 Cookie.Valid
    /// Reports whether the cookie is valid. Returns `errors::nil` if so,
    /// else an error describing the first problem.
    ///
    /// Line-by-line port of `(*Cookie).Valid()` (cookie.go:328).
    pub fn Valid(&self) -> error {
        // Go: if c == nil { return errors.New("http: nil Cookie") }   — we have &self, so always non-nil
        // Go: if !isToken(c.Name) { ... }
        if !super::http::isToken(&self.Name) {
            return errors::New(string("http: invalid Cookie.Name"));
        }
        // Go: if !c.Expires.IsZero() && !validCookieExpires(c.Expires) { ... }
        if !self.Expires.IsZero() && !validCookieExpires(&self.Expires) {
            return errors::New(string("http: invalid Cookie.Expires"));
        }
        // Go: for i := 0; i < len(c.Value); i++ { if !validCookieValueByte(c.Value[i]) { … } }
        for i in 0..self.Value.Len() {
            if !validCookieValueByte(self.Value[i]) {
                return errors::New(string("http: invalid byte in Cookie.Value"));
            }
        }
        // Go: if len(c.Path) > 0 { for i ... validCookiePathByte ... }
        if self.Path.Len() > 0 {
            for i in 0..self.Path.Len() {
                if !validCookiePathByte(self.Path[i]) {
                    return errors::New(string("http: invalid byte in Cookie.Path"));
                }
            }
        }
        // Go: if len(c.Domain) > 0 { if !validCookieDomain(c.Domain) { … } }
        if self.Domain.Len() > 0 && !validCookieDomain(&self.Domain) {
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

// go: sdk 1.25.5 net/http/cookie.go:371-415 readCookies
/// Parse all "Cookie" header lines from `h`. If `filter` is non-empty,
/// only cookies named `filter` are returned. Mirrors `readCookies`
/// (cookie.go:371).
pub(crate) fn readCookies(h: &Header, filter: &string) -> slice<Cookie> {
    let lines = h.Values(string("Cookie"));
    if lines.Len() == 0 {
        return slice::<Cookie>::__from_vec(Vec::new());
    }
    let mut total_segments: usize = 0;
    for i in 0..lines.Len() {
        total_segments += strings::Count(lines[i].clone(), string(";")) as usize + 1;
    }
    if !cookieNumWithinMax(total_segments) {
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
            if !super::http::isToken(&name) {
                continue;
            }
            if filter.Len() > 0 && *filter != name {
                continue;
            }
            let (val, quoted, ok) = parseCookieValue(&val_raw, true);
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

// go: sdk 1.25.5 net/http/cookie.go:228-246 readSetCookies
/// Parse all "Set-Cookie" headers from `h`. Mirrors `readSetCookies`
/// (cookie.go:228). Used by the (future) `Response` type.
pub(crate) fn readSetCookies(h: &Header) -> slice<Cookie> {
    let lines = h.Values(string("Set-Cookie"));
    if lines.Len() == 0 || !cookieNumWithinMax(lines.Len() as usize) {
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

// go: sdk 1.25.5 net/http/cookie.go:251-255 SetCookie
/// `http.SetCookie(w, c)` — appends `Set-Cookie: c.String()` to the
/// response header. Drops cookies with invalid names. Mirrors
/// `SetCookie` (cookie.go:251).
pub fn SetCookie(w: &(dyn super::ResponseWriter + Send + Sync + 'static), c: &Cookie) {
    let v = c.String();
    if v.Len() == 0 {
        return;
    }
    w.Header().Add(string("Set-Cookie"), v);
}

// ─── helpers — RFC 6265 byte classes, sanitizers, parser ─────────────

// go: sdk 1.25.5 net/http/cookie.go:520-522 validCookieValueByte
/// `validCookieValueByte` — RFC 6265 cookie-octet (loosened to allow
/// space/comma; emitted quoted by `sanitizeCookieValue`).
fn validCookieValueByte(b: byte) -> bool {
    0x20 <= b && b < 0x7f && b != b'"' && b != b';' && b != b'\\'
}

// go: sdk 1.25.5 net/http/cookie.go:530-532 validCookiePathByte
fn validCookiePathByte(b: byte) -> bool {
    0x20 <= b && b < 0x7f && b != b';'
}

// go: sdk 1.25.5 net/http/cookie.go:489-489 cookieNameSanitizer
/// RFC 7230 token char — used for cookie *names*. Allows alnum and
/// `!#$%&'*+-.^_` `\`` `|~`.
/// Go: `strings.NewReplacer("\n", "-", "\r", "-")`.
///
/// A `var` in Go, built once. goish rebuilds it per call; Replacer is
/// a pure value, so the result is the same.
fn cookieNameSanitizer() -> strings::Replacer {
    return strings::NewReplacer(crate::goslice::slice::__from_vec(alloc::vec![
        string("\n"),
        string("-"),
        string("\r"),
        string("-"),
    ]));
}

// go: sdk 1.25.5 net/http/cookie.go:491-493 sanitizeCookieName
/// Note what this does NOT do: it does not reject a bad name, it
/// rewrites the two bytes that could split a header and passes
/// everything else through. `Request.AddCookie` is the only caller, and
/// it is why AddCookie must not go through `Cookie.String()`, which
/// drops a non-token name entirely.
pub(crate) fn sanitizeCookieName(n: string) -> string {
    return cookieNameSanitizer().Replace(n);
}

// go: sdk 1.25.5 net/http/cookie.go:509-518 sanitizeCookieValue
/// Line-by-line port of `sanitizeCookieValue` (cookie.go:509).
pub(crate) fn sanitizeCookieValue(v: string, quoted: bool) -> string {
    // Go: v = sanitizeOrWarn("Cookie.Value", validCookieValueByte, v)
    let v = sanitizeOrWarn(string("Cookie.Value"), validCookieValueByte, v);
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

// go: sdk 1.25.5 net/http/cookie.go:526-528 sanitizeCookiePath
/// Line-by-line port of `sanitizeCookiePath` (cookie.go:526).
fn sanitizeCookiePath(v: string) -> string {
    sanitizeOrWarn(string("Cookie.Path"), validCookiePathByte, v)
}

// go: sdk 1.25.5 net/http/cookie.go:534-554 sanitizeOrWarn
/// Line-by-line port of `sanitizeOrWarn` (cookie.go:534). Go's version
/// logs the offending byte via `log.Printf`; goish silently drops
/// since `log` isn't ported. Behavior on the wire is identical.
fn sanitizeOrWarn(_field_name: string, valid: fn(byte) -> bool, v: string) -> string {
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

// go: sdk 1.25.5 net/http/cookie.go:565-577 parseCookieValue
/// Line-by-line port of `parseCookieValue` (cookie.go:565).
/// Strips matching outer quotes when `allow_double_quote` is set;
/// rejects invalid bytes.
fn parseCookieValue(raw: &string, allow_double_quote: bool) -> (string, bool, bool) {
    // Go: var quoted bool
    let mut quoted = false;
    // Go: if allowDoubleQuote && len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
    //         raw = raw[1 : len(raw)-1]; quoted = true
    //     }
    let raw = if allow_double_quote && raw.Len() > 1 && raw[0] == b'"' && raw[raw.Len() - 1] == b'"'
    {
        quoted = true;
        string::from_bytes(&raw.as_bytes()[1..(raw.Len() - 1) as usize])
    } else {
        raw.clone()
    };
    // Go: for i := 0; i < len(raw); i++ { if !validCookieValueByte(raw[i]) { return "", quoted, false } }
    for i in 0..raw.Len() {
        if !validCookieValueByte(raw[i]) {
            return (string(""), quoted, false);
        }
    }
    // Go: return raw, quoted, true
    (raw, quoted, true)
}

// go: sdk 1.25.5 net/http/cookie.go:418-426 validCookieDomain
/// Go: "validCookieDomain reports whether v is a valid cookie
/// domain-value."
///
/// This used to call a private `is_ipv4_literal` on the stated grounds
/// that `net::ParseIP` was not ported. It is (src/net/mod.rs), and the
/// substitute was not equivalent: ParseIP also accepts the IPv4-mapped
/// and dotted-quad-in-IPv6 forms. Go's own body is back.
fn validCookieDomain(v: &string) -> bool {
    if isCookieDomainName(v) {
        return true;
    }
    if !crate::net::ParseIP(v.clone()).IsNil() && !strings::Contains(v.clone(), string(":")) {
        return true;
    }
    return false;
}

// go: sdk 1.25.5 net/http/cookie.go:429-432 validCookieExpires
/// Go: "IETF RFC 6265 Section 5.1.1.5, the year must not be less than
/// 1601."
///
/// The IsZero guard is NOT belt-and-braces: goish's zero time::Time is
/// the Unix epoch, where Go's is year 1. Without it an unset Expires
/// would pass `Year() >= 1601` as 1970 and Cookie.String() would emit
/// `; Expires=Thu, 01 Jan 1970 00:00:00 GMT` — which browsers read as
/// "delete this cookie now".
fn validCookieExpires(t: &time::Time) -> bool {
    return !t.IsZero() && t.Year() >= 1601;
}

// go: sdk 1.25.5 net/http/cookie.go:437-487 isCookieDomainName
/// Line-by-line port of `isCookieDomainName` (cookie.go:437). Direct
/// copy of net's `isDomainName` with underscore disallowed.
fn isCookieDomainName(s: &string) -> bool {
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
// go: none — goish-only. Go renders and parses the Expires attribute
// with time.Format / time.Parse against the layout
//   "Mon, 02 Jan 2006 15:04:05 GMT"
// (plus a legacy fallback on read). goish HAS time::Format and
// time::Parse — an older note here claiming otherwise was wrong — so
// this hand-rolled pair is a divergence to remove, not a necessity.
// Removing it is its own change: it alters the accepted input set, and
// the round-trip test is what would have to grow first.

const DAY_NAMES: [&[byte; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTH_NAMES: [&[byte; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

// go: none — goish-only: fills a fixed 29-byte buffer where Go calls
// `c.Expires.UTC().AppendFormat(buf[:0], TimeFormat)`. See the note on
// DAY_NAMES above.
pub(crate) fn append_imf_fixdate_into<'a>(buf: &'a mut [byte; 29], t: &time::Time) -> &'a [byte] {
    let weekday = (t.Weekday().Int() as usize) % 7;
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

// go: none — goish-only, see append_imf_fixdate_into.
fn write_2(dst: &mut [byte], n: u32) {
    dst[0] = b'0' + ((n / 10) % 10) as byte;
    dst[1] = b'0' + (n % 10) as byte;
}
// go: none — goish-only, see append_imf_fixdate_into.
fn write_4(dst: &mut [byte], n: u32) {
    dst[0] = b'0' + ((n / 1000) % 10) as byte;
    dst[1] = b'0' + ((n / 100) % 10) as byte;
    dst[2] = b'0' + ((n / 10) % 10) as byte;
    dst[3] = b'0' + (n % 10) as byte;
}

// go: none — goish-only: Go parses Expires with
// `time.Parse(time.RFC1123, v)` and a legacy fallback layout. See the
// note on DAY_NAMES above. Returns None on any shape mismatch — the
// caller falls through to the legacy form.
fn parse_imf_fixdate(s: &string) -> Option<time::Time> {
    parse_cookie_date(s.as_bytes(), b' ')
}

// go: none — goish-only, see parse_imf_fixdate. Parses
// "Mon, 02-Jan-2006 15:04:05 MST" — dash-separated d-M-y.
fn parse_legacy_cookie_date(s: &string) -> Option<time::Time> {
    parse_cookie_date(s.as_bytes(), b'-')
}

// go: none — goish-only, see parse_imf_fixdate.
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
        time::UTC,
    ))
}

// go: none — goish-only, see parse_imf_fixdate.
fn read_2(b: &[u8]) -> Option<u32> {
    if !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
        return None;
    }
    Some(((b[0] - b'0') as u32) * 10 + (b[1] - b'0') as u32)
}

// go: none — goish-only, see parse_imf_fixdate.
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

// go: none — goish-only, see parse_imf_fixdate.
fn month_index(b: &[u8]) -> Option<u32> {
    for (i, m) in MONTH_NAMES.iter().enumerate() {
        if eq_case_insensitive(b, &m[..]) {
            return Some(i as u32);
        }
    }
    None
}

// go: none — goish-only, see parse_imf_fixdate.
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
