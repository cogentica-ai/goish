// net/url — Go's `net/url` package, ported to goish.
//
// Parses URLs and implements query escaping per RFC 3986.
//
// **Public-API discipline**: every signature uses goish lowercase
// types (`string`, `slice<byte>`, `int`, multi-return tuples).
// No `Vec<u8>`, `&str`, `&[u8]`, `String` leak.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error, ErrorTrait};
use crate::gomap;
use crate::strings;
use crate::types::int;
use crate::{byte, nil, slice, string};

// ─── Error types ─────────────────────────────────────────────────────

/// `url.Error` reports an error and the operation + URL that caused it.
/// Mirrors `net/url.Error` (url.go:28-32).
#[derive(Clone)]
pub struct Error {
    pub Op: string,
    pub URL: string,
    pub Err: error,
}

impl ErrorTrait for Error {
    fn Error(&self) -> string {
        let inner = if self.Err.IsNil() {
            string::from_static("<nil>")
        } else {
            self.Err.Error()
        };
        crate::Sprintf!("%s %q: %s", self.Op.clone(), self.URL.clone(), inner)
    }
    fn Unwrap(&self) -> error {
        self.Err.clone()
    }
}

impl Error {
    pub fn new<O: Into<string>, U: Into<string>>(op: O, url: U, err: error) -> error {
        errors::Wrap(Error {
            Op: op.into(),
            URL: url.into(),
            Err: err,
        })
    }
}

/// `url.EscapeError` — wraps the malformed escape sequence text.
/// Mirrors `net/url.EscapeError` (url.go:90).
#[derive(Clone)]
pub struct EscapeError(pub string);

impl ErrorTrait for EscapeError {
    fn Error(&self) -> string {
        let mut buf = string::from_static("invalid URL escape ");
        buf = buf + crate::strconv::Quote(self.0.clone());
        buf
    }
}

impl EscapeError {
    pub fn new<S: Into<string>>(s: S) -> error {
        errors::Wrap(EscapeError(s.into()))
    }
}

/// `url.InvalidHostError` — wraps the invalid host character.
/// Mirrors `net/url.InvalidHostError` (url.go:96).
#[derive(Clone)]
pub struct InvalidHostError(pub string);

impl ErrorTrait for InvalidHostError {
    fn Error(&self) -> string {
        let mut buf = string::from_static("invalid character ");
        buf = buf + crate::strconv::Quote(self.0.clone());
        buf = buf + string::from_static(" in host name");
        buf
    }
}

impl InvalidHostError {
    pub fn new<S: Into<string>>(s: S) -> error {
        errors::Wrap(InvalidHostError(s.into()))
    }
}

// ─── Encoding mode ───────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Encoding {
    EncodePath,
    EncodePathSegment,
    EncodeHost,
    EncodeZone,
    EncodeUserPassword,
    EncodeQueryComponent,
    EncodeFragment,
}

use Encoding::*;

const UPPER_HEX: &[u8] = b"0123456789ABCDEF";

fn is_hex(c: byte) -> bool {
    matches!(c, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')
}

fn un_hex(c: byte) -> byte {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex character"),
    }
}

/// Return true if the specified character should be escaped when
/// appearing in a URL string, according to RFC 3986.
fn should_escape(c: byte, mode: Encoding) -> bool {
    // §2.3 Unreserved characters (alphanum)
    if c.is_ascii_alphanumeric() {
        return false;
    }

    if mode == EncodeHost || mode == EncodeZone {
        match c {
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':'
            | b'[' | b']' | b'<' | b'>' | b'"' => {
                return false;
            }
            _ => {}
        }
    }

    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            EncodePath => return c == b'?',
            EncodePathSegment => return c == b'/' || c == b';' || c == b',' || c == b'?',
            EncodeUserPassword => return c == b'@' || c == b'/' || c == b'?' || c == b':',
            EncodeQueryComponent => return true,
            EncodeFragment => return false,
            _ => {}
        },
        _ => {}
    }

    if mode == EncodeFragment {
        match c {
            b'!' | b'(' | b')' | b'*' => return false,
            _ => {}
        }
    }

    true
}

// ─── Unescape / Escape ────────────────────────────────────────────────

fn unescape(s: string, mode: Encoding) -> (string, error) {
    let s_bytes = s.as_bytes();
    let n = s_bytes.iter().filter(|&&c| c == b'%').count();
    let has_plus = s_bytes
        .iter()
        .any(|&c| c == b'+' && mode == EncodeQueryComponent);

    if n == 0 && !has_plus {
        return (s, nil.into());
    }

    // Count %, check that they're well-formed.
    let mut i = 0;
    let len = s.Len();
    while i < len {
        match s_bytes[i as usize] {
            b'%' => {
                if i + 2 >= len
                    || !is_hex(s_bytes[(i + 1) as usize])
                    || !is_hex(s_bytes[(i + 2) as usize])
                {
                    let mut sub = s.slice(i, len);
                    if sub.Len() > 3 {
                        sub = sub.slice(0, 3);
                    }
                    return (string::new(), EscapeError::new(sub));
                }
                if mode == EncodeHost
                    && un_hex(s_bytes[(i + 1) as usize]) < 8
                    && s.slice(i, i + 3) != "%25"
                {
                    return (string::new(), EscapeError::new(s.slice(i, i + 3)));
                }
                if mode == EncodeZone {
                    let v =
                        un_hex(s_bytes[(i + 1) as usize]) << 4 | un_hex(s_bytes[(i + 2) as usize]);
                    if s.slice(i, i + 3) != "%25" && v != b' ' && should_escape(v, EncodeHost) {
                        return (string::new(), EscapeError::new(s.slice(i, i + 3)));
                    }
                }
                i += 3;
            }
            b'+' => {
                i += 1;
            }
            _ => {
                if (mode == EncodeHost || mode == EncodeZone)
                    && s_bytes[i as usize] < 0x80
                    && should_escape(s_bytes[i as usize], mode)
                {
                    return (string::new(), InvalidHostError::new(s.slice(i, i + 1)));
                }
                i += 1;
            }
        }
    }

    // Build result
    let mut t = Vec::with_capacity(s_bytes.len() - 2 * n);
    let mut i = 0;
    while i < len {
        match s_bytes[i as usize] {
            b'%' => {
                t.push(un_hex(s_bytes[(i + 1) as usize]) << 4 | un_hex(s_bytes[(i + 2) as usize]));
                i += 3;
            }
            b'+' => {
                if mode == EncodeQueryComponent {
                    t.push(b' ');
                } else {
                    t.push(b'+');
                }
                i += 1;
            }
            c => {
                t.push(c);
                i += 1;
            }
        }
    }

    (string::from_bytes(&t), nil.into())
}

/// `QueryUnescape(s)` (url.go:189) — inverse of QueryEscape.
pub fn QueryUnescape<S: Into<string>>(s: S) -> (string, error) {
    unescape(s.into(), EncodeQueryComponent)
}

/// `PathUnescape(s)` (url.go:200) — inverse of PathEscape.
pub fn PathUnescape<S: Into<string>>(s: S) -> (string, error) {
    unescape(s.into(), EncodePathSegment)
}

fn escape(s: string, mode: Encoding) -> string {
    let s_bytes = s.as_bytes();
    let mut space_count = 0;
    let mut hex_count = 0;
    for &c in s_bytes.iter() {
        if should_escape(c, mode) {
            if c == b' ' && mode == EncodeQueryComponent {
                space_count += 1;
            } else {
                hex_count += 1;
            }
        }
    }

    if space_count == 0 && hex_count == 0 {
        return s;
    }

    let required = s_bytes.len() + 2 * hex_count;
    let mut t = Vec::with_capacity(required);

    if hex_count == 0 {
        for &c in s_bytes.iter() {
            if c == b' ' && mode == EncodeQueryComponent {
                t.push(b'+');
            } else {
                t.push(c);
            }
        }
        return string::from_bytes(&t);
    }

    for &c in s_bytes.iter() {
        if c == b' ' && mode == EncodeQueryComponent {
            t.push(b'+');
        } else if should_escape(c, mode) {
            t.push(b'%');
            t.push(UPPER_HEX[(c as usize) >> 4]);
            t.push(UPPER_HEX[(c as usize) & 0xf]);
        } else {
            t.push(c);
        }
    }
    string::from_bytes(&t)
}

/// `QueryEscape(s)` (url.go:281) — escapes for URL query.
pub fn QueryEscape<S: Into<string>>(s: S) -> string {
    escape(s.into(), EncodeQueryComponent)
}

/// `PathEscape(s)` (url.go:287) — escapes for URL path segment.
pub fn PathEscape<S: Into<string>>(s: S) -> string {
    escape(s.into(), EncodePathSegment)
}

// ─── Userinfo ───────────────────────────────────────────────────────

/// `url.Userinfo` (url.go:401) — username and password information.
#[derive(Clone, Default)]
pub struct Userinfo {
    username: string,
    password: string,
    passwordSet: bool,
}

impl Userinfo {
    /// `User(username)` (url.go:391) — returns Userinfo with username, no password.
    pub fn User<U: Into<string>>(username: U) -> Userinfo {
        Userinfo {
            username: username.into(),
            password: string::new(),
            passwordSet: false,
        }
    }

    /// `UserPassword(username, password)` (url.go:399) — returns Userinfo with both.
    pub fn UserPassword<U: Into<string>, P: Into<string>>(username: U, password: P) -> Userinfo {
        Userinfo {
            username: username.into(),
            password: password.into(),
            passwordSet: true,
        }
    }

    /// `u.Username()` (url.go:407) — returns the username.
    pub fn Username(&self) -> string {
        self.username.clone()
    }

    /// `u.Password()` (url.go:410) — returns (password, ok).
    pub fn Password(&self) -> (string, bool) {
        (self.password.clone(), self.passwordSet)
    }

    /// `u.String()` (url.go:419) — returns the encoded userinfo string.
    pub fn String(&self) -> string {
        let mut s = escape(self.username.clone(), EncodeUserPassword);
        if self.passwordSet {
            s = s + ":";
            s = s + escape(self.password.clone(), EncodeUserPassword);
        }
        s
    }

    /// `u.SetPassword(password)` — internal helper.
    pub fn SetPassword<P: Into<string>>(&mut self, password: P) {
        self.password = password.into();
        self.passwordSet = true;
    }
}

// Nil support for *Userinfo
impl PartialEq<crate::nilval::Nil> for Userinfo {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.username.Len() == 0 && !self.passwordSet
    }
}
impl PartialEq<Userinfo> for crate::nilval::Nil {
    fn eq(&self, other: &Userinfo) -> bool {
        other.username.Len() == 0 && !other.passwordSet
    }
}
impl From<crate::nilval::Nil> for Userinfo {
    fn from(_: crate::nilval::Nil) -> Self {
        Userinfo::default()
    }
}

// ─── URL ──────────────────────────────────────────────────────────────

/// `url.URL` (url.go:375) — represents a parsed URL (URI reference).
#[derive(Clone, Default)]
pub struct URL {
    pub Scheme: string,
    pub Opaque: string,
    pub User: Userinfo,
    pub Host: string,
    pub Path: string,
    pub RawPath: string,
    pub OmitHost: bool,
    pub ForceQuery: bool,
    pub RawQuery: string,
    pub Fragment: string,
    pub RawFragment: string,
}

impl URL {
    /// `u.String()` (url.go:804) — reassembles the URL into a valid URL string.
    pub fn String(&self) -> string {
        let mut buf = strings::Builder::new();

        if self.Scheme.Len() != 0 {
            buf.WriteString(self.Scheme.clone());
            buf.WriteString(":");
        }

        if self.Opaque.Len() != 0 {
            buf.WriteString(self.Opaque.clone());
        } else {
            if self.Scheme.Len() != 0 || self.Host.Len() != 0 || self.Path.Len() != 0 {
                if self.OmitHost && self.Host.Len() == 0 && self.Path.Len() == 0 {
                    // omit //host
                } else {
                    if self.Host.Len() != 0 || self.Path.Len() != 0 || self.Scheme.Len() != 0 {
                        buf.WriteString("//");
                    }
                    let ui = self.User.clone();
                    if ui != nil {
                        buf.WriteString(ui.String());
                        buf.WriteString("@");
                    }
                    buf.WriteString(self.Host.clone());
                }
            }
            let path = self.EscapedPath();
            if path.Len() != 0 && path.as_bytes()[0] != b'/' && self.Host.Len() != 0 {
                buf.WriteString("/");
            }
            buf.WriteString(path);
        }

        if self.ForceQuery || self.RawQuery.Len() != 0 {
            buf.WriteString("?");
            buf.WriteString(self.RawQuery.clone());
        }

        if self.Fragment.Len() != 0 {
            buf.WriteString("#");
            buf.WriteString(self.EscapedFragment());
        }

        buf.String()
    }

    /// `u.EscapedPath()` (url.go:681) — returns the escaped form of u.Path.
    /// Returns u.RawPath only when it is a valid escaping of u.Path
    /// (i.e., unescape(RawPath) == Path). Otherwise ignores RawPath.
    pub fn EscapedPath(&self) -> string {
        if self.RawPath.Len() != 0 && self.validEncodedPath(&self.RawPath) {
            let (p, err) = unescape(self.RawPath.clone(), EncodePath);
            if err == nil && p == self.Path {
                return self.RawPath.clone();
            }
        }
        if self.Path == string("*") {
            return self.Path.clone();
        }
        escape(self.Path.clone(), EncodePath)
    }

    /// `u.EscapedFragment()` (url.go:714) — returns the escaped form of u.Fragment.
    pub fn EscapedFragment(&self) -> string {
        if self.RawFragment.Len() != 0 && self.validEncodedFragment(&self.RawFragment) {
            return self.RawFragment.clone();
        }
        escape(self.Fragment.clone(), EncodeFragment)
    }

    /// Check that RawPath is a valid encoded path.
    fn validEncodedPath(&self, raw: &string) -> bool {
        let bytes = raw.as_bytes();
        let mut i = 0;
        let len = raw.Len();
        while i < len {
            let c = bytes[i as usize];
            if c == b'%' {
                if i + 2 >= len
                    || !is_hex(bytes[(i + 1) as usize])
                    || !is_hex(bytes[(i + 2) as usize])
                {
                    return false;
                }
            } else if should_escape(c, EncodePath) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Check that RawFragment is a valid encoded fragment.
    fn validEncodedFragment(&self, raw: &string) -> bool {
        let bytes = raw.as_bytes();
        let mut i = 0;
        let len = raw.Len();
        while i < len {
            let c = bytes[i as usize];
            if c == b'%' {
                if i + 2 >= len
                    || !is_hex(bytes[(i + 1) as usize])
                    || !is_hex(bytes[(i + 2) as usize])
                {
                    return false;
                }
            } else if should_escape(c, EncodeFragment) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// `u.Hostname()` (url.go:1138) — returns u.Host, stripping any port number.
    pub fn Hostname(&self) -> string {
        let host = self.Host.clone();
        let colon = strings::IndexByte(host.clone(), b':');
        if colon < 0 {
            return host;
        }
        let host_bytes = host.as_bytes();
        if host.Len() > 0 && host_bytes[0] == b'[' {
            let bracket = strings::IndexByte(host.clone(), b']');
            if bracket > 0 {
                return host.slice(1, bracket);
            }
        }
        host.slice(0, colon)
    }

    /// `u.Port()` (url.go:1155) — returns the port part of u.Host, without the leading colon.
    pub fn Port(&self) -> string {
        let host = self.Host.clone();
        let colon = strings::IndexByte(host.clone(), b':');
        if colon < 0 {
            return string::new();
        }
        let host_bytes = host.as_bytes();
        if host.Len() > 0 && host_bytes[0] == b'[' {
            let bracket = strings::IndexByte(host.clone(), b']');
            if bracket > 0 {
                let after = host.slice(bracket + 1, host.Len());
                let after_bytes = after.as_bytes();
                if after.Len() > 0 && after_bytes[0] == b':' {
                    return after.slice(1, after.Len());
                }
            }
            return string::new();
        }
        host.slice(colon + 1, host.Len())
    }

    /// `u.IsAbs()` (url.go:1124) — reports whether URL is absolute.
    pub fn IsAbs(&self) -> bool {
        self.Scheme.Len() != 0
    }

    /// `u.Parse(ref)` (url.go:1084) — parses a URL reference in the context of u.
    pub fn Parse(&self, ref_: string) -> (URL, error) {
        let (refurl, err) = Parse(ref_);
        if err != nil {
            return (URL::default(), err);
        }
        self.ResolveReference(&refurl)
    }

    /// `u.ResolveReference(ref)` (url.go:1094) — resolves a URI reference.
    pub fn ResolveReference(&self, ref_: &URL) -> (URL, error) {
        let mut url = ref_.clone();
        if ref_.Scheme.Len() == 0 {
            url.Scheme = self.Scheme.clone();
        }
        if ref_.Scheme.Len() != 0 || ref_.Host.Len() != 0 || ref_.User != nil {
            return (url, nil.into());
        }
        if ref_.Opaque.Len() == 0 {
            url.User = self.User.clone();
            url.Host = self.Host.clone();
            if ref_.Path.Len() == 0 && !ref_.ForceQuery {
                url.RawPath = self.RawPath.clone();
                if ref_.RawQuery.Len() == 0 {
                    url.RawQuery = self.RawQuery.clone();
                }
            } else if self.Path.Len() != 0
                && ref_.Path.Len() != 0
                && ref_.Path.as_bytes()[0] != b'/'
            {
                let (new_path, new_raw_path) = self.merge_path(ref_);
                url.Path = new_path;
                url.RawPath = new_raw_path;
            }
        }
        if ref_.Opaque.Len() == 0 && ref_.Path.Len() == 0 && !ref_.ForceQuery {
            url.RawQuery = self.RawQuery.clone();
        }
        (url, nil.into())
    }

    fn merge_path(&self, ref_: &URL) -> (string, string) {
        let mut merged = self.Path.clone();
        let last_slash = strings::LastIndexByte(merged.clone(), b'/');
        if last_slash >= 0 {
            merged = merged.slice(0, last_slash + 1);
        } else {
            merged = string::new();
        }
        merged = merged + ref_.Path.clone();

        let mut raw_merged = self.RawPath.clone();
        if raw_merged.Len() != 0 {
            let last_slash = strings::LastIndexByte(raw_merged.clone(), b'/');
            if last_slash >= 0 {
                raw_merged = raw_merged.slice(0, last_slash + 1);
            } else {
                raw_merged = string::new();
            }
            raw_merged = raw_merged + ref_.RawPath.clone();
        }
        (merged, raw_merged)
    }

    /// `u.RequestURI()` (url.go:820) — returns the encoded path?query or opaque?query.
    pub fn RequestURI(&self) -> string {
        let mut result = self.EscapedPath();
        if self.Opaque.Len() != 0 {
            result = self.Opaque.clone();
        }
        if self.ForceQuery || self.RawQuery.Len() != 0 {
            result = result + "?";
            result = result + self.RawQuery.clone();
        }
        result
    }

    /// `u.Redacted()` (url.go:832) — returns the URL string with any password replaced.
    pub fn Redacted(&self) -> string {
        let mut u = self.clone();
        if u.User.passwordSet {
            u.User.SetPassword("xxxxx");
        }
        u.String()
    }

    /// `u.JoinPath(elem ...)` (url.go:1205) — appends path elements.
    pub fn JoinPath(&self, elem: slice<string>) -> (URL, error) {
        let mut url = self.clone();
        let mut parts = Vec::with_capacity(elem.Len() as usize + 1);
        parts.push(url.Path.clone());
        for e in elem.iter() {
            parts.push(e.clone());
        }
        url.Path = crate::path::Join(slice::__from_vec(parts));
        url.RawPath = string::new();
        (url, nil.into())
    }
}

// Nil support for URL
impl PartialEq<crate::nilval::Nil> for URL {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.Scheme.Len() == 0
            && self.Opaque.Len() == 0
            && self.User == nil
            && self.Host.Len() == 0
            && self.Path.Len() == 0
    }
}
impl PartialEq<URL> for crate::nilval::Nil {
    fn eq(&self, other: &URL) -> bool {
        other.Scheme.Len() == 0
            && other.Opaque.Len() == 0
            && other.User == nil
            && other.Host.Len() == 0
            && other.Path.Len() == 0
    }
}
impl From<crate::nilval::Nil> for URL {
    fn from(_: crate::nilval::Nil) -> Self {
        URL::default()
    }
}

// ─── Parse ───────────────────────────────────────────────────────────

/// `Parse(rawurl)` (url.go:466) — parses rawurl into a URL structure.
pub fn Parse<S: Into<string>>(rawurl: S) -> (URL, error) {
    parse(rawurl.into(), false)
}

/// `ParseRequestURI(rawurl)` (url.go:474) — parses rawurl as a request URI.
pub fn ParseRequestURI<S: Into<string>>(rawurl: S) -> (URL, error) {
    parse(rawurl.into(), true)
}

fn parse(mut rawurl: string, via_request: bool) -> (URL, error) {
    let bytes = rawurl.as_bytes();
    let raw_len = rawurl.Len();

    // Cut off #fragment first
    let mut frag = string::new();
    let mut i = 0;
    let mut in_brackets = false;
    while i < raw_len {
        match bytes[i as usize] {
            b'[' => in_brackets = true,
            b']' => in_brackets = false,
            b'#' => {
                if !in_brackets {
                    frag = rawurl.slice(i + 1, raw_len);
                    rawurl = rawurl.slice(0, i);
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let bytes = rawurl.as_bytes();
    let raw_len = rawurl.Len();

    // Extract scheme
    let mut scheme = string::new();
    let mut path = rawurl.clone();
    let mut has_scheme = false;

    i = 0;
    while i < raw_len {
        let c = bytes[i as usize];
        if c == b':' {
            if i == 0 {
                return (
                    URL::default(),
                    Error::new(
                        "parse",
                        rawurl.clone(),
                        errors::New("missing protocol scheme"),
                    ),
                );
            }
            scheme = rawurl.slice(0, i);
            path = rawurl.slice(i + 1, raw_len);
            has_scheme = true;
            break;
        }
        if !c.is_ascii_alphabetic() {
            if !c.is_ascii_digit() && c != b'+' && c != b'-' && c != b'.' {
                break;
            }
            if i == 0 {
                break;
            }
        }
        i += 1;
    }

    // Lowercase scheme
    scheme = strings::ToLower(scheme);

    if has_scheme {
        let path_bytes = path.as_bytes();
        if path.Len() >= 2 && path_bytes[0] == b'/' && path_bytes[1] == b'/' {
            // Split authority from path at first '/' or '?'
            let rest = path.slice(2, path.Len());
            let (auth_str, path_query) = split_authority_path(rest);
            let (u, err) = parse_authority(auth_str);
            if err != nil {
                return (u, err);
            }
            let mut u = u;
            u.Scheme = scheme;
            u.Fragment = frag;
            set_path_query(&mut u, path_query);
            return (u, nil.into());
        }

        if via_request {
            return (
                URL::default(),
                Error::new(
                    "parse",
                    rawurl.clone(),
                    errors::New("invalid URI for request"),
                ),
            );
        }

        let mut u = URL::default();
        u.Scheme = scheme;
        u.Opaque = path.clone();
        u.Fragment = frag;
        return (u, nil.into());
    }

    // Relative path
    if via_request && raw_len > 0 && bytes[0] == b'/' {
        if raw_len > 1 && bytes[1] == b'/' {
            let rest = path.slice(2, path.Len());
            let (auth_str, path_query) = split_authority_path(rest);
            let (u, err) = parse_authority(auth_str);
            if err != nil {
                return (u, err);
            }
            let mut u = u;
            u.Fragment = frag;
            set_path_query(&mut u, path_query);
            return (u, nil.into());
        }
        let mut u = URL::default();
        u.Path = path.clone();
        u.Fragment = frag;
        return (u, nil.into());
    }

    // Check for \r or \n in path
    if strings::IndexByte(path.clone(), b'\r') >= 0 || strings::IndexByte(path.clone(), b'\n') >= 0
    {
        return (
            URL::default(),
            Error::new(
                "parse",
                rawurl.clone(),
                errors::New("invalid control character in URL"),
            ),
        );
    }

    let mut u = URL::default();
    u.Path = path.clone();
    u.Fragment = frag;
    (u, nil.into())
}

/// Split `rest` (everything after `//`) into (authority, path_query).
/// Authority ends at the first `/` or `?`; the delimiter is kept in path_query.
fn split_authority_path(rest: string) -> (string, string) {
    let bytes = rest.as_bytes();
    let n = rest.Len();
    let mut i: int = 0;
    while i < n {
        match bytes[i as usize] {
            b'/' | b'?' => break,
            _ => {}
        }
        i += 1;
    }
    (rest.slice(0, i), rest.slice(i, n))
}

/// Parse path and optional query from `path_query` (e.g. "/the/path?q=1")
/// and set them on the URL.
fn set_path_query(u: &mut URL, path_query: string) {
    let bytes = path_query.as_bytes();
    let n = path_query.Len();
    let mut qi: int = 0;
    let mut found_q = false;
    while qi < n {
        if bytes[qi as usize] == b'?' {
            found_q = true;
            break;
        }
        qi += 1;
    }
    if found_q {
        u.Path = path_query.slice(0, qi);
        u.RawQuery = path_query.slice(qi + 1, n);
    } else {
        u.Path = path_query.clone();
    }
}

fn parse_authority(authority: string) -> (URL, error) {
    let bytes = authority.as_bytes();
    let auth_len = authority.Len();
    let mut i = 0;
    let mut host_start = 0;
    let mut has_user = false;

    while i < auth_len {
        if bytes[i as usize] == b'@' {
            has_user = true;
            host_start = i + 1;
            break;
        }
        i += 1;
    }

    let mut user = Userinfo::default();
    let host;

    if has_user {
        let userinfo = authority.slice(0, i);
        let colon = strings::IndexByte(userinfo.clone(), b':');
        if colon >= 0 {
            let (u, err) = unescape(userinfo.slice(0, colon), EncodeUserPassword);
            if err != nil {
                return (URL::default(), Error::new("parse", authority.clone(), err));
            }
            let (p, err2) = unescape(
                userinfo.slice(colon + 1, userinfo.Len()),
                EncodeUserPassword,
            );
            if err2 != nil {
                return (URL::default(), Error::new("parse", authority.clone(), err2));
            }
            user = Userinfo {
                username: u,
                password: p,
                passwordSet: true,
            };
        } else {
            let (u, err) = unescape(userinfo, EncodeUserPassword);
            if err != nil {
                return (URL::default(), Error::new("parse", authority.clone(), err));
            }
            user = Userinfo {
                username: u,
                password: string::new(),
                passwordSet: false,
            };
        }
        host = authority.slice(host_start, auth_len);
    } else {
        host = authority.clone();
    }

    // Validate host
    let host_bytes = host.as_bytes();
    let host_len = host.Len();
    let mut j = 0;
    let mut in_brackets = false;
    while j < host_len {
        match host_bytes[j as usize] {
            b'%' => {
                if j + 2 >= host_len
                    || !is_hex(host_bytes[(j + 1) as usize])
                    || !is_hex(host_bytes[(j + 2) as usize])
                {
                    let end = (j + 3).min(host_len);
                    return (
                        URL::default(),
                        Error::new(
                            "parse",
                            authority.clone(),
                            EscapeError::new(host.slice(j, end)),
                        ),
                    );
                }
                let v = un_hex(host_bytes[(j + 1) as usize]) << 4
                    | un_hex(host_bytes[(j + 2) as usize]);
                if v != b'%' && should_escape(v, EncodeHost) {
                    return (
                        URL::default(),
                        Error::new(
                            "parse",
                            authority.clone(),
                            InvalidHostError::new(string::from_bytes(&[v])),
                        ),
                    );
                }
                j += 3;
            }
            b'[' => {
                in_brackets = true;
                j += 1;
            }
            b']' => {
                in_brackets = false;
                j += 1;
            }
            c => {
                if !in_brackets && c < 0x80 && should_escape(c, EncodeHost) {
                    return (
                        URL::default(),
                        Error::new(
                            "parse",
                            authority.clone(),
                            InvalidHostError::new(host.slice(j, j + 1)),
                        ),
                    );
                }
                j += 1;
            }
        }
    }

    // Validate port if present (host:port form, excluding IPv6 bracket addresses)
    // In Go's net/url, a non-numeric port causes a parse error.
    {
        let port_str = {
            let h = host.as_bytes();
            let hn = host.Len();
            if hn > 0 && h[0] == b'[' {
                // IPv6 bracketed address: [::1]:5000 — find closing bracket
                let mut bi = 1;
                while bi < hn && h[bi as usize] != b']' {
                    bi += 1;
                }
                bi += 1; // skip ']'
                if bi < hn && h[bi as usize] == b':' {
                    Some(host.slice(bi + 1, hn))
                } else {
                    None
                }
            } else {
                // Find last ':' for port
                let mut ci = hn - 1;
                let mut found_colon = false;
                while ci >= 0 {
                    if h[ci as usize] == b':' {
                        found_colon = true;
                        break;
                    }
                    if ci == 0 {
                        break;
                    }
                    ci -= 1;
                }
                if found_colon && ci > 0 {
                    Some(host.slice(ci + 1, hn))
                } else {
                    None
                }
            }
        };
        if let Some(port) = port_str {
            if port.Len() > 0 {
                let pb = port.as_bytes();
                let mut valid = true;
                let mut k = 0;
                while k < port.Len() {
                    if pb[k as usize] < b'0' || pb[k as usize] > b'9' {
                        valid = false;
                        break;
                    }
                    k += 1;
                }
                if !valid {
                    return (
                        URL::default(),
                        Error::new("parse", authority.clone(), errors::New("invalid port")),
                    );
                }
            }
        }
    }

    let mut u = URL::default();
    u.User = user;
    u.Host = host;
    (u, nil.into())
}

// ─── Values / query parsing ──────────────────────────────────────────

/// `url.Values` (url.go:858) — map[string][]string for query parameters.
pub type Values = gomap::map<string, slice<string>>;

/// `ParseQuery(query)` (url.go:861) — parses a URL-encoded query string.
pub fn ParseQuery<S: Into<string>>(query: S) -> (Values, error) {
    let query = query.into();
    let mut m = Values::new();
    let mut err: error = nil.into();

    if query.Len() == 0 {
        return (m, err);
    }

    let bytes = query.as_bytes();
    let q_len = query.Len();
    let mut start = 0;
    let mut i = 0;
    while i <= q_len {
        if i == q_len || bytes[i as usize] == b'&' || bytes[i as usize] == b';' {
            let part = query.slice(start, i);
            let key;
            let mut value = string::new();

            let eq = strings::IndexByte(part.clone(), b'=');
            if eq >= 0 {
                let (k, kerr) = QueryUnescape(part.slice(0, eq));
                if !kerr.IsNil() {
                    err = kerr;
                }
                let (v, verr) = QueryUnescape(part.slice(eq + 1, part.Len()));
                if !verr.IsNil() {
                    err = verr;
                }
                key = k;
                value = v;
            } else {
                let (k, kerr) = QueryUnescape(part);
                if !kerr.IsNil() {
                    err = kerr;
                }
                key = k;
            }

            if key.Len() != 0 {
                let (existing, ok) = m.Get(key.clone());
                if ok {
                    let mut v = Vec::with_capacity(existing.Len() as usize + 1);
                    for j in 0..existing.Len() {
                        v.push(existing[j].clone());
                    }
                    v.push(value);
                    m.Set(key.clone(), slice::__from_vec(v));
                } else {
                    let mut v = Vec::with_capacity(1);
                    v.push(value);
                    m.Set(key.clone(), slice::__from_vec(v));
                }
            }
            start = i + 1;
        }
        i += 1;
    }

    (m, err)
}

/// `ParseQueryValues(query)` (url.go:900) — parses into ordered map.
pub fn ParseQueryValues<S: Into<string>>(query: S) -> (Values, error) {
    ParseQuery(query)
}

// ─── Values helper functions ─────────────────────────────────────────

/// `v.Get(key)` (url.go:920) — returns the first value for key, or "".
pub fn ValuesGet(v: &Values, key: string) -> string {
    let (vals, ok) = v.Get(key);
    if !ok || vals.Len() == 0 {
        return string::new();
    }
    vals[0].clone()
}

/// `v.Set(key, value)` (url.go:930) — sets key to single value.
pub fn ValuesSet(v: &mut Values, key: string, value: string) {
    let mut s = Vec::with_capacity(1);
    s.push(value);
    v.Set(key, slice::__from_vec(s));
}

/// `v.Add(key, value)` (url.go:940) — appends value to key's slice.
pub fn ValuesAdd(v: &mut Values, key: string, value: string) {
    let (existing, ok) = v.Get(key.clone());
    if ok {
        let mut s = Vec::with_capacity(existing.Len() as usize + 1);
        for j in 0..existing.Len() {
            s.push(existing[j].clone());
        }
        s.push(value);
        v.Set(key, slice::__from_vec(s));
    } else {
        let mut s = Vec::with_capacity(1);
        s.push(value);
        v.Set(key, slice::__from_vec(s));
    }
}

/// `v.Del(key)` (url.go:950) — deletes the key.
pub fn ValuesDel(v: &mut Values, key: string) {
    v.Delete(key);
}

/// `v.Has(key)` (url.go:960) — reports whether key exists.
pub fn ValuesHas(v: &Values, key: string) -> bool {
    v.Has(key)
}

/// `v.Encode()` (url.go:970) — encodes values into query string.
pub fn ValuesEncode(v: &Values) -> string {
    let mut buf = strings::Builder::new();
    let mut keys: Vec<string> = Vec::new();
    for (k, _) in v.__iter() {
        keys.push(k.clone());
    }
    keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let mut first = true;
    for key in keys {
        let (vals, _) = v.Get(key.clone());
        for j in 0..vals.Len() {
            if !first {
                buf.WriteString("&");
            }
            first = false;
            buf.WriteString(QueryEscape(key.clone()));
            buf.WriteString("=");
            buf.WriteString(QueryEscape(vals[j].clone()));
        }
    }
    buf.String()
}
