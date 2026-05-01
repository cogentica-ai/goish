// net/http/url — slim port of Go's net/url URL type.
//
// Mirrors `runtime/url.URL` (Go 1.25 src/net/url/url.go:375) for the
// subset HTTP servers actually need:
//
//   pub struct URL {
//       pub Scheme:   string,
//       pub Host:     string,
//       pub Path:     string,   // /index.html
//       pub RawPath:  string,
//       pub RawQuery: string,
//   }
//
// `parse_request_uri` accepts only the request-target form (origin
// or absolute-URI). It does not perform full RFC 3986 parsing.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::string;

/// `net/url.URL` — slim. Only fields HTTP routing typically reads.
#[derive(Clone)]
pub struct URL {
    pub Scheme: string,
    pub Host: string,
    /// Decoded path. For now we don't percent-decode — `Path` and
    /// `RawPath` carry the same bytes. Sufficient for common APIs.
    pub Path: string,
    pub RawPath: string,
    pub RawQuery: string,
}

impl URL {
    pub(crate) fn empty() -> Self {
        URL {
            Scheme: string::new(),
            Host: string::new(),
            Path: string::new(),
            RawPath: string::new(),
            RawQuery: string::new(),
        }
    }

    /// `(u *URL).IsAbs()` (url.go:1116) — reports whether the URL is
    /// absolute. Absolute URLs always have a non-empty Scheme.
    pub fn IsAbs(&self) -> bool {
        // Go: return u.Scheme != ""
        self.Scheme.Len() != 0
    }

    /// `(u *URL).RequestURI()` (url.go:1186) — return the encoded
    /// path?query string used in an HTTP request line. Slim port:
    /// goish's URL has no Opaque or ForceQuery, so the choice is just
    /// RawPath (preferred when set) ?: Path, plus an optional
    /// `?<RawQuery>` suffix. An empty path is rendered as "/".
    pub fn RequestURI(&self) -> string {
        // Go: result := u.Opaque; if result == "" { result := u.EscapedPath(); if result == "" { result = "/" } }
        let mut result: string = if self.RawPath.Len() != 0 {
            self.RawPath.clone()
        } else if self.Path.Len() != 0 {
            self.Path.clone()
        } else {
            string("/")
        };
        // Go: if u.ForceQuery || u.RawQuery != "" { result += "?" + u.RawQuery }
        if self.RawQuery.Len() != 0 {
            let mut b = crate::strings::Builder::new();
            b.Grow(result.Len() + 1 + self.RawQuery.Len());
            let _ = b.WriteString(result.clone());
            let _ = b.WriteByte(b'?');
            let _ = b.WriteString(self.RawQuery.clone());
            result = b.String();
        }
        result
    }

    /// `(u *URL).Hostname()` (url.go:1208) — return u.Host with the
    /// optional `:port` suffix removed. IPv6 brackets are stripped.
    pub fn Hostname(&self) -> string {
        let (host, _) = split_host_port(self.Host.clone());
        host
    }

    /// `(u *URL).Port()` (url.go:1216) — return the numeric port from
    /// u.Host (without the leading colon), or "" if absent or invalid.
    pub fn Port(&self) -> string {
        let (_, port) = split_host_port(self.Host.clone());
        port
    }

    /// `(u *URL).Query()` (url.go:1179) — parse RawQuery and return
    /// the resulting map. Malformed pairs are silently dropped (use
    /// `ParseQuery` directly to surface errors).
    pub fn Query(&self) -> crate::gomap::map<string, crate::goslice::slice<string>> {
        let (v, _) = ParseQuery(self.RawQuery.clone());
        v
    }

    /// Render as the request-target string. For URLs parsed from a
    /// request-target this is the inverse of `parse_request_uri`.
    pub fn String(&self) -> string {
        let mut out: Vec<u8> = Vec::with_capacity(64);
        if !self.Scheme.as_bytes().is_empty() {
            out.extend_from_slice(self.Scheme.as_bytes());
            out.extend_from_slice(b"://");
            out.extend_from_slice(self.Host.as_bytes());
        }
        out.extend_from_slice(self.Path.as_bytes());
        if !self.RawQuery.as_bytes().is_empty() {
            out.push(b'?');
            out.extend_from_slice(self.RawQuery.as_bytes());
        }
        string::from_bytes(&out)
    }
}

/// `url.ParseRequestURI` — parse a request-target.
///
/// Accepts:
///   - Origin form:  `/path?query`
///   - Absolute form: `http://host/path?query`
///   - Asterisk form: `*` (kept as Path = "*")
///   - Authority form (CONNECT): caller pre-prefixes "http://"
///
/// Does not validate UTF-8, percent-encoding, or character class.
/// HTTP routing only cares about Path / RawQuery in 99% of cases.
pub(crate) fn parse_request_uri(raw: &string) -> Result<URL, string> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return Err(string("net/http: empty request-target"));
    }

    // Asterisk form (used for OPTIONS *).
    if bytes == b"*" {
        return Ok(URL {
            Scheme: string::new(),
            Host: string::new(),
            Path: string("*"),
            RawPath: string("*"),
            RawQuery: string::new(),
        });
    }

    let (scheme, host, rest) = if let Some(idx) = find_subseq(bytes, b"://") {
        // Absolute-URI form: scheme://host/path?query
        let scheme_b = &bytes[..idx];
        let after = &bytes[idx + 3..];
        // host runs to the first '/' or '?', or end.
        let host_end = after
            .iter()
            .position(|&b| b == b'/' || b == b'?')
            .unwrap_or(after.len());
        let host_b = &after[..host_end];
        let rest = &after[host_end..];
        (scheme_b, host_b, rest)
    } else if bytes[0] == b'/' {
        // Origin form: /path?query
        (&bytes[..0], &bytes[..0], bytes)
    } else {
        // Bare authority (CONNECT) — caller wraps in "http://" first.
        // If we land here it's malformed.
        return Err(string("net/http: malformed request-target"));
    };

    // Split rest on first '?' into path / query.
    let (path, query) = match rest.iter().position(|&b| b == b'?') {
        Some(q) => (&rest[..q], &rest[q + 1..]),
        None => (rest, &rest[..0]),
    };

    let path_str = if path.is_empty() {
        if !host.is_empty() {
            string("/")
        } else {
            string::new()
        }
    } else {
        string::from_bytes(path)
    };

    Ok(URL {
        Scheme: string::from_bytes(scheme),
        Host: string::from_bytes(host),
        Path: path_str.clone(),
        RawPath: path_str,
        RawQuery: string::from_bytes(query),
    })
}

/// Find the first index of `needle` in `hay`, or `None`.
fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    'outer: for i in 0..=(hay.len() - needle.len()) {
        for j in 0..needle.len() {
            if hay[i + j] != needle[j] {
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}

// ─── ParseQuery / QueryUnescape ──────────────────────────────────────
//
// Line-by-line ports of Go 1.25 src/net/url/url.go's ParseQuery (line 879)
// and QueryUnescape (line 277). Slim — strict mode only (Go's default
// since 1.16; no semicolon separator support, errors propagate).

use crate::errors::{self, error};
use crate::gomap::map;
use crate::goslice::slice;
use crate::strings;
use crate::types::{byte, int};

/// `url.ParseQuery(query)` — parse "k1=v1&k2=v2" into Values
/// (`map<string, slice<string>>`). Mirrors url.go:879.
///
/// Reports an error for malformed escape sequences but still returns
/// whatever Values it could parse (matching Go).
pub fn ParseQuery(query: string) -> (map<string, slice<string>>, error) {
    let mut m: map<string, slice<string>> = map::<string, slice<string>>::new();
    let err = parse_query(&mut m, query);
    (m, err)
}

fn parse_query(m: &mut map<string, slice<string>>, mut query: string) -> error {
    // Go: var err error
    let mut err: error = errors::nil;
    // Go: for query != "" { … }
    while query.Len() > 0 {
        // Go: var key string
        // Go: key, query, _ = strings.Cut(query, "&")
        let (key, rest, _) = strings::Cut(query, string("&"));
        query = rest;
        // Go: if strings.Contains(key, ";") { err = fmt.Errorf(...); continue }
        if strings::Contains(key.clone(), string(";")) {
            if err.IsNil() {
                err = errors::New(string("invalid semicolon separator in query"));
            }
            continue;
        }
        // Go: if key == "" { continue }
        if key.Len() == 0 {
            continue;
        }
        // Go: key, value, _ := strings.Cut(key, "=")
        let (raw_k, raw_v, _) = strings::Cut(key, string("="));
        // Go: key, err1 := QueryUnescape(key); if err1 != nil { … continue }
        let (uk, e1) = QueryUnescape(raw_k);
        if !e1.IsNil() {
            if err.IsNil() {
                err = e1;
            }
            continue;
        }
        let (uv, e2) = QueryUnescape(raw_v);
        if !e2.IsNil() {
            if err.IsNil() {
                err = e2;
            }
            continue;
        }
        // Go: m[key] = append(m[key], value)
        let (existing, _) = m.Get(uk.clone());
        let updated = crate::append!(existing, uv);
        m.Set(uk, updated);
    }
    err
}

/// `url.QueryUnescape(s)` — invert query-string percent-encoding.
/// Slim port of url.go:277 (strict mode).
pub fn QueryUnescape(s: string) -> (string, error) {
    unescape(s, true)
}

/// `url.PathUnescape(s)` — like QueryUnescape but does not turn `+`
/// into space. Mirrors url.go:303.
pub fn PathUnescape(s: string) -> (string, error) {
    unescape(s, false)
}

/// `url.QueryEscape(s)` (url.go:281) — percent-encode `s` so it is
/// safe inside the query component of a URL. Spaces become `+`.
pub fn QueryEscape(s: string) -> string {
    escape(s, EncodingMode::QueryComponent)
}

/// `(v Values).Encode()` (url.go:1028) — URL-encode `v` into the
/// `key=val&key=val` form, with keys sorted lexicographically. Each
/// key and value is escaped via `QueryEscape`. Multi-value keys
/// produce multiple `k=v` pairs in the order stored.
///
/// Free function rather than a method because goish models `Values`
/// as the bare gomap type.
pub fn ValuesEncode(v: crate::gomap::map<string, crate::goslice::slice<string>>) -> string {
    // Go: if len(v) == 0 { return "" }
    if v.Len() == 0 {
        return string::new();
    }
    // Go: var buf strings.Builder
    let mut buf = crate::strings::Builder::new();
    // Go: for _, k := range slices.Sorted(maps.Keys(v)) { ... }
    let keys = v.Keys(); // gomap::Keys returns BTreeMap-sorted slice
    let mut i: int = 0;
    while i < keys.Len() {
        let k = keys[i].clone();
        let (vs, _) = v.Get(k.clone());
        let key_escaped = QueryEscape(k);
        // Go: for _, v := range vs { ... }
        let mut j: int = 0;
        while j < vs.Len() {
            // Go: if buf.Len() > 0 { buf.WriteByte('&') }
            if buf.Len() > 0 {
                let _ = buf.WriteByte(b'&');
            }
            let _ = buf.WriteString(key_escaped.clone());
            let _ = buf.WriteByte(b'=');
            let _ = buf.WriteString(QueryEscape(vs[j].clone()));
            j += 1;
        }
        i += 1;
    }
    buf.String()
}

/// `url.PathEscape(s)` (url.go:287) — percent-encode `s` so it is
/// safe inside a single URL path segment (i.e. `/`, `;`, `,`, `?` are
/// all escaped). Spaces become `%20`.
pub fn PathEscape(s: string) -> string {
    escape(s, EncodingMode::PathSegment)
}

/// Subset of url.go's `encoding` enum (url.go:78). The full Go enum
/// also distinguishes encodePath / encodeHost / encodeZone /
/// encodeUserPassword / encodeFragment; we only ship the two modes
/// that QueryEscape + PathEscape need.
#[derive(Copy, Clone, PartialEq, Eq)]
enum EncodingMode {
    PathSegment,
    QueryComponent,
}

/// Line-by-line port of `escape` (url.go:291).
fn escape(s: string, mode: EncodingMode) -> string {
    // Go: spaceCount, hexCount := 0, 0
    let mut space_count: int = 0;
    let mut hex_count: int = 0;
    // Go: for i := 0; i < len(s); i++ { c := s[i] ... }
    let mut i: int = 0;
    while i < s.Len() {
        let c: byte = s[i];
        if should_escape(c, mode) {
            if c == b' ' && mode == EncodingMode::QueryComponent {
                space_count += 1;
            } else {
                hex_count += 1;
            }
        }
        i += 1;
    }

    // Go: if spaceCount == 0 && hexCount == 0 { return s }
    if space_count == 0 && hex_count == 0 {
        return s;
    }

    // Go: required := len(s) + 2*hexCount; t := make([]byte, required)
    let required = (s.Len() + 2 * hex_count) as usize;
    let mut t: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(required);

    // Go: if hexCount == 0 { copy(t, s); for i { if s[i] == ' ' { t[i] = '+' } }
    if hex_count == 0 {
        let mut i: int = 0;
        while i < s.Len() {
            let c: byte = s[i];
            if c == b' ' {
                t.push(b'+');
            } else {
                t.push(c);
            }
            i += 1;
        }
        return string::from_bytes(&t);
    }

    // Go: j := 0; for i := 0; i < len(s); i++ { switch ... }
    let upperhex = b"0123456789ABCDEF";
    let mut i: int = 0;
    while i < s.Len() {
        let c: byte = s[i];
        if c == b' ' && mode == EncodingMode::QueryComponent {
            t.push(b'+');
        } else if should_escape(c, mode) {
            t.push(b'%');
            t.push(upperhex[(c >> 4) as usize]);
            t.push(upperhex[(c & 15) as usize]);
        } else {
            t.push(c);
        }
        i += 1;
    }
    string::from_bytes(&t)
}

/// Line-by-line port of `shouldEscape` (url.go:107). Slim mode set
/// matches `EncodingMode`.
fn should_escape(c: byte, mode: EncodingMode) -> bool {
    // Go: §2.3 Unreserved characters (alphanum)
    if (b'a' <= c && c <= b'z') || (b'A' <= c && c <= b'Z') || (b'0' <= c && c <= b'9') {
        return false;
    }
    // Go: §2.3 Unreserved characters (mark)
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        _ => {}
    }
    // Go: §2.2 Reserved characters
    match c {
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            // Go: encodePathSegment — return c == '/' || c == ';' || c == ',' || c == '?'
            EncodingMode::PathSegment => {
                return c == b'/' || c == b';' || c == b',' || c == b'?';
            }
            // Go: encodeQueryComponent — RFC reserves everything.
            EncodingMode::QueryComponent => return true,
        },
        _ => {}
    }
    // Everything else must be escaped.
    true
}

fn unescape(s: string, query_mode: bool) -> (string, error) {
    // First pass: count '%' escapes, validate, count '+' (query only).
    let mut n: int = 0;
    let mut has_plus = false;
    let mut i: int = 0;
    while i < s.Len() {
        let c: byte = s[i];
        if c == b'%' {
            n += 1;
            if i + 2 >= s.Len() || !is_hex(s[i + 1]) || !is_hex(s[i + 2]) {
                return (string::new(), errors::New(string("invalid URL escape")));
            }
            i += 3;
        } else if c == b'+' {
            has_plus = true;
            i += 1;
        } else {
            i += 1;
        }
    }
    // Fast path.
    if n == 0 && !(query_mode && has_plus) {
        return (s, errors::nil);
    }
    // Second pass: emit decoded bytes via a goish slice<byte>.
    let mut out = crate::make!([]byte, 0);
    let mut i: int = 0;
    while i < s.Len() {
        let c: byte = s[i];
        if c == b'%' {
            let hi = unhex(s[i + 1]);
            let lo = unhex(s[i + 2]);
            out = crate::append!(out, (hi << 4) | lo);
            i += 3;
        } else if c == b'+' && query_mode {
            out = crate::append!(out, b' ');
            i += 1;
        } else {
            out = crate::append!(out, c);
            i += 1;
        }
    }
    (crate::convert::string(out), errors::nil)
}

fn is_hex(c: byte) -> bool {
    (c >= b'0' && c <= b'9') || (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F')
}

/// Line-by-line port of `splitHostPort` (url.go:1224).
fn split_host_port(host_port: string) -> (string, string) {
    // Go: host = hostPort
    let mut host: string = host_port;
    let mut port: string = string::new();

    // Go: colon := strings.LastIndexByte(host, ':')
    let colon = crate::bytes::LastIndexByte(crate::convert::bytes(host.clone()), b':');
    if colon != -1 {
        // Go: if validOptionalPort(host[colon:]) { ... }
        let suffix = string::from_bytes(&host.as_bytes()[colon as usize..]);
        if valid_optional_port(suffix.clone()) {
            // Go: host, port = host[:colon], host[colon+1:]
            let pre = string::from_bytes(&host.as_bytes()[..colon as usize]);
            let post =
                string::from_bytes(&host.as_bytes()[(colon as usize) + 1..]);
            host = pre;
            port = post;
        }
    }

    // Go: if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
    if crate::strings::HasPrefix(host.clone(), string("["))
        && crate::strings::HasSuffix(host.clone(), string("]"))
    {
        // Go: host = host[1 : len(host)-1]
        host = string::from_bytes(&host.as_bytes()[1..host.Len() as usize - 1]);
    }

    (host, port)
}

/// Line-by-line port of `validOptionalPort` (url.go:819). Reports
/// whether `port` is "" or matches `:\d*`.
fn valid_optional_port(port: string) -> bool {
    // Go: if port == "" { return true }
    if port.Len() == 0 {
        return true;
    }
    // Go: if port[0] != ':' { return false }
    if port[0] != b':' {
        return false;
    }
    // Go: for _, b := range port[1:] { if b < '0' || b > '9' { return false } }
    let mut i: int = 1;
    while i < port.Len() {
        let b: byte = port[i];
        if b < b'0' || b > b'9' {
            return false;
        }
        i += 1;
    }
    true
}

fn unhex(c: byte) -> byte {
    if c >= b'0' && c <= b'9' {
        c - b'0'
    } else if c >= b'a' && c <= b'f' {
        c - b'a' + 10
    } else if c >= b'A' && c <= b'F' {
        c - b'A' + 10
    } else {
        0
    }
}
