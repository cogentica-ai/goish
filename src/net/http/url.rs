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
