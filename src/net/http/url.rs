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
