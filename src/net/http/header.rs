// net/http/header — Go's `Header map[string][]string`.
//
// Headers are case-insensitive on the wire but stored canonicalized
// ("Content-Type" not "content-type") so route handlers can do plain
// `h.Get(string("Content-Type"))` lookups.
//
// Public type is `Header`, a thin wrapper over `gomap<string, slice<string>>`
// with case-insensitive `Get`/`Set`/`Add` matching Go's
// `net/http.Header` API (Go 1.25 src/net/http/header.go:24).

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::gomap::map;
use crate::goslice::slice;
use crate::string;

/// Go's `net/http.Header` — `map<string, slice<string>>`.
///
/// Stored under canonical keys (e.g. "Content-Type"). All lookup
/// methods canonicalize the input key, so callers may pass any
/// casing.
#[derive(Clone)]
pub struct Header {
    inner: map<string, slice<string>>,
}

impl Header {
    /// `make(http.Header)` — fresh empty header map.
    pub fn new() -> Self {
        Header {
            inner: map::<string, slice<string>>::new(),
        }
    }

    /// `h.Set(key, value)` — replaces any existing values associated
    /// with `key`. Mirrors `Header.Set` (header.go:53).
    pub fn Set(&mut self, key: string, value: string) {
        let k = canonical_key(&key);
        let mut v: Vec<string> = Vec::with_capacity(1);
        v.push(value);
        self.inner.Set(k, slice::<string>::__from_vec(v));
    }

    /// `h.Add(key, value)` — appends to any existing values.
    pub fn Add(&mut self, key: string, value: string) {
        let k = canonical_key(&key);
        let (existing, ok) = self.inner.Get(k.clone());
        let mut v: Vec<string> = if ok {
            existing.__into_vec()
        } else {
            Vec::with_capacity(1)
        };
        v.push(value);
        self.inner.Set(k, slice::<string>::__from_vec(v));
    }

    /// `h.Get(key)` — first value, or empty string if absent. Same
    /// behavior as Go's `Header.Get` (header.go:43).
    pub fn Get(&self, key: string) -> string {
        let k = canonical_key(&key);
        let (values, ok) = self.inner.Get(k);
        if ok && values.Len() > 0 {
            values[0].clone()
        } else {
            string::new()
        }
    }

    /// `h.Values(key)` — all values for `key`. Empty slice if absent.
    pub fn Values(&self, key: string) -> slice<string> {
        let k = canonical_key(&key);
        let (values, ok) = self.inner.Get(k);
        if ok {
            values
        } else {
            slice::<string>::__from_vec(Vec::new())
        }
    }

    /// `h.Del(key)` — remove all values for `key`.
    pub fn Del(&mut self, key: string) {
        let k = canonical_key(&key);
        self.inner.Delete(k);
    }

    /// Number of distinct keys (not total values).
    pub fn Len(&self) -> usize {
        self.inner.Len() as usize
    }

    /// Internal: the backing map for iteration. Used by the response
    /// writer to serialize headers onto the wire.
    #[doc(hidden)]
    pub fn __inner(&self) -> &map<string, slice<string>> {
        &self.inner
    }
}

/// Canonicalize a header name. RFC 7230: lowercase except the first
/// letter and any letter following a `-`. So `content-type` →
/// `Content-Type`, `accept-encoding` → `Accept-Encoding`.
///
/// Mirrors `net/textproto.CanonicalMIMEHeaderKey` for ASCII.
pub(crate) fn canonical_key(s: &string) -> string {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut upper = true;
    for &b in bytes {
        let c = if upper {
            ascii_to_upper(b)
        } else {
            ascii_to_lower(b)
        };
        out.push(c);
        upper = b == b'-';
    }
    string::from_bytes(&out)
}

#[inline]
fn ascii_to_upper(b: u8) -> u8 {
    if (b'a'..=b'z').contains(&b) {
        b - 32
    } else {
        b
    }
}

#[inline]
fn ascii_to_lower(b: u8) -> u8 {
    if (b'A'..=b'Z').contains(&b) {
        b + 32
    } else {
        b
    }
}
