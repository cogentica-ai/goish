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
use crate::types::{byte, int};

/// Go's `net/http.Header` — `map<string, slice<string>>`.
///
/// Stored under canonical keys (e.g. "Content-Type"). All lookup
/// methods canonicalize the input key, so callers may pass any
/// casing.
#[derive(Clone)]
pub struct Header {
    inner: map<string, slice<string>>,
}

// `for k, v := range h.Header` — Go iterates the underlying
// `map[string][]string` directly. The forwarding impl delegates to
// the inner map's RangeIter, yielding `(&string, &slice<string>)`.
// Without this, the transpiler emits `range!(req.Header)` which fails
// to find a RangeIter impl on the Header newtype.
impl<'a> crate::range::RangeIter for &'a Header {
    type Item = <&'a map<string, slice<string>> as crate::range::RangeIter>::Item;
    type Iter = <&'a map<string, slice<string>> as crate::range::RangeIter>::Iter;
    fn range(self) -> Self::Iter {
        crate::range::RangeIter::range(&self.inner)
    }
}

// Symmetric: `range!(&h.Header)` produces `&&Header` — forward the
// same way as `&Header`.
impl<'a> crate::range::RangeIter for &&'a Header {
    type Item = <&'a map<string, slice<string>> as crate::range::RangeIter>::Item;
    type Iter = <&'a map<string, slice<string>> as crate::range::RangeIter>::Iter;
    fn range(self) -> Self::Iter {
        crate::range::RangeIter::range(&(*self).inner)
    }
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
    ///
    /// Generic over `impl Into<string>` for both args so callers can
    /// pass `&str` literals directly: `h.Set("Content-Type", "text/plain")`
    /// without wrapping in `string("…")`.
    pub fn Set<K: Into<string>, V: Into<string>>(&mut self, key: K, value: V) {
        let k = canonical_key(&key.into());
        let mut v: Vec<string> = Vec::with_capacity(1);
        v.push(value.into());
        self.inner.Set(k, slice::<string>::__from_vec(v));
    }

    /// `h.Add(key, value)` — appends to any existing values.
    pub fn Add<K: Into<string>, V: Into<string>>(&mut self, key: K, value: V) {
        let k = canonical_key(&key.into());
        self.__add_canonical(k, value.into());
    }

    /// Crate-internal Add for callers whose key is ALREADY in
    /// canonical form (the request parser emits pre-canonicalized,
    /// mostly interned names) — skips the canonicalization pass.
    pub(crate) fn __add_canonical(&mut self, k: string, value: string) {
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
    pub fn Get<K: Into<string>>(&self, key: K) -> string {
        let k = canonical_key(&key.into());
        let (values, ok) = self.inner.Get(k);
        if ok && values.Len() > 0 {
            values[0].clone()
        } else {
            string::new()
        }
    }

    /// `h.Values(key)` — all values for `key`. Empty slice if absent.
    pub fn Values<K: Into<string>>(&self, key: K) -> slice<string> {
        let k = canonical_key(&key.into());
        let (values, ok) = self.inner.Get(k);
        if ok {
            values
        } else {
            slice::<string>::__from_vec(Vec::new())
        }
    }

    /// `h.Del(key)` — remove all values for `key`.
    pub fn Del<K: Into<string>>(&mut self, key: K) {
        let k = canonical_key(&key.into());
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

    /// `h.Clone()` — return a deep copy. Mirrors `Header.Clone`
    /// (header.go:94). Goish gomap clones internally, but we go
    /// through Set() so each value slice is independently owned.
    pub fn Clone(&self) -> Header {
        let mut out = Header::new();
        for (k, v) in self.inner.__iter() {
            // Go: h2[k] = sv[:n:n]  (independent slice copy)
            let copied = v.clone();
            out.inner.Set(k.clone(), copied);
        }
        out
    }

    /// `h.Write(w)` — write the header in HTTP wire format
    /// (`Key: value\r\n` per line). Mirrors `Header.Write`
    /// (header.go:85).
    pub fn Write<W: crate::io::Writer>(&self, w: &mut W) -> crate::error {
        self.WriteSubset(w, &map::<string, bool>::new())
    }

    /// `h.WriteSubset(w, exclude)` — like `Write` but skips keys
    /// where `exclude[key] == true`. Mirrors header.go:186.
    pub fn WriteSubset<W: crate::io::Writer>(
        &self,
        w: &mut W,
        exclude: &map<string, bool>,
    ) -> crate::error {
        // Go: kvs, _ := h.sortedKeyValues(exclude)
        // Sorting requires reading all keys; since gomap has no Keys()
        // surface here, we collect via __iter and sort in Vec.
        let mut kvs: Vec<(string, slice<string>)> = Vec::new();
        for (k, v) in self.inner.__iter() {
            // Go: if !exclude[k] { kvs = append(kvs, keyValues{k, vv}) }
            let (skip, _) = exclude.Get(k.clone());
            if skip {
                continue;
            }
            kvs.push((k.clone(), v.clone()));
        }
        // Go: slices.SortFunc(kvs, func(a, b) int { return strings.Compare(a.key, b.key) })
        kvs.sort_by(|a, b| {
            crate::strings::Compare(a.0.clone(), b.0.clone()).cmp(&0)
        });
        // Go: for _, kv := range kvs { for _, v := range kv.values { ws.WriteString(...) } }
        for (k, vv) in kvs.iter() {
            for i in 0..vv.Len() {
                let v = vv[i].clone();
                // Go: v = headerNewlineToSpace.Replace(v); v = textproto.TrimString(v)
                let v = sanitize_header_value(v);
                let (_, e1) = w.Write(crate::convert::bytes(k.clone()));
                if !e1.IsNil() {
                    return e1;
                }
                let (_, e2) = w.Write(crate::convert::bytes(": "));
                if !e2.IsNil() {
                    return e2;
                }
                let (_, e3) = w.Write(crate::convert::bytes(v));
                if !e3.IsNil() {
                    return e3;
                }
                let (_, e4) = w.Write(crate::convert::bytes("\r\n"));
                if !e4.IsNil() {
                    return e4;
                }
            }
        }
        crate::errors::nil
    }
}

/// `http.TimeFormat` (header.go:42) — the canonical HTTP-date layout
/// used in Date / Last-Modified / Expires headers. RFC 7231 §7.1.1.1
/// (IMF-fixdate). Matches Go's `TimeFormat` constant.
pub const TimeFormat: &str = "Mon, 02 Jan 2006 15:04:05 GMT";

/// `http.ParseTime(text)` (header.go:129) — parse an HTTP-date.
///
/// **Slim port deviation:** Go iterates through three layouts
/// (IMF-fixdate / RFC 850 / ANSI C asctime). Goish supports only
/// IMF-fixdate (`Mon, 02 Jan 2006 15:04:05 GMT`) and the legacy
/// dash-separated cookie form (`Mon, 02-Jan-2006 15:04:05 MST`).
/// `time::Parse` is not yet ported; once it lands this function
/// will gain the third form.
pub fn ParseTime<T: Into<string>>(text: T) -> (crate::time::Time, crate::error) {
    let text: string = text.into();
    if let Some(t) = parse_http_date(text.as_bytes(), b' ') {
        return (t, crate::errors::nil);
    }
    if let Some(t) = parse_http_date(text.as_bytes(), b'-') {
        return (t, crate::errors::nil);
    }
    (
        crate::time::Time::default(),
        crate::errors::New(string("http: invalid date format")),
    )
}

const HTTP_MONTH_NAMES: [&[byte; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun",
    b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

fn parse_http_date(b: &[byte], sep: byte) -> Option<crate::time::Time> {
    if b.len() < 25 {
        return None;
    }
    let mut i = 0;
    while i < b.len() && b[i] != b',' {
        i += 1;
    }
    if i == b.len() {
        return None;
    }
    let after = &b[i + 1..];
    let after = if !after.is_empty() && after[0] == b' ' {
        &after[1..]
    } else {
        after
    };
    if after.len() < 20 {
        return None;
    }
    let day = http_read_2(&after[0..2])?;
    if after[2] != sep {
        return None;
    }
    let month_idx = http_month_index(&after[3..6])?;
    if after[6] != sep {
        return None;
    }
    let year = http_read_4(&after[7..11])?;
    if after[11] != b' ' {
        return None;
    }
    let hh = http_read_2(&after[12..14])?;
    if after[14] != b':' {
        return None;
    }
    let mm = http_read_2(&after[15..17])?;
    if after[17] != b':' {
        return None;
    }
    let ss = http_read_2(&after[18..20])?;
    if day == 0 || day > 31 || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    Some(crate::time::Date(
        year as int,
        month_idx as int + 1,
        day as int,
        hh as int,
        mm as int,
        ss as int,
        0,
        crate::time::UTC,
    ))
}

fn http_read_2(b: &[byte]) -> Option<u32> {
    if !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
        return None;
    }
    Some(((b[0] - b'0') as u32) * 10 + (b[1] - b'0') as u32)
}
fn http_read_4(b: &[byte]) -> Option<u32> {
    let mut acc: u32 = 0;
    for &c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc * 10 + (c - b'0') as u32;
    }
    Some(acc)
}
fn http_month_index(b: &[byte]) -> Option<u32> {
    for (i, m) in HTTP_MONTH_NAMES.iter().enumerate() {
        if b.len() == 3
            && (b[0] | 0x20) == (m[0] | 0x20)
            && (b[1] | 0x20) == (m[1] | 0x20)
            && (b[2] | 0x20) == (m[2] | 0x20)
        {
            return Some(i as u32);
        }
    }
    None
}

/// Replace newlines/CRs with spaces and trim OWS — Go's
/// `headerNewlineToSpace.Replace` + `textproto.TrimString`.
fn sanitize_header_value(s: string) -> string {
    let mut b = crate::strings::Builder::new();
    b.Grow(s.Len());
    for i in 0..s.Len() {
        let c = s[i];
        if c == b'\n' || c == b'\r' {
            let _ = b.WriteByte(b' ');
        } else {
            let _ = b.WriteByte(c);
        }
    }
    crate::strings::TrimSpace(b.String())
}

/// `http.CanonicalHeaderKey(s)` (header.go:234) — public canonical
/// form. Mirrors Go's delegation to `textproto.CanonicalMIMEHeaderKey`.
/// `content-type` → `Content-Type`, `accept-encoding` → `Accept-Encoding`.
pub fn CanonicalHeaderKey<S: Into<string>>(s: S) -> string {
    let s: string = s.into();
    canonical_key(&s)
}

/// Canonicalize a header name. RFC 7230: lowercase except the first
/// letter and any letter following a `-`. So `content-type` →
/// `Content-Type`, `accept-encoding` → `Accept-Encoding`.
///
/// Mirrors `net/textproto.CanonicalMIMEHeaderKey` for ASCII.
pub(crate) fn canonical_key(s: &string) -> string {
    canonical_key_bytes(s.as_bytes())
}

/// Canonical-form interning for the header names that dominate real
/// traffic — Go keeps a `commonHeader` map for exactly this
/// (net/textproto/reader.go:715 `canonicalMIMEHeaderKey` common-key
/// lookup). `from_static` is zero-alloc, so both the parse path and
/// every literal-keyed `Header.Get("Content-Length")` call become
/// allocation-free.
fn intern_header_name(canon: &[u8]) -> Option<&'static str> {
    Some(match canon {
        b"Host" => "Host",
        b"User-Agent" => "User-Agent",
        b"Accept" => "Accept",
        b"Accept-Encoding" => "Accept-Encoding",
        b"Accept-Language" => "Accept-Language",
        b"Connection" => "Connection",
        b"Content-Length" => "Content-Length",
        b"Content-Type" => "Content-Type",
        b"Transfer-Encoding" => "Transfer-Encoding",
        b"Expect" => "Expect",
        b"Cookie" => "Cookie",
        b"Set-Cookie" => "Set-Cookie",
        b"Authorization" => "Authorization",
        b"Cache-Control" => "Cache-Control",
        b"Origin" => "Origin",
        b"Referer" => "Referer",
        b"Location" => "Location",
        b"Date" => "Date",
        b"Server" => "Server",
        b"X-Forwarded-For" => "X-Forwarded-For",
        b"X-Forwarded-Proto" => "X-Forwarded-Proto",
        b"X-Forwarded-Host" => "X-Forwarded-Host",
        b"Upgrade" => "Upgrade",
        b"If-Modified-Since" => "If-Modified-Since",
        b"If-None-Match" => "If-None-Match",
        b"Last-Modified" => "Last-Modified",
        b"Range" => "Range",
        _ => return None,
    })
}

/// Byte-slice canonicalization used directly by the request parser
/// (no intermediate `string` for the raw name). Canonical form is
/// built in a stack buffer for typical-length names, matched against
/// the interned common set, and only materialized on the heap for
/// uncommon names.
pub(crate) fn canonical_key_bytes(bytes: &[u8]) -> string {
    if bytes.len() <= 64 {
        let mut stack = [0u8; 64];
        let mut upper = true;
        for (i, &b) in bytes.iter().enumerate() {
            stack[i] = if upper {
                ascii_to_upper(b)
            } else {
                ascii_to_lower(b)
            };
            upper = b == b'-';
        }
        let canon = &stack[..bytes.len()];
        if let Some(s) = intern_header_name(canon) {
            return string::from_static(s);
        }
        return string::from_bytes(canon);
    }
    // Long-tail names: heap-build the canonical form.
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
