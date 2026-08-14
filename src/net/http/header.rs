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
use crate::len;

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

    // go: sdk 1.25.5 net/http/header.go:34-41 Header.Set
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

    // go: sdk 1.25.5 net/http/header.go:26-32 Header.Add
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

    // go: sdk 1.25.5 net/http/header.go:43-51 Header.Get
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

    // go: sdk 1.25.5 net/http/header.go:62-68 Header.get
    /// `h.get(key)` — like `Get`, but `key` must ALREADY be in
    /// canonical form: Go's unexported `get` is a raw map lookup and
    /// does no canonicalization, so it is case-SENSITIVE.
    /// `h.get("content-type")` is "" where `h.Get("content-type")`
    /// finds the value.
    pub fn get<K: Into<string>>(&self, key: K) -> string {
        let (v, ok) = self.inner.Get(key.into());
        if ok && v.Len() > 0 {
            return v[0].clone();
        }
        return string::new();
    }

    // go: sdk 1.25.5 net/http/header.go:72-75 Header.has
    /// `h.has(key)` — key presence, distinct from `Get` returning "".
    /// Unexported in Go; serveError needs it to tell an absent header
    /// from one explicitly set to the empty string.
    pub fn has<K: Into<string>>(&self, key: K) -> bool {
        let k = canonical_key(&key.into());
        let (_values, ok) = self.inner.Get(k);
        return ok;
    }

    // go: sdk 1.25.5 net/http/header.go:53-60 Header.Values
    pub fn Values<K: Into<string>>(&self, key: K) -> slice<string> {
        let k = canonical_key(&key.into());
        let (values, ok) = self.inner.Get(k);
        if ok {
            values
        } else {
            slice::<string>::__from_vec(Vec::new())
        }
    }

    // go: sdk 1.25.5 net/http/header.go:76-82 Header.Del
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
    /// Raw map assignment, bypassing canonicalisation and the
    /// one-value-per-Add shape. Go writes `h[key] = vals` (and
    /// `h[key] = nil`) directly in transfer.go's fixTrailer and
    /// mergeSetHeader; `Set`/`Add` cannot express an empty value list.
    /// The caller is responsible for passing a canonical key.
    pub(crate) fn __set_values(&mut self, key: string, vals: slice<string>) {
        self.inner.Set(key, vals);
    }

    pub fn __inner(&self) -> &map<string, slice<string>> {
        &self.inner
    }

    // go: sdk 1.25.5 net/http/header.go:93-118 Header.Clone
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
    // go: sdk 1.25.5 net/http/header.go:84-87 Header.Write
    /// Write a header in wire format.
    pub fn Write<W: crate::io::Writer>(&self, w: &mut W) -> crate::error {
        return self.write(w);
    }

    // go: sdk 1.25.5 net/http/header.go:89-91 Header.write
    //
    // Go's `write` exists only to carry the ClientTrace down to
    // writeSubset; goish does not thread one yet (see writeSubset), so
    // this is the same one-line delegation minus that argument.
    pub fn write<W: crate::io::Writer>(&self, w: &mut W) -> crate::error {
        return self.writeSubset(w, &map::<string, bool>::new());
    }

    /// `h.WriteSubset(w, exclude)` — like `Write` but skips keys
    /// where `exclude[key] == true`. Mirrors header.go:186.
    // go: sdk 1.25.5 net/http/header.go:182-188 Header.WriteSubset
    /// Write a header in wire format, omitting keys for which
    /// `exclude[key]` is true. Keys are NOT canonicalized before the
    /// exclude lookup, matching Go.
    pub fn WriteSubset<W: crate::io::Writer>(
        &self,
        w: &mut W,
        exclude: &map<string, bool>,
    ) -> crate::error {
        return self.writeSubset(w, exclude);
    }

    // go: sdk 1.25.5 net/http/header.go:190-224 Header.writeSubset
    //
    // Go takes a third parameter, `trace *httptrace.ClientTrace`, and
    // calls `trace.WroteHeaderField(key, vals)` per key. goish's
    // Transport does not thread a ClientTrace through header writing
    // yet, so the parameter is omitted rather than accepted and
    // ignored — a `None` that is never non-None reads as wired-up when
    // it is not. Restoring it is a signature change here plus a call
    // site in the transport.
    //
    // Go also wraps `w` in `stringWriter{w}` when it is not already an
    // io.StringWriter; goish's io::Writer has no WriteString sibling to
    // dispatch on, so the bytes go through `Write` directly and the
    // wrapper has no work to do.
    pub fn writeSubset<W: crate::io::Writer>(
        &self,
        w: &mut W,
        exclude: &map<string, bool>,
    ) -> crate::error {
        let sorter = self.sortedKeyValues(exclude);
        // Cheap Arc-backed handle clone, so `sorter` stays movable
        // into `Put` while the loop still reads the entries.
        let kvs = sorter.kvs.clone();
        let kvs = &kvs;
        let n = len(kvs);
        let mut i: int = 0;
        while i < n {
            let k = kvs[i].key.clone();
            let vv = kvs[i].values.clone();
            i += 1;
            // Go: if !httpguts.ValidHeaderFieldName(kv.key) { continue }
            // — "This could be an error. In the common case of writing
            // response headers, however, we have no good way to provide
            // the error back to the server handler, so just drop invalid
            // headers instead." goish's `isToken` IS
            // httpguts.ValidHeaderFieldName; http.go:218 says so.
            // Without this a key like "Bad Name" or one holding a
            // newline is written to the wire verbatim, which is header
            // injection.
            if !super::http::isToken(&k) {
                continue;
            }
            let mut j: int = 0;
            while j < len(&vv) {
                // Go: v = headerNewlineToSpace.Replace(v)
                //     v = textproto.TrimString(v)
                let v = sanitize_header_value(vv[j].clone());
                j += 1;
                for part in [k.clone(), string(": "), v, string("\r\n")] {
                    let (_, e) = w.Write(crate::convert::bytes(part));
                    if !e.IsNil() {
                        headerSorterPool().Put(sorter);
                        return e;
                    }
                }
            }
        }
        headerSorterPool().Put(sorter);
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 net/http/header.go:164-181 Header.sortedKeyValues
    //
    // Go returns `(kvs []keyValues, hs *headerSorter)` — two views of
    // ONE backing array, so the caller can both range the slice and
    // hand the sorter back to the pool. Rust cannot hand out an
    // aliasing pair safely, and cloning the slice would defeat the
    // pool, so goish returns the sorter alone and the caller reads
    // `sorter.kvs`. Same allocation reuse, one return value.
    pub fn sortedKeyValues(&self, exclude: &map<string, bool>) -> headerSorter {
        let mut hs = headerSorterPool().Get();
        let mut kvs: alloc::vec::Vec<keyValues> = alloc::vec::Vec::new();
        for (k, vv) in self.inner.__iter() {
            let (skip, _) = exclude.Get(k.clone());
            if !skip {
                kvs.push(keyValues { key: k.clone(), values: vv.clone() });
            }
        }
        // Go: slices.SortFunc(hs.kvs, func(a, b) int {
        //         return strings.Compare(a.key, b.key) })
        // Sorted before wrapping: goish's sort::Slice is index-based
        // like Go's sort.Slice, so its comparator would have to capture
        // the slice that sort::Slice already borrows mutably. The
        // ordering is identical either way — strings.Compare is a plain
        // byte compare, and header keys are unique so the sort's
        // stability is not observable.
        kvs.sort_by(|a, b| {
            crate::strings::Compare(a.key.clone(), b.key.clone()).cmp(&0)
        });
        hs.kvs = slice::__from_vec(kvs);
        return hs;
    }
}

// go: sdk 1.25.5 net/http/header.go:139-139 headerNewlineToSpace
//
// Go builds a `strings.Replacer`; goish's equivalent is applied by
// `sanitize_header_value` below, which the writer already calls. This
// exposes the same replacer so the mapping has one definition.
pub fn headerNewlineToSpace() -> crate::strings::Replacer {
    return crate::strings::NewReplacer(slice::__from_vec(alloc::vec![
        string("\n"),
        string(" "),
        string("\r"),
        string(" "),
    ]));
}

// go: sdk 1.25.5 net/http/header.go:142-144 stringWriter
//
// Go wraps a plain io.Writer so it can be written to with WriteString.
// goish's io::Writer has no WriteString sibling to dispatch on, so
// this exists for parity of the declaration set and forwards.
pub struct stringWriter<'a, W: crate::io::Writer> {
    pub w: &'a mut W,
}

impl<'a, W: crate::io::Writer> stringWriter<'a, W> {
    // go: sdk 1.25.5 net/http/header.go:146-148 stringWriter.WriteString
    pub fn WriteString(&mut self, s: string) -> (int, crate::error) {
        return self.w.Write(crate::convert::bytes(s));
    }
}

// go: sdk 1.25.5 net/http/header.go:150-153 keyValues
#[derive(Clone, Default)]
pub struct keyValues {
    pub key: string,
    pub values: slice<string>,
}

// go: sdk 1.25.5 net/http/header.go:155-158 headerSorter
/// Contains a slice of keyValues sorted by keyValues.key.
#[derive(Clone, Default)]
pub struct headerSorter {
    pub kvs: slice<keyValues>,
}

// go: sdk 1.25.5 net/http/header.go:160-162 headerSorterPool
//
// History: wiring this pool into sortedKeyValues used to SIGSEGV
// http_complex_api at exit (~3-6 of 8 runs, 2026-08-14). The pool was
// innocent: its `Mutex::Lock` parked the goroutine while the CALLER
// (`response::flush`) held a runtime `SpinLock` guard across the
// whole render — and a SpinLock guard must never straddle a park (its
// m.locks bump/drop lands on two different Ms after migration). The
// responsewriter locks are `sync::Mutex` now, the scheduler traps the
// pattern loudly ("schedule: holding locks"), and this pool is wired
// exactly as Go wires it.
pub fn headerSorterPool() -> &'static crate::sync::Pool<headerSorter> {
    static POOL: crate::lazy::Lazy<crate::sync::Pool<headerSorter>> =
        crate::lazy::Lazy::new(|| crate::sync::Pool::new(|| headerSorter::default()));
    return POOL.get();
}

/// `http.TimeFormat` (header.go:42) — the canonical HTTP-date layout
/// used in Date / Last-Modified / Expires headers. RFC 7231 §7.1.1.1
/// (IMF-fixdate). Matches Go's `TimeFormat` constant.
pub const TimeFormat: &str = "Mon, 02 Jan 2006 15:04:05 GMT";

// go: sdk 1.25.5 net/http/header.go:120-124 timeFormats
pub fn timeFormats() -> slice<string> {
    return slice::__from_vec(alloc::vec![
        string(TimeFormat),
        string(crate::time::RFC850),
        string(crate::time::ANSIC),
    ]);
}

// go: sdk 1.25.5 net/http/header.go:126-137 ParseTime
//
/// `http.ParseTime(text)` — parse an HTTP-date, trying each of the
/// three formats HTTP/1.1 allows: [`TimeFormat`] (IMF-fixdate),
/// `time::RFC850` and `time::ANSIC` (asctime).
///
/// goish's `time::Parse` whitelists layouts and rejects both
/// day-name-comma forms ("time: unsupported layout"), so IMF-fixdate
/// and RFC 850 are scanned by hand below and only asctime goes
/// through `time::Parse`. The scanners are strict in the same places
/// Go is — every rule below was read off Go 1.25.5 with
/// scripts/goref.sh, not from the layout strings:
///
///  * The weekday must be well-formed but need NOT agree with the
///    date: `Mon, 06 Nov 1994` parses even though that day was a
///    Sunday. IMF-fixdate wants the three-letter abbreviation and
///    rejects the full name; RFC 850 wants the full name and rejects
///    the abbreviation.
///  * Weekday and month names are ASCII case-insensitive
///    (`sunday`, `SUN`, `nov` all parse) but the zone is NOT: `gmt`
///    is rejected.
///  * IMF-fixdate requires the literal zone `GMT`. `UTC`, `XYZ`,
///    `+0000` and a missing zone are all errors.
///  * RFC 850 accepts ANY three-letter uppercase zone abbreviation
///    and treats it as UTC — `EST` and `XYZ` both yield the same
///    instant as `GMT` — but a missing or two-letter zone is an error.
///  * RFC 850 years are two digits and pivot at 69: `69` is 1969,
///    `68` is 2068.
pub fn ParseTime<T: Into<string>>(text: T) -> (crate::time::Time, crate::error) {
    let text: string = text.into();
    let b = text.as_bytes();
    if let Some(t) = parse_imf_fixdate(b) {
        return (t, crate::errors::nil);
    }
    if let Some(t) = parse_rfc850(b) {
        return (t, crate::errors::nil);
    }
    let (t, err) = crate::time::Parse(string(crate::time::ANSIC), text);
    if err == crate::errors::nil {
        return (t, crate::errors::nil);
    }
    return (
        crate::time::Time::default(),
        crate::errors::New(string("http: invalid date format")),
    );
}

const HTTP_MONTH_NAMES: [&[byte; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun",
    b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Three-letter weekday abbreviations, in Go's `time` order.
const HTTP_DAY_ABBRS: [&[byte; 3]; 7] =
    [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];

/// Full weekday names, same order.
const HTTP_DAY_FULL: [&str; 7] = [
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
];

// go: none — goish-only scanner helper. Go reaches these
// formats through time.Parse, whose layout engine goish does not
// have for the day-name-comma forms; see ParseTime above.
/// ASCII case-insensitive byte-slice compare — the weekday and month
/// name matching Go does, without pulling in a Unicode fold.
fn http_eq_fold(a: &[byte], b: &[byte]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if (a[i] | 0x20) != (b[i] | 0x20) {
            return false;
        }
        i += 1;
    }
    return true;
}

// go: none — goish-only scanner helper. Go reaches these
// formats through time.Parse, whose layout engine goish does not
// have for the day-name-comma forms; see ParseTime above.
fn http_is_day_abbr(b: &[byte]) -> bool {
    for d in HTTP_DAY_ABBRS.iter() {
        if http_eq_fold(b, *d) {
            return true;
        }
    }
    return false;
}

// go: none — goish-only scanner helper. Go reaches these
// formats through time.Parse, whose layout engine goish does not
// have for the day-name-comma forms; see ParseTime above.
fn http_is_day_full(b: &[byte]) -> bool {
    for d in HTTP_DAY_FULL.iter() {
        if http_eq_fold(b, d.as_bytes()) {
            return true;
        }
    }
    return false;
}

// go: none — goish-only scanner helper. Go reaches these
// formats through time.Parse, whose layout engine goish does not
// have for the day-name-comma forms; see ParseTime above.
/// A three-letter uppercase zone abbreviation. RFC 850's `MST` slot
/// accepts any such run and, for a name Go does not know, gives it a
/// zero offset — so `EST` and `XYZ` both land on the same instant as
/// `GMT`. Lowercase is rejected.
fn http_is_zone_abbr(b: &[byte]) -> bool {
    if b.len() != 3 {
        return false;
    }
    let mut i = 0;
    while i < 3 {
        if b[i] < b'A' || b[i] > b'Z' {
            return false;
        }
        i += 1;
    }
    return true;
}

// go: none — goish-only scanner helper. Go reaches these
// formats through time.Parse, whose layout engine goish does not
// have for the day-name-comma forms; see ParseTime above.
fn http_mk_time(year: u32, month_idx: u32, day: u32, hh: u32, mm: u32, ss: u32) -> Option<crate::time::Time> {
    if day == 0 || day > 31 || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    return Some(crate::time::Date(
        year as int,
        month_idx as int + 1,
        day as int,
        hh as int,
        mm as int,
        ss as int,
        0,
        crate::time::UTC,
    ));
}

// go: none — goish-only scanner helper. Go reaches these
// formats through time.Parse, whose layout engine goish does not
// have for the day-name-comma forms; see ParseTime above.
/// IMF-fixdate — `Sun, 06 Nov 1994 08:49:37 GMT`, exactly 29 bytes.
fn parse_imf_fixdate(b: &[byte]) -> Option<crate::time::Time> {
    if b.len() != 29 {
        return None;
    }
    if !http_is_day_abbr(&b[0..3]) || b[3] != b',' || b[4] != b' ' {
        return None;
    }
    let day = http_read_2(&b[5..7])?;
    if b[7] != b' ' {
        return None;
    }
    let month_idx = http_month_index(&b[8..11])?;
    if b[11] != b' ' {
        return None;
    }
    let year = http_read_4(&b[12..16])?;
    if b[16] != b' ' {
        return None;
    }
    let hh = http_read_2(&b[17..19])?;
    if b[19] != b':' {
        return None;
    }
    let mm = http_read_2(&b[20..22])?;
    if b[22] != b':' {
        return None;
    }
    let ss = http_read_2(&b[23..25])?;
    if b[25] != b' ' || &b[26..29] != b"GMT" {
        return None;
    }
    return http_mk_time(year, month_idx, day, hh, mm, ss);
}

// go: none — goish-only scanner helper. Go reaches these
// formats through time.Parse, whose layout engine goish does not
// have for the day-name-comma forms; see ParseTime above.
/// RFC 850 — `Sunday, 06-Nov-94 08:49:37 GMT`. The weekday is a full
/// name of variable length, so the tail is measured from the comma.
fn parse_rfc850(b: &[byte]) -> Option<crate::time::Time> {
    let mut comma = 0;
    while comma < b.len() && b[comma] != b',' {
        comma += 1;
    }
    if comma == b.len() || !http_is_day_full(&b[0..comma]) {
        return None;
    }
    let r = &b[comma + 1..];
    // " 06-Nov-94 08:49:37 GMT"
    if r.len() != 23 || r[0] != b' ' {
        return None;
    }
    let day = http_read_2(&r[1..3])?;
    if r[3] != b'-' {
        return None;
    }
    let month_idx = http_month_index(&r[4..7])?;
    if r[7] != b'-' {
        return None;
    }
    let yy = http_read_2(&r[8..10])?;
    if r[10] != b' ' {
        return None;
    }
    let hh = http_read_2(&r[11..13])?;
    if r[13] != b':' {
        return None;
    }
    let mm = http_read_2(&r[14..16])?;
    if r[16] != b':' {
        return None;
    }
    let ss = http_read_2(&r[17..19])?;
    if r[19] != b' ' || !http_is_zone_abbr(&r[20..23]) {
        return None;
    }
    // Go's two-digit-year pivot: >= 69 is 19xx, below is 20xx.
    let year = if yy >= 69 { 1900 + yy } else { 2000 + yy };
    return http_mk_time(year, month_idx, day, hh, mm, ss);
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

// go: sdk 1.25.5 net/http/header.go:228-234 CanonicalHeaderKey
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
    // Go: textproto.CanonicalMIMEHeaderKey walks the bytes first and
    // returns s UNCHANGED the moment it meets one that is not a valid
    // header field byte — "If s contains a space or invalid header
    // field bytes, it is returned without modifications."
    //
    // goish canonicalized regardless, so `CanonicalHeaderKey("Bad Name")`
    // came back "Bad name" where Go gives "Bad Name". That silently
    // rewrites a caller's key, and since Set/Get/Add/Del all route
    // through here, an invalid key was stored under a name the caller
    // never used.
    let mut i = 0;
    while i < bytes.len() {
        if !super::http::isTokenByte(bytes[i]) {
            return string::from_bytes(bytes);
        }
        i += 1;
    }
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

// go: sdk 1.25.5 net/http/header.go:236-270 hasToken
//
// hasToken reports whether token appears with v, ASCII
// case-insensitive, with space or comma boundaries.
// token must be all lowercase.
// v may contain mixed cased.
pub fn hasToken<V: Into<string>, T: Into<string>>(v: V, token: T) -> bool {
    let v: string = v.into();
    let token: string = token.into();
    if len(&token) > len(&v) || token == "" {
        return false;
    }
    if v == token {
        return true;
    }
    let mut sp: int = 0;
    while sp <= len(&v) - len(&token) {
        // Check that first character is good.
        // The token is ASCII, so checking only a single byte
        // is sufficient. We skip this potential starting
        // position if both the first byte and its potential
        // ASCII uppercase equivalent (b|0x20) don't match.
        // False positives ('^' => '~') are caught by EqualFold.
        let b = v[sp];
        if b != token[0] && (b | 0x20) != token[0] {
            sp += 1;
            continue;
        }
        // Check that start pos is on a valid token boundary.
        if sp > 0 && !isTokenBoundary(v[sp - 1]) {
            sp += 1;
            continue;
        }
        // Check that end pos is on a valid token boundary.
        let endPos = sp + len(&token);
        if endPos != len(&v) && !isTokenBoundary(v[endPos]) {
            sp += 1;
            continue;
        }
        if crate::net::http::internal::ascii::EqualFold(
            v.slice(sp, sp + len(&token)),
            token.clone(),
        ) {
            return true;
        }
        sp += 1;
    }
    return false;
}

// go: sdk 1.25.5 net/http/header.go:272-274 isTokenBoundary
pub fn isTokenBoundary(b: byte) -> bool {
    return b == b' ' || b == b',' || b == b'\t';
}
