// net/http/fs — FileServer / ServeFile / Dir.
//
// Slim line-by-line port of Go 1.25 src/net/http/fs.go (~1000 LOC,
// goish slims to the static-content serving path most users need).
// No Range support, no If-Modified-Since, no directory index HTML —
// these are flagged for follow-up iterations.
//
// Public API:
//   pub struct Dir { … }                           // Go: type Dir string
//   pub fn FileServer(root: Dir) -> Arc<dyn Handler>
//   pub fn ServeFile(w, r, name)

#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;

use alloc::sync::Arc;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::Reader;
use crate::os;
use crate::string;
use crate::strings;
use crate::time;
use crate::types::{byte, int, rune};

use super::request::Request;
use super::response::ResponseWriter;
use super::server::{Handler, NotFound};
use crate::delete;
use crate::io::fs;
use super::header::{ParseTime, TimeFormat};
use super::status::{StatusMovedPermanently, StatusNotModified, StatusPreconditionFailed};
use crate::go;
use crate::len;
use crate::nil;
use crate::nilable;
use crate::net::textproto;
use crate::range;

/// `http.Dir(root)` — bind a filesystem root directory. Mirrors Go's
/// `type Dir string` (fs.go:44).
#[derive(Clone)]
pub struct Dir {
    root: string,
}

pub fn NewDir<R: Into<string>>(root: R) -> Dir {
    let root: string = root.into();
    Dir { root }
}

impl Dir {
    /// Resolve a request URL path to an absolute filesystem path,
    /// rejecting any attempt to escape `root` via `..` segments.
    fn resolve(&self, name: &string) -> Option<string> {
        // Reject if name contains `..` after path::Clean — same shape
        // as Go's check (fs.go:88).
        let cleaned = crate::path::Clean(name.clone());
        if strings::Contains(cleaned.clone(), string("../")) {
            return None;
        }
        let mut b = strings::Builder::new();
        let _ = b.WriteString(self.root.clone());
        // Ensure single slash join.
        let r = self.root.as_bytes();
        let need_slash =
            !(r.len() > 0 && r[r.len() - 1] == b'/')
                && !(cleaned.Len() > 0 && cleaned[0] == b'/');
        if need_slash {
            let _ = b.WriteByte(b'/');
        }
        let _ = b.WriteString(cleaned);
        Some(b.String())
    }
}

/// `http.ServeFile(w, r, name)` (fs.go:814) — serve the named file.
pub fn ServeFile<N: Into<string>>(w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request, name: N){
    let name: string = name.into();
    serve_file_path(w, r, name);
}

fn serve_file_path(w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request, path: string) {
    // Stat to verify existence and reject directories (slim — Go also
    // serves directory indexes).
    let (fi, err) = os::Stat(path.clone());
    if !err.IsNil() {
        NotFound(w, r);
        return;
    }
    if fi.IsDir() {
        // Try `<dir>/index.html` (mirrors Go's localRedirect → indexPage).
        let mut b = strings::Builder::new();
        let _ = b.WriteString(path.clone());
        if !strings::HasSuffix(path.clone(), string("/")) {
            let _ = b.WriteByte(b'/');
        }
        let _ = b.WriteString("index.html");
        let candidate = b.String();
        let (ifi, ierr) = os::Stat(candidate.clone());
        if ierr.IsNil() && !ifi.IsDir() {
            return serve_regular_file(w, r, candidate, ifi);
        }
        // No index.html — emit an HTML directory listing.
        return dir_list(w, r, path);
    }
    serve_regular_file(w, r, path, fi);
}

/// Line-by-line port of `dirList` (fs.go:139). Renders an HTML
/// directory listing — entries sorted by name, directories suffixed
/// with `/`. Missing pieces vs Go: no URL-escape on the href (slim;
/// goish has http::PathEscape but legacy dirList uses url.URL{Path:n}).
fn dir_list(w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request, path: string) {
    let (entries, err) = os::ReadDir(path);
    if !err.IsNil() {
        super::server::Error(
            w,
            string("Error reading directory"),
            super::status::StatusInternalServerError,
        );
        return;
    }
    // Go: sort.Slice — os::ReadDir already returns sorted, no extra step.
    w.Header().Set(
        string("Content-Type"),
        string("text/html; charset=utf-8"),
    );
    let mut buf = strings::Builder::new();
    let _ = buf.WriteString("<!doctype html>\n");
    let _ = buf.WriteString("<meta name=\"viewport\" content=\"width=device-width\">\n");
    let _ = buf.WriteString("<pre>\n");
    for i in 0..entries.Len() {
        let e = entries[i].clone();
        let mut name = e.Name();
        if e.IsDir() {
            let mut nb = strings::Builder::new();
            let _ = nb.WriteString(name.clone());
            let _ = nb.WriteByte(b'/');
            name = nb.String();
        }
        let escaped = super::url::PathEscape(name.clone());
        let _ = buf.WriteString("<a href=\"");
        let _ = buf.WriteString(escaped);
        let _ = buf.WriteString("\">");
        let _ = buf.WriteString(html_replace(name));
        let _ = buf.WriteString("</a>\n");
    }
    let _ = buf.WriteString("</pre>\n");
    let _ = w.Write(crate::convert::bytes(buf.String()));
}

/// Slim analogue of Go's `htmlReplacer` (fs.go:135).
fn html_replace(s: string) -> string {
    let mut b = strings::Builder::new();
    b.Grow(s.Len());
    for i in 0..s.Len() {
        let c: crate::types::byte = s[i];
        match c {
            b'&' => {
                let _ = b.WriteString("&amp;");
            }
            b'<' => {
                let _ = b.WriteString("&lt;");
            }
            b'>' => {
                let _ = b.WriteString("&gt;");
            }
            b'"' => {
                let _ = b.WriteString("&#34;");
            }
            b'\'' => {
                let _ = b.WriteString("&#39;");
            }
            _ => {
                let _ = b.WriteByte(c);
            }
        }
    }
    b.String()
}

fn serve_regular_file(w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request, path: string, fi: os::FileInfoData) {
    // Open + read fully into a slice<byte>. Range slicing happens
    // after the read since v1 has no streaming Read with seek loops.
    let (mut f, err) = os::Open(path.clone());
    if !err.IsNil() {
        super::server::Error(
            w,
            string("file open failed"),
            super::status::StatusInternalServerError,
        );
        return;
    }
    // err is nil ⇒ Open returned a non-nil File. Narrow.
    let f = f.MustMut();
    let want = fi.Size();
    let mut body = make_zero_buf(want);
    let (got, _e) = f.Read(&mut body);
    let _ = f.Close();
    let body = if got < want {
        body.slice(0, got)
    } else {
        body
    };
    let size = body.Len();

    // Content-Type via extension lookup, then sniffing fallback.
    let ext = ext_of(&path);
    let mut ct = crate::mime::TypeByExtension(ext);
    if ct.Len() == 0 {
        ct = super::sniff::DetectContentType(body.clone());
    }
    w.Header().Set(string("Content-Type"), ct);
    // Last-Modified header from Stat (RFC 7232 §2.2). Mirrors
    // Go's writeNotModified-supporting branch in fs.go:setLastModified.
    let mtime = fi.ModTime();
    if !mtime.IsZero() {
        let mut buf: [crate::types::byte; 29] = [0; 29];
        let appended = imf_fixdate_into(&mut buf, &mtime);
        w.Header()
            .Set(string("Last-Modified"), string::from_bytes(appended));
        // If-Modified-Since handling — return 304 if the resource
        // hasn't changed since the client's cached copy.
        let ims = r.Header.Get(string("If-Modified-Since"));
        if ims.Len() > 0 {
            let (since, terr) = super::header::ParseTime(ims);
            if terr.IsNil() && !mtime.After(since) {
                w.WriteHeader(super::status::StatusNotModified);
                return;
            }
        }
    }
    // Range header — single-range only for v1 (the common case).
    let range_hdr = r.Header.Get(string("Range"));
    if range_hdr.Len() > 0 {
        let (ranges, perr) = parseRange(range_hdr, size);
        if !perr.IsNil() || ranges.Len() == 0 {
            // Malformed → 416 Requested Range Not Satisfiable.
            w.Header().Set(
                string("Content-Range"),
                crate::Sprintf!("bytes */{}", size),
            );
            w.WriteHeader(super::status::StatusRequestedRangeNotSatisfiable);
            return;
        }
        if ranges.Len() == 1 {
            let r0 = ranges[0];
            w.Header()
                .Set(string("Content-Range"), r0.contentRange(size));
            w.Header()
                .Set(string("Content-Length"), crate::strconv::Itoa(r0.length));
            w.WriteHeader(super::status::StatusPartialContent);
            let part = body.slice(r0.start, r0.start + r0.length);
            let _ = w.Write(part);
            return;
        }
        // Multi-range → fall through to whole-body 200 (v1 deviation
        // from Go which would emit multipart/byteranges).
    }
    let _ = w.Write(body);
}

/// Inline IMF-fixdate writer for Last-Modified. Mirrors the helper
/// in cookie.rs but kept private here to avoid a circular dependency.
fn imf_fixdate_into<'a>(
    buf: &'a mut [crate::types::byte; 29],
    t: &crate::time::Time,
) -> &'a [crate::types::byte] {
    const DAYS: [&[crate::types::byte; 3]; 7] =
        [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
    const MONS: [&[crate::types::byte; 3]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun",
        b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
    ];
    let weekday = (t.Weekday().Int() as usize) % 7;
    let (year, month, day) = t.Date();
    let (hh, mm, ss) = t.Clock();
    let dn = DAYS[weekday];
    let mn = MONS[((month - 1) as usize) % 12];
    buf[0] = dn[0];
    buf[1] = dn[1];
    buf[2] = dn[2];
    buf[3] = b',';
    buf[4] = b' ';
    buf[5] = b'0' + ((day / 10) % 10) as crate::types::byte;
    buf[6] = b'0' + (day % 10) as crate::types::byte;
    buf[7] = b' ';
    buf[8] = mn[0];
    buf[9] = mn[1];
    buf[10] = mn[2];
    buf[11] = b' ';
    buf[12] = b'0' + ((year / 1000) % 10) as crate::types::byte;
    buf[13] = b'0' + ((year / 100) % 10) as crate::types::byte;
    buf[14] = b'0' + ((year / 10) % 10) as crate::types::byte;
    buf[15] = b'0' + (year % 10) as crate::types::byte;
    buf[16] = b' ';
    buf[17] = b'0' + ((hh / 10) % 10) as crate::types::byte;
    buf[18] = b'0' + (hh % 10) as crate::types::byte;
    buf[19] = b':';
    buf[20] = b'0' + ((mm / 10) % 10) as crate::types::byte;
    buf[21] = b'0' + (mm % 10) as crate::types::byte;
    buf[22] = b':';
    buf[23] = b'0' + ((ss / 10) % 10) as crate::types::byte;
    buf[24] = b'0' + (ss % 10) as crate::types::byte;
    buf[25] = b' ';
    buf[26] = b'G';
    buf[27] = b'M';
    buf[28] = b'T';
    &buf[..]
}

/// `http.FileServer(root)` (fs.go:971) — Handler that serves files
/// from `root`. Combine with `http.StripPrefix` to mount under a
/// subpath (matches Go's idiom).
pub fn FileServer(root: Dir) -> Arc<dyn Handler> {
    Arc::new(FileHandler { root })
}

struct FileHandler {
    root: Dir,
}

impl Handler for FileHandler {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
        // Go: upath := r.URL.Path; if !strings.HasPrefix(upath, "/") { upath = "/" + upath; r.URL.Path = upath }
        let mut upath = r.URL.Path.clone();
        if !strings::HasPrefix(upath.clone(), string("/")) {
            let mut b = strings::Builder::new();
            let _ = b.WriteByte(b'/');
            let _ = b.WriteString(upath);
            upath = b.String();
        }
        match self.root.resolve(&upath) {
            None => NotFound(w, r),
            Some(p) => serve_file_path(w, r, p),
        }
    }
}

// ─── Range header parsing (fs.go:998-1116) ───────────────────────────

// go: sdk 1.25.5 net/http/fs.go:268-268 errNoOverlap
crate::var! {
    pub errNoOverlap: error = "invalid range: failed to overlap";
}

// go: sdk 1.25.5 net/http/fs.go:997-1000 httpRange
#[derive(Clone, Copy)]
pub struct httpRange {
    pub start: int,
    pub length: int,
}

impl httpRange {
    // go: sdk 1.25.5 net/http/fs.go:1002-1004 httpRange.contentRange
    pub fn contentRange(&self, size: int) -> string {
        return crate::Sprintf!(
            "bytes %d-%d/%d",
            self.start,
            self.start + self.length - 1,
            size
        );
    }

    // go: sdk 1.25.5 net/http/fs.go:1006-1013 httpRange.mimeHeader
    pub fn mimeHeader(&self, contentType: string, size: int) -> textproto::MIMEHeader {
        let mut h = textproto::MIMEHeader::new();
        h.Set(
            string("Content-Range"),
            slice::__from_vec(alloc::vec![self.contentRange(size)]),
        );
        h.Set(
            string("Content-Type"),
            slice::__from_vec(alloc::vec![contentType]),
        );
        return h;
    }
}

// go: sdk 1.25.5 net/http/fs.go:1015-1088 parseRange
//
// Go splits on "," with strings.SplitSeq and trims each element with
// textproto.TrimString, which strips the four ASCII space bytes
// (' ', '\t', '\n', '\r') and nothing else. strings.TrimSpace would
// additionally strip Unicode whitespace such as '\v' and U+00A0, so it
// accepts Range headers Go rejects. Confirmed against Go 1.25.5:
// "bytes=\n0-99" parses, and so does "bytes= 0 - 99 ".
pub fn parseRange<S: Into<string>>(s: S, size: int) -> (slice<httpRange>, error) {
    let s: string = s.into();
    if s == "" {
        return (slice::new(), nil.into()); // header not present
    }
    let b = string("bytes=");
    if !strings::HasPrefix(s.clone(), b.clone()) {
        return (slice::new(), errors::New(string("invalid range")));
    }
    let mut ranges: alloc::vec::Vec<httpRange> = alloc::vec::Vec::new();
    let mut noOverlap = false;
    let parts = strings::Split(strings::TrimPrefix(s, b), string(","));
    let pn = len(&parts);
    let mut pi: int = 0;
    while pi < pn {
        let ra = textproto::TrimString(parts[pi].clone());
        pi += 1;
        if ra == "" {
            continue;
        }
        let (start, end, ok) = strings::Cut(ra, string("-"));
        if !ok {
            return (slice::new(), errors::New(string("invalid range")));
        }
        let start = textproto::TrimString(start);
        let end = textproto::TrimString(end);
        let mut r = httpRange { start: 0, length: 0 };
        if start == "" {
            // If no start is specified, end specifies the range start
            // relative to the end of the file, and we are dealing with
            // <suffix-length> which has to be a non-negative integer as
            // per RFC 7233 Section 2.1 "Byte-Ranges".
            if end == "" || end[0] == b'-' {
                return (slice::new(), errors::New(string("invalid range")));
            }
            let (mut i, err) = crate::strconv::ParseInt(end, 10, 64);
            if i < 0 || err != nil {
                return (slice::new(), errors::New(string("invalid range")));
            }
            if i > size {
                i = size;
            }
            r.start = size - i;
            r.length = size - r.start;
        } else {
            let (i, err) = crate::strconv::ParseInt(start, 10, 64);
            if err != nil || i < 0 {
                return (slice::new(), errors::New(string("invalid range")));
            }
            if i >= size {
                // If the range begins after the size of the content,
                // then it does not overlap.
                noOverlap = true;
                continue;
            }
            r.start = i;
            if end == "" {
                // If no end is specified, range extends to end of the file.
                r.length = size - r.start;
            } else {
                let (mut i, err) = crate::strconv::ParseInt(end, 10, 64);
                if err != nil || r.start > i {
                    return (slice::new(), errors::New(string("invalid range")));
                }
                if i >= size {
                    i = size - 1;
                }
                r.length = i - r.start + 1;
            }
        }
        ranges.push(r);
    }
    if noOverlap && ranges.is_empty() {
        // The specified ranges did not overlap with the content.
        return (slice::new(), errNoOverlap.into());
    }
    return (slice::__from_vec(ranges), nil.into());
}

// go: sdk 1.25.5 net/http/fs.go:1090-1090 countingWriter
//
// Go writes `type countingWriter int64` and takes `*countingWriter` as
// the io.Writer. A Rust newtype struct is the same thing with a field
// name; `.0` stands in for Go's `*w`.
pub struct countingWriter(pub int);

impl crate::io::Writer for countingWriter {
    // go: sdk 1.25.5 net/http/fs.go:1092-1095 countingWriter.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        self.0 += len(&p);
        return (len(&p), nil.into());
    }
}

// go: sdk 1.25.5 net/http/fs.go:1111-1116 sumRangesSize
pub fn sumRangesSize(ranges: &slice<httpRange>) -> int {
    let mut size: int = 0;
    let n = len(ranges);
    let mut i: int = 0;
    while i < n {
        size += ranges[i].length;
        i += 1;
    }
    return size;
}

// ─── small helpers ───────────────────────────────────────────────────

/// Allocate a `slice<byte>` of length `n`, zero-initialized.
fn make_zero_buf(n: int) -> slice<byte> {
    slice::<byte>::__from_vec(alloc::vec![0u8; n as usize])
}

/// Return the file extension (including the leading dot) of `path`,
/// or empty if there is none. Mirrors `path.Ext`.
fn ext_of(path: &string) -> string {
    let bs = path.as_bytes();
    let mut i = bs.len();
    while i > 0 {
        let c = bs[i - 1];
        if c == b'/' {
            break;
        }
        if c == b'.' {
            return string::from_bytes(&bs[i - 1..]);
        }
        i -= 1;
    }
    string::new()
}

// go: none — goish idiom: `FileHandler` is unexported, so only this
// module can register it. See AGENTS.md §9b.
pub(super) fn register_fs_impls() {
    super::server::__goish_register_Handler_impl::<FileHandler>();
}

// go: sdk 1.25.5 net/http/fs.go:463-465 etagStrongMatch
pub fn etagStrongMatch<S: Into<string>, S2: Into<string>>(a: S, b: S2) -> bool {
    let a = a.into();
    let b = b.into();
    return a == b && a != "" && a[0] == 34 /*'"'*/;
}

// go: sdk 1.25.5 net/http/fs.go:469-471 etagWeakMatch
pub fn etagWeakMatch<S: Into<string>, S2: Into<string>>(a: S, b: S2) -> bool {
    let a = a.into();
    let b = b.into();
    return strings::TrimPrefix(a, string("W/")) == strings::TrimPrefix(b, string("W/"));
}

// go: sdk 1.25.5 net/http/fs.go:617-619 isZeroTime
pub fn isZeroTime(t: time::Time) -> bool {
    return t.IsZero() || t.Equal(unixEpochTime.clone());
}

// go: sdk 1.25.5 net/http/fs.go:873-873 isSlashRune
pub fn isSlashRune(r: rune) -> bool {
    return r == 47 /*'/'*/ || r == 92 /*'\\'*/;
}

// go: sdk 1.25.5 net/http/fs.go:614-614 unixEpochTime
pub static unixEpochTime: crate::lazy::Lazy<time::Time> = crate::lazy::Lazy::new(|| time::Unix(0, 0));

// go: sdk 1.25.5 net/http/fs.go:436-459 scanETag
pub fn scanETag<S: Into<string>>(mut s: S) -> (string, string) {
    #[allow(unused_mut)]
    let mut s = s.into();
    s = textproto::TrimString(s);
    let mut start = 0;
    if strings::HasPrefix(s.clone(), string("W/")) {
        start = 2;
    }
    if len(&s.slice(start, len(&s))) < 2 || s[start] != 34 /*'"'*/ {
        return (string(""), string(""));
    }
    {
        let mut i = start.wrapping_add(1);
        while i < len(&s) {
            let c = s[i];
            if c == 0x21 || c >= 0x23 && c <= 0x7E || c >= 0x80 {
            } else if c == 34 /*'"'*/ {
                return (s.slice(0, i.wrapping_add(1)), s.slice(i.wrapping_add(1), len(&s)));
            } else {
                return (string(""), string(""));
            }
            i = i.wrapping_add(1);
        }
    }
    return (string(""), string(""));
}

// go: sdk 1.25.5 net/http/fs.go:562-581 checkIfModifiedSince
pub fn checkIfModifiedSince(r: nilable![&Request], mut modtime: time::Time) -> condResult {
    if r.Must().Method != "GET" && r.Must().Method != "HEAD" {
        return condNone;
    }
    let ims = r.Must().Header.Get(string("If-Modified-Since"));
    if ims == "" || isZeroTime(modtime) {
        return condNone;
    }
    let (t, err) = ParseTime(ims);
    if err != nil {
        return condNone;
    }
    modtime = modtime.Truncate(time::Second);
    {
        let ret = modtime.Compare(t);
        if ret <= 0 {
            return condFalse;
        }
    }
    return condTrue;
}

// go: sdk 1.25.5 net/http/fs.go:621-625 setLastModified
pub fn setLastModified(w: &(dyn ResponseWriter + Send + Sync + 'static), modtime: time::Time) {
    if !isZeroTime(modtime) {
        w.Header().Set(string("Last-Modified"), modtime.UTC().Format(TimeFormat));
    }
}

// go: sdk 1.25.5 net/http/fs.go:627-641 writeNotModified
pub fn writeNotModified(w: &(dyn ResponseWriter + Send + Sync + 'static)) {
    let mut h = w.Header();
    h.Del(string("Content-Type"));
    h.Del(string("Content-Length"));
    h.Del(string("Content-Encoding"));
    if h.Get(string("Etag")) != "" {
        h.Del(string("Last-Modified"));
    }
    w.WriteHeader(StatusNotModified);
}

// go: sdk 1.25.5 net/http/fs.go:475-475 condResult
#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct condResult(pub int);

crate::derive_go_hash_newtype!(condResult);

// go: sdk 1.25.5 net/http/fs.go:477-481 condNone
pub const condNone: condResult = condResult(0);
// go: sdk 1.25.5 net/http/fs.go:477-481 condTrue
pub const condTrue: condResult = condResult(1);
// go: sdk 1.25.5 net/http/fs.go:477-481 condFalse
pub const condFalse: condResult = condResult(2);

// go: sdk 1.25.5 net/http/fs.go:483-511 checkIfMatch
pub fn checkIfMatch(w: &(dyn ResponseWriter + Send + Sync + 'static), r: nilable![&Request]) -> condResult {
    let mut im = r.Must().Header.Get(string("If-Match"));
    if im == "" {
        return condNone;
    }
    loop {
        im = textproto::TrimString(im);
        if len(&im) == 0 {
            break;
        }
        if im[0] == 44 /*','*/ {
            im = im.slice(1, len(&im));
            continue;
        }
        if im[0] == 42 /*'*'*/ {
            return condTrue;
        }
        let (etag, remain) = scanETag(im.clone());
        if etag == "" {
            break;
        }
        if etagStrongMatch(etag, w.Header().Get(string("Etag"))) {
            return condTrue;
        }
        im = remain;
    }
    return condFalse;
}

// go: sdk 1.25.5 net/http/fs.go:513-530 checkIfUnmodifiedSince
pub fn checkIfUnmodifiedSince(r: nilable![&Request], mut modtime: time::Time) -> condResult {
    let ius = r.Must().Header.Get(string("If-Unmodified-Since"));
    if ius == "" || isZeroTime(modtime) {
        return condNone;
    }
    let (t, err) = ParseTime(ius);
    if err != nil {
        return condNone;
    }
    modtime = modtime.Truncate(time::Second);
    {
        let ret = modtime.Compare(t);
        if ret <= 0 {
            return condTrue;
        }
    }
    return condFalse;
}

// go: sdk 1.25.5 net/http/fs.go:532-560 checkIfNoneMatch
pub fn checkIfNoneMatch(w: &(dyn ResponseWriter + Send + Sync + 'static), r: nilable![&Request]) -> condResult {
    let inm = r.Must().Header.Get(string("If-None-Match"));
    if inm == "" {
        return condNone;
    }
    let mut buf = inm;
    loop {
        buf = textproto::TrimString(buf);
        if len(&buf) == 0 {
            break;
        }
        if buf[0] == 44 /*','*/ {
            buf = buf.slice(1, len(&buf));
            continue;
        }
        if buf[0] == 42 /*'*'*/ {
            return condFalse;
        }
        let (etag, remain) = scanETag(buf.clone());
        if etag == "" {
            break;
        }
        if etagWeakMatch(etag, w.Header().Get(string("Etag"))) {
            return condFalse;
        }
        buf = remain;
    }
    return condTrue;
}

// go: sdk 1.25.5 net/http/fs.go:583-612 checkIfRange
pub fn checkIfRange(w: &(dyn ResponseWriter + Send + Sync + 'static), r: nilable![&Request], modtime: time::Time) -> condResult {
    if r.Must().Method != "GET" && r.Must().Method != "HEAD" {
        return condNone;
    }
    let ir = r.Must().Header.Get(string("If-Range"));
    if ir == "" {
        return condNone;
    }
    let (etag, _) = scanETag(ir.clone());
    if etag != "" {
        if etagStrongMatch(etag, w.Header().Get(string("Etag"))) {
            return condTrue;
        } else {
            return condFalse;
        }
    }
    if modtime.IsZero() {
        return condFalse;
    }
    let (t, err) = ParseTime(ir);
    if err != nil {
        return condFalse;
    }
    if t.Unix() == modtime.Unix() {
        return condTrue;
    }
    return condFalse;
}

// go: sdk 1.25.5 net/http/fs.go:645-676 checkPreconditions
pub fn checkPreconditions(w: &(dyn ResponseWriter + Send + Sync + 'static), r: nilable![&Request], modtime: time::Time) -> (bool, string) {
    #[allow(unused_mut)]
    let mut rangeHeader: string = Default::default();
    let mut ch = checkIfMatch(w, r);
    if ch == condNone {
        ch = checkIfUnmodifiedSince(r, modtime);
    }
    if ch == condFalse {
        w.WriteHeader(StatusPreconditionFailed);
        return (true, string(""));
    }
    if checkIfNoneMatch(w, r) == condFalse {
        if r.Must().Method == "GET" || r.Must().Method == "HEAD" {
            writeNotModified(w);
            return (true, string(""));
        } else {
            w.WriteHeader(StatusPreconditionFailed);
            return (true, string(""));
        }
    } else if checkIfNoneMatch(w, r) == condNone {
        if checkIfModifiedSince(r, modtime) == condFalse {
            writeNotModified(w);
            return (true, string(""));
        }
    }
    rangeHeader = r.Must().Header.Get(string("Range"));
    if rangeHeader != "" && checkIfRange(w, r, modtime) == condFalse {
        rangeHeader = string("");
    }
    return (false, rangeHeader);
}

impl fileInfoDirs {
    // go: sdk 1.25.5 net/http/fs.go:129-129 fileInfoDirs.len
    pub fn len(&self) -> int {
        return len(&self.0);
    }
}

impl fileInfoDirs {
    // go: sdk 1.25.5 net/http/fs.go:130-130 fileInfoDirs.isDir
    pub fn isDir(&mut self, i: int) -> bool {
        return self[i].IsDir();
    }
}

impl fileInfoDirs {
    // go: sdk 1.25.5 net/http/fs.go:131-131 fileInfoDirs.name
    pub fn name(&mut self, i: int) -> string {
        return self[i].Name();
    }
}

impl dirEntryDirs {
    // go: sdk 1.25.5 net/http/fs.go:135-135 dirEntryDirs.len
    pub fn len(&self) -> int {
        return len(&self.0);
    }
}

impl dirEntryDirs {
    // go: sdk 1.25.5 net/http/fs.go:136-136 dirEntryDirs.isDir
    pub fn isDir(&mut self, i: int) -> bool {
        return self[i].IsDir();
    }
}

impl dirEntryDirs {
    // go: sdk 1.25.5 net/http/fs.go:137-137 dirEntryDirs.name
    pub fn name(&mut self, i: int) -> string {
        return self[i].Name();
    }
}

// go: sdk 1.25.5 net/http/fs.go:188-212 serveError
pub fn serveError<S: Into<string>>(w: &(dyn ResponseWriter + Send + Sync + 'static), text: S, code: int) {
    let text = text.into();
    let h = w.Header();
    for k in [string("Cache-Control"), string("Content-Encoding"),
                  string("Etag"), string("Last-Modified")] {
        if !h.has(k.clone()) {
            continue;
        }
        // goish has no internal/godebug, so the
        // `httpservecontentkeepheaders=1` opt-out cannot be read. Go's
        // default with the variable unset is this branch.
        h.Del(k.clone());
    }
    super::server::Error(w, text, code);
}

// go: sdk 1.25.5 net/http/fs.go:785-791 localRedirect
pub fn localRedirect<S: Into<string>>(w: &(dyn ResponseWriter + Send + Sync + 'static), r: nilable![&Request], mut newPath: S) {
    #[allow(unused_mut)]
    let mut newPath = newPath.into();
    {
        let q = r.Must().URL.RawQuery.clone();
        if q != "" {
            newPath += string("?") + q;
        }
    }
    w.Header().Set(string("Location"), newPath);
    w.WriteHeader(StatusMovedPermanently);
}

// go: sdk 1.25.5 net/http/fs.go:121-125 anyDirs
#[goish::interface] // goishlint:ignore GOISH022 - attribute macro path; `goish::` is the spelling everywhere
pub trait anyDirs {
    fn len(&self) -> int;
    fn name(&mut self, i: int) -> string;
    fn isDir(&mut self, i: int) -> bool;
}

// go: sdk 1.25.5 net/http/fs.go:127-127 fileInfoDirs
#[derive(Default, Clone)]
pub struct fileInfoDirs(pub slice<alloc::sync::Arc<dyn fs::FileInfo + Send + Sync>>);

impl core::ops::Deref for fileInfoDirs {
    type Target = slice<alloc::sync::Arc<dyn fs::FileInfo + Send + Sync>>;
    // go: none — Deref plumbing for the newtype; Go's `fileInfoDirs` IS a
    // slice, so indexing and len need no method there.
    fn deref(&self) -> &slice<alloc::sync::Arc<dyn fs::FileInfo + Send + Sync>> {
        return &self.0;
    }
}

impl core::ops::DerefMut for fileInfoDirs {
    // go: none — Deref plumbing, as above.
    fn deref_mut(&mut self) -> &mut slice<alloc::sync::Arc<dyn fs::FileInfo + Send + Sync>> {
        return &mut self.0;
    }
}

// go: sdk 1.25.5 net/http/fs.go:133-133 dirEntryDirs
#[derive(Default, Clone)]
pub struct dirEntryDirs(pub slice<alloc::sync::Arc<dyn fs::DirEntry + Send + Sync>>);

impl core::ops::Deref for dirEntryDirs {
    type Target = slice<alloc::sync::Arc<dyn fs::DirEntry + Send + Sync>>;
    // go: none — Deref plumbing for the newtype; Go's `dirEntryDirs` IS a
    // slice, so indexing and len need no method there.
    fn deref(&self) -> &slice<alloc::sync::Arc<dyn fs::DirEntry + Send + Sync>> {
        return &self.0;
    }
}

impl core::ops::DerefMut for dirEntryDirs {
    // go: none — Deref plumbing, as above.
    fn deref_mut(&mut self) -> &mut slice<alloc::sync::Arc<dyn fs::DirEntry + Send + Sync>> {
        return &mut self.0;
    }
}

// go: sdk 1.25.5 net/http/fs.go:875-877 fileHandler
#[derive(Clone)]
pub struct fileHandler {
    pub root: alloc::sync::Arc<dyn FileSystem + Send + Sync>,
}

// go: sdk 1.25.5 net/http/fs.go:879-881 ioFS
#[derive(Clone)]
pub struct ioFS {
    pub fsys: alloc::sync::Arc<dyn fs::FS + Send + Sync>,
}

// go: sdk 1.25.5 net/http/fs.go:883-885 ioFile
#[derive(Clone)]
pub struct ioFile {
    pub file: alloc::sync::Arc<dyn fs::File + Send + Sync>,
}

// go: sdk 1.25.5 net/http/fs.go:49-67 mapOpenError
//
// `stat` is Go's `func(string) (fs.FileInfo, error)` parameter, spelled
// as a borrowed closure so both call sites can pass their own
// filesystem's stat without either one owning it.
pub fn mapOpenError(
    originalErr: error,
    name: string,
    sep: rune,
    stat: &dyn Fn(string) -> (Arc<dyn fs::FileInfo + Send + Sync>, error),
) -> error {
    if errors::Is(originalErr.clone(), fs::ErrNotExist)
        || errors::Is(originalErr.clone(), fs::ErrPermission)
    {
        return originalErr;
    }

    let sepstr = string::from_rune(sep);
    let parts = strings::Split(name, sepstr.clone());
    let n = len(&parts);
    let mut i: int = 0;
    while i < n {
        let idx = i;
        i += 1;
        if parts[idx] == "" {
            continue;
        }
        let (fi, err) = stat(strings::Join(parts.slice(0, idx + 1), sepstr.clone()));
        if err != nil {
            return originalErr;
        }
        if !fi.IsDir() {
            return fs::ErrNotExist.into();
        }
    }
    return originalErr;
}

// go: sdk 1.25.5 net/http/fs.go:906-906 errMissingSeek
crate::var! {
    pub errMissingSeek: error = "io.File missing Seek method";
}

// go: sdk 1.25.5 net/http/fs.go:907-907 errMissingReadDir
crate::var! {
    pub errMissingReadDir: error = "io.File directory missing ReadDir method";
}

impl ioFS {
    // go: sdk 1.25.5 net/http/fs.go:887-900 ioFS.Open
    pub fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        let name = if name == "/" {
            string(".")
        } else {
            strings::TrimPrefix(name, "/")
        };
        let (file, err) = self.fsys.Open(name.clone());
        if err != nil {
            let fsys = self.fsys.clone();
            let mapped = mapOpenError(err, name.clone(), crate::rune('/'), &move |path: string| {
                return fs::Stat(&*fsys, path);
            });
            return (crate::nil.into(), mapped);
        }
        return (Arc::new(ioFile { file }) as Arc<dyn File + Send + Sync>, nil.into());
    }
}

impl ioFile {
    // go: sdk 1.25.5 net/http/fs.go:902-902 ioFile.Close
    pub fn Close(&self) -> error {
        return self.file.Close();
    }

    // go: sdk 1.25.5 net/http/fs.go:903-903 ioFile.Read
    pub fn Read(&self, b: &mut slice<byte>) -> (int, error) {
        return self.file.Read(b);
    }

    // go: sdk 1.25.5 net/http/fs.go:909-915 ioFile.Seek
    //
    // Go asserts `f.file.(io.Seeker)`. goish's io::Seeker takes
    // `&mut self` — a seek moves the cursor — but `f.file` is an
    // `Arc<dyn fs::File>`, which yields no `&mut`. The assertion can
    // therefore never succeed here, and Go's own miss branch is the
    // faithful result: a file whose method set lacks Seek reports
    // errMissingSeek. Wiring the success branch needs fs::File to
    // expose seeking the way ResponseWriter/io::Writer was bridged.
    pub fn Seek(&self, _offset: i64, _whence: int) -> (i64, error) {
        return (0, errMissingSeek.into());
    }

    // go: sdk 1.25.5 net/http/fs.go:917-923 ioFile.ReadDir
    pub fn ReadDir(&self, count: int) -> (slice<Arc<dyn fs::DirEntry + Send + Sync>>, error) {
        let (d, ok) = crate::cast!(&*self.file, fs::ReadDirFile);
        if !ok {
            return (slice::new(), errMissingReadDir.into());
        }
        return d.ReadDir(count);
    }
}

impl File for ioFile {
    // go: sdk 1.25.5 net/http/fs.go:904-904 ioFile.Stat
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        return self.file.Stat();
    }

    // go: sdk 1.25.5 net/http/fs.go:925-949 ioFile.Readdir
    fn Readdir(&self, count: int) -> (slice<Arc<dyn fs::FileInfo + Send + Sync>>, error) {
        let (d, ok) = crate::cast!(&*self.file, fs::ReadDirFile);
        if !ok {
            return (slice::new(), errMissingReadDir.into());
        }
        let mut list: slice<Arc<dyn fs::FileInfo + Send + Sync>> = slice::new();
        loop {
            let (dirs, err) = d.ReadDir(count - len(&list));
            let dn = len(&dirs);
            let mut di: int = 0;
            while di < dn {
                let (info, ierr) = dirs[di].Info();
                di += 1;
                if ierr != nil {
                    // Pretend it doesn't exist, like (*os.File).Readdir does.
                    continue;
                }
                list = crate::append!(list, info);
            }
            if err != nil {
                return (list, err);
            }
            if count < 0 || len(&list) >= count {
                break;
            }
        }
        return (list, nil.into());
    }
}

impl FileSystem for ioFS {
    // go: none — the FileSystem interface method forwards to ioFS::Open,
    // which carries the anchor; Go's ioFS has the one Open method and
    // satisfies FileSystem structurally.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        return ioFS::Open(self, name);
    }
}

// go: sdk 1.25.5 net/http/fs.go:951-956 FS
pub fn FS(fsys: Arc<dyn fs::FS + Send + Sync>) -> Arc<dyn FileSystem + Send + Sync> {
    return Arc::new(ioFS { fsys }) as Arc<dyn FileSystem + Send + Sync>;
}

// go: sdk 1.25.5 net/http/fs.go:105-107 FileSystem
#[crate::interface]
pub trait FileSystem {
    fn Open(&self, name: string) -> (alloc::sync::Arc<dyn File + Send + Sync>, error);
}

// go: sdk 1.25.5 net/http/fs.go:113-119 File
#[crate::interface]
pub trait File {
    fn Readdir(&self, count: int) -> (slice<alloc::sync::Arc<dyn fs::FileInfo + Send + Sync>>, error);
    fn Stat(&self) -> (alloc::sync::Arc<dyn fs::FileInfo + Send + Sync>, error);
}
