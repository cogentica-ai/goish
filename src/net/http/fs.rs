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
use crate::types::{byte, int};

use super::request::Request;
use super::response::ResponseWriter;
use super::server::{Handler, NotFound};

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
        let (ranges, perr) = ParseRange(range_hdr, size);
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
                .Set(string("Content-Range"), r0.ContentRange(size));
            w.Header()
                .Set(string("Content-Length"), crate::strconv::Itoa(r0.Length));
            w.WriteHeader(super::status::StatusPartialContent);
            let part = body.slice(r0.Start, r0.Start + r0.Length);
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

// ─── Range header parsing (fs.go:1015) ───────────────────────────────

/// `httpRange` (fs.go:998) — a parsed byte range. Public so callers
/// (e.g. CDNs / partial transfer tooling) can act on the parsed list.
#[derive(Clone, Copy)]
pub struct HttpRange {
    pub Start: int,
    pub Length: int,
}

impl HttpRange {
    /// `r.ContentRange(size)` (fs.go:1002) — render a "bytes A-B/SIZE"
    /// string for the Content-Range header.
    pub fn ContentRange(&self, size: int) -> string {
        crate::Sprintf!(
            "bytes %d-%d/%d",
            self.Start,
            self.Start + self.Length - 1,
            size
        )
    }
}

/// `parseRange(s, size)` (fs.go:1015) — parse a Range header per
/// RFC 7233 §3.1. Returns `(ranges, ok)`; `ok=false` when the header
/// is malformed.
pub fn ParseRange<S: Into<string>>(s: S, size: int) -> (slice<HttpRange>, error) {
    let s: string = s.into();
    // Go: if s == "" { return nil, nil }
    if s.Len() == 0 {
        return (slice::<HttpRange>::__from_vec(alloc::vec::Vec::new()), errors::nil);
    }
    // Go: const b = "bytes="; if !strings.HasPrefix(s, b) { return nil, errors.New(...) }
    if !strings::HasPrefix(s.clone(), string("bytes=")) {
        return (
            slice::<HttpRange>::__from_vec(alloc::vec::Vec::new()),
            errors::New(string("invalid range")),
        );
    }
    let body = strings::TrimPrefix(s, string("bytes="));
    let mut ranges: alloc::vec::Vec<HttpRange> = alloc::vec::Vec::new();
    let mut no_overlap = false;
    let parts = strings::Split(body, string(","));
    for i in 0..parts.Len() {
        let ra = strings::TrimSpace(parts[i].clone());
        // Go: if ra == "" { continue }
        if ra.Len() == 0 {
            continue;
        }
        // Go: start, end, ok := strings.Cut(ra, "-")
        let (start, end, ok) = strings::Cut(ra, string("-"));
        if !ok {
            return (
                slice::<HttpRange>::__from_vec(alloc::vec::Vec::new()),
                errors::New(string("invalid range")),
            );
        }
        let start = strings::TrimSpace(start);
        let end = strings::TrimSpace(end);
        let mut r = HttpRange { Start: 0, Length: 0 };
        if start.Len() == 0 {
            // Suffix form: "bytes=-N" → last N bytes.
            if end.Len() == 0 || end[0] == b'-' {
                return (
                    slice::<HttpRange>::__from_vec(alloc::vec::Vec::new()),
                    errors::New(string("invalid range")),
                );
            }
            let (mut n, perr) = crate::strconv::Atoi(end);
            if !perr.IsNil() || n < 0 {
                return (
                    slice::<HttpRange>::__from_vec(alloc::vec::Vec::new()),
                    errors::New(string("invalid range")),
                );
            }
            if n > size {
                n = size;
            }
            r.Start = size - n;
            r.Length = size - r.Start;
        } else {
            let (i_start, perr) = crate::strconv::Atoi(start);
            if !perr.IsNil() || i_start < 0 {
                return (
                    slice::<HttpRange>::__from_vec(alloc::vec::Vec::new()),
                    errors::New(string("invalid range")),
                );
            }
            if i_start >= size {
                no_overlap = true;
                continue;
            }
            r.Start = i_start;
            if end.Len() == 0 {
                r.Length = size - r.Start;
            } else {
                let (mut i_end, perr) = crate::strconv::Atoi(end);
                if !perr.IsNil() || r.Start > i_end {
                    return (
                        slice::<HttpRange>::__from_vec(alloc::vec::Vec::new()),
                        errors::New(string("invalid range")),
                    );
                }
                if i_end >= size {
                    i_end = size - 1;
                }
                r.Length = i_end - r.Start + 1;
            }
        }
        ranges.push(r);
    }
    if no_overlap && ranges.is_empty() {
        return (
            slice::<HttpRange>::__from_vec(alloc::vec::Vec::new()),
            errors::New(string("requested range not satisfiable")),
        );
    }
    (slice::<HttpRange>::__from_vec(ranges), errors::nil)
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
