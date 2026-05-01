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
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::{Closer, Reader};
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

pub fn NewDir(root: string) -> Dir {
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
pub fn ServeFile(w: &mut ResponseWriter, r: &Request, name: string) {
    serve_file_path(w, r, name);
}

fn serve_file_path(w: &mut ResponseWriter, r: &Request, path: string) {
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
        NotFound(w, r);
        return;
    }
    serve_regular_file(w, r, path, fi);
}

fn serve_regular_file(w: &mut ResponseWriter, r: &Request, path: string, fi: os::FileInfo) {
    let _ = r;
    // Open + read fully into a slice<byte>.
    let (mut f, err) = os::Open(path.clone());
    if !err.IsNil() {
        super::server::Error(
            w,
            string("file open failed"),
            super::status::StatusInternalServerError,
        );
        return;
    }
    let want = fi.Size();
    let mut body = make_zero_buf(want);
    let (got, _e) = f.Read(&mut body);
    let _ = f.Close();
    let body = if got < want {
        body.slice(0, got)
    } else {
        body
    };

    // Content-Type via extension lookup, then sniffing fallback.
    let ext = ext_of(&path);
    let mut ct = crate::mime::TypeByExtension(ext);
    if ct.Len() == 0 {
        ct = super::sniff::DetectContentType(body.clone());
    }
    w.Header().Set(string("Content-Type"), ct);
    let _ = w.Write(body);
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
    fn ServeHTTP(&self, w: &mut ResponseWriter, r: &Request) {
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
pub fn ParseRange(s: string, size: int) -> (slice<HttpRange>, error) {
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
