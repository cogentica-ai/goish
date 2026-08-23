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

use super::header::{ParseTime, TimeFormat};
use super::request::Request;
use super::responsewriter::ResponseWriter;
use super::server::Handler;
use super::status::{
    StatusForbidden, StatusInternalServerError, StatusMovedPermanently, StatusNotFound,
    StatusNotModified, StatusPreconditionFailed,
};
use crate::io::fs;
use crate::len;
use crate::net::textproto;
use crate::nil;
use crate::nilable;

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

impl FileSystem for Dir {
    // go: sdk 1.25.5 net/http/fs.go:76-96 Dir.Open
    //
    // Go's receiver is `d Dir` where `type Dir string`; goish's Dir is
    // a one-field struct over the same string, so `self.root` stands
    // in for Go's `string(d)`.
    fn Open(&self, name: string) -> (Arc<dyn File + Send + Sync>, error) {
        // Go: path := path.Clean("/" + name)[1:]
        let cleaned = crate::path::Clean(string("/") + name);
        let mut path = cleaned.slice(1, len(&cleaned));
        // Go: if path == "" { path = "." }
        if path == "" {
            path = string(".");
        }
        // Go: path, err := filepath.Localize(path)
        //     if err != nil { return nil, errInvalidUnsafePath }
        let (path, lerr) = crate::path::filepath::Localize(path);
        if lerr != nil {
            return (crate::nil.into(), errInvalidUnsafePath.into());
        }
        // Go: dir := string(d); if dir == "" { dir = "." }
        let mut dir = self.root.clone();
        if dir == "" {
            dir = string(".");
        }
        // Go: fullName := filepath.Join(dir, path)
        let fullName = crate::path::filepath::Join(slice::__from_vec(alloc::vec![dir, path]));
        // Go: f, err := os.Open(fullName)
        let (f, oerr) = os::Open(fullName.clone());
        if oerr != nil {
            // Go: return nil, mapOpenError(err, fullName,
            //         filepath.Separator, os.Stat)
            let mapped = mapOpenError(
                oerr,
                fullName.clone(),
                crate::rune(crate::path::filepath::Separator),
                &|p: string| {
                    let (fi, e) = os::Stat(p);
                    if e != nil {
                        return (crate::nil.into(), e);
                    }
                    return (
                        Arc::new(fi) as Arc<dyn fs::FileInfo + Send + Sync>,
                        nil.into(),
                    );
                },
            );
            return (crate::nil.into(), mapped);
        }
        // Go: return f, nil — *os.File IS an http.File; goish wraps.
        // os::Open returns `nilable<File>`; err == nil means it is set.
        return (
            Arc::new(osFile {
                f: crate::runtime::spin::SpinLock::new(f.Must().clone()),
                name: fullName,
            }) as Arc<dyn File + Send + Sync>,
            nil.into(),
        );
    }
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

fn serve_regular_file(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: &Request,
    path: string,
    fi: os::FileInfoData,
) {
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
    let body = if got < want { body.slice(0, got) } else { body };
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
            w.Header()
                .Set(string("Content-Range"), crate::Sprintf!("bytes */{}", size));
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
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
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

// go: sdk 1.25.5 net/http/fs.go:971-973 FileServer
//
/// Return a handler that serves HTTP requests with the contents of
/// the file system rooted at `root`. Combine with [`StripPrefix`] to
/// mount under a subpath.
pub fn FileServer(root: Arc<dyn FileSystem + Send + Sync>) -> Arc<dyn Handler> {
    return Arc::new(fileHandler { root }) as Arc<dyn Handler>;
}

// go: sdk 1.25.5 net/http/fs.go:984-986 FileServerFS
pub fn FileServerFS(root: Arc<dyn fs::FS + Send + Sync>) -> Arc<dyn Handler> {
    return FileServer(FS(root));
}

impl Handler for fileHandler {
    // go: sdk 1.25.5 net/http/fs.go:988-995 fileHandler.ServeHTTP
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &Request) {
        // Go: upath := r.URL.Path
        //     if !strings.HasPrefix(upath, "/") {
        //         upath = "/" + upath; r.URL.Path = upath }
        //
        // Go mutates r.URL.Path so downstream sees the fixed path;
        // goish's ServeHTTP takes `&Request`, so the corrected path is
        // used locally and the request is not rewritten. serveFile
        // reads r.URL.Path again for its redirect decisions, which is
        // the one place the difference could show — only for a request
        // whose path did not start with '/', which ReadRequest does
        // not produce.
        let mut upath = r.URL.Path.clone();
        if !strings::HasPrefix(upath.clone(), string("/")) {
            upath = string("/") + upath;
        }
        serveFile(
            w,
            crate::nilable_ref::new(r),
            self.root.clone(),
            crate::path::Clean(upath),
            true,
        );
    }
}

// go: sdk 1.25.5 net/http/fs.go:814-826 ServeFile
//
/// Reply to the request with the contents of the named file or
/// directory.
///
/// Go's warning applies here too: if `name` is built from a
/// user-supplied path, the caller must sanitize it — `ServeFile`
/// rejects only a request whose URL path contains "..", not a `name`
/// that does.
pub fn ServeFile<N: Into<string>>(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: &Request,
    name: N,
) {
    let name: string = name.into();
    if containsDotDot(r.URL.Path.clone()) {
        // Go: "Too many programs use r.URL.Path to construct the
        // argument to serveFile. Reject the request under the
        // assumption that happened here and '..' may not be wanted."
        serveError(
            w,
            string("invalid URL path"),
            super::status::StatusBadRequest,
        );
        return;
    }
    let (dir, file) = crate::path::filepath::Split(name);
    serveFile(
        w,
        crate::nilable_ref::new(r),
        Arc::new(NewDir(dir)) as Arc<dyn FileSystem + Send + Sync>,
        file,
        false,
    );
}

// go: sdk 1.25.5 net/http/fs.go:848-859 ServeFileFS
pub fn ServeFileFS<N: Into<string>>(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: &Request,
    fsys: Arc<dyn fs::FS + Send + Sync>,
    name: N,
) {
    if containsDotDot(r.URL.Path.clone()) {
        serveError(
            w,
            string("invalid URL path"),
            super::status::StatusBadRequest,
        );
        return;
    }
    serveFile(w, crate::nilable_ref::new(r), FS(fsys), name.into(), false);
}

// go: sdk 1.25.5 net/http/fs.go:679-762 serveFile
//
// Go's `fs FileSystem` parameter shadows the `fs` package inside the
// body; goish names it `fsys` since `crate::io::fs` is in scope here.
pub fn serveFile(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: nilable![&Request],
    fsys: Arc<dyn FileSystem + Send + Sync>,
    name: string,
    redirect: bool,
) {
    let indexPage = string("/index.html");

    // Go: redirect .../index.html to .../
    // "can't use Redirect() because that would make the path absolute,
    // which would be a problem running under StripPrefix"
    if !r.IsNil() && strings::HasSuffix(r.Must().URL.Path.clone(), indexPage.clone()) {
        localRedirect(w, r, string("./"));
        return;
    }

    let (mut f, err) = fsys.Open(name.clone());
    if err != nil {
        let (msg, code) = toHTTPError(err);
        serveError(w, msg, code);
        return;
    }

    let (mut d, serr) = f.Stat();
    if serr != nil {
        let (msg, code) = toHTTPError(serr);
        let _ = f.Close();
        serveError(w, msg, code);
        return;
    }

    let urlpath = if r.IsNil() {
        string("")
    } else {
        r.Must().URL.Path.clone()
    };

    if redirect {
        // Go: redirect to canonical path — "/" at end of directory url.
        // r.URL.Path always begins with "/".
        if d.IsDir() {
            if len(&urlpath) > 0 && urlpath[len(&urlpath) - 1] != b'/' {
                let _ = f.Close();
                localRedirect(w, r, crate::path::Base(urlpath) + "/");
                return;
            }
        } else if len(&urlpath) > 0 && urlpath[len(&urlpath) - 1] == b'/' {
            let base = crate::path::Base(urlpath.clone());
            if base == "/" || base == "." {
                // Go: "The FileSystem maps a path like '/' or '/./' to
                // a file instead of a directory."
                let _ = f.Close();
                serveError(
                    w,
                    string("http: attempting to traverse a non-directory"),
                    StatusInternalServerError,
                );
                return;
            }
            let _ = f.Close();
            localRedirect(w, r, string("../") + base);
            return;
        }
    }

    if d.IsDir() {
        // Go: redirect if the directory name doesn't end in a slash.
        if urlpath == "" || urlpath[len(&urlpath) - 1] != b'/' {
            let _ = f.Close();
            localRedirect(w, r, crate::path::Base(urlpath) + "/");
            return;
        }

        // Go: use contents of index.html for directory, if present.
        let index = strings::TrimSuffix(name.clone(), string("/")) + indexPage;
        let (ff, ierr) = fsys.Open(index);
        if ierr == nil {
            let (dd, derr) = ff.Stat();
            if derr == nil {
                let _ = f.Close();
                d = dd;
                f = ff;
            } else {
                let _ = ff.Close();
            }
        }
    }

    // Still a directory? (we didn't find an index.html file)
    if d.IsDir() {
        if checkIfModifiedSince(r, d.ModTime()) == condFalse {
            writeNotModified(w);
            let _ = f.Close();
            return;
        }
        setLastModified(w, d.ModTime());
        dirList(w, r, &*f);
        let _ = f.Close();
        return;
    }

    // serveContent will check modification time.
    // Go: sizeFunc := func() (int64, error) { return d.Size(), nil }
    let mut rs = fileReadSeeker { f: f.clone() };
    serveContent(w, r, d.Name(), d.ModTime(), (d.Size(), nil.into()), &mut rs);
    let _ = f.Close();
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
        let mut r = httpRange {
            start: 0,
            length: 0,
        };
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

// go: sdk 1.25.5 net/http/fs.go:1097-1109 rangesMIMESize
//
// Returns the number of bytes it takes to encode the provided ranges
// as a multipart response.
//
// Go calls `mw.CreatePart(header)`, which writes the part HEADERS and
// hands back a Writer the caller may write a body to; here no body is
// written, and the body bytes are accounted separately by
// `encSize += ra.length`. goish's multipart Writer does not hand out a
// borrowed sub-Writer — it exposes `WritePart(header, body)` — so the
// same effect is `WritePart(header, <empty>)`: headers emitted, no
// body. The counting therefore matches.
//
// Go passes `textproto.MIMEHeader` straight to CreatePart because in
// Go it and `http.Header` are the same underlying map type. goish's
// `http::Header` is a struct, so the mimeHeader map is copied into one
// here. Both keys mimeHeader produces are already canonical, so `Add`
// does not rewrite them.
pub fn rangesMIMESize(ranges: &slice<httpRange>, contentType: string, contentSize: int) -> int {
    let mut w = countingWriter(0);
    let mut encSize: int = 0;
    {
        let mut mw = crate::mime::multipart::NewWriter(&mut w);
        let n = len(ranges);
        let mut i: int = 0;
        while i < n {
            let mh = ranges[i].mimeHeader(contentType.clone(), contentSize);
            let mut h = super::header::Header::new();
            for (k, vs) in mh.__iter() {
                let vn = len(vs);
                let mut j: int = 0;
                while j < vn {
                    h.Add(k.clone(), vs[j].clone());
                    j += 1;
                }
            }
            let _ = mw.WritePart(h, slice::new());
            encSize += ranges[i].length;
            i += 1;
        }
        let _ = mw.Close();
    }
    encSize += w.0;
    return encSize;
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
    super::server::__goish_register_Handler_impl::<fileHandler>();
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

// go: sdk 1.25.5 net/http/fs.go:73-73 errInvalidUnsafePath
crate::var! {
    pub errInvalidUnsafePath: error = "http: invalid or unsafe file path";
}

// go: sdk 1.25.5 net/http/fs.go:264-264 errSeeker
crate::var! {
    pub errSeeker: error = "seeker can't seek";
}

// go: sdk 1.25.5 net/http/fs.go:861-871 containsDotDot
//
// Go iterates strings.FieldsFuncSeq, a lazy sequence; goish's
// strings::FieldsFunc materialises the same fields into a slice. The
// early `strings.Contains(v, "..")` guard keeps the allocation off the
// common path exactly as it does in Go.
pub fn containsDotDot(v: string) -> bool {
    if !strings::Contains(v.clone(), string("..")) {
        return false;
    }
    let ents = strings::FieldsFunc(v, isSlashRune);
    let n = len(&ents);
    let mut i: int = 0;
    while i < n {
        if ents[i] == ".." {
            return true;
        }
        i += 1;
    }
    return false;
}

// go: sdk 1.25.5 net/http/fs.go:766-781 toHTTPError
//
// Go's comment: the error is not returned to the client, only the
// mapped message, so a filesystem layout cannot be probed through it.
pub fn toHTTPError(err: error) -> (string, int) {
    if errors::Is(err.clone(), fs::ErrNotExist) {
        return (string("404 page not found"), StatusNotFound);
    }
    if errors::Is(err.clone(), fs::ErrPermission) {
        return (string("403 Forbidden"), StatusForbidden);
    }
    if errors::Is(err.clone(), errInvalidUnsafePath) {
        return (string("404 page not found"), StatusNotFound);
    }
    // Default:
    return (
        string("500 Internal Server Error"),
        StatusInternalServerError,
    );
}

// go: sdk 1.25.5 net/http/fs.go:614-614 unixEpochTime
pub static unixEpochTime: crate::lazy::Lazy<time::Time> =
    crate::lazy::Lazy::new(|| time::Unix(0, 0));

// go: sdk 1.25.5 net/http/fs.go:436-459 scanETag
pub fn scanETag<S: Into<string>>(s: S) -> (string, string) {
    #[allow(unused_mut)]
    let mut s = s.into();
    s = textproto::TrimString(s);
    let mut start = 0;
    if strings::HasPrefix(s.clone(), string("W/")) {
        start = 2;
    }
    if len(&s.slice(start, len(&s))) < 2 || s[start] != 34
    /*'"'*/
    {
        return (string(""), string(""));
    }
    {
        let mut i = start.wrapping_add(1);
        while i < len(&s) {
            let c = s[i];
            if c == 0x21 || c >= 0x23 && c <= 0x7E || c >= 0x80 {
            } else if c == 34
            /*'"'*/
            {
                return (
                    s.slice(0, i.wrapping_add(1)),
                    s.slice(i.wrapping_add(1), len(&s)),
                );
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
        w.Header()
            .Set(string("Last-Modified"), modtime.UTC().Format(TimeFormat));
    }
}

// go: sdk 1.25.5 net/http/fs.go:627-641 writeNotModified
pub fn writeNotModified(w: &(dyn ResponseWriter + Send + Sync + 'static)) {
    let h = w.Header();
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
pub fn checkIfMatch(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: nilable![&Request],
) -> condResult {
    let mut im = r.Must().Header.Get(string("If-Match"));
    if im == "" {
        return condNone;
    }
    loop {
        im = textproto::TrimString(im);
        if len(&im) == 0 {
            break;
        }
        if im[0] == 44
        /*','*/
        {
            im = im.slice(1, len(&im));
            continue;
        }
        if im[0] == 42
        /*'*'*/
        {
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
pub fn checkIfNoneMatch(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: nilable![&Request],
) -> condResult {
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
        if buf[0] == 44
        /*','*/
        {
            buf = buf.slice(1, len(&buf));
            continue;
        }
        if buf[0] == 42
        /*'*'*/
        {
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
pub fn checkIfRange(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: nilable![&Request],
    modtime: time::Time,
) -> condResult {
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
pub fn checkPreconditions(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: nilable![&Request],
    modtime: time::Time,
) -> (bool, string) {
    #[allow(unused_mut)]
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
    let mut rangeHeader = r.Must().Header.Get(string("Range"));
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
// goishlint:ignore GOISH021 httpservecontentkeepheaders — the GODEBUG
// setting is not declared because internal/godebug is not ported (it
// needs internal/bisect and internal/godebugs, both absent). Its only
// effect is to let a user OPT OUT of deleting these four headers on a
// ServeContent error; with the variable unset — Go's default, and the
// only reachable state here — the deletion below is exactly Go's
// behaviour. Declaring a stub whose Value() is always "" would add
// surface that reads as wired-up and is not.
pub fn serveError<S: Into<string>>(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    text: S,
    code: int,
) {
    let text = text.into();
    let h = w.Header();
    for k in [
        string("Cache-Control"),
        string("Content-Encoding"),
        string("Etag"),
        string("Last-Modified"),
    ] {
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
pub fn localRedirect<S: Into<string>>(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: nilable![&Request],
    newPath: S,
) {
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

// go: none — goish-only carry, no Go counterpart.
//
// Go's `http.File` EMBEDS io.Reader and io.Seeker, so a File simply IS
// an io.ReadSeeker and ServeContent takes one directly. goish's
// `File::Read`/`Seek` take `&self` — the file is shared behind an Arc
// — while `io::Reader`/`io::Seeker` take `&mut self`, so the two do
// not unify. This carries one to the other, the same shape as
// `response::AsWriter`.
pub struct fileReadSeeker {
    pub f: Arc<dyn File + Send + Sync>,
}

impl crate::io::Reader for fileReadSeeker {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return self.f.Read(p);
    }
}

impl crate::io::Seeker for fileReadSeeker {
    fn Seek(&mut self, offset: crate::types::int64, whence: int) -> (crate::types::int64, error) {
        return self.f.Seek(offset, whence);
    }
}

// go: sdk 1.25.5 net/http/fs.go:227-258 ServeContent
//
/// Reply to the request using the content in the provided ReadSeeker.
/// The main benefit of ServeContent over io.Copy is that it handles
/// Range requests properly, sets the MIME type, and handles
/// If-Match, If-Unmodified-Since, If-None-Match, If-Modified-Since
/// and If-Range requests.
pub fn ServeContent<C: crate::io::Reader + crate::io::Seeker>(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    req: nilable![&Request],
    name: string,
    modtime: time::Time,
    content: &mut C,
) {
    // Go: sizeFunc := func() (int64, error) { … }
    //
    // Go closes over `content`; a Rust closure capturing `&mut content`
    // would conflict with serveContent's own use of it, so the size is
    // computed here and handed down as an already-resolved value.
    // serveContent's parameter is `Result`-shaped for the same reason
    // Go's is a func: serveFile supplies the size from Stat without
    // seeking.
    let (end, e1) = content.Seek(0, crate::io::SeekEnd);
    if e1 != nil {
        serveContent(w, req, name, modtime, (0, errSeeker.into()), content);
        return;
    }
    let (_, e2) = content.Seek(0, crate::io::SeekStart);
    if e2 != nil {
        serveContent(w, req, name, modtime, (0, errSeeker.into()), content);
        return;
    }
    serveContent(w, req, name, modtime, (end, nil.into()), content);
}

// go: sdk 1.25.5 net/http/fs.go:274-431 serveContent
//
// Go's fifth parameter is `sizeFunc func() (int64, error)`, called
// once after the Content-Type work. goish passes the already-computed
// `(size, err)` pair instead: the closure would have to capture
// `content` mutably while serveContent also reads and seeks it, which
// the borrow checker rejects. Both callers evaluate it at the same
// point in the sequence Go does, so the observable order of a seek
// failure versus a Content-Type sniff is unchanged.
pub fn serveContent<C: crate::io::Reader + crate::io::Seeker>(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    r: nilable![&Request],
    name: string,
    modtime: time::Time,
    sizeAndErr: (crate::types::int64, error),
    content: &mut C,
) {
    setLastModified(w, modtime);
    let (done, rangeReq) = checkPreconditions(w, r, modtime);
    if done {
        return;
    }

    let mut code = super::status::StatusOK;

    // Go: ctypes, haveType := w.Header()["Content-Type"]
    // If Content-Type isn't set, use the file's extension to find it,
    // but if it is set explicitly, do not sniff the type.
    let haveType = w.Header().has(string("Content-Type"));
    let mut ctype: string;
    if !haveType {
        ctype = crate::mime::TypeByExtension(crate::path::Ext(name.clone()));
        if ctype == "" {
            // Read a chunk to decide between utf-8 text and binary.
            let mut buf: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; super::sniff::sniffLen as usize]);
            let (n, _) = crate::io::ReadFull(content, &mut buf);
            ctype = super::sniff::DetectContentType(buf.slice(0, n));
            // Go: rewind to output whole file.
            let (_, err) = content.Seek(0, crate::io::SeekStart);
            if err != nil {
                serveError(w, string("seeker can't seek"), StatusInternalServerError);
                return;
            }
        }
        w.Header().Set(string("Content-Type"), ctype.clone());
    } else {
        let ctypes = w.Header().Values(string("Content-Type"));
        ctype = if len(&ctypes) > 0 {
            ctypes[0].clone()
        } else {
            string("")
        };
    }

    let (size, serr) = sizeAndErr;
    if serr != nil {
        serveError(w, serr.Error(), StatusInternalServerError);
        return;
    }
    if size < 0 {
        // Go: "Should never happen but just to be sure".
        serveError(
            w,
            string("negative content size computed"),
            StatusInternalServerError,
        );
        return;
    }

    // Handle the Content-Range header.
    let mut sendSize = size;
    let (mut ranges, perr) = parseRange(rangeReq, size);
    if perr != nil {
        if errors::Is(perr.clone(), errNoOverlap) && size == 0 {
            // Go: "Some clients add a Range header to all requests to
            // limit the size of the response. If the file is empty,
            // ignore the range header and respond with a 200 rather
            // than a 416."
            ranges = slice::new();
        } else {
            if errors::Is(perr.clone(), errNoOverlap) {
                w.Header()
                    .Set(string("Content-Range"), crate::Sprintf!("bytes */%d", size));
            }
            serveError(
                w,
                perr.Error(),
                super::status::StatusRequestedRangeNotSatisfiable,
            );
            return;
        }
    }

    if sumRangesSize(&ranges) > size {
        // Go: "The total number of bytes in all the ranges is larger
        // than the size of the file by itself, so this is probably an
        // attack, or a dumb client. Ignore the range request."
        ranges = slice::new();
    }

    // Go builds the multi-range body through an io.Pipe and a
    // goroutine feeding multipart parts. goish's multipart Writer has
    // no borrowed per-part Writer — it exposes WritePart(header, body)
    // — so the parts are assembled into a buffer here instead. Same
    // bytes on the wire; the divergence is that a multi-range response
    // is materialised rather than streamed, so a request for many
    // large ranges holds them in memory.
    let mut multipartBody: slice<byte> = slice::new();
    if len(&ranges) == 1 {
        // RFC 7233 §4.1: a server MUST NOT generate a multipart
        // response to a request for a single range.
        let ra = ranges[0];
        let (_, err) = content.Seek(ra.start, crate::io::SeekStart);
        if err != nil {
            serveError(
                w,
                err.Error(),
                super::status::StatusRequestedRangeNotSatisfiable,
            );
            return;
        }
        sendSize = ra.length;
        code = super::status::StatusPartialContent;
        w.Header()
            .Set(string("Content-Range"), ra.contentRange(size));
    } else if len(&ranges) > 1 {
        let mut buf = crate::bytes::Buffer::new();
        let mut mw = crate::mime::multipart::NewWriter(&mut buf);
        w.Header().Set(
            string("Content-Type"),
            string("multipart/byteranges; boundary=") + mw.Boundary(),
        );
        let n = len(&ranges);
        let mut i: int = 0;
        while i < n {
            let ra = ranges[i];
            i += 1;
            let (_, serr) = content.Seek(ra.start, crate::io::SeekStart);
            if serr != nil {
                serveError(w, serr.Error(), StatusInternalServerError);
                return;
            }
            let mut part: slice<byte> = slice::__from_vec(alloc::vec![0u8; ra.length as usize]);
            let (rn, rerr) = crate::io::ReadFull(content, &mut part);
            if rerr != nil && rn == 0 {
                serveError(w, rerr.Error(), StatusInternalServerError);
                return;
            }
            let mh = ra.mimeHeader(ctype.clone(), size);
            let mut h = super::header::Header::new();
            for (k, vs) in mh.__iter() {
                let vn = len(vs);
                let mut j: int = 0;
                while j < vn {
                    h.Add(k.clone(), vs[j].clone());
                    j += 1;
                }
            }
            let _ = mw.WritePart(h, part.slice(0, rn));
        }
        let _ = mw.Close();
        multipartBody = buf.Bytes();
        sendSize = len(&multipartBody);
        code = super::status::StatusPartialContent;
    }

    w.Header().Set(string("Accept-Ranges"), string("bytes"));

    // Go: skip Content-Length if the user set Content-Encoding, because
    // a ResponseWriter that gzips on the fly would make it wrong — but
    // always set it for a range request, where it has to be right.
    if len(&ranges) > 0 || w.Header().Get(string("Content-Encoding")) == "" {
        w.Header().Set(
            string("Content-Length"),
            crate::strconv::FormatInt(sendSize, 10),
        );
    }
    w.WriteHeader(code);

    if r.IsNil() || r.Must().Method != "HEAD" {
        if len(&ranges) > 1 {
            let _ = w.Write(multipartBody);
        } else {
            let mut aw = super::responsewriter::AsWriter(w);
            let _ = crate::io::CopyN(&mut aw, content, sendSize);
        }
    }
}

// go: sdk 1.25.5 net/http/fs.go:139-178 dirList
//
// Go prefers ReadDir over Readdir "because the former doesn't require
// calling Stat on every entry of a directory on Unix", and falls back
// when the file is not an fs.ReadDirFile. goish keeps both paths: the
// assertion is `cast!(f, fs::ReadDirFile)`, which succeeds for a MapFS
// directory and misses for the os-backed `osFile`, so the fallback is
// the live path for http::Dir.
//
// Go logs the read error through `logf(r, …)`, which routes to the
// serving Server's ErrorLog. goish's logf hangs off Server and dirList
// has no handle to one here, so the error reaches the client as the
// same 500 and is not logged. Threading it needs the Server on the
// request, which goish does not carry yet.
pub fn dirList(
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    _r: nilable![&Request],
    f: &(dyn File + Send + Sync + 'static),
) {
    // Go: if d, ok := f.(fs.ReadDirFile); ok { … } else { … }
    let mut names: alloc::vec::Vec<(string, bool)> = alloc::vec::Vec::new();
    let (d, ok) = crate::cast!(f, fs::ReadDirFile);
    let err = if ok {
        let (list, e) = d.ReadDir(-1);
        let n = len(&list);
        let mut i: int = 0;
        while i < n {
            names.push((list[i].Name(), list[i].IsDir()));
            i += 1;
        }
        e
    } else {
        let (list, e) = f.Readdir(-1);
        let n = len(&list);
        let mut i: int = 0;
        while i < n {
            names.push((list[i].Name(), list[i].IsDir()));
            i += 1;
        }
        e
    };

    if err != nil {
        // Go: logf(r, "http: error reading directory: %v", err)
        super::server::Error(
            w,
            string("Error reading directory"),
            StatusInternalServerError,
        );
        return;
    }

    // Go: sort.Slice(dirs, func(i, j int) bool {
    //         return dirs.name(i) < dirs.name(j) })
    names.sort_by(|a, b| crate::strings::Compare(a.0.clone(), b.0.clone()).cmp(&0));

    w.Header()
        .Set(string("Content-Type"), string("text/html; charset=utf-8"));
    let mut buf = strings::Builder::new();
    let _ = buf.WriteString("<!doctype html>\n");
    let _ = buf.WriteString("<meta name=\"viewport\" content=\"width=device-width\">\n");
    let _ = buf.WriteString("<pre>\n");
    for (nm, isdir) in names.iter() {
        let mut name = nm.clone();
        if *isdir {
            name = name + "/";
        }
        // Go: name may contain '?' or '#', which must be escaped to
        // remain part of the URL path and not start a query string or
        // fragment — so the href goes through url.URL{Path: name},
        // NOT through raw interpolation.
        let mut u = super::url::URL::default();
        u.Path = name.clone();
        let _ = buf.WriteString("<a href=\"");
        let _ = buf.WriteString(u.String());
        let _ = buf.WriteString("\">");
        let _ = buf.WriteString(html_replace(name));
        let _ = buf.WriteString("</a>\n");
    }
    let _ = buf.WriteString("</pre>\n");
    let _ = w.Write(crate::convert::bytes(buf.String()));
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

// go: none — goish-only adapter, no Go counterpart.
//
// Go's `Dir.Open` returns `*os.File`, which satisfies `http.File`
// directly: its method set already has Close/Read/Seek/Readdir/Stat.
// goish's `os::File` is two methods short of that shape —
// `Close` takes `&mut self` because it owns the fd, and there is no
// `Readdir` (only `Readdirnames`) — and `http::File` hands out
// `&self` through an `Arc`. This carries one to the other, the same
// way `response::AsWriter` carries a ResponseWriter to an io::Writer.
//
// The lock is what supplies the `&mut` for Close; every other method
// on `os::File` already takes `&self`, so it is uncontended in the
// serving path.
pub struct osFile {
    f: crate::runtime::spin::SpinLock<os::File>,
    name: string,
}

impl File for osFile {
    // go: none — forwards to os::File::Close, which needs the &mut the
    // lock supplies.
    fn Close(&self) -> error {
        return self.f.lock().Close();
    }

    // go: none — forwards to os::File::Read.
    fn Read(&self, p: &mut slice<byte>) -> (int, error) {
        return self.f.lock().Read(p);
    }

    // go: none — forwards to os::File::Seek.
    fn Seek(&self, offset: crate::types::int64, whence: int) -> (crate::types::int64, error) {
        return self.f.lock().Seek(offset, whence);
    }

    // go: none — forwards to os::File::Stat, boxing the concrete
    // FileInfoData into the interface http::File returns.
    fn Stat(&self) -> (Arc<dyn fs::FileInfo + Send + Sync>, error) {
        let (fi, err) = self.f.lock().Stat();
        if err != nil {
            return (crate::nil.into(), err);
        }
        return (
            Arc::new(fi) as Arc<dyn fs::FileInfo + Send + Sync>,
            nil.into(),
        );
    }

    // go: none — Go's os.File.Readdir reads the directory stream and
    // honours `count` by consuming that many entries, so successive
    // calls advance. goish's os::ReadDir reads the WHOLE directory,
    // so this returns a prefix and does not advance: a caller that
    // pages with count > 0 sees the same first `count` entries each
    // time. dirList and Go's own FileServer path both call
    // Readdir(-1), which is exact.
    fn Readdir(&self, count: int) -> (slice<Arc<dyn fs::FileInfo + Send + Sync>>, error) {
        let (entries, err) = os::ReadDir(self.name.clone());
        if err != nil {
            return (slice::new(), err);
        }
        let mut out: alloc::vec::Vec<Arc<dyn fs::FileInfo + Send + Sync>> = alloc::vec::Vec::new();
        let n = len(&entries);
        let mut i: int = 0;
        while i < n {
            if count > 0 && crate::int(out.len()) >= count {
                break;
            }
            let (info, ierr) = entries[i].Info();
            i += 1;
            if ierr != nil {
                // Go's (*os.File).Readdir skips an entry whose lstat
                // fails rather than aborting the listing.
                continue;
            }
            out.push(info);
        }
        return (slice::__from_vec(out), nil.into());
    }
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
        return (
            Arc::new(ioFile { file }) as Arc<dyn File + Send + Sync>,
            nil.into(),
        );
    }
}

impl ioFile {
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
    // go: sdk 1.25.5 net/http/fs.go:902-902 ioFile.Close
    fn Close(&self) -> error {
        return self.file.Close();
    }

    // go: sdk 1.25.5 net/http/fs.go:903-903 ioFile.Read
    fn Read(&self, b: &mut slice<byte>) -> (int, error) {
        return self.file.Read(b);
    }

    // go: sdk 1.25.5 net/http/fs.go:909-915 ioFile.Seek
    //
    // Go asserts `f.file.(io.Seeker)`. goish's io::Seeker takes
    // `&mut self`, which the `Arc<dyn fs::File>` held here cannot
    // give, so the assertion targets fs::SeekableFile — the same
    // capability with the `&self` receiver this module already uses
    // for Read. A file whose type does not implement it takes Go's
    // miss branch and reports errMissingSeek, exactly as a Go file
    // lacking Seek would.
    fn Seek(&self, offset: crate::types::int64, whence: int) -> (crate::types::int64, error) {
        let (s, ok) = crate::cast!(&*self.file, fs::SeekableFile);
        if !ok {
            return (0, errMissingSeek.into());
        }
        return s.Seek(offset, whence);
    }

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
//
// Go's http.File embeds io.Closer, io.Reader and io.Seeker alongside
// Readdir and Stat. goish's #[interface] macro does not model embedded
// interfaces, so the three inherited methods are RE-DECLARED here, the
// same way io/fs.rs spells out ReadDirFile. Without them `File` was a
// two-method shell and serveContent — which needs an io.ReadSeeker —
// had nothing to stand on.
//
// The receivers are `&self`, matching io/fs.rs's `File::Read(&self)`:
// a file owns its cursor behind interior mutability, and a `&mut`
// receiver cannot be reached through the `Arc<dyn File>` that Open
// returns.
#[crate::interface]
pub trait File {
    fn Close(&self) -> error;
    fn Read(&self, p: &mut slice<byte>) -> (int, error);
    fn Seek(&self, offset: crate::types::int64, whence: int) -> (crate::types::int64, error);
    fn Readdir(
        &self,
        count: int,
    ) -> (
        slice<alloc::sync::Arc<dyn fs::FileInfo + Send + Sync>>,
        error,
    );
    fn Stat(&self) -> (alloc::sync::Arc<dyn fs::FileInfo + Send + Sync>, error);
}
