// mime/multipart/reader — Reader for parsing multipart messages.

//
// Slim port of Go 1.25 src/mime/multipart/multipart.go. Drops the
// streaming bufio.Reader.Peek scanner in favor of a single-pass scan
// over a `slice<byte>` provided up-front. This is sufficient for HTTP
// servers that already buffer the request body (goish's Request.Body
// is `slice<byte>`).
//
// ─── Go's streaming half, and where it went ─────────────────────────
//
// Thirteen of Go's declarations exist to read a part off a
// bufio.Reader without ever holding it whole: the scanner, its
// one-byte lookahead, the readers that wrap it. An eager reader needs
// none of them. They are waived below — but only AFTER the behaviour
// each one carries was run against Go, because "replaced by design"
// is what a defect hides behind. Two of these thirteen turned out to
// be defects: the boundary scanner truncated a part at data that
// merely started like the boundary, and the header parser rejected
// folded lines. Both are fixed, and the waivers cite the smokes that
// would catch them coming back.
//
// go: waived matchAfterPrefix — `find_boundary` below, the rule that
// a boundary match is only real if the next byte is space, tab, CR,
// LF or `-` (examples/multipart_falseboundary_ref_smoke.rs).
// go: waived scanUntilBoundary — the same search, run over bytes
// already in hand instead of a streaming window
// (examples/multipart_boundary_ref_smoke.rs).
// go: waived Reader.isBoundaryDelimiterLine — the delimiter-line
// test, including the transport padding RFC 2046 5.1 allows and the
// LF-only mode Go switches into; same smoke, rows lwsp-* and lf-only.
// go: waived Reader.isFinalBoundary — the closing `--` test; same
// smoke, rows lwsp-final and lwsp-both.
// go: waived skipLWSPChar — the padding skip both of those use.
// go: waived readMIMEHeader — the part's header block, CONTINUED
// lines and all (examples/multipart_headers_ref_smoke.rs).
// go: waived Part.populateHeaders — the same block plus its limits;
// the 10000-header count is enforced inline here
// (examples/multipart_maxheaders_smoke.rs), and maxMIMEHeaderSize is
// not ported for the reason given at the header loop.
// go: waived maxMIMEHeaders — that count, as a literal rather than a
// godebug-tunable.
// go: waived Part.parseContentDisposition — FormName and FileName
// parse the header directly (examples/multipart_disposition_ref_smoke.rs).
// go: waived newPart — the constructor; next_part builds the Part
// inline because there is no reader to attach to it.
// go: waived partReader.Read — Go's undecoded reader over a part;
// here NextRawPart returns a Part whose bytes ARE undecoded and whose
// Read walks them (examples/multipart_rawpart_ref_smoke.rs).
// go: waived stickyErrorReader.Read — makes a streaming read error
// repeat; an eager reader has no stream left to fail.
// go: waived sectionReadCloser.Close — closes a section of the
// spill-to-disk temp file, which formdata.rs documents as absent
// wholesale (the budget it protected IS kept and tested).
//
// Design notes:
//   * Boundary handling matches RFC 2046: each part is preceded by
//     `\r\n--<boundary>` (or `--<boundary>` at the very start), and the
//     terminator is `\r\n--<boundary>--`.
//   * The Reader holds the body and a cursor; NextPart advances past
//     the next boundary, parses headers, and returns the part body
//     (the bytes between the headers' trailing `\r\n\r\n` and the
//     start of the next boundary).
//   * Returns io::EOF after the closing boundary has been consumed.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::convert::bytes;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io;
use crate::net::http::Header;
use crate::string;
use crate::strings;
use crate::types::{byte, int};

/// `multipart.Part` (multipart.go:52). Slim version — Header + Body
/// only; no streaming Read off the underlying connection. The body is
/// already materialized as a `slice<byte>`.
#[derive(Clone)]
pub struct Part {
    pub Header: Header,
    pub Body: slice<byte>,
    /// Read cursor. Go's Part IS an io.Reader over the part's bytes
    /// (multipart.go:196), and callers copy it straight into a file
    /// with io.Copy. `Body` stays public because this port hands the
    /// whole part over at once; the cursor is what makes the Go
    /// spelling work too.
    off: usize,
}

impl Part {
    /// `(*Part).FormName()` (multipart.go:74). Returns the `name=`
    /// param of the Content-Disposition header (when type is
    /// "form-data"), else "".
    pub fn FormName(&self) -> string {
        let cd = self.Header.Get(string("Content-Disposition"));
        if cd.Len() == 0 {
            return string::new();
        }
        let (mt, params, err) = crate::mime::ParseMediaType(cd);
        if !err.IsNil() || mt != "form-data" {
            return string::new();
        }
        let (v, _) = params.Get(string("name"));
        v
    }

    /// `(*Part).FileName()` (multipart.go:88). Returns the `filename=`
    /// param of the Content-Disposition header, else "".
    pub fn FileName(&self) -> string {
        let cd = self.Header.Get(string("Content-Disposition"));
        if cd.Len() == 0 {
            return string::new();
        }
        let (_, params, err) = crate::mime::ParseMediaType(cd);
        if !err.IsNil() {
            return string::new();
        }
        let (v, _) = params.Get(string("filename"));
        // Go: if filename == "" { return "" }
        if v.Len() == 0 {
            return string::new();
        }
        // Go: "RFC 7578, Section 4.2 requires that if a filename is
        // provided, the directory path information must not be used."
        //     return filepath.Base(filename)
        //
        // This was returning the parameter verbatim, so a part sent
        // with filename="../../etc/passwd" reported exactly that, and
        // any handler doing the obvious `os.Create(part.FileName())`
        // wrote outside its upload directory. The base-naming is not a
        // tidy-up, it is the defence RFC 7578 asks for, and it is why
        // Go's answer here is "passwd".
        return crate::path::filepath::Base(v);
    }
}

/// `multipart.Reader` (multipart.go:301). Holds the message body and a
/// cursor; `NextPart()` advances through the body part-by-part.
pub struct Reader {
    body: slice<byte>,
    boundary: string,
    pos: int,
    finished: bool,
    /// Go's `Reader.nl`: "\r\n" normally, "\n" once the FIRST
    /// delimiter line has been seen to end with a bare LF. Go
    /// (isBoundaryDelimiterLine): "On the first part, see our lines are
    /// ending in \n instead of \r\n and switch into that mode if so.
    /// This is a violation of the spec, but occurs in practice." goish
    /// was CRLF-only, so a body from any client that sends bare LF —
    /// and real ones do — failed to parse at all.
    lf_only: bool,
}

/// `multipart.NewReader(r, boundary)` (multipart.go:457). Slim port:
/// `r` is provided as the already-buffered body bytes rather than an
/// io.Reader, since goish HTTP requests carry their body as a
/// slice<byte>.
pub fn NewReader<B: Into<string>>(body: slice<byte>, boundary: B) -> Reader {
    let boundary: string = boundary.into();
    Reader {
        body,
        boundary,
        pos: 0,
        finished: false,
        lf_only: false,
    }
}

impl Reader {
    /// `(*Reader).NextPart()`, multipart.go line 371 — return the next
    /// part. Returns `io::EOF` after the last part. Go: "As a special
    /// case, if the Content-Transfer-Encoding header has a value of
    /// quoted-printable, that header is instead hidden and the body is
    /// transparently decoded during Read calls."
    pub fn NextPart(&mut self) -> (Part, error) {
        return self.next_part(false);
    }

    // goishlint:ignore GOISH014 — this file is an UNANCHORED slim
    // port and its other declarations carry no anchors either;
    // anchoring these alone would make it CLAIM multipart.go, and
    // that is all-or-nothing (all sixteen unported declarations,
    // plus a rename). Go origin named in prose below.
    /// multipart.go line 380. Go: "Unlike NextPart, it does not have special handling for
    /// Content-Transfer-Encoding: quoted-printable." A caller that
    /// wants the bytes as sent — a proxy relaying a part, a signature
    /// check over the encoded form — needs this one.
    pub fn NextRawPart(&mut self) -> (Part, error) {
        return self.next_part(true);
    }

    // goishlint:ignore GOISH014 — this file is an UNANCHORED slim
    // port and its other declarations carry no anchors either;
    // anchoring these alone would make it CLAIM multipart.go, and
    // that is all-or-nothing (all sixteen unported declarations,
    // plus a rename). Go origin named in prose below.
    /// The shared body of the two above (multipart.go line 384); Go
    /// splits them the same way,
    /// on a `rawPart bool`.
    fn next_part(&mut self, raw_part: bool) -> (Part, error) {
        if self.finished {
            return (empty_part(), io::EOF.into());
        }
        let body_bytes = body_as_slice(&self.body);
        let dash_boundary_bytes: Vec<u8> = make_dash_boundary(&self.boundary);
        let close_marker: &[u8] = b"--";

        let n = body_bytes.len();
        let mut p = self.pos as usize;

        // 1. Locate the start of this part.
        if p == 0 {
            // First part: the body should start with `--<boundary>` or
            // skip leading preamble until we find `\r\n--<boundary>`.
            if has_prefix(&body_bytes[p..], &dash_boundary_bytes) {
                p += dash_boundary_bytes.len();
            } else {
                // The preamble is skipped by looking for the delimiter
                // on a line of its own. Try CRLF first, then bare LF,
                // because the mode is only decided once the delimiter
                // has been found.
                let crlf = make_nl_dash_boundary(&self.boundary, false);
                let lf = make_nl_dash_boundary(&self.boundary, true);
                // Same matchAfterPrefix rule as the part scan: a
                // preamble carrying a line that merely starts like the
                // boundary must not open a part.
                match find_boundary(&body_bytes[p..], &crlf) {
                    Some(off) => p += off + crlf.len(),
                    None => match find_boundary(&body_bytes[p..], &lf) {
                        Some(off) => {
                            self.lf_only = true;
                            p += off + lf.len();
                        }
                        None => {
                            // Go: `fmt.Errorf("multipart: NextPart: %w", err)`
                            // — a body that never contains a delimiter
                            // is MALFORMED, not merely finished. goish
                            // returned a bare io.EOF, so the ordinary
                            // `if err == io.EOF { break }` loop read
                            // rubbish as "zero parts, fine". The wrap
                            // keeps errors.Is(err, io.EOF) true, as
                            // Go's does.
                            self.finished = true;
                            return (
                                empty_part(),
                                crate::fmt::Errorf!("multipart: NextPart: %w", io::EOF.into()),
                            );
                        }
                    },
                }
            }
            // Go (isBoundaryDelimiterLine): after the delimiter and any
            // linear whitespace, a lone "\n" rather than "\r\n" puts
            // the whole reader into LF mode for the rest of the body.
            {
                let mut q = p;
                while q < n && (body_bytes[q] == b' ' || body_bytes[q] == b'\t') {
                    q += 1;
                }
                if q < n && body_bytes[q] == b'\n' {
                    self.lf_only = true;
                }
            }
        } else {
            // Subsequent parts: the previous NextPart left us pointed
            // *just after* the closing `\r\n--<boundary>` of the
            // previous part.
            // (Done implicitly below.)
        }

        // 2. Check for closing marker `--`.
        if p + close_marker.len() <= n && &body_bytes[p..p + close_marker.len()] == close_marker {
            self.finished = true;
            return (empty_part(), io::EOF.into());
        }

        // 3. Skip transport-padding + CRLF after the boundary line.
        while p < n && (body_bytes[p] == b' ' || body_bytes[p] == b'\t') {
            p += 1;
        }
        let nl_len = if self.lf_only { 1usize } else { 2usize };
        if self.lf_only {
            if p < n && body_bytes[p] == b'\n' {
                p += 1;
            }
        } else if p + 1 < n && body_bytes[p] == b'\r' && body_bytes[p + 1] == b'\n' {
            p += 2;
        }

        // 4. Parse headers until blank line.
        let mut header = Header::new();
        // Go bounds a part's headers at maxMIMEHeaders (multipart.go:355,
        // default 10000) and answers ErrMessageTooLarge past it. goish's
        // loop had no bound at all, so one part could carry as many
        // headers as the body had room for — and each becomes a Header
        // map entry, which is a large multiple of the four bytes
        // "a:b\r\n" costs on the wire. Combined with maxParts, Go's
        // ceiling is 1000 parts x 10000 headers; goish had 1000 x
        // unbounded.
        //
        // Go's GODEBUG override (multipartmaxheaders) has nothing to
        // read here: goish has no internal/godebug, so the default is
        // the value. Recorded in ROADMAP section 3 with the other
        // GODEBUG branches.
        //
        // Counted down exactly as Go counts: 10000 headers are allowed
        // and the 10001st fails, which is what the pinned 9998/10001
        // rows in multipart_maxheaders_smoke straddle.
        //
        // Go's OTHER bound, maxMIMEHeaderSize (multipart.go:348,
        // 10 << 20), is not ported, and the reason it is not a hole is
        // worth writing down rather than rediscovering. Go streams the
        // body through a bufio.Reader, so an unbounded header block
        // would be read incrementally and could exceed any buffer;
        // goish's Reader owns the whole body as a `slice<byte>` before
        // parsing starts, so a header block cannot be larger than the
        // body already in memory. That body is capped at 16 MiB by
        // __read_request_server (ROADMAP section 0 A).
        //
        // So the exposure is a header block of up to the body cap where
        // Go stops at 10 MiB — a bounded difference, not an unbounded
        // one. If section 0 A is ever decided in favour of STREAMING,
        // this stops being true and maxMIMEHeaderSize has to be ported
        // with it.
        let mut maxHeaders: i64 = 10000;
        // The header a continuation line would extend.
        let mut last_key = string::new();
        loop {
            // Find next CRLF.
            let line_start = p;
            let mut line_end = p;
            if self.lf_only {
                while line_end < n && body_bytes[line_end] != b'\n' {
                    line_end += 1;
                }
            } else {
                while line_end + 1 < n
                    && !(body_bytes[line_end] == b'\r' && body_bytes[line_end + 1] == b'\n')
                {
                    line_end += 1;
                }
            }
            if line_end >= n {
                self.finished = true;
                return (
                    empty_part(),
                    errors::New(string("multipart: unexpected EOF in headers")),
                );
            }
            let line = &body_bytes[line_start..line_end];
            p = line_end + nl_len; // consume the line ending
            if line.is_empty() {
                break;
            }
            // A line beginning with space or tab CONTINUES the header
            // before it — RFC 5322's obsolete folding, which Go still
            // accepts because textproto.ReadMIMEHeader reads a
            // CONTINUED line, not a CRLF-delimited one. Splitting on
            // CRLF alone made every folded header "malformed" and
            // failed the whole part, not just that header.
            //
            // Go's join, measured: one space, then the continuation
            // with its own leading whitespace removed, and the final
            // value left-trimmed. That is why `X: a\r\n     b` is
            // "a b" (the run collapses), `X: a\r\n ` keeps its
            // trailing space, and `X: \r\n b` is "b" and not " b".
            if line[0] == b' ' || line[0] == b'\t' {
                let mut c_start = 0usize;
                while c_start < line.len() && (line[c_start] == b' ' || line[c_start] == b'\t') {
                    c_start += 1;
                }
                let cont = string::from_bytes(&line[c_start..]);
                if last_key.Len() != 0 {
                    let prev = header.Get(last_key.clone());
                    let joined = prev + string(" ") + cont;
                    let trimmed = crate::strings::TrimLeft(joined, string(" \t"));
                    header.Set(last_key.clone(), trimmed);
                    continue;
                }
                // A continuation with nothing to continue is malformed,
                // exactly as a line with no colon is.
                return (
                    empty_part(),
                    errors::New(string("multipart: malformed header")),
                );
            }
            // Parse "Key: Value".
            let colon = match line.iter().position(|b| *b == b':') {
                Some(i) => i,
                None => {
                    return (
                        empty_part(),
                        errors::New(string("multipart: malformed header")),
                    );
                }
            };
            let key = string::from_bytes(&line[..colon]);
            let mut v_start = colon + 1;
            while v_start < line.len() && (line[v_start] == b' ' || line[v_start] == b'\t') {
                v_start += 1;
            }
            let value = string::from_bytes(&line[v_start..]);
            maxHeaders -= 1;
            if maxHeaders < 0 {
                return (empty_part(), super::formdata::ErrMessageTooLarge.into());
            }
            last_key = key.clone();
            header.Add(key, value);
        }

        // 5. Body of this part runs until the next delimiter, which is
        //    preceded by the line ending this body is using.
        let nl_dash_boundary = make_nl_dash_boundary(&self.boundary, self.lf_only);
        match find_boundary(&body_bytes[p..], &nl_dash_boundary) {
            Some(off) => {
                let body_end = p + off;
                let mut part_body = self.body.slice(p as int, body_end as int);
                self.pos = (body_end + nl_dash_boundary.len()) as int;
                // Go (multipart.go:159-165): NextPart decodes a
                // quoted-printable part TRANSPARENTLY and removes the
                // header, so a caller reading the body never sees the
                // encoding. Go matches the value case-insensitively.
                // goish returned the raw "=3D" text and left the header
                // in place, so every quoted-printable upload arrived
                // still encoded.
                let cte = string::from("Content-Transfer-Encoding");
                if !raw_part
                    && crate::strings::EqualFold(
                        header.Get(cte.clone()),
                        string::from("quoted-printable"),
                    )
                {
                    header.Del(cte);
                    let mut src = crate::bytes::NewReader(part_body.clone());
                    let mut qr = crate::mime::quotedprintable::NewReader(&mut src);
                    let (decoded, qerr) = crate::io::ReadAll(&mut qr);
                    if !qerr.IsNil() {
                        return (empty_part(), qerr);
                    }
                    part_body = decoded;
                }
                (
                    Part {
                        Header: header,
                        Body: part_body,
                        off: 0,
                    },
                    errors::nil,
                )
            }
            None => {
                self.finished = true;
                (
                    empty_part(),
                    errors::New(string("multipart: unexpected EOF in part body")),
                )
            }
        }
    }
}

fn empty_part() -> Part {
    Part {
        Header: Header::new(),
        Body: slice::<byte>::__from_vec(Vec::new()),
        off: 0,
    }
}

// goishlint:ignore GOISH014 — this file is an UNANCHORED slim
// port and its other declarations carry no anchors either;
// anchoring these alone would make it CLAIM multipart.go, and
// that is all-or-nothing (all sixteen unported declarations,
// plus a rename). Go origin named in prose below.
/// multipart.go line 184. Go: "Read reads the body of a part, after its headers and before
/// the next part (if any) begins." Go's streams off the wire; this one
/// walks the bytes the Reader already holds, which is the same
/// contract to a caller: bytes, then io.EOF at the part's end.
impl io::Reader for Part {
    // goishlint:ignore GOISH014 — see the note above this impl: the
    // file is an unanchored slim port, and anchoring one declaration
    // would make it claim multipart.go all-or-nothing.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let total = self.Body.Len() as usize;
        if self.off >= total {
            return (0, io::EOF.into());
        }
        let want = core::cmp::min(p.Len() as usize, total - self.off);
        for i in 0..want {
            p[i] = self.Body[crate::int(self.off + i)];
        }
        self.off += want;
        return (crate::int(want), errors::nil);
    }
}

fn make_dash_boundary(boundary: &string) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + boundary.Len() as usize);
    v.extend_from_slice(b"--");
    let bs = bytes(boundary.clone());
    for i in 0..bs.Len() {
        v.push(bs[i]);
    }
    v
}

fn make_nl_dash_boundary(boundary: &string, lf_only: bool) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + boundary.Len() as usize);
    if lf_only {
        v.extend_from_slice(b"\n--");
    } else {
        v.extend_from_slice(b"\r\n--");
    }
    let bs = bytes(boundary.clone());
    for i in 0..bs.Len() {
        v.push(bs[i]);
    }
    v
}

fn body_as_slice(body: &slice<byte>) -> Vec<u8> {
    let mut v = Vec::with_capacity(body.Len() as usize);
    for i in 0..body.Len() {
        v.push(body[i]);
    }
    v
}

fn has_prefix(hay: &[u8], needle: &[u8]) -> bool {
    if hay.len() < needle.len() {
        return false;
    }
    &hay[..needle.len()] == needle
}

// goishlint:ignore GOISH014 — this file is an UNANCHORED slim port;
// anchoring one declaration would make it claim multipart.go
// all-or-nothing. Go origin named in prose below.
/// Go's `matchAfterPrefix` (multipart.go line 295) as a search: find
/// the next occurrence of `needle` that is REALLY a boundary, not data
/// that merely starts like one.
///
/// Go's rule is the byte after the boundary. Space, tab, CR or LF end
/// a delimiter line; `--` makes it the final boundary; anything else
/// means this is ordinary content and the part continues. Without the
/// check, a part carrying a line like `--Bxyz` was truncated there and
/// the parse then failed on the text after it as a malformed header —
/// silent data loss followed by a confusing error.
fn find_boundary(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let mut from = 0usize;
    while from <= hay.len() {
        let rel = match find_subseq(&hay[from..], needle) {
            Some(i) => i,
            None => return None,
        };
        let at = from + rel;
        let after = at + needle.len();
        if after >= hay.len() {
            // Go: `len(buf) == len(prefix)` with a read error — the
            // boundary ends the input.
            return Some(at);
        }
        let c = hay[after];
        if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' {
            return Some(at);
        }
        if c == b'-' && after + 1 < hay.len() && hay[after + 1] == b'-' {
            return Some(at);
        }
        // Not a boundary: step past this candidate and keep looking.
        from = at + 1;
    }
    return None;
}

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

// Suppress unused imports when feature gates trim the surface area.
#[allow(dead_code)]
fn __force_use(_: int, _: &strings::Builder) {}
