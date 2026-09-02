// mime/multipart/reader — Reader for parsing multipart messages.
//
// Slim port of Go 1.25 src/mime/multipart/multipart.go. Drops the
// streaming bufio.Reader.Peek scanner in favor of a single-pass scan
// over a `slice<byte>` provided up-front. This is sufficient for HTTP
// servers that already buffer the request body (goish's Request.Body
// is `slice<byte>`).
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
    /// `(*Reader).NextPart()` (multipart.go:343) — return the next
    /// part. Returns `io::EOF` after the last part.
    pub fn NextPart(&mut self) -> (Part, error) {
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
                match find_subseq(&body_bytes[p..], &crlf) {
                    Some(off) => p += off + crlf.len(),
                    None => match find_subseq(&body_bytes[p..], &lf) {
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
            header.Add(key, value);
        }

        // 5. Body of this part runs until the next delimiter, which is
        //    preceded by the line ending this body is using.
        let nl_dash_boundary = make_nl_dash_boundary(&self.boundary, self.lf_only);
        match find_subseq(&body_bytes[p..], &nl_dash_boundary) {
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
                if crate::strings::EqualFold(
                    header.Get(cte.clone()),
                    string::from("quoted-printable"),
                ) {
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
