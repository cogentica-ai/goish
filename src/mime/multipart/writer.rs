// mime/multipart/writer — Writer for assembling multipart messages.
//
// Slim line-by-line port of Go 1.25 src/mime/multipart/writer.go.
// Drops:
//   - The lastpart "must close before next CreatePart" rewind logic
//     (handled inline; we don't allocate Part trait objects).
//   - The textproto.MIMEHeader generic interface — goish uses
//     `http::Header` (same key-canonicalization semantics).

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::convert::bytes;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::Writer as IoWriter;
use crate::net::http::Header;
use crate::string;
use crate::strings;
use crate::types::{byte, int};

/// `multipart.Writer` (writer.go:20). Generates multipart messages by
/// emitting boundary-delimited parts to an underlying writer.
pub struct Writer<W: IoWriter> {
    w: W,
    boundary: string,
    has_lastpart: bool,
}

/// `multipart.NewWriter(w)` (writer.go:28). Construct a Writer with a
/// random boundary.
pub fn NewWriter<W: IoWriter>(w: W) -> Writer<W> {
    Writer {
        w,
        boundary: random_boundary(),
        has_lastpart: false,
    }
}

impl<W: IoWriter> Writer<W> {
    /// `(*Writer).Boundary()` (writer.go:36) — current boundary string.
    pub fn Boundary(&self) -> string {
        self.boundary.clone()
    }

    /// `(*Writer).SetBoundary(s)` (writer.go:46) — override the random
    /// default with an explicit boundary. Must be called before any
    /// parts are written.
    pub fn SetBoundary<B: Into<string>>(&mut self, boundary: B) -> error {
        let boundary: string = boundary.into();
        if self.has_lastpart {
            return errors::New(string("mime: SetBoundary called after write"));
        }
        // Go: rfc2046#section-5.1.1 — 1..=70 bytes.
        if boundary.Len() < 1 || boundary.Len() > 70 {
            return errors::New(string("mime: invalid boundary length"));
        }
        let bs = boundary.as_bytes();
        let end = bs.len() - 1;
        for (i, b) in bs.iter().enumerate() {
            let c = *b;
            if (b'A' <= c && c <= b'Z') || (b'a' <= c && c <= b'z') || (b'0' <= c && c <= b'9') {
                continue;
            }
            match c {
                b'\'' | b'(' | b')' | b'+' | b'_' | b',' | b'-' | b'.' | b'/' | b':' | b'='
                | b'?' => continue,
                b' ' => {
                    if i != end {
                        continue;
                    }
                }
                _ => {}
            }
            return errors::New(string("mime: invalid boundary character"));
        }
        self.boundary = boundary;
        errors::nil
    }

    /// `(*Writer).FormDataContentType()` (writer.go:75). Returns the
    /// `multipart/form-data; boundary=...` Content-Type, quoting the
    /// boundary when it contains tspecials.
    pub fn FormDataContentType(&self) -> string {
        let b = self.boundary.clone();
        // Go: if strings.ContainsAny(b, `()<>@,;:\"/[]?= `) { b = `"`+b+`"` }
        let needs_quote = strings::ContainsAny(b.clone(), string("()<>@,;:\\\"/[]?= "));
        let mut out = strings::Builder::new();
        let _ = out.WriteString("multipart/form-data; boundary=");
        if needs_quote {
            let _ = out.WriteByte(b'"');
            let _ = out.WriteString(b);
            let _ = out.WriteByte(b'"');
        } else {
            let _ = out.WriteString(b);
        }
        out.String()
    }

    /// Internal: emit the boundary line + sorted headers + blank line.
    /// Returns nil on success or the underlying Writer's error.
    fn emit_part_head(&mut self, header: &Header) -> error {
        let mut b = strings::Builder::new();
        if self.has_lastpart {
            let _ = b.WriteString("\r\n--");
        } else {
            let _ = b.WriteString("--");
        }
        let _ = b.WriteString(self.boundary.clone());
        let _ = b.WriteString("\r\n");

        // Go: for _, k := range slices.Sorted(maps.Keys(header))
        let inner = header.__inner();
        let mut keys: Vec<string> = inner.__iter().map(|(k, _)| k.clone()).collect();
        keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for k in keys.iter() {
            let (vs, _) = inner.Get(k.clone());
            for i in 0..vs.Len() {
                let _ = b.WriteString(k.clone());
                let _ = b.WriteString(": ");
                let _ = b.WriteString(vs[i].clone());
                let _ = b.WriteString("\r\n");
            }
        }
        let _ = b.WriteString("\r\n");

        let payload = bytes(b.String());
        let (_, err) = self.w.Write(payload);
        if err.IsNil() {
            self.has_lastpart = true;
        }
        err
    }

    /// `(*Writer).CreatePart(header)` slim variant (writer.go:98).
    /// Goish doesn't yield a borrowed sub-Writer trait object; instead
    /// the caller writes part bodies via `WritePart(header, body)` or
    /// the convenience `WriteField` / `WriteFile` methods. The `body`
    /// is written verbatim immediately after the headers.
    pub fn WritePart(&mut self, header: Header, body: slice<byte>) -> error {
        let err = self.emit_part_head(&header);
        if !err.IsNil() {
            return err;
        }
        let (_, werr) = self.w.Write(body);
        werr
    }

    /// `(*Writer).CreateFormField + Write` (writer.go:145, :160) —
    /// emit a `form-data; name=…` part with the given string value.
    pub fn WriteField<F: Into<string>, V: Into<string>>(
        &mut self,
        fieldname: F,
        value: V,
    ) -> error {
        let fieldname: string = fieldname.into();
        let value: string = value.into();
        let mut h = Header::new();
        let mut cd = strings::Builder::new();
        let _ = cd.WriteString("form-data; name=\"");
        let _ = cd.WriteString(escape_quotes(fieldname));
        let _ = cd.WriteString("\"");
        h.Set(string("Content-Disposition"), cd.String());
        self.WritePart(h, bytes(value))
    }

    /// `(*Writer).CreateFormFile + Write` (writer.go:136). Emit a
    /// `form-data; name=…; filename=…` part with body and
    /// `Content-Type: application/octet-stream`.
    pub fn WriteFile<F: Into<string>, F1: Into<string>>(
        &mut self,
        fieldname: F,
        filename: F1,
        body: slice<byte>,
    ) -> error {
        let fieldname: string = fieldname.into();
        let filename: string = filename.into();
        let mut h = Header::new();
        h.Set(
            string("Content-Disposition"),
            FileContentDisposition(fieldname, filename),
        );
        h.Set(string("Content-Type"), string("application/octet-stream"));
        self.WritePart(h, body)
    }

    /// `(*Writer).Close()` (writer.go:171) — write the closing boundary.
    pub fn Close(&mut self) -> error {
        let mut tail = strings::Builder::new();
        let _ = tail.WriteString("\r\n--");
        let _ = tail.WriteString(self.boundary.clone());
        let _ = tail.WriteString("--\r\n");
        let (_, err) = self.w.Write(bytes(tail.String()));
        err
    }
}

/// `multipart.FileContentDisposition(field, filename)` (writer.go:154).
pub fn FileContentDisposition<F: Into<string>, F1: Into<string>>(
    fieldname: F,
    filename: F1,
) -> string {
    let fieldname: string = fieldname.into();
    let filename: string = filename.into();
    let mut b = strings::Builder::new();
    let _ = b.WriteString("form-data; name=\"");
    let _ = b.WriteString(escape_quotes(fieldname));
    let _ = b.WriteString("\"; filename=\"");
    let _ = b.WriteString(escape_quotes(filename));
    let _ = b.WriteString("\"");
    b.String()
}

/// Line-by-line port of `escapeQuotes` (writer.go:130) — replace `\\`
/// with `\\\\` and `"` with `\"`.
fn escape_quotes(s: string) -> string {
    let mut b = strings::Builder::new();
    let bs = s.as_bytes();
    for c in bs.iter() {
        match *c {
            b'\\' => {
                let _ = b.WriteByte(b'\\');
                let _ = b.WriteByte(b'\\');
            }
            b'"' => {
                let _ = b.WriteByte(b'\\');
                let _ = b.WriteByte(b'"');
            }
            other => {
                let _ = b.WriteByte(other);
            }
        }
    }
    b.String()
}

/// Line-by-line port of `randomBoundary` (writer.go:85). Reads 30
/// random bytes from the kernel CSPRNG and renders them as 60 lower-
/// hex digits.
fn random_boundary() -> string {
    const N: usize = 30;
    let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; N]);
    let _ = crate::crypto::rand::Read(&mut buf);
    let hex = b"0123456789abcdef";
    let mut out: Vec<u8> = Vec::with_capacity(2 * N);
    for i in 0..N as int {
        let b: byte = buf[i];
        out.push(hex[(b >> 4) as usize]);
        out.push(hex[(b & 0x0f) as usize]);
    }
    string::from_bytes(&out)
}
