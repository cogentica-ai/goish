// go: file mime/multipart/writer.go decls: NewWriter, Writer.Boundary, Writer.SetBoundary, Writer.FormDataContentType, randomBoundary, Writer.CreatePart, escapeQuotes, Writer.CreateFormFile, Writer.CreateFormField, FileContentDisposition, Writer.WriteField, Writer.Close, part.close, part.Write
//
// goishlint:ignore GOISH021 quoteEscaper — Go's package-level
//     `strings.NewReplacer("\\", "\\\\", `"`, "\\\"")` exists so
//     `escapeQuotes` can build the replacer once. goish's
//     `escapeQuotes` walks the string with a two-case match, so there
//     is no replacer to hoist.
//
// The `decls:` manifest above lists writer.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the `Writer` or `part` structs there would report them as dropped
// ports. They are not dropped — each carries its own `// go: sdk`
// anchor below.
//
// mime/multipart/writer.go — assembling multipart messages.
//
// Go's `CreatePart` returns an `io.Writer` that is really a `*part`
// holding a back-pointer to its `*Writer`, and the `Writer` keeps that
// same pointer in `lastpart` so the next `CreatePart` (or `Close`) can
// close it. goish cannot hold a back-pointer, so `part` is a *borrow*
// of the Writer and the two fields that have to outlive it — `closed`
// and `we`, the last write error — live in `Writer.lastpart` instead.
//
// That makes Go's documented rule ("after calling CreatePart, any
// previous part may no longer be written to") a borrow-checker rule
// rather than a runtime error: the old `part` cannot still be alive
// when `CreatePart` is called again.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::convert::{bytes, int as toint};
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io::Writer as IoWriter;
use crate::net::http::Header;
use crate::string;
use crate::strings;
use crate::types::{byte, int};

// go: sdk 1.25.5 mime/multipart/writer.go:170-174 part
/// The state Go keeps in the `*part` its `CreatePart` hands back.
///
/// goish's `part` handle is a borrow of the `Writer`, so it cannot
/// carry state that must survive it; `closed` and `we` live here,
/// inside `Writer.lastpart`, which is the field Go reaches them
/// through anyway.
struct lastPart {
    // Go: closed bool
    closed: bool,
    // Go: we error — last error that occurred writing
    we: error,
}

// go: sdk 1.25.5 mime/multipart/writer.go:19-23 Writer
/// `multipart.Writer` — generates multipart messages.
pub struct Writer<W: IoWriter> {
    w: W,
    boundary: string,
    lastpart: Option<lastPart>,
}

// go: sdk 1.25.5 mime/multipart/writer.go:26-31 NewWriter
/// A new multipart [`Writer`] with a random boundary, writing to `w`.
pub fn NewWriter<W: IoWriter>(w: W) -> Writer<W> {
    return Writer {
        w,
        boundary: randomBoundary(),
        lastpart: None,
    };
}

// go: sdk 1.25.5 mime/multipart/writer.go:80-87 randomBoundary
/// Thirty bytes from the CSPRNG, rendered as sixty lower-hex digits.
fn randomBoundary() -> string {
    const N: usize = 30;
    let mut buf = slice::<byte>::__from_vec(alloc::vec![0; N]);
    // Go: _, err := io.ReadFull(rand.Reader, buf[:]); if err != nil { panic(err) }
    let (_, err) = crate::crypto::rand::Read(&mut buf);
    if !err.IsNil() {
        panic!("multipart: randomBoundary: crypto/rand failed");
    }
    // Go: return fmt.Sprintf("%x", buf[:])
    let hexdigits = b"0123456789abcdef";
    let mut out: Vec<byte> = Vec::with_capacity(2 * N);
    let mut i: int = 0;
    while i < toint(N) {
        let b: byte = buf[i];
        out.push(hexdigits[(b >> 4) as usize]);
        out.push(hexdigits[(b & 0x0f) as usize]);
        i += 1;
    }
    return string::from_bytes(&out);
}

// go: sdk 1.25.5 mime/multipart/writer.go:125-127 escapeQuotes
/// Go builds a `strings.Replacer` once and reuses it; goish walks the
/// string, which is the same two substitutions: `\` for `\\` and `"`
/// for `\"`.
fn escapeQuotes(s: string) -> string {
    let mut b = strings::Builder::new();
    for c in s.as_bytes().iter() {
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
    return b.String();
}

// go: sdk 1.25.5 mime/multipart/writer.go:147-151 FileContentDisposition
/// The value of a `Content-Disposition` header with the given field
/// name and file name.
pub fn FileContentDisposition<F: Into<string>, F1: Into<string>>(
    fieldname: F,
    filename: F1,
) -> string {
    // Go: fmt.Sprintf(`form-data; name="%s"; filename="%s"`, …)
    let mut b = strings::Builder::new();
    let _ = b.WriteString("form-data; name=\"");
    let _ = b.WriteString(escapeQuotes(fieldname.into()));
    let _ = b.WriteString("\"; filename=\"");
    let _ = b.WriteString(escapeQuotes(filename.into()));
    let _ = b.WriteString("\"");
    return b.String();
}

// go: sdk 1.25.5 mime/multipart/writer.go:170-174 part
/// The `io.Writer` Go's [`Writer::CreatePart`] returns.
///
// goishlint:ignore GOISH019 part — Go's `part` is `{mw *Writer, closed
//     bool, we error}` and lives as long as its Writer, because it
//     holds a back-pointer. goish's is a *borrow* of the Writer, so
//     the two fields that must outlive the handle — `closed` and `we`
//     — moved into `Writer.lastpart`, which is the field Go reads them
//     back through. Nothing is dropped.
pub struct part<'a, W: IoWriter> {
    mw: &'a mut Writer<W>,
}

impl<'a, W: IoWriter> part<'a, W> {
    // go: sdk 1.25.5 mime/multipart/writer.go:181-190 part.Write
    pub fn Write(&mut self, d: slice<byte>) -> (int, error) {
        // Go: if p.closed { return 0, errors.New(…) }
        let closed = match self.mw.lastpart.as_ref() {
            Some(lp) => lp.closed,
            None => true,
        };
        if closed {
            return (
                0,
                errors::New(string("multipart: can't write to finished part")),
            );
        }
        let (n, err) = self.mw.w.Write(d);
        if !err.IsNil() {
            if let Some(lp) = self.mw.lastpart.as_mut() {
                lp.we = err.clone();
            }
        }
        return (n, err);
    }
}

impl<'a, W: IoWriter> IoWriter for part<'a, W> {
    // go: none — goish idiom: Go's `*part` satisfies `io.Writer`
    //     structurally; goish forwards the trait method to the
    //     inherent one so both spellings work.
    fn Write(&mut self, d: slice<byte>) -> (int, error) {
        return part::Write(self, d);
    }
}

impl<W: IoWriter> Writer<W> {
    // go: sdk 1.25.5 mime/multipart/writer.go:34-36 Writer.Boundary
    /// The [`Writer`]'s boundary.
    pub fn Boundary(&self) -> string {
        return self.boundary.clone();
    }

    // go: sdk 1.25.5 mime/multipart/writer.go:44-67 Writer.SetBoundary
    /// Overrides the randomly generated boundary separator with an
    /// explicit value.
    ///
    /// Must be called before any parts are created, may only contain
    /// certain ASCII characters, and must be non-empty and at most 70
    /// bytes long.
    pub fn SetBoundary<B: Into<string>>(&mut self, boundary: B) -> error {
        let boundary: string = boundary.into();
        if self.lastpart.is_some() {
            return errors::New(string("mime: SetBoundary called after write"));
        }
        // Go: rfc2046#section-5.1.1
        if boundary.Len() < 1 || boundary.Len() > 70 {
            return errors::New(string("mime: invalid boundary length"));
        }
        let bs = boundary.as_bytes();
        let end = bs.len() - 1;
        let mut i = 0usize;
        while i < bs.len() {
            let b = bs[i];
            if (b'A' <= b && b <= b'Z') || (b'a' <= b && b <= b'z') || (b'0' <= b && b <= b'9') {
                i += 1;
                continue;
            }
            let mut allowed = matches!(
                b,
                b'\'' | b'(' | b')' | b'+' | b'_' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
            );
            // Go: case ' ': if i != end { continue } — a trailing space
            // is the one disallowed placement.
            if b == b' ' && i != end {
                allowed = true;
            }
            if !allowed {
                return errors::New(string("mime: invalid boundary character"));
            }
            i += 1;
        }
        self.boundary = boundary;
        return errors::nil;
    }

    // go: sdk 1.25.5 mime/multipart/writer.go:71-78 Writer.FormDataContentType
    /// The `Content-Type` for an HTTP `multipart/form-data` with this
    /// [`Writer`]'s boundary, quoting the boundary when it holds one of
    /// RFC 2045's tspecials, or a space.
    pub fn FormDataContentType(&self) -> string {
        let mut b = self.boundary.clone();
        if strings::ContainsAny(b.clone(), string("()<>@,;:\\\"/[]?= ")) {
            let mut q = strings::Builder::new();
            let _ = q.WriteByte(b'"');
            let _ = q.WriteString(b);
            let _ = q.WriteByte(b'"');
            b = q.String();
        }
        let mut out = strings::Builder::new();
        let _ = out.WriteString("multipart/form-data; boundary=");
        let _ = out.WriteString(b);
        return out.String();
    }

    // go: sdk 1.25.5 mime/multipart/writer.go:176-179 part.close
    // goishlint:ignore GOISH014 — the anchor names Go's `part.close`.
    //     Go calls it through the `lastpart` back-pointer; goish keeps
    //     `part`'s state in `Writer.lastpart`, so the method lives on
    //     the Writer and reads exactly the same two fields.
    fn closeLastPart(&mut self) -> error {
        return match self.lastpart.as_mut() {
            Some(lp) => {
                lp.closed = true;
                lp.we.clone()
            }
            None => errors::nil,
        };
    }

    // go: sdk 1.25.5 mime/multipart/writer.go:93-120 Writer.CreatePart
    /// Creates a new multipart section with the provided header. The
    /// body of the part should be written to the returned writer.
    ///
    /// Go returns `nil` alongside the error; goish must return a handle
    /// either way, so on error the part is already closed and any
    /// `Write` on it reports "can't write to finished part".
    pub fn CreatePart(&mut self, header: Header) -> (part<'_, W>, error) {
        if self.lastpart.is_some() {
            let err = self.closeLastPart();
            if !err.IsNil() {
                self.lastpart = Some(lastPart {
                    closed: true,
                    we: err.clone(),
                });
                return (part { mw: self }, err);
            }
        }

        let mut b = strings::Builder::new();
        if self.lastpart.is_some() {
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
            let mut i: int = 0;
            while i < vs.Len() {
                let _ = b.WriteString(k.clone());
                let _ = b.WriteString(": ");
                let _ = b.WriteString(vs[i].clone());
                let _ = b.WriteString("\r\n");
                i += 1;
            }
        }
        let _ = b.WriteString("\r\n");

        let (_, err) = self.w.Write(bytes(b.String()));
        if !err.IsNil() {
            self.lastpart = Some(lastPart {
                closed: true,
                we: err.clone(),
            });
            return (part { mw: self }, err);
        }
        self.lastpart = Some(lastPart {
            closed: false,
            we: errors::nil,
        });
        return (part { mw: self }, errors::nil);
    }

    // go: sdk 1.25.5 mime/multipart/writer.go:131-137 Writer.CreateFormFile
    /// A convenience wrapper around [`Writer::CreatePart`]: a new
    /// form-data header with the given field name and file name.
    pub fn CreateFormFile<F: Into<string>, F1: Into<string>>(
        &mut self,
        fieldname: F,
        filename: F1,
    ) -> (part<'_, W>, error) {
        let mut h = Header::new();
        h.Set(
            string("Content-Disposition"),
            FileContentDisposition(fieldname.into(), filename.into()),
        );
        h.Set(string("Content-Type"), string("application/octet-stream"));
        return self.CreatePart(h);
    }

    // go: sdk 1.25.5 mime/multipart/writer.go:141-145 Writer.CreateFormField
    /// Calls [`Writer::CreatePart`] with a header naming the field.
    pub fn CreateFormField<F: Into<string>>(&mut self, fieldname: F) -> (part<'_, W>, error) {
        let mut h = Header::new();
        // Go: fmt.Sprintf(`form-data; name="%s"`, escapeQuotes(fieldname))
        let mut cd = strings::Builder::new();
        let _ = cd.WriteString("form-data; name=\"");
        let _ = cd.WriteString(escapeQuotes(fieldname.into()));
        let _ = cd.WriteString("\"");
        h.Set(string("Content-Disposition"), cd.String());
        return self.CreatePart(h);
    }

    // go: sdk 1.25.5 mime/multipart/writer.go:154-161 Writer.WriteField
    /// Calls [`Writer::CreateFormField`] and then writes the value.
    pub fn WriteField<F: Into<string>, V: Into<string>>(
        &mut self,
        fieldname: F,
        value: V,
    ) -> error {
        let value: string = value.into();
        let (mut p, err) = self.CreateFormField(fieldname);
        if !err.IsNil() {
            return err;
        }
        let (_, err) = p.Write(bytes(value));
        return err;
    }

    // go: none — goish idiom: `CreatePart` followed by one `Write`, in
    //     a single call. It predates `CreatePart` here (goish had no
    //     borrowed sub-writer) and `net/http/fs.rs` still uses it to
    //     emit a headers-only part.
    pub fn WritePart(&mut self, header: Header, body: slice<byte>) -> error {
        let (mut p, err) = self.CreatePart(header);
        if !err.IsNil() {
            return err;
        }
        if body.Len() == 0 {
            return errors::nil;
        }
        let (_, werr) = p.Write(body);
        return werr;
    }

    // go: none — goish idiom: `CreateFormFile` followed by one `Write`,
    //     the file-part twin of `WritePart`.
    pub fn WriteFile<F: Into<string>, F1: Into<string>>(
        &mut self,
        fieldname: F,
        filename: F1,
        body: slice<byte>,
    ) -> error {
        let (mut p, err) = self.CreateFormFile(fieldname, filename);
        if !err.IsNil() {
            return err;
        }
        let (_, werr) = p.Write(body);
        return werr;
    }

    // go: sdk 1.25.5 mime/multipart/writer.go:165-168 Writer.Close
    /// Finishes the multipart message and writes the trailing boundary
    /// end line to the output.
    pub fn Close(&mut self) -> error {
        if self.lastpart.is_some() {
            let err = self.closeLastPart();
            if !err.IsNil() {
                return err;
            }
            self.lastpart = None;
        }
        // Go: fmt.Fprintf(w.w, "\r\n--%s--\r\n", w.boundary)
        let mut tail = strings::Builder::new();
        let _ = tail.WriteString("\r\n--");
        let _ = tail.WriteString(self.boundary.clone());
        let _ = tail.WriteString("--\r\n");
        let (_, err) = self.w.Write(bytes(tail.String()));
        return err;
    }
}
