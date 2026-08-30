// go: file mime/quotedprintable/writer.go decls: NewWriter, Writer.Write, Writer.Close, Writer.write, Writer.encode, Writer.checkLastByte, Writer.insertSoftLineBreak, Writer.insertCRLF, Writer.flush, isWhitespace
//
// The `decls:` manifest above lists writer.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the `Writer` struct or the `lineMaxLen`/`upperhex` constants there
// would report them as dropped ports. They are not dropped — each
// carries its own `// go: sdk` anchor below.
//
// mime/quotedprintable/writer.go — the RFC 2045 §6.7 encoder.
//
// The whole design is one 78-byte line buffer and an index into it. A
// line may hold at most 76 characters, so `write` inserts a soft line
// break ("=" + CRLF) at 75 and `encode` reserves three columns for an
// "=XX" escape before it starts one. The two extra bytes are what makes
// the CRLF always fit.
//
// `checkLastByte` is the subtle one: a space or tab at the end of a
// line would be eaten by any transport that strips trailing whitespace,
// so it is re-encoded as "=20" or "=09" — but only when the line
// actually ends, which is why `Close` calls it and a mid-line space
// does not.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::convert::int as toint;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int};

// go: sdk 1.25.5 mime/quotedprintable/writer.go:9-9 lineMaxLen
const lineMaxLen: usize = 76;

// go: sdk 1.25.5 mime/quotedprintable/writer.go:112-112 upperhex
const upperhex: &[byte] = b"0123456789ABCDEF";

// go: sdk 1.25.5 mime/quotedprintable/writer.go:11-21 Writer
/// `quotedprintable.Writer` — a quoted-printable writer, standing in
/// for Go's `io.WriteCloser`.
pub struct Writer<W: io::Writer> {
    /// Binary mode treats the writer's input as pure binary and
    /// processes end-of-line bytes as binary data.
    pub Binary: bool,

    w: W,
    i: usize,
    line: [byte; 78],
    cr: bool,
}

// go: sdk 1.25.5 mime/quotedprintable/writer.go:23-26 NewWriter
/// A new [`Writer`] that writes to `w`.
pub fn NewWriter<W: io::Writer>(w: W) -> Writer<W> {
    return Writer {
        Binary: false,
        w,
        i: 0,
        line: [0; 78],
        cr: false,
    };
}

// go: sdk 1.25.5 mime/quotedprintable/writer.go:160-162 isWhitespace
fn isWhitespace(b: byte) -> bool {
    return b == b' ' || b == b'\t';
}

impl<W: io::Writer> Writer<W> {
    // go: sdk 1.25.5 mime/quotedprintable/writer.go:31-62 Writer.Write
    /// Encodes `p` and writes it to the underlying writer, limiting
    /// line length to 76 characters. The encoded bytes are not
    /// necessarily flushed until the [`Writer`] is closed.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let raw: &[byte] = &p;
        let mut n: usize = 0;
        let mut i: usize = 0;
        while i < raw.len() {
            let b = raw[i];
            // Go: simple writes are done in batch.
            if (b >= b'!' && b <= b'~' && b != b'=')
                || isWhitespace(b)
                || (!self.Binary && (b == b'\n' || b == b'\r'))
            {
                i += 1;
                continue;
            }

            if i > n {
                let chunk: alloc::vec::Vec<byte> = raw[n..i].to_vec();
                let err = self.write(&chunk);
                if !err.IsNil() {
                    return (toint(n), err);
                }
                n = i;
            }

            let err = self.encode(b);
            if !err.IsNil() {
                return (toint(n), err);
            }
            n += 1;
            i += 1;
        }

        if n == raw.len() {
            return (toint(n), errors::nil);
        }

        let chunk: alloc::vec::Vec<byte> = raw[n..].to_vec();
        let err = self.write(&chunk);
        if !err.IsNil() {
            return (toint(n), err);
        }

        return (toint(raw.len()), errors::nil);
    }

    // go: sdk 1.25.5 mime/quotedprintable/writer.go:66-72 Writer.Close
    /// Closes the [`Writer`], flushing any unwritten data to the
    /// underlying writer — but not closing that writer.
    pub fn Close(&mut self) -> error {
        let err = self.checkLastByte();
        if !err.IsNil() {
            return err;
        }
        return self.flush();
    }

    // go: sdk 1.25.5 mime/quotedprintable/writer.go:75-108 Writer.write
    /// Emits literal text, holding output to 76 characters per line.
    fn write(&mut self, p: &[byte]) -> error {
        let mut k = 0usize;
        while k < p.len() {
            let b = p[k];
            k += 1;
            if b == b'\n' || b == b'\r' {
                // If the previous byte was \r, the CRLF has already
                // been inserted.
                if self.cr && b == b'\n' {
                    self.cr = false;
                    continue;
                }

                if b == b'\r' {
                    self.cr = true;
                }

                let err = self.checkLastByte();
                if !err.IsNil() {
                    return err;
                }
                let err = self.insertCRLF();
                if !err.IsNil() {
                    return err;
                }
                continue;
            }

            if self.i == lineMaxLen - 1 {
                let err = self.insertSoftLineBreak();
                if !err.IsNil() {
                    return err;
                }
            }

            self.line[self.i] = b;
            self.i += 1;
            self.cr = false;
        }

        return errors::nil;
    }

    // go: sdk 1.25.5 mime/quotedprintable/writer.go:110-110 Writer.encode
    /// Writes one byte as "=XX", starting a new line first if three
    /// columns will not fit.
    fn encode(&mut self, b: byte) -> error {
        if lineMaxLen - 1 - self.i < 3 {
            let err = self.insertSoftLineBreak();
            if !err.IsNil() {
                return err;
            }
        }

        self.line[self.i] = b'=';
        self.line[self.i + 1] = upperhex[(b >> 4) as usize];
        self.line[self.i + 2] = upperhex[(b & 0x0f) as usize];
        self.i += 3;

        return errors::nil;
    }

    // go: sdk 1.25.5 mime/quotedprintable/writer.go:115-128 Writer.checkLastByte
    /// Encodes the last buffered byte if it is a space or a tab, so a
    /// transport that strips trailing whitespace cannot eat it.
    fn checkLastByte(&mut self) -> error {
        if self.i == 0 {
            return errors::nil;
        }

        let b = self.line[self.i - 1];
        if isWhitespace(b) {
            self.i -= 1;
            let err = self.encode(b);
            if !err.IsNil() {
                return err;
            }
        }

        return errors::nil;
    }

    // go: sdk 1.25.5 mime/quotedprintable/writer.go:130-135 Writer.insertSoftLineBreak
    fn insertSoftLineBreak(&mut self) -> error {
        self.line[self.i] = b'=';
        self.i += 1;

        return self.insertCRLF();
    }

    // go: sdk 1.25.5 mime/quotedprintable/writer.go:137-143 Writer.insertCRLF
    fn insertCRLF(&mut self) -> error {
        self.line[self.i] = b'\r';
        self.line[self.i + 1] = b'\n';
        self.i += 2;

        return self.flush();
    }

    // go: sdk 1.25.5 mime/quotedprintable/writer.go:145-152 Writer.flush
    fn flush(&mut self) -> error {
        let buf = slice::__from_vec(self.line[..self.i].to_vec());
        let (_, err) = self.w.Write(buf);
        if !err.IsNil() {
            return err;
        }

        self.i = 0;
        return errors::nil;
    }
}

impl<W: io::Writer> io::Writer for Writer<W> {
    // go: none — goish idiom: Go's `*Writer` satisfies `io.WriteCloser`
    //     structurally; goish forwards the trait method to the inherent
    //     one so both spellings work.
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return Writer::Write(self, p);
    }
}

impl<W: io::Writer> io::Closer for Writer<W> {
    // go: none — goish idiom: the `io::Closer` half of the same
    //     forward, so `Writer<W>` is an `io::WriteCloser`.
    fn Close(&mut self) -> error {
        return Writer::Close(self);
    }
}
