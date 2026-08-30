// go: file mime/quotedprintable/reader.go decls: NewReader, fromHex, readHexByte, isQPDiscardWhitespace, Reader.Read
//
// The `decls:` manifest above lists reader.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the `Reader` struct or the `crlf`/`lf`/`softSuffix`/`lwspChar` package
// vars there would report them as dropped ports. They are not dropped —
// each carries its own `// go: sdk` anchor below.
//
// mime/quotedprintable/reader.go — the RFC 2045 §6.7 decoder.
//
// The decoder is defined as much by what it tolerates as by what it
// decodes. Go documents four deviations from the RFC, all of them
// leniency: "=\n" counts as a soft line break as well as "=\r\n"; a
// bare '\r' or '\n' passes through; a trailing '=' at end of message is
// ignored; and an '=' not followed by two hex digits is taken as a
// literal '=' unless it sits at end of line. Every one of them is a
// real message some encoder produced, so none can be dropped.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::bufio;
use crate::bytes;
use crate::convert::int as toint;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int, rune};

// go: sdk 1.25.5 mime/quotedprintable/reader.go:16-20 Reader
/// `quotedprintable.Reader` — a quoted-printable decoder.
///
/// Go's `line []byte` is a view that walks forward through the buffer;
/// goish holds the same bytes in an owned `Vec<byte>` and drains from
/// the front, since a struct field cannot borrow a sibling field.
pub struct Reader<R: io::Reader> {
    br: bufio::Reader<R>,
    // Go: rerr error — last read error
    rerr: error,
    // Go: line []byte — to be consumed before more of br
    line: Vec<byte>,
}

// go: sdk 1.25.5 mime/quotedprintable/reader.go:23-27 NewReader
/// A quoted-printable reader, decoding from `r`.
pub fn NewReader<R: io::Reader>(r: R) -> Reader<R> {
    return Reader {
        br: bufio::NewReader(r),
        rerr: errors::nil,
        line: Vec::new(),
    };
}

// go: sdk 1.25.5 mime/quotedprintable/reader.go:29-40 fromHex
/// One hex digit to its value. Lower case is accepted as well as upper:
/// Go's comment is "Accept badly encoded bytes."
fn fromHex(b: byte) -> (byte, error) {
    if b >= b'0' && b <= b'9' {
        return (b - b'0', errors::nil);
    }
    if b >= b'A' && b <= b'F' {
        return (b - b'A' + 10, errors::nil);
    }
    // Go: accept badly encoded bytes.
    if b >= b'a' && b <= b'f' {
        return (b - b'a' + 10, errors::nil);
    }
    return (
        0,
        crate::fmt::Errorf!("quotedprintable: invalid hex byte 0x%02x", b),
    );
}

// go: sdk 1.25.5 mime/quotedprintable/reader.go:42-54 readHexByte
/// The two hex digits after an '=' as one byte.
fn readHexByte(v: &[byte]) -> (byte, error) {
    if v.len() < 2 {
        return (0, io::ErrUnexpectedEOF.into());
    }
    let (hb, err) = fromHex(v[0]);
    if !err.IsNil() {
        return (0, err);
    }
    let (lb, err) = fromHex(v[1]);
    if !err.IsNil() {
        return (0, err);
    }
    return (hb << 4 | lb, errors::nil);
}

// go: sdk 1.25.5 mime/quotedprintable/reader.go:56-62 isQPDiscardWhitespace
/// The whitespace a line's right edge is trimmed of before the soft
/// line-break test.
fn isQPDiscardWhitespace(r: rune) -> bool {
    // Go: switch r { case '\n', '\r', ' ', '\t': return true }
    return matches!(r, 0x0A | 0x0D | 0x20 | 0x09);
}

// go: sdk 1.25.5 mime/quotedprintable/reader.go:64-70 crlf
const crlf: &[byte] = b"\r\n";

// go: sdk 1.25.5 mime/quotedprintable/reader.go:64-70 lf
const lf: &[byte] = b"\n";

// go: sdk 1.25.5 mime/quotedprintable/reader.go:64-70 softSuffix
const softSuffix: &[byte] = b"=";

// go: sdk 1.25.5 mime/quotedprintable/reader.go:64-70 lwspChar
const lwspChar: &[byte] = b" \t";

impl<R: io::Reader> Reader<R> {
    // go: sdk 1.25.5 mime/quotedprintable/reader.go:73-140 Reader.Read
    /// Reads and decodes quoted-printable data from the underlying
    /// reader.
    ///
    /// Deviations from RFC 2045, all of them Go's:
    ///   1. as well as "=\r\n", "=\n" is treated as a soft line break.
    ///   2. a '\r' or '\n' not preceded by '=' passes through, which is
    ///      what other broken QP encoders and decoders do.
    ///   3. a soft line break ('=') at end of message is accepted
    ///      (golang.org/issue/15486) and silently ignored.
    ///   4. an '=' not followed by two hex digits is taken as a literal
    ///      '=' — but not at end of line (golang.org/issue/13219).
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let mut n: int = 0;
        let mut pi: usize = 0;
        let plen = p.Len() as usize;

        // Go: for len(p) > 0 { … }
        while pi < plen {
            if self.line.is_empty() {
                if !self.rerr.IsNil() {
                    return (n, self.rerr.clone());
                }
                let (l, rerr) = self.br.ReadSlice(b'\n');
                let l_raw: &[byte] = &l;
                self.line = l_raw.to_vec();
                self.rerr = rerr;

                // Does the line end in CRLF instead of just LF?
                let hasLF = self.line.ends_with(lf);
                let hasCR = self.line.ends_with(crlf);
                let wholeLine: Vec<byte> = self.line.clone();
                let trimmed = bytes::TrimRightFunc(slice::__from_vec(wholeLine.clone()), |r| {
                    return isQPDiscardWhitespace(r);
                });
                let trimmed_raw: &[byte] = &trimmed;
                self.line = trimmed_raw.to_vec();

                if self.line.ends_with(softSuffix) {
                    // Go: rightStripped := bytes.TrimLeft(wholeLine[len(r.line):], lwspChar)
                    let after: Vec<byte> = wholeLine[self.line.len()..].to_vec();
                    let rightStripped = bytes::TrimLeft(
                        slice::__from_vec(after),
                        slice::__from_vec(lwspChar.to_vec()),
                    );
                    let rs_raw: &[byte] = &rightStripped;
                    let new_len = self.line.len() - 1;
                    self.line.truncate(new_len);
                    // Go: the trailing '=' is a soft line break only if
                    // what follows it is an end of line — or nothing at
                    // all, at end of message (issue 15486).
                    if !rs_raw.starts_with(lf)
                        && !rs_raw.starts_with(crlf)
                        && !(rs_raw.is_empty()
                            && !self.line.is_empty()
                            && errors::Is(self.rerr.clone(), io::EOF))
                    {
                        self.rerr = crate::fmt::Errorf!(
                            "quotedprintable: invalid bytes after =: %q",
                            rightStripped.clone()
                        );
                    }
                } else if hasLF {
                    if hasCR {
                        self.line.push(b'\r');
                        self.line.push(b'\n');
                    } else {
                        self.line.push(b'\n');
                    }
                }
                continue;
            }

            // Go: b := r.line[0]
            let mut b = self.line[0];
            // Go consumes 2 of the 3 bytes of an "=XX" escape inside the
            // switch and the third below; goish records the decision and
            // drains once.
            let mut escape = false;

            if b == b'=' {
                let (decoded, err) = readHexByte(&self.line[1..]);
                if !err.IsNil() {
                    if self.line.len() >= 2 && self.line[1] != b'\r' && self.line[1] != b'\n' {
                        // Take the = as a literal =.
                        b = b'=';
                    } else {
                        return (n, err);
                    }
                } else {
                    b = decoded;
                    escape = true;
                }
            } else if b == b'\t' || b == b'\r' || b == b'\n' {
                // Go: break — pass through verbatim.
            } else if b >= 0x80 {
                // As an extension to RFC 2045, values >= 0x80 are
                // accepted without complaint. Issue 22597.
            } else if b < b' ' || b > b'~' {
                return (
                    n,
                    crate::fmt::Errorf!(
                        "quotedprintable: invalid unescaped byte 0x%02x in body",
                        b
                    ),
                );
            }

            p[toint(pi)] = b;
            pi += 1;
            if escape {
                self.line.drain(0..3);
            } else {
                self.line.drain(0..1);
            }
            n += 1;
        }
        return (n, errors::nil);
    }
}

impl<R: io::Reader> io::Reader for Reader<R> {
    // go: none — goish idiom: Go's `*Reader` satisfies `io.Reader`
    //     structurally; goish forwards the trait method to the inherent
    //     one so both spellings work.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Reader::Read(self, p);
    }
}
