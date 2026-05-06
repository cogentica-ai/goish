// mime/quotedprintable — RFC 2045 §6.7 quoted-printable encoding.
//
// Reference: /share/go/src/mime/quotedprintable/{reader.go, writer.go}
//
// Slim deviations:
//   * Reader and Writer return concrete generic structs Reader<R> /
//     Writer<W> rather than `io.Reader` / `io.WriteCloser`. Same
//     trade as the rest of goish — no Box<dyn>; callers compose via
//     concrete types.
//   * Reader uses bufio::Reader internally (NewReader wraps unbuffered
//     io::Reader inputs); for callers passing already-buffered input,
//     wrap once and use NewReader.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::bufio;
use crate::bytes;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int, rune};

// ─── Reader (reader.go:17) ───────────────────────────────────────────

/// `quotedprintable.Reader` — quoted-printable decoder.
pub struct Reader<R: io::Reader> {
    br: bufio::Reader<R>,
    rerr: error,
    line: Vec<byte>,
}

/// `quotedprintable.NewReader(r)` (reader.go:24).
pub fn NewReader<R: io::Reader>(r: R) -> Reader<R> {
    Reader {
        br: bufio::NewReader(r),
        rerr: errors::nil,
        line: Vec::new(),
    }
}

/// `fromHex(b)` (reader.go:30) — decode a single hex digit.
fn from_hex(b: byte) -> (byte, error) {
    // Go: switch { case b >= '0' && b <= '9': return b - '0', nil … }
    if b >= b'0' && b <= b'9' {
        return (b - b'0', errors::nil);
    }
    if b >= b'A' && b <= b'F' {
        return (b - b'A' + 10, errors::nil);
    }
    if b >= b'a' && b <= b'f' {
        return (b - b'a' + 10, errors::nil);
    }
    (0, errors::New(invalid_hex_msg(b)))
}

fn invalid_hex_msg(b: byte) -> string {
    let mut v: Vec<byte> = Vec::with_capacity(40);
    v.extend_from_slice(b"quotedprintable: invalid hex byte 0x");
    let upper = b"0123456789ABCDEF";
    v.push(upper[((b >> 4) & 0xF) as usize]);
    v.push(upper[(b & 0xF) as usize]);
    string::from_bytes(&v)
}

/// `readHexByte(v)` (reader.go:43).
fn read_hex_byte(v: &[byte]) -> (byte, error) {
    if v.len() < 2 {
        return (0, io::ErrUnexpectedEOF.into());
    }
    let (hb, err1) = from_hex(v[0]);
    if !err1.IsNil() {
        return (0, err1);
    }
    let (lb, err2) = from_hex(v[1]);
    if !err2.IsNil() {
        return (0, err2);
    }
    (hb << 4 | lb, errors::nil)
}

/// `isQPDiscardWhitespace(r)` (reader.go:57).
fn is_qp_discard_whitespace(r: rune) -> bool {
    matches!(r, 0x0A | 0x0D | 0x20 | 0x09)
}

impl<R: io::Reader> io::Reader for Reader<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: for len(p) > 0 { … }
        let mut n: int = 0;
        let mut p_idx: usize = 0;
        let p_total = p.len() as usize;
        while p_idx < p_total {
            if self.line.is_empty() {
                if !self.rerr.IsNil() {
                    return (n, self.rerr.clone());
                }
                let (l, rerr) = self.br.ReadSlice(b'\n');
                let l_raw: &[byte] = &l;
                let line_vec: Vec<byte> = l_raw.to_vec();
                self.line = line_vec.clone();
                self.rerr = rerr;
                // Go: hasLF / hasCR; wholeLine := r.line; r.line = TrimRightFunc(...)
                let has_lf = bytes::HasSuffix(
                    slice::__from_vec(self.line.clone()),
                    slice::__from_vec(alloc::vec![b'\n']),
                );
                let has_cr = bytes::HasSuffix(
                    slice::__from_vec(self.line.clone()),
                    slice::__from_vec(alloc::vec![b'\r', b'\n']),
                );
                let whole_line: Vec<byte> = self.line.clone();
                let trimmed = bytes::TrimRightFunc(
                    slice::__from_vec(self.line.clone()),
                    |r: rune| is_qp_discard_whitespace(r),
                );
                let trimmed_raw: &[byte] = &trimmed;
                self.line = trimmed_raw.to_vec();
                let has_soft = bytes::HasSuffix(
                    slice::__from_vec(self.line.clone()),
                    slice::__from_vec(alloc::vec![b'=']),
                );
                if has_soft {
                    // Go: rightStripped := bytes.TrimLeft(wholeLine[len(r.line):], lwspChar)
                    let after = whole_line[self.line.len()..].to_vec();
                    let stripped = bytes::TrimLeft(
                        slice::__from_vec(after),
                        slice::__from_vec(alloc::vec![b' ', b'\t']),
                    );
                    let stripped_raw: &[byte] = &stripped;
                    // Go: r.line = r.line[:len(r.line)-1]
                    let new_len = self.line.len() - 1;
                    self.line.truncate(new_len);
                    let pre_lf = stripped_raw.starts_with(b"\n");
                    let pre_crlf = stripped_raw.starts_with(b"\r\n");
                    let eof_with_data =
                        stripped_raw.is_empty() && !self.line.is_empty() && is_eof(&self.rerr);
                    if !pre_lf && !pre_crlf && !eof_with_data {
                        // Go: r.rerr = fmt.Errorf("quotedprintable: invalid bytes after =: %q", rightStripped)
                        self.rerr = errors::New(string::from_static(
                            "quotedprintable: invalid bytes after =",
                        ));
                    }
                } else if has_lf {
                    if has_cr {
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
            // Track whether to advance past 2 hex digits.
            let mut consume_extra_two = false;

            if b == b'=' {
                // Go: b, err = readHexByte(r.line[1:])
                let tail: &[byte] = &self.line[1..];
                let (decoded, herr) = read_hex_byte(tail);
                if !herr.IsNil() {
                    if self.line.len() >= 2 && self.line[1] != b'\r' && self.line[1] != b'\n' {
                        // Go: take the = as a literal =.
                        b = b'=';
                    } else {
                        return (n, herr);
                    }
                } else {
                    b = decoded;
                    consume_extra_two = true;
                }
            } else if b == b'\t' || b == b'\r' || b == b'\n' {
                // pass through verbatim
            } else if b >= 0x80 {
                // accept high bytes (issue 22597)
            } else if b < b' ' || b > b'~' {
                return (
                    n,
                    errors::New(string::from_static(
                        "quotedprintable: invalid unescaped byte in body",
                    )),
                );
            }

            p[p_idx as int] = b;
            p_idx += 1;
            if consume_extra_two {
                self.line.drain(0..3);
            } else {
                self.line.drain(0..1);
            }
            n += 1;
        }
        (n, errors::nil)
    }
}

fn is_eof(e: &error) -> bool {
    !e.IsNil() && errors::Is(e.clone(), io::EOF)
}

// ─── Writer (writer.go:12) ───────────────────────────────────────────

const LINE_MAX_LEN: usize = 76;
const UPPER_HEX: &[byte] = b"0123456789ABCDEF";

/// `quotedprintable.Writer` — encoder. Emit at most 76 chars per line,
/// soft-break with "=" + CRLF when needed. Close to flush.
pub struct Writer<W: io::Writer> {
    /// `Binary` — treat input as pure binary; \r/\n are bytes, not EOLs.
    pub Binary: bool,

    w: W,
    i: usize,
    line: [byte; 78],
    cr: bool,
    closed: bool,
}

/// `quotedprintable.NewWriter(w)` (writer.go:24).
pub fn NewWriter<W: io::Writer>(w: W) -> Writer<W> {
    Writer {
        Binary: false,
        w,
        i: 0,
        line: [0u8; 78],
        cr: false,
        closed: false,
    }
}

fn is_whitespace(b: byte) -> bool {
    b == b' ' || b == b'\t'
}

impl<W: io::Writer> Writer<W> {
    fn flush(&mut self) -> error {
        let buf = slice::__from_vec(self.line[..self.i].to_vec());
        let (_n, err) = self.w.Write(buf);
        if !err.IsNil() {
            return err;
        }
        self.i = 0;
        errors::nil
    }

    fn insert_crlf(&mut self) -> error {
        self.line[self.i] = b'\r';
        self.line[self.i + 1] = b'\n';
        self.i += 2;
        self.flush()
    }

    fn insert_soft_line_break(&mut self) -> error {
        self.line[self.i] = b'=';
        self.i += 1;
        self.insert_crlf()
    }

    fn encode_byte(&mut self, b: byte) -> error {
        // Go: if lineMaxLen-1-w.i < 3 { soft break }
        if LINE_MAX_LEN - 1 - self.i < 3 {
            let e = self.insert_soft_line_break();
            if !e.IsNil() {
                return e;
            }
        }
        self.line[self.i] = b'=';
        self.line[self.i + 1] = UPPER_HEX[(b >> 4) as usize];
        self.line[self.i + 2] = UPPER_HEX[(b & 0x0F) as usize];
        self.i += 3;
        errors::nil
    }

    fn check_last_byte(&mut self) -> error {
        if self.i == 0 {
            return errors::nil;
        }
        let b = self.line[self.i - 1];
        if is_whitespace(b) {
            self.i -= 1;
            return self.encode_byte(b);
        }
        errors::nil
    }

    fn write_chunk(&mut self, p: &[byte]) -> error {
        // Go: write — limits output to 76 cols, handles CR/LF specially.
        for &b in p {
            if b == b'\n' || b == b'\r' {
                if self.cr && b == b'\n' {
                    self.cr = false;
                    continue;
                }
                if b == b'\r' {
                    self.cr = true;
                }
                let e = self.check_last_byte();
                if !e.IsNil() {
                    return e;
                }
                let e2 = self.insert_crlf();
                if !e2.IsNil() {
                    return e2;
                }
                continue;
            }
            if self.i == LINE_MAX_LEN - 1 {
                let e = self.insert_soft_line_break();
                if !e.IsNil() {
                    return e;
                }
            }
            self.line[self.i] = b;
            self.i += 1;
            self.cr = false;
        }
        errors::nil
    }
}

impl<W: io::Writer> io::Writer for Writer<W> {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let raw: &[byte] = &p;
        let mut n: usize = 0;
        let mut i: usize = 0;
        while i < raw.len() {
            let b = raw[i];
            // Go: simple writes batched
            let simple = (b >= b'!' && b <= b'~' && b != b'=')
                || is_whitespace(b)
                || (!self.Binary && (b == b'\n' || b == b'\r'));
            if simple {
                i += 1;
                continue;
            }
            if i > n {
                let e = self.write_chunk(&raw[n..i]);
                if !e.IsNil() {
                    return (n as int, e);
                }
                n = i;
            }
            let e = self.encode_byte(b);
            if !e.IsNil() {
                return (n as int, e);
            }
            n += 1;
            i += 1;
        }
        if n == raw.len() {
            return (n as int, errors::nil);
        }
        let e = self.write_chunk(&raw[n..]);
        if !e.IsNil() {
            return (n as int, e);
        }
        (raw.len() as int, errors::nil)
    }
}

impl<W: io::Writer> io::Closer for Writer<W> {
    fn Close(&mut self) -> error {
        if self.closed {
            return errors::nil;
        }
        self.closed = true;
        let e = self.check_last_byte();
        if !e.IsNil() {
            return e;
        }
        self.flush()
    }
}
