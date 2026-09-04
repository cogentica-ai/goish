// net/textproto/reader.rs — slim line-by-line port of Go 1.25 net/textproto/reader.go.
// goishlint:ignore GOISH018 Cmd, Dial, Close, Error, DotReader, ReadCodeLine, ReadResponse, ReadDotBytes, ReadDotLines, NewConn, Read, readCodeLine, parseCodeLine, mustHaveFieldNameColon, trim, TrimString, TrimBytes, isASCIISpace, closeDot, initCommonHeader, skipSpace, upcomingHeaderKeys, readLineSlice, readContinuedLineSlice, noValidation — the anchors in this file reach two Go files: reader.go, which it ports, and textproto.go for `isASCIILetter`. Everything listed is the `Conn` CLIENT surface — Dial, Cmd, the numeric-response readers and the dot-encoding reader — which goish does not port; `Error` and `ProtocolError` DO exist, in mod.rs, and `mustHaveFieldNameColon`/`trim` are the `ValidatorKind` enum and `trim_slice` here. `TrimString`, `TrimBytes` and `isASCIISpace` are in mod.rs, `closeDot` belongs to the dot reader, and `initCommonHeader` builds Go's lookup table. `noValidation` is `ValidatorKind::None`.
// goishlint:ignore GOISH021 Conn, Error, ProtocolError, dotReader, toLower, commonHeader, commonHeaderOnce, dotReaderState, nl — the same split: `Error` and `ProtocolError` are in mod.rs, `Conn`/`dotReader` belong to the unported client surface, and `toLower`/`commonHeader` are Go's lookup tables for a canonicaliser goish computes directly; `nl` is a one-byte literal at its use site.
//
// Source: go1.25.5/src/net/textproto/reader.go
//
// Slim deviations:
//   * `dotReader`, `ReadCodeLine`, `ReadResponse`, `ReadDotBytes`, `ReadDotLines`
//     are NOT ported in v1: SMTP/NNTP framing is out of scope. HTTP server
//     parsing only needs ReadLine and ReadMIMEHeader.
//   * `commonHeader` interning table is omitted — the canonicalizer always
//     allocates a fresh string. This costs a tiny allocation per header but
//     keeps the port table-free.
//   * `r.buf` (per-Reader scratch) stays a `Vec<byte>` (internal buffer).
//
// All public function names match Go exactly (PascalCase). Body bytes are
// expressed in goish primitives (slice<byte>, bytes::IndexByte, bytes::Cut,
// bytes::TrimLeft, byte literals) — no `&[u8]` or `Vec<u8>` slot through.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::bufio;
use crate::bytes;
use crate::errors::{self, error, nil};
use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int};

use super::{MIMEHeader, ProtocolError};

// Go: reader.go:22
//   var errMessageTooLarge = errors.New("message too large")
fn errMessageTooLarge() -> error {
    errors::New(string::from_static("message too large"))
}

// Go: reader.go:26-30
//   type Reader struct { R *bufio.Reader; dot *dotReader; buf []byte }
//
// Slim: dot is omitted (DotReader unported). buf is the scratch slice
// reused across readContinuedLineSlice calls.
pub struct Reader<R: io::Reader> {
    pub R: bufio::Reader<R>,
    buf: Vec<byte>,
}

// go: sdk 1.25.5 net/textproto/reader.go:37-39 NewReader
// Go: reader.go:37-39
//   func NewReader(r *bufio.Reader) *Reader { return &Reader{R: r} }
pub fn NewReader<R: io::Reader>(r: bufio::Reader<R>) -> Reader<R> {
    Reader {
        R: r,
        buf: Vec::new(),
    }
}

// go: none — goish-only: the get half of net/http's
// textprotoReaderPool (newTextprotoReader, request.go:1038).
/// Build a Reader with a recycled scratch buffer; the take-back half
/// is `__into_parts`. Go pools the whole `*textproto.Reader` struct
/// (swapping `tr.R`); goish's Reader OWNS its bufio reader and is
/// generic over `R`, so the reusable allocation (the line-scratch
/// `buf`) is what crosses the pool.
pub(crate) fn __new_reader_with_scratch<R: io::Reader>(
    r: bufio::Reader<R>,
    scratch: bufio::PoolBuf,
) -> Reader<R> {
    let mut scratch = scratch.0;
    scratch.clear();
    return Reader { R: r, buf: scratch };
}

impl<R: io::Reader> Reader<R> {
    // go: none — goish-only: the put half of net/http's
    // textprotoReaderPool (putTextprotoReader, request.go:1047).
    /// Consume the Reader, returning `(inner bufio reader, scratch)`.
    /// Mirrors Go's `r.R = nil` detach — ownership forces goish to
    /// hand the bufio reader back instead of nil-ing a pointer.
    pub(crate) fn __into_parts(self) -> (bufio::Reader<R>, bufio::PoolBuf) {
        return (self.R, bufio::PoolBuf(self.buf));
    }

    // go: none — goish-only test hook.
    /// Identity of the scratch allocation, null while the scratch has
    /// never allocated (an empty Vec's dangling as_ptr is EQUAL
    /// across instances, which would make a reuse assertion pass
    /// vacuously).
    #[doc(hidden)]
    pub fn __scratch_ptr(&self) -> *const u8 {
        if self.buf.capacity() == 0 {
            return core::ptr::null();
        }
        return self.buf.as_ptr();
    }
}

impl<R: io::Reader> Reader<R> {
    // go: sdk 1.25.5 net/textproto/reader.go:43-46 Reader.ReadLine
    // Go: reader.go:43-46
    //   func (r *Reader) ReadLine() (string, error) {
    //       line, err := r.readLineSlice(-1)
    //       return string(line), err
    //   }
    pub fn ReadLine(&mut self) -> (string, error) {
        let (line, err) = self.readLineSlice(-1);
        (string::from_bytes(line.as_ref()), err)
    }

    // go: sdk 1.25.5 net/textproto/reader.go:49-55 Reader.ReadLineBytes
    // Go: reader.go:49-55
    //   func (r *Reader) ReadLineBytes() ([]byte, error) { ... }
    pub fn ReadLineBytes(&mut self) -> (slice<byte>, error) {
        let (line, err) = self.readLineSlice(-1);
        // Go: if line != nil { line = bytes.Clone(line) }
        // Slim: __from_vec already takes ownership of a fresh Vec, so no
        //       additional clone is necessary.
        (line, err)
    }

    // go: sdk 1.25.5 net/textproto/reader.go:60-81 Reader.readLineSlice
    // Go: reader.go:60-81
    //   func (r *Reader) readLineSlice(lim int64) ([]byte, error) { ... }
    fn readLineSlice(&mut self, lim: int) -> (slice<byte>, error) {
        // Go: r.closeDot()  — slim-omitted (no DotReader in v1).
        let mut line: Vec<byte> = Vec::new();
        loop {
            let (l, more, err) = self.R.ReadLine();
            if err != nil {
                return (slice::__from_vec(Vec::new()), err);
            }
            // Go: if lim >= 0 && int64(len(line))+int64(len(l)) > lim
            if lim >= 0 && (line.len() as int) + l.Len() > lim {
                return (slice::__from_vec(Vec::new()), errMessageTooLarge());
            }
            // Go: if line == nil && !more { return l, nil }
            if line.is_empty() && !more {
                return (l, nil);
            }
            // Go: line = append(line, l...)
            for i in 0..l.Len() {
                line.push(l[i]);
            }
            if !more {
                break;
            }
        }
        (slice::__from_vec(line), nil)
    }

    // go: sdk 1.25.5 net/textproto/reader.go:101-104 Reader.ReadContinuedLine
    // Go: reader.go:101-104
    //   func (r *Reader) ReadContinuedLine() (string, error) { ... }
    pub fn ReadContinuedLine(&mut self) -> (string, error) {
        let (line, err) = self.readContinuedLineSlice(-1, ValidatorKind::None);
        (string::from_bytes(line.as_ref()), err)
    }

    // go: sdk 1.25.5 net/textproto/reader.go:122-128 Reader.ReadContinuedLineBytes
    // Go: reader.go:122-128
    //   func (r *Reader) ReadContinuedLineBytes() ([]byte, error) { ... }
    pub fn ReadContinuedLineBytes(&mut self) -> (slice<byte>, error) {
        let (line, err) = self.readContinuedLineSlice(-1, ValidatorKind::None);
        // Go bytes.Clone — slim: already a fresh slice.
        (line, err)
    }

    // go: sdk 1.25.5 net/textproto/reader.go:135-187 Reader.readContinuedLineSlice
    // Go: reader.go:135-187
    //   func (r *Reader) readContinuedLineSlice(lim int64,
    //                                            validateFirstLine func([]byte) error) ([]byte, error)
    //
    // Slim: validateFirstLine is encoded as a small enum so the port
    // doesn't need to thread function pointers through goish (the only
    // two callers are noValidation and mustHaveFieldNameColon).
    fn readContinuedLineSlice(
        &mut self,
        lim: int,
        validate: ValidatorKind,
    ) -> (slice<byte>, error) {
        // Go: if validateFirstLine == nil { return nil, fmt.Errorf("missing validateFirstLine func") }
        // Slim: enum has a None variant; no nil check needed.
        let _ = validate;

        // Go: line, err := r.readLineSlice(lim)
        let (line, err) = self.readLineSlice(lim);
        if err != nil {
            return (slice::__from_vec(Vec::new()), err);
        }

        // Go: if len(line) == 0 { return line, nil }
        if line.Len() == 0 {
            return (line, nil);
        }

        // Go: if err := validateFirstLine(line); err != nil { return nil, err }
        if let Err(e) = run_validator(validate, &line) {
            return (slice::__from_vec(Vec::new()), e);
        }

        // Go: r.R.Buffered() > 1
        if self.R.Buffered() > 1 {
            // Go: peek, _ := r.R.Peek(2)
            let (peek, _) = self.R.Peek(2);
            let pb: &[byte] = peek.as_ref();
            // Go: len(peek) > 0 && (isASCIILetter(peek[0]) || peek[0] == '\n') ||
            //     len(peek) == 2 && peek[0] == '\r' && peek[1] == '\n'
            let optimistic = (!pb.is_empty() && (isASCIILetter(pb[0]) || pb[0] == b'\n'))
                || (pb.len() == 2 && pb[0] == b'\r' && pb[1] == b'\n');
            if optimistic {
                return (trim_slice(&line), nil);
            }
        }

        // Go: r.buf = append(r.buf[:0], trim(line)...)
        self.buf.clear();
        let trimmed = trim_slice(&line);
        let traw: &[byte] = trimmed.as_ref();
        for &b in traw {
            self.buf.push(b);
        }

        // Go: if lim < 0 { lim = math.MaxInt64 }
        let mut lim = if lim < 0 { i64::MAX } else { lim };
        lim -= self.buf.len() as int;

        // Go: for r.skipSpace() > 0 { ... }
        loop {
            if self.skipSpace() == 0 {
                break;
            }
            // Go: r.buf = append(r.buf, ' ')
            self.buf.push(b' ');
            if (self.buf.len() as int) >= lim {
                return (slice::__from_vec(Vec::new()), errMessageTooLarge());
            }
            let (line2, err2) = self.readLineSlice(lim - self.buf.len() as int);
            if err2 != nil {
                break;
            }
            let t2 = trim_slice(&line2);
            let t2raw: &[byte] = t2.as_ref();
            for &b in t2raw {
                self.buf.push(b);
            }
        }
        let buf_copy = self.buf.clone();
        (slice::__from_vec(buf_copy), nil)
    }

    // go: sdk 1.25.5 net/textproto/reader.go:190-205 Reader.skipSpace
    // Go: reader.go:190-205
    //   func (r *Reader) skipSpace() int { ... }
    fn skipSpace(&mut self) -> int {
        let mut n: int = 0;
        loop {
            let (c, err) = self.R.ReadByte();
            if err != nil {
                break;
            }
            if c != b' ' && c != b'\t' {
                let _ = self.R.UnreadByte();
                break;
            }
            n += 1;
        }
        n
    }

    // go: sdk 1.25.5 net/textproto/reader.go:506-508 Reader.ReadMIMEHeader
    // Go: reader.go:506-508
    //   func (r *Reader) ReadMIMEHeader() (MIMEHeader, error) {
    //       return readMIMEHeader(r, math.MaxInt64, math.MaxInt64)
    //   }
    pub fn ReadMIMEHeader(&mut self) -> (MIMEHeader, error) {
        readMIMEHeader(self, i64::MAX, i64::MAX)
    }

    // go: sdk 1.25.5 net/textproto/reader.go:620-642 Reader.upcomingHeaderKeys
    // Go: reader.go:620-642
    //   func (r *Reader) upcomingHeaderKeys() (n int)
    fn upcomingHeaderKeys(&mut self) -> int {
        // Go: r.R.Peek(1) — force buffer load.
        let _ = self.R.Peek(1);
        let s = self.R.Buffered();
        if s == 0 {
            return 0;
        }
        let (peek_slice, _) = self.R.Peek(s);
        let mut peek: &[byte] = peek_slice.as_ref();
        let nl: &[byte] = b"\n";
        let mut n: int = 0;
        while !peek.is_empty() && n < 1000 {
            // Go: line, peek, _ = bytes.Cut(peek, nl)
            let (line, rest) = match cut_bytes(peek, nl) {
                Some((a, b)) => (a, b),
                None => (peek, &[][..]),
            };
            // Go: if len(line) == 0 || (len(line) == 1 && line[0] == '\r') { break }
            if line.is_empty() || (line.len() == 1 && line[0] == b'\r') {
                break;
            }
            // Go: if line[0] == ' ' || line[0] == '\t' { continue }
            if line[0] == b' ' || line[0] == b'\t' {
                peek = rest;
                continue;
            }
            n += 1;
            peek = rest;
        }
        n
    }
}

// Go: reader.go:108-118
//   func trim(s []byte) []byte { ... }  — leading/trailing space|tab.
fn trim_slice(s: &slice<byte>) -> slice<byte> {
    let raw: &[byte] = s.as_ref();
    let mut i: usize = 0;
    while i < raw.len() && (raw[i] == b' ' || raw[i] == b'\t') {
        i += 1;
    }
    let mut n: usize = raw.len();
    while n > i && (raw[n - 1] == b' ' || raw[n - 1] == b'\t') {
        n -= 1;
    }
    let mut out: Vec<byte> = Vec::with_capacity(n - i);
    for k in i..n {
        out.push(raw[k]);
    }
    slice::__from_vec(out)
}

// Validator selector for readContinuedLineSlice.
#[derive(Copy, Clone)]
enum ValidatorKind {
    None,
    MustHaveFieldNameColon,
}

// Go: reader.go:604
//   func noValidation(_ []byte) error { return nil }
// Go: reader.go:609-614
//   func mustHaveFieldNameColon(line []byte) error
fn run_validator(kind: ValidatorKind, line: &slice<byte>) -> Result<(), error> {
    match kind {
        ValidatorKind::None => Ok(()),
        ValidatorKind::MustHaveFieldNameColon => {
            if bytes::IndexByte(line.clone(), b':') < 0 {
                // Go: ProtocolError(fmt.Sprintf("malformed MIME header:
                // missing colon: %q", line)).
                //
                // The format string here was `"{}"` — a RUST placeholder
                // in a Go format string, which `Sprintf` copies out
                // literally and then reports the unused argument after.
                // The message read `missing colon: {}%!(EXTRA
                // string="A 1")`. It was invisible until `%!(EXTRA …)`
                // existed to say an argument had gone nowhere.
                let raw: &[byte] = line.as_ref();
                let msg = crate::Sprintf!(
                    "malformed MIME header: missing colon: %q",
                    string::from_bytes(raw)
                );
                return Err(errors::Wrap(ProtocolError(msg)));
            }
            Ok(())
        }
    }
}

// `bytes.Cut` for raw &[byte] views, used by upcomingHeaderKeys.
// (We can't use bytes::Cut because it consumes slice<byte>; here we
// need to keep slicing the same Peek-borrowed buffer.)
fn cut_bytes<'a>(s: &'a [byte], sep: &[byte]) -> Option<(&'a [byte], &'a [byte])> {
    if sep.is_empty() {
        return None;
    }
    let n = sep.len();
    if s.len() < n {
        return None;
    }
    for i in 0..=s.len() - n {
        if &s[i..i + n] == sep {
            return Some((&s[..i], &s[i + n..]));
        }
    }
    None
}

// go: sdk 1.25.5 net/textproto/textproto.go:152-155 isASCIILetter
// Go: textproto.go:152-155
//   func isASCIILetter(b byte) bool {
//       b |= 0x20
//       return 'a' <= b && b <= 'z'
//   }
fn isASCIILetter(b: byte) -> bool {
    let lower = b | 0x20;
    b'a' <= lower && lower <= b'z'
}

// Go: reader.go:485
//   var colon = []byte(":")
const COLON: byte = b':';

// go: sdk 1.25.5 net/textproto/reader.go:515-600 readMIMEHeader
// Go: reader.go:515-600
//   func readMIMEHeader(r *Reader, maxMemory, maxHeaders int64) (MIMEHeader, error)
fn readMIMEHeader<R: io::Reader>(
    r: &mut Reader<R>,
    mut max_memory: int,
    mut max_headers: int,
) -> (MIMEHeader, error) {
    // Go: hint := r.upcomingHeaderKeys()
    let mut hint = r.upcomingHeaderKeys();
    if hint > 1000 {
        hint = 1000;
    }
    let _ = hint; // We don't preallocate strs in goish; let-it-grow.

    // Go: m := make(MIMEHeader, hint)
    let mut m: MIMEHeader = map::new();

    // Go: maxMemory -= 400
    max_memory -= 400;
    const MAP_ENTRY_OVERHEAD: int = 200;

    // Go: if buf, err := r.R.Peek(1); err == nil && (buf[0] == ' ' || buf[0] == '\t')
    {
        let (buf, perr) = r.R.Peek(1);
        if perr == nil && buf.Len() >= 1 && (buf[0] == b' ' || buf[0] == b'\t') {
            const ERROR_LIMIT: int = 80;
            let (line, err) = r.readLineSlice(ERROR_LIMIT);
            if err != nil {
                return (m, err);
            }
            let raw: &[byte] = line.as_ref();
            // Go: ProtocolError("malformed MIME header initial line: " +
            // string(line)) — a concatenation, not a format.
            let lstr = string::from_bytes(raw);
            let msg = string::from_static("malformed MIME header initial line: ") + lstr;
            return (m, errors::Wrap(ProtocolError(msg)));
        }
    }

    // Go: for { kv, err := r.readContinuedLineSlice(maxMemory, mustHaveFieldNameColon)
    //          if len(kv) == 0 { return m, err }
    //          ... }
    loop {
        let (kv, err) = r.readContinuedLineSlice(max_memory, ValidatorKind::MustHaveFieldNameColon);
        if kv.Len() == 0 {
            return (m, err);
        }

        // Go: k, v, ok := bytes.Cut(kv, colon)
        let (k, v, ok) = bytes::Cut(kv.clone(), slice::__from_vec(alloc::vec![COLON]));
        if !ok {
            let kvstr = string::from_bytes(kv.as_ref());
            let msg = string::from_static("malformed MIME header line: ") + kvstr;
            return (m, errors::Wrap(ProtocolError(msg)));
        }

        // Go: key, ok := canonicalMIMEHeaderKey(k)
        let (key, ok2) = canonicalMIMEHeaderKey(k);
        if !ok2 {
            let kvstr = string::from_bytes(kv.as_ref());
            let msg = string::from_static("malformed MIME header line: ") + kvstr;
            return (m, errors::Wrap(ProtocolError(msg)));
        }

        // Go: for _, c := range v { if !validHeaderValueByte(c) { ... } }
        let vraw: &[byte] = v.as_ref();
        for &c in vraw {
            if !validHeaderValueByte(c) {
                let kvstr = string::from_bytes(kv.as_ref());
                let msg = string::from_static("malformed MIME header line: ") + kvstr;
                return (m, errors::Wrap(ProtocolError(msg)));
            }
        }

        max_headers -= 1;
        if max_headers < 0 {
            return (map::new(), errMessageTooLarge());
        }

        // Go: value := string(bytes.TrimLeft(v, " \t"))
        let trimmed = bytes::TrimLeft(v.clone(), slice::__from_vec(alloc::vec![b' ', b'\t']));
        let value = string::from_bytes(trimmed.as_ref());

        // Go: vv := m[key]; if vv == nil { maxMemory -= int64(len(key)) + mapEntryOverhead }
        let exists = m.Has(key.clone());
        if !exists {
            max_memory -= key.Len();
            max_memory -= MAP_ENTRY_OVERHEAD;
        }
        max_memory -= value.Len();
        if max_memory < 0 {
            return (m, errMessageTooLarge());
        }

        // Go: m[key] = append(vv, value)
        let mut cur: Vec<string> = if exists {
            m[key.clone()].clone().__into_vec()
        } else {
            Vec::new()
        };
        cur.push(value);
        m[key] = slice::__from_vec(cur);

        if err != nil {
            return (m, err);
        }
    }
}

// go: sdk 1.25.5 net/textproto/reader.go:683-709 validHeaderFieldByte
// Go: reader.go:683-709
//   func validHeaderFieldByte(c byte) bool
//
// RFC 7230 token char set: ALPHA / DIGIT / "!#$%&'*+-.^_`|~"
pub fn validHeaderFieldByte(c: byte) -> bool {
    match c {
        b'0'..=b'9'
        | b'a'..=b'z'
        | b'A'..=b'Z'
        | b'!'
        | b'#'
        | b'$'
        | b'%'
        | b'&'
        | b'\''
        | b'*'
        | b'+'
        | b'-'
        | b'.'
        | b'^'
        | b'_'
        | b'`'
        | b'|'
        | b'~' => true,
        _ => false,
    }
}

// go: sdk 1.25.5 net/textproto/reader.go:723-735 validHeaderValueByte
// Go: reader.go:723-735
//   func validHeaderValueByte(c byte) bool
//
// VCHAR (%x21-7E) | SP (%x20) | HTAB (%x09).
pub fn validHeaderValueByte(c: byte) -> bool {
    c == b'\t' || (c >= 0x20 && c <= 0x7e)
}

// go: sdk 1.25.5 net/textproto/reader.go:747-794 canonicalMIMEHeaderKey
// Go: reader.go:747-794
//   func canonicalMIMEHeaderKey(a []byte) (_ string, ok bool)
//
// Mutates `a` in place when valid; returns the canonical string.
// Slim: we work on a Vec<byte> copy so the input slice<byte> isn't
// disturbed (Go can mutate because `a` is a fresh alloc from
// readContinuedLineSlice).
fn canonicalMIMEHeaderKey(a: slice<byte>) -> (string, bool) {
    if a.Len() == 0 {
        return (string::new(), false);
    }
    let raw: &[byte] = a.as_ref();
    // Go: noCanon := false
    let mut no_canon = false;
    for &c in raw {
        if validHeaderFieldByte(c) {
            continue;
        }
        if c == b' ' {
            no_canon = true;
            continue;
        }
        return (string::from_bytes(raw), false);
    }
    if no_canon {
        return (string::from_bytes(raw), true);
    }

    // Canonicalize: first letter upper, upper after each '-', else lower.
    let mut out: Vec<byte> = Vec::with_capacity(raw.len());
    let mut upper = true;
    for &c in raw {
        let mut ch = c;
        if upper && ch >= b'a' && ch <= b'z' {
            ch -= b'a' - b'A';
        } else if !upper && ch >= b'A' && ch <= b'Z' {
            ch += b'a' - b'A';
        }
        out.push(ch);
        upper = ch == b'-';
    }
    (string::from_bytes(&out), true)
}

// go: sdk 1.25.5 net/textproto/reader.go:215-241 parseCodeLine
/// Go: split a response line into its numeric code, its
/// continuation flag and its message, checking the code against
/// `expectCode`.
///
/// Four rules, all of them load-bearing:
///
///   * The line must be at least four bytes and its FOURTH byte must
///     be a space or a hyphen. "220\r\n" is short, and so is
///     "220x ..." — the check is positional, not "starts with three
///     digits".
///   * A hyphen there means the response continues on the next line.
///   * A code below 100 is rejected as invalid even when it parses,
///     which is why "99 too small" fails on the positional check and
///     "099 x" would fail on this one.
///   * `expectCode` is matched by WIDTH: 1..9 checks the leading
///     digit, 10..99 the leading two, 100..999 the whole code. A
///     mismatch does not clear `code` or `message` — it reports an
///     `Error{code, message}` beside them, so a caller that ignores
///     the error still sees what the server said.
pub(crate) fn parseCodeLine(line: string, expectCode: int) -> (int, bool, string, error) {
    let b = line.as_bytes();
    if b.len() < 4 || (b[3] != b' ' && b[3] != b'-') {
        return (
            int::from(0),
            false,
            string::from_static(""),
            errors::Wrap(ProtocolError(
                string::from_static("short response: ") + line.clone(),
            )),
        );
    }
    let continued = b[3] == b'-';
    let head = string::from_bytes(&b[0..3]);
    let (code, aerr) = crate::strconv::Atoi(head);
    if !aerr.IsNil() || code < 100 {
        return (
            int::from(0),
            false,
            string::from_static(""),
            errors::Wrap(ProtocolError(
                string::from_static("invalid response code: ") + line.clone(),
            )),
        );
    }
    let message = string::from_bytes(&b[4..]);
    let ec = expectCode;
    let mismatch = (1 <= ec && ec < 10 && code / 100 != ec)
        || (10 <= ec && ec < 100 && code / 10 != ec)
        || (100 <= ec && ec < 1000 && code != ec);
    if mismatch {
        return (
            code,
            continued,
            message.clone(),
            errors::Wrap(super::Error {
                Code: code,
                Msg: message,
            }),
        );
    }
    return (code, continued, message, nil);
}

impl<R: io::Reader> Reader<R> {
    // go: sdk 1.25.5 net/textproto/reader.go:207-213 Reader.readCodeLine
    /// Read one line and parse it as a response code line.
    fn readCodeLine(&mut self, expectCode: int) -> (int, bool, string, error) {
        let (line, err) = self.ReadLine();
        if !err.IsNil() {
            return (int::from(0), false, string::from_static(""), err);
        }
        return parseCodeLine(line, expectCode);
    }

    // go: sdk 1.25.5 net/textproto/reader.go:252-258 Reader.ReadCodeLine
    /// Go: "ReadCodeLine reads a response code line of the form
    /// `code message` … If the response is multi-line, ReadCodeLine
    /// returns an error."
    ///
    /// The multi-line error carries the FIRST line's message, not the
    /// whole response — ReadResponse is the one that joins them.
    pub fn ReadCodeLine(&mut self, expectCode: int) -> (int, string, error) {
        let (code, continued, message, err) = self.readCodeLine(expectCode);
        if err.IsNil() && continued {
            return (
                code,
                message.clone(),
                errors::Wrap(ProtocolError(
                    string::from_static("unexpected multi-line response: ") + message,
                )),
            );
        }
        return (code, message, err);
    }

    // go: sdk 1.25.5 net/textproto/reader.go:286-314 Reader.ReadResponse
    /// Go: "ReadResponse reads a multi-line response of the form …
    /// Each line is a code followed by a hyphen, except the last."
    ///
    /// Lines are joined with '\n' — not "\r\n", and not the line's own
    /// terminator. A continuation line whose code does NOT match the
    /// first is appended VERBATIM (trailing CR/LF trimmed) and the
    /// loop keeps going, which is how a server that changes code
    /// mid-response cannot end the read early.
    pub fn ReadResponse(&mut self, expectCode: int) -> (int, string, error) {
        let (code, first_continued, first, mut err) = self.readCodeLine(expectCode);
        let multi = first_continued;
        let mut continued = first_continued;
        let mut message = first;
        while continued {
            let (line, lerr) = self.ReadLine();
            if !lerr.IsNil() {
                return (int::from(0), string::from_static(""), lerr);
            }
            let (code2, cont2, more, perr) = parseCodeLine(line.clone(), int::from(0));
            if !perr.IsNil() || code2 != code {
                message = message + string::from_static("\n") + trim_right_crlf(&line);
                continued = true;
                continue;
            }
            continued = cont2;
            message = message + string::from_static("\n") + more;
        }
        if !err.IsNil() && multi && message.Len() != 0 {
            // Go: "replace one line error message with all lines".
            err = errors::Wrap(super::Error {
                Code: code,
                Msg: message.clone(),
            });
        }
        return (code, message, err);
    }
}

// go: none — goish-only: Go writes `strings.TrimRight(line, "\r\n")`
// inline. goish's Reader.ReadLine already strips the terminator, so
// this only matters for a line that carried an embedded one.
/// Drop any trailing CR and LF bytes.
fn trim_right_crlf(s: &string) -> string {
    let b = s.as_bytes();
    let mut end = b.len();
    while end > 0 && (b[end - 1] == b'\r' || b[end - 1] == b'\n') {
        end -= 1;
    }
    return string::from_bytes(&b[..end]);
}

// go: sdk 1.25.5 net/textproto/reader.go:339-342 dotReader
/// Go's `dotReader`, the decoder `DotReader` hands back.
///
/// Go's holds a `*Reader` and the parent holds a `*dotReader` back, so
/// `closeDot` can drain an abandoned decoder before the next read.
/// goish's borrows the parent mutably instead, which makes the case
/// closeDot guards against — reading the parent while a decoder is
/// still live — impossible to write rather than something to clean up
/// after. A decoder ABANDONED mid-block still leaves the stream
/// mid-block, exactly as Go's does before closeDot runs; call
/// `Drain` if the rest of the block must be consumed.
pub struct dotReader<'a, R: io::Reader> {
    r: &'a mut Reader<R>,
    state: u8,
}

// go: none — goish-only: the state constants Go declares inside
// `dotReader.Read` as a `const (… = iota)` block.
const stateBeginLine: u8 = 0;
const stateDot: u8 = 1;
const stateDotCR: u8 = 2;
const stateCR: u8 = 3;
const stateData: u8 = 4;
const stateEOF: u8 = 5;

impl<'a, R: io::Reader> dotReader<'a, R> {
    // go: sdk 1.25.5 net/textproto/reader.go:434-446
    // (Go's `Reader.closeDot`; the name diverges because the receiver
    // does — see the doc below.)
    /// Go: "drains the current DotReader if any, making sure that it
    /// reads until the ending dot line." goish cannot reach the
    /// parent while this borrow is live, so the drain is a method on
    /// the decoder rather than on the Reader.
    pub fn Drain(&mut self) {
        let mut buf = crate::make!([]byte, 128);
        loop {
            let (_n, err) = io::Reader::Read(self, &mut buf);
            if !err.IsNil() {
                return;
            }
        }
    }
}

impl<'a, R: io::Reader> io::Reader for dotReader<'a, R> {
    // go: sdk 1.25.5 net/textproto/reader.go:345-430 dotReader.Read
    /// Go: "Run data through a simple state machine to elide leading
    /// dots, rewrite trailing \r\n into \n, and detect ending .\r\n
    /// line."
    ///
    /// Two details the state machine exists for, both measured: a
    /// lone `\r` that is NOT followed by `\n` is emitted as data
    /// (stateCR unreads and writes the saved `\r`), and a line
    /// beginning `.` that is not the terminator has exactly ONE dot
    /// removed — so "..stuffed" decodes to ".stuffed" and ".leading"
    /// decodes to "leading".
    ///
    /// Running out of input before the terminator is
    /// `io.ErrUnexpectedEOF`, not `io.EOF`, and whatever was decoded
    /// so far still comes back.
    fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        let mut n: usize = 0;
        let mut err = nil;
        while n < b.len() && self.state != stateEOF {
            let (mut c, rerr) = self.r.R.ReadByte();
            if !rerr.IsNil() {
                if crate::errors::Is(rerr.clone(), io::EOF) {
                    err = io::ErrUnexpectedEOF.into();
                } else {
                    err = rerr;
                }
                break;
            }
            match self.state {
                stateBeginLine => {
                    if c == b'.' {
                        self.state = stateDot;
                        continue;
                    }
                    if c == b'\r' {
                        self.state = stateCR;
                        continue;
                    }
                    self.state = stateData;
                }
                stateDot => {
                    if c == b'\r' {
                        self.state = stateDotCR;
                        continue;
                    }
                    if c == b'\n' {
                        self.state = stateEOF;
                        continue;
                    }
                    self.state = stateData;
                }
                stateDotCR => {
                    if c == b'\n' {
                        self.state = stateEOF;
                        continue;
                    }
                    // Go: "Not part of .\r\n. Consume leading dot and
                    // emit saved \r."
                    let _ = self.r.R.UnreadByte();
                    c = b'\r';
                    self.state = stateData;
                }
                stateCR => {
                    if c == b'\n' {
                        self.state = stateBeginLine;
                    } else {
                        // Go: "Not part of \r\n. Emit saved \r"
                        let _ = self.r.R.UnreadByte();
                        c = b'\r';
                        self.state = stateData;
                    }
                }
                _ => {
                    if c == b'\r' {
                        self.state = stateCR;
                        continue;
                    }
                    if c == b'\n' {
                        self.state = stateBeginLine;
                    }
                }
            }
            b[n] = c;
            n += 1;
        }
        if err.IsNil() && self.state == stateEOF {
            err = io::EOF.into();
        }
        let n64 = i64::try_from(n).unwrap_or(i64::MAX);
        return (int::from(n64), err);
    }
}

impl<R: io::Reader> Reader<R> {
    // go: sdk 1.25.5 net/textproto/reader.go:333-337 Reader.DotReader
    /// Go: "returns a new Reader that satisfies Reads using the
    /// decoded text of a dot-encoded block read from r."
    pub fn DotReader(&mut self) -> dotReader<'_, R> {
        return dotReader {
            r: self,
            state: stateBeginLine,
        };
    }

    // go: sdk 1.25.5 net/textproto/reader.go:449-451 Reader.ReadDotBytes
    /// Go: "reads a dot-encoding and returns the decoded data."
    pub fn ReadDotBytes(&mut self) -> (slice<byte>, error) {
        let mut d = self.DotReader();
        return io::ReadAll(&mut d);
    }

    // go: sdk 1.25.5 net/textproto/reader.go:457-483 Reader.ReadDotLines
    /// Go: "reads a dot-encoding and returns a slice containing the
    /// decoded lines, with the final \r\n or \n elided from each."
    ///
    /// Go's own comment says why this is not ReadDotBytes plus a
    /// Split: "reading a line at a time avoids needing a large
    /// contiguous block of memory and is simpler."
    ///
    /// A dot alone ends the block; any other leading dot has exactly
    /// one removed. Running out of input first is
    /// io.ErrUnexpectedEOF, with the lines read so far returned
    /// beside it.
    pub fn ReadDotLines(&mut self) -> (slice<string>, error) {
        let mut v = slice::<string>::new();
        let mut err = nil;
        loop {
            let (line, lerr) = self.ReadLine();
            if !lerr.IsNil() {
                if crate::errors::Is(lerr.clone(), io::EOF) {
                    err = io::ErrUnexpectedEOF.into();
                } else {
                    err = lerr;
                }
                break;
            }
            // Go: "Dot by itself marks end; otherwise cut one dot."
            let lb = line.as_bytes();
            let line = if lb.len() > 0 && lb[0] == b'.' {
                if lb.len() == 1 {
                    break;
                }
                string::from_bytes(&lb[1..])
            } else {
                line
            };
            v = crate::append!(v, line);
        }
        return (v, err);
    }
}
