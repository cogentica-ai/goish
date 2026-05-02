// net/textproto/reader.rs — slim line-by-line port of Go 1.25 net/textproto/reader.go.
//
// Source: /nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/net/textproto/reader.go
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
use alloc::string::String;
use alloc::vec::Vec;

use crate::bufio;
use crate::bytes;
use crate::errors::{self, error, nil, ErrorTrait};
use crate::goslice::slice;
use crate::gomap::map;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int};

use super::{ProtocolError, MIMEHeader};

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

// Go: reader.go:37-39
//   func NewReader(r *bufio.Reader) *Reader { return &Reader{R: r} }
pub fn NewReader<R: io::Reader>(r: bufio::Reader<R>) -> Reader<R> {
    Reader { R: r, buf: Vec::new() }
}

impl<R: io::Reader> Reader<R> {
    // Go: reader.go:43-46
    //   func (r *Reader) ReadLine() (string, error) {
    //       line, err := r.readLineSlice(-1)
    //       return string(line), err
    //   }
    pub fn ReadLine(&mut self) -> (string, error) {
        let (line, err) = self.readLineSlice(-1);
        (string::from_bytes(line.as_ref()), err)
    }

    // Go: reader.go:49-55
    //   func (r *Reader) ReadLineBytes() ([]byte, error) { ... }
    pub fn ReadLineBytes(&mut self) -> (slice<byte>, error) {
        let (line, err) = self.readLineSlice(-1);
        // Go: if line != nil { line = bytes.Clone(line) }
        // Slim: __from_vec already takes ownership of a fresh Vec, so no
        //       additional clone is necessary.
        (line, err)
    }

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

    // Go: reader.go:101-104
    //   func (r *Reader) ReadContinuedLine() (string, error) { ... }
    pub fn ReadContinuedLine(&mut self) -> (string, error) {
        let (line, err) = self.readContinuedLineSlice(-1, ValidatorKind::None);
        (string::from_bytes(line.as_ref()), err)
    }

    // Go: reader.go:122-128
    //   func (r *Reader) ReadContinuedLineBytes() ([]byte, error) { ... }
    pub fn ReadContinuedLineBytes(&mut self) -> (slice<byte>, error) {
        let (line, err) = self.readContinuedLineSlice(-1, ValidatorKind::None);
        // Go bytes.Clone — slim: already a fresh slice.
        (line, err)
    }

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
            let optimistic = (!pb.is_empty()
                && (isASCIILetter(pb[0]) || pb[0] == b'\n'))
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

    // Go: reader.go:506-508
    //   func (r *Reader) ReadMIMEHeader() (MIMEHeader, error) {
    //       return readMIMEHeader(r, math.MaxInt64, math.MaxInt64)
    //   }
    pub fn ReadMIMEHeader(&mut self) -> (MIMEHeader, error) {
        readMIMEHeader(self, i64::MAX, i64::MAX)
    }

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
                let raw: &[byte] = line.as_ref();
                let qs = quote_byteslice(raw);
                let msg = crate::Sprintf!("malformed MIME header: missing colon: {}", qs);
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

// Helper: Go-style %q quoting for a byte slice (used in error messages).
// Slim: only handles printable ASCII + standard escapes.
fn quote_byteslice(b: &[byte]) -> string {
    let mut s = String::with_capacity(b.len() + 2);
    s.push('"');
    for &c in b {
        match c {
            b'\\' => s.push_str("\\\\"),
            b'"' => s.push_str("\\\""),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7e => s.push(c as char),
            _ => {
                // Octal-style fallback (Go uses \xHH); we use \xHH too.
                use core::fmt::Write;
                let _ = write!(s, "\\x{:02x}", c);
            }
        }
    }
    s.push('"');
    string::from_bytes(s.as_bytes())
}

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
            let lstr = string::from_bytes(raw);
            let msg = crate::Sprintf!("malformed MIME header initial line: {}", lstr);
            return (m, errors::Wrap(ProtocolError(msg)));
        }
    }

    // Go: for { kv, err := r.readContinuedLineSlice(maxMemory, mustHaveFieldNameColon)
    //          if len(kv) == 0 { return m, err }
    //          ... }
    loop {
        let (kv, err) =
            r.readContinuedLineSlice(max_memory, ValidatorKind::MustHaveFieldNameColon);
        if kv.Len() == 0 {
            return (m, err);
        }

        // Go: k, v, ok := bytes.Cut(kv, colon)
        let (k, v, ok) = bytes::Cut(kv.clone(), slice::__from_vec(alloc::vec![COLON]));
        if !ok {
            let kvstr = string::from_bytes(kv.as_ref());
            let msg = crate::Sprintf!("malformed MIME header line: {}", kvstr);
            return (m, errors::Wrap(ProtocolError(msg)));
        }

        // Go: key, ok := canonicalMIMEHeaderKey(k)
        let (key, ok2) = canonicalMIMEHeaderKey(k);
        if !ok2 {
            let kvstr = string::from_bytes(kv.as_ref());
            let msg = crate::Sprintf!("malformed MIME header line: {}", kvstr);
            return (m, errors::Wrap(ProtocolError(msg)));
        }

        // Go: for _, c := range v { if !validHeaderValueByte(c) { ... } }
        let vraw: &[byte] = v.as_ref();
        for &c in vraw {
            if !validHeaderValueByte(c) {
                let kvstr = string::from_bytes(kv.as_ref());
                let msg = crate::Sprintf!("malformed MIME header line: {}", kvstr);
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

// Go: reader.go:723-735
//   func validHeaderValueByte(c byte) bool
//
// VCHAR (%x21-7E) | SP (%x20) | HTAB (%x09).
pub fn validHeaderValueByte(c: byte) -> bool {
    c == b'\t' || (c >= 0x20 && c <= 0x7e)
}

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
