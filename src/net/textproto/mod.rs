// net/textproto — generic text-based protocol support (HTTP, NNTP, SMTP).
//
// Line-by-line port of:
//   /nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/
//     net/textproto/textproto.go     (Error, ProtocolError, TrimString)
//     net/textproto/header.go        (MIMEHeader)
//     net/textproto/writer.go        (Writer, dotWriter, PrintfLine)
//
// Slim deviations:
//   * `Conn`, `Pipeline`, `Reader` are not ported in v1: HTTP doesn't
//     consume them (it has its own header reader), and SMTP/NNTP are
//     out of v1 scope.
//   * `MIMEHeader` is `map<string, slice<string>>`. The map keys must
//     already be canonicalized; the methods canonicalize for the caller.
//   * `dotWriter` is a struct that writes to a referenced bufio writer
//     by raw pointer — no goroutine sharing — matching Go's lifetime.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::bufio;
use crate::errors::{error, nil, ErrorTrait};
use crate::goslice::slice;
use crate::gomap::map;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int};

// ─── Error / ProtocolError (textproto.go:38, :49) ───────────────────

/// `textproto.Error` (textproto.go:38) — numeric error response from a server.
#[derive(Clone)]
pub struct Error {
    pub Code: int,
    pub Msg: string,
}

impl ErrorTrait for Error {
    fn Error(&self) -> string {
        // Go: fmt.Sprintf("%03d %s", e.Code, e.Msg)
        let mut out = alloc::string::String::new();
        // Manual %03d — pad with zeros to width 3.
        let n = self.Code;
        if n >= 0 && n < 1000 {
            let n3 = n as u32;
            out.push((b'0' + (n3 / 100) as u8) as char);
            out.push((b'0' + ((n3 / 10) % 10) as u8) as char);
            out.push((b'0' + (n3 % 10) as u8) as char);
        } else {
            push_dec(&mut out, n);
        }
        out.push(' ');
        let mb = crate::gostring::__crate_as_bytes(&self.Msg);
        if let Ok(s) = core::str::from_utf8(mb) {
            out.push_str(s);
        }
        string::from_bytes(out.as_bytes())
    }
}

fn push_dec(out: &mut alloc::string::String, mut n: int) {
    if n == 0 {
        out.push('0');
        return;
    }
    if n < 0 {
        out.push('-');
        n = -n;
    }
    let mut digits: Vec<u8> = Vec::new();
    while n > 0 {
        digits.push(b'0' + ((n % 10) as u8));
        n /= 10;
    }
    for &d in digits.iter().rev() {
        out.push(d as char);
    }
}

/// `textproto.ProtocolError` (textproto.go:49) — protocol violation.
#[derive(Clone)]
pub struct ProtocolError(pub string);

impl ErrorTrait for ProtocolError {
    fn Error(&self) -> string {
        self.0.clone()
    }
}

// ─── TrimString / TrimBytes (textproto.go:127, :138) ────────────────

/// `textproto.TrimString(s)` (textproto.go:127) — strip leading/trailing
/// ASCII space (' ', '\t', '\n', '\r').
pub fn TrimString(s: string) -> string {
    let b = crate::gostring::__crate_as_bytes(&s);
    let mut lo = 0usize;
    let mut hi = b.len();
    while lo < hi && isASCIISpace(b[lo]) {
        lo += 1;
    }
    while lo < hi && isASCIISpace(b[hi - 1]) {
        hi -= 1;
    }
    string::from_bytes(&b[lo..hi])
}

/// `textproto.TrimBytes(b)` (textproto.go:138) — slice variant of TrimString.
pub fn TrimBytes(b: slice<byte>) -> slice<byte> {
    let raw: &[byte] = &b;
    let mut lo = 0usize;
    let mut hi = raw.len();
    while lo < hi && isASCIISpace(raw[lo]) {
        lo += 1;
    }
    while lo < hi && isASCIISpace(raw[hi - 1]) {
        hi -= 1;
    }
    slice::__from_vec(raw[lo..hi].to_vec())
}

// Go: textproto.go:148
fn isASCIISpace(b: byte) -> bool {
    b == b' ' || b == b'\t' || b == b'\n' || b == b'\r'
}

// ─── MIMEHeader (header.go:9) ───────────────────────────────────────

/// `textproto.MIMEHeader` (header.go:9) — `map[string][]string`.
///
/// Canonicalizes keys via `CanonicalMIMEHeaderKey` on Add/Set/Get/Values/Del.
/// To use non-canonical keys, access the underlying map directly.
pub type MIMEHeader = map<string, slice<string>>;

/// `textproto.CanonicalMIMEHeaderKey(s)` (reader.go:651). Re-exported
/// from the http header implementation since both produce the same
/// RFC 9112 canonical form (`content-type` → `Content-Type`).
pub fn CanonicalMIMEHeaderKey(s: string) -> string {
    crate::net::http::CanonicalHeaderKey(s)
}

/// `(MIMEHeader).Add(key, value)` (header.go:13).
pub fn Add(h: &mut MIMEHeader, key: string, value: string) {
    let k = CanonicalMIMEHeaderKey(key);
    let cur = if h.Has(k.clone()) {
        h[k.clone()].clone()
    } else {
        slice::__from_vec(Vec::new())
    };
    let mut v: Vec<string> = cur.__into_vec();
    v.push(value);
    h[k] = slice::__from_vec(v);
}

/// `(MIMEHeader).Set(key, value)` (header.go:21).
pub fn Set(h: &mut MIMEHeader, key: string, value: string) {
    let k = CanonicalMIMEHeaderKey(key);
    h[k] = slice::__from_vec(alloc::vec![value]);
}

/// `(MIMEHeader).Get(key)` (header.go:30).
pub fn Get(h: &MIMEHeader, key: string) -> string {
    let k = CanonicalMIMEHeaderKey(key);
    if !h.Has(k.clone()) {
        return string::new();
    }
    let v = h[k].clone();
    if v.Len() == 0 {
        return string::new();
    }
    v[0].clone()
}

/// `(MIMEHeader).Values(key)` (header.go:46).
pub fn Values(h: &MIMEHeader, key: string) -> slice<string> {
    let k = CanonicalMIMEHeaderKey(key);
    if !h.Has(k.clone()) {
        return slice::__from_vec(Vec::new());
    }
    h[k].clone()
}

/// `(MIMEHeader).Del(key)` (header.go:54).
pub fn Del(h: &mut MIMEHeader, key: string) {
    let k = CanonicalMIMEHeaderKey(key);
    h.Delete(k);
}

// ─── Writer (writer.go:14) ──────────────────────────────────────────

/// `textproto.Writer` (writer.go:14).
pub struct Writer<W: io::Writer> {
    pub W: bufio::Writer<W>,
    /// `dot` field equivalent — we store dotWriter state inline rather
    /// than as a separate handle since goish doesn't ship a stable raw
    /// pointer abstraction. `DotWriter` returns a borrowing helper that
    /// must be `Close()`d before the next call.
    in_dot: bool,
}

/// `textproto.NewWriter(w)` (writer.go:21).
pub fn NewWriter<W: io::Writer>(w: bufio::Writer<W>) -> Writer<W> {
    Writer { W: w, in_dot: false }
}

const CRNL: &[byte] = &[b'\r', b'\n'];
const DOTCRNL: &[byte] = &[b'.', b'\r', b'\n'];

impl<W: io::Writer> Writer<W> {
    /// `(*Writer).PrintfLine(format, args...)` (writer.go:29).
    ///
    /// Slim form: takes a pre-formatted string (callers run
    /// `fmt::Sprintf!(format, args)` first). The original Go signature is
    /// variadic over `any` which we can't replicate without macro
    /// machinery; the macro layer in goish (`Fprintf!`) is the
    /// idiomatic path for variadic format calls.
    pub fn PrintfLine(&mut self, line: string) -> error {
        self.closeDot();
        let (_, err) = self.W.WriteString(line);
        if !err.IsNil() {
            return err;
        }
        let (_, err) = self.W.Write(slice::__from_vec(CRNL.to_vec()));
        if !err.IsNil() {
            return err;
        }
        self.W.Flush()
    }

    /// `(*Writer).DotWriter()` (writer.go:43) — returns a writer that
    /// applies dot-encoding (escapes leading dots, normalizes \n → \r\n,
    /// emits final ".\r\n" on Close).
    ///
    /// Callers must call `Close()` on the returned helper before the
    /// next `Writer` method (matches Go documentation).
    pub fn DotWriter<'a>(&'a mut self) -> DotWriter<'a, W> {
        self.closeDot();
        self.in_dot = true;
        DotWriter {
            w: self,
            state: WSTATE_BEGIN,
        }
    }

    fn closeDot(&mut self) {
        // No-op when in_dot was already cleared by an explicit Close.
        // (Go's pattern relies on dotWriter setting w.dot = nil; here
        // the borrow checker prevents the dotWriter and Writer from
        // coexisting, so this is effectively redundant.)
        self.in_dot = false;
    }
}

// Go: writer.go:60-65 — dotWriter states.
const WSTATE_BEGIN: int = 0;
const WSTATE_BEGIN_LINE: int = 1;
const WSTATE_CR: int = 2;
const WSTATE_DATA: int = 3;

/// `textproto.dotWriter` (writer.go:55) — borrowing dot-encoder.
pub struct DotWriter<'a, W: io::Writer> {
    w: &'a mut Writer<W>,
    state: int,
}

impl<'a, W: io::Writer> DotWriter<'a, W> {
    /// `(*dotWriter).Write(b)` (writer.go:67).
    pub fn Write(&mut self, b: slice<byte>) -> (int, error) {
        let raw: &[byte] = &b;
        let mut n: usize = 0;
        while n < raw.len() {
            let c = raw[n];
            match self.state {
                WSTATE_BEGIN | WSTATE_BEGIN_LINE => {
                    self.state = WSTATE_DATA;
                    if c == b'.' {
                        let err = self.w.W.WriteByte(b'.');
                        if !err.IsNil() {
                            return (n as int, err);
                        }
                    }
                    // fallthrough into WSTATE_DATA logic below.
                    if c == b'\r' {
                        self.state = WSTATE_CR;
                    }
                    if c == b'\n' {
                        let err = self.w.W.WriteByte(b'\r');
                        if !err.IsNil() {
                            return (n as int, err);
                        }
                        self.state = WSTATE_BEGIN_LINE;
                    }
                }
                WSTATE_DATA => {
                    if c == b'\r' {
                        self.state = WSTATE_CR;
                    }
                    if c == b'\n' {
                        let err = self.w.W.WriteByte(b'\r');
                        if !err.IsNil() {
                            return (n as int, err);
                        }
                        self.state = WSTATE_BEGIN_LINE;
                    }
                }
                WSTATE_CR => {
                    self.state = WSTATE_DATA;
                    if c == b'\n' {
                        self.state = WSTATE_BEGIN_LINE;
                    }
                }
                _ => {}
            }
            let err = self.w.W.WriteByte(c);
            if !err.IsNil() {
                return (n as int, err);
            }
            n += 1;
        }
        (n as int, nil)
    }

    /// `(*dotWriter).Close()` (writer.go:103) — flushes the trailer
    /// (".\r\n") according to current state.
    pub fn Close(mut self) -> error {
        // Go: switch d.state { default: WriteByte('\r'); fallthrough
        //                       case CR: WriteByte('\n'); fallthrough
        //                       case BeginLine: Write(".\r\n") }
        match self.state {
            WSTATE_BEGIN | WSTATE_BEGIN_LINE => {
                // Already at line start — emit ".\r\n" only.
                let err = self.w.W.WriteByte(b'.');
                if !err.IsNil() {
                    return err;
                }
                let err = self.w.W.WriteByte(b'\r');
                if !err.IsNil() {
                    return err;
                }
                let err = self.w.W.WriteByte(b'\n');
                if !err.IsNil() {
                    return err;
                }
            }
            WSTATE_CR => {
                let err = self.w.W.WriteByte(b'\n');
                if !err.IsNil() {
                    return err;
                }
                let err = self.w.W.WriteByte(b'.');
                if !err.IsNil() {
                    return err;
                }
                let err = self.w.W.WriteByte(b'\r');
                if !err.IsNil() {
                    return err;
                }
                let err = self.w.W.WriteByte(b'\n');
                if !err.IsNil() {
                    return err;
                }
            }
            _ => {
                // Mid-line — emit \r\n.\r\n.
                let err = self.w.W.WriteByte(b'\r');
                if !err.IsNil() {
                    return err;
                }
                let err = self.w.W.WriteByte(b'\n');
                if !err.IsNil() {
                    return err;
                }
                let err = self.w.W.WriteByte(b'.');
                if !err.IsNil() {
                    return err;
                }
                let err = self.w.W.WriteByte(b'\r');
                if !err.IsNil() {
                    return err;
                }
                let err = self.w.W.WriteByte(b'\n');
                if !err.IsNil() {
                    return err;
                }
            }
        }
        let _ = DOTCRNL; // referenced for clarity
        self.w.in_dot = false;
        self.w.W.Flush()
    }
}
