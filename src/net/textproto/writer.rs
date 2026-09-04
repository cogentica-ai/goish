// net/textproto/writer — Go 1.25.5 src/net/textproto/writer.go.
//
// One `.rs` per `.go` (§33).

#![allow(non_snake_case)]

extern crate alloc;

use crate::bufio;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int};

// go: sdk 1.25.5 net/textproto/writer.go:15-18 Writer
/// Go: "A Writer implements convenience methods for writing requests
/// or responses to a text protocol network connection."
// goishlint:ignore GOISH019 Writer — Go's carries a `dot *dotWriter`
// back-pointer so `closeDot` can flush an abandoned encoder. goish's
// encoder borrows the parent mutably, which makes that state
// unrepresentable rather than something to track.
pub struct Writer<W: io::Writer> {
    pub W: bufio::Writer<W>,
}

// go: sdk 1.25.5 net/textproto/writer.go:21-23 NewWriter
/// Go: "NewWriter returns a new Writer writing to w."
pub fn NewWriter<W: io::Writer>(w: bufio::Writer<W>) -> Writer<W> {
    return Writer { W: w };
}

// go: none — goish-only: Go writes the literal `[]byte(".\r\n")` as
// the package var `dotcrnl`.
/// The line that terminates a dot-encoded block.
const dotcrnl: &[u8] = b".\r\n";

impl<W: io::Writer> Writer<W> {
    // go: sdk 1.25.5 net/textproto/writer.go:29-40 Writer.PrintfLine
    /// Go: "PrintfLine writes the formatted output followed by \r\n."
    ///
    /// goish takes the formatted string rather than a format and
    /// arguments: `Sprintf!` is a macro here, so the caller writes
    /// `w.PrintfLine(fmt::Sprintf!("%d %s", code, msg))`. The name
    /// keeps Go's because the wire behaviour is Go's.
    ///
    /// It appends \r\n UNCONDITIONALLY — it does not check whether the text already
    /// ends in a line terminator, so `PrintfLine("already\r\n")`
    /// writes "already\r\n\r\n". Measured; a port that "helpfully"
    /// suppressed the second pair would break every protocol that
    /// sends a deliberate blank line.
    // goishlint:ignore GOISH020 PrintfLine — Go's is variadic
    // (format, args...); goish's `Sprintf!` is a macro, so the caller
    // formats and this takes the finished string. See the doc above.
    pub fn PrintfLine(&mut self, s: string) -> error {
        let (_n, err) = self.W.WriteString(s);
        if !err.IsNil() {
            return err;
        }
        let e = self.W.WriteByte(b'\r');
        if !e.IsNil() {
            return e;
        }
        let e = self.W.WriteByte(b'\n');
        if !e.IsNil() {
            return e;
        }
        return self.W.Flush();
    }

    // go: sdk 1.25.5 net/textproto/writer.go:43-47 Writer.DotWriter
    /// Go: "DotWriter returns a writer that can be used to write a
    /// dot-encoding to w. It takes care of inserting leading dots
    /// when necessary, translating line-ending \n into \r\n, and
    /// adding the final .\r\n line."
    ///
    /// As with DotReader, goish borrows the parent instead of holding
    /// a back-pointer, so Go's `closeDot` has nothing to guard
    /// against: the parent cannot be written to while the encoder is
    /// alive. The encoder must still be Closed to emit the
    /// terminator.
    pub fn DotWriter(&mut self) -> dotWriter<'_, W> {
        return dotWriter {
            w: self,
            state: wstateBegin,
        };
    }
}

// go: none — goish-only: the state constants Go declares as a
// `const (… = iota)` block beside dotWriter.
const wstateBegin: u8 = 0;
const wstateBeginLine: u8 = 1;
const wstateCR: u8 = 2;
const wstateData: u8 = 3;

// go: sdk 1.25.5 net/textproto/writer.go:55-58 dotWriter
/// Go's dot-encoder. See `Writer::DotWriter`.
pub struct dotWriter<'a, W: io::Writer> {
    w: &'a mut Writer<W>,
    state: u8,
}

impl<'a, W: io::Writer> io::Writer for dotWriter<'a, W> {
    // go: sdk 1.25.5 net/textproto/writer.go:67-101 dotWriter.Write
    /// Three transformations, all measured:
    ///
    ///   * a `.` at the START of a line gets a second one, so
    ///     ".leading" goes out as "..leading" — a dot anywhere else
    ///     is untouched, which is why "mid.dot" is unchanged;
    ///   * a bare `\n` becomes `\r\n`;
    ///   * a lone `\r` NOT followed by `\n` passes through as data.
    ///
    /// The returned count is of INPUT bytes consumed, not bytes
    /// written — "line one\nline two\n" reports 18 while writing 20.
    fn Write(&mut self, b: slice<byte>) -> (int, error) {
        let mut n: usize = 0;
        let mut err = nil;
        while n < b.len() {
            let c = b[n];
            // Go writes this as a `switch` with two fallthroughs; the
            // begin states fall into the data state after escaping a
            // leading dot.
            if self.state == wstateBegin || self.state == wstateBeginLine {
                self.state = wstateData;
                if c == b'.' {
                    let e = self.w.W.WriteByte(b'.');
                    if !e.IsNil() {
                        err = e;
                        break;
                    }
                }
            }
            if self.state == wstateData {
                if c == b'\r' {
                    self.state = wstateCR;
                }
                if c == b'\n' {
                    let e = self.w.W.WriteByte(b'\r');
                    if !e.IsNil() {
                        err = e;
                        break;
                    }
                    self.state = wstateBeginLine;
                }
            } else if self.state == wstateCR {
                self.state = wstateData;
                if c == b'\n' {
                    self.state = wstateBeginLine;
                }
            }
            let e = self.w.W.WriteByte(c);
            if !e.IsNil() {
                err = e;
                break;
            }
            n += 1;
        }
        let n64 = i64::try_from(n).unwrap_or(i64::MAX);
        return (int::from(n64), err);
    }
}

impl<'a, W: io::Writer> io::Closer for dotWriter<'a, W> {
    // go: sdk 1.25.5 net/textproto/writer.go:103-118 dotWriter.Close
    /// Emit whatever line ending the body still owes, then the
    /// terminating ".\r\n", then flush.
    ///
    /// An EMPTY body still gets a CRLF first: the initial state falls
    /// through Go's `default` arm, so `DotWriter().Close()` with
    /// nothing written emits "\r\n.\r\n". Measured — a port that
    /// treated "nothing written" as "nothing to terminate" would send
    /// a body the peer reads as unterminated.
    fn Close(&mut self) -> error {
        if self.state != wstateCR && self.state != wstateBeginLine {
            let e = self.w.W.WriteByte(b'\r');
            if !e.IsNil() {
                return e;
            }
            self.state = wstateCR;
        }
        if self.state == wstateCR {
            let e = self.w.W.WriteByte(b'\n');
            if !e.IsNil() {
                return e;
            }
        }
        let (_n, e) = self
            .w
            .W
            .Write(crate::convert::bytes(string::from_bytes(dotcrnl)));
        if !e.IsNil() {
            return e;
        }
        return self.w.W.Flush();
    }
}
