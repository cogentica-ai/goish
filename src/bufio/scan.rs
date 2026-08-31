// go: file bufio/scan.go decls: ErrFinalToken, NewScanner, Scanner.Err, Scanner.Bytes, Scanner.Text, Scanner.Scan, Scanner.advance, Scanner.setErr, Scanner.Buffer, Scanner.Split, ScanBytes, ScanRunes, dropCR, ScanLines, isSpace, ScanWords
//
// `ErrFinalToken` is a package-level `var` in Go and lives in the
// module root here — the root holds every sentinel, because Go splits
// them across two `var` blocks, one per file, and both files read both
// sets. It is named in the manifest anyway because goish spells it as a
// `fn`: `errors::New` is not `const`.
//
// goishlint:ignore GOISH021 errorRune — Go's `var errorRune =
//     []byte(string(utf8.RuneError))` is a package-level slice so
//     `ScanRunes` can return it without re-encoding. goish's ScanRunes
//     encodes U+FFFD into a 4-byte stack array at the one site that
//     needs it, so there is nothing to hoist.
//
// bufio/scan.go — the `Scanner`: line-, byte-, rune- and word-tokenized
// reading over an `io.Reader`.
//
// A `SplitFunc` is called with everything buffered so far and a flag
// saying whether the reader has hit EOF, and answers with how far to
// advance, the token to hand back, and an error. Returning a nil token
// means "no token yet, read more" — which is why goish's token is an
// `Option<slice<byte>>`: Go distinguishes a nil `[]byte` from an empty
// one, and a blank line is an empty token, not the absence of one.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::convert::int as toint;
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::runtime::spin::SpinLock;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

use super::bufio::{cached_error, index_byte, maxConsecutiveEmptyReads, ErrNoProgress};

// ─── Constants ────────────────────────────────────────────────────────

// go: sdk 1.25.5 bufio/scan.go:77-85 MaxScanTokenSize
/// The maximum size used to buffer a token unless the user provides an
/// explicit buffer with [`Scanner::Buffer`]. The maximum token size is
/// roughly `MaxScanTokenSize` unless the caller does so.
pub const MaxScanTokenSize: int = 64 * 1024;

// go: sdk 1.25.5 bufio/scan.go:77-85 startBufSize
/// The size of the buffer the Scanner starts with.
const startBufSize: usize = 4096;

// go: sdk 1.25.5 bufio/scan.go:70-75 ErrTooLong
crate::var! {
    /// The token was longer than the Scanner's buffer allows.
    pub ErrTooLong: error            = "bufio.Scanner: token too long";
    /// A SplitFunc returned a negative advance count.
    pub ErrNegativeAdvance: error    = "bufio.Scanner: SplitFunc returns negative advance count";
    /// A SplitFunc advanced past the end of the input.
    pub ErrAdvanceTooFar: error      = "bufio.Scanner: SplitFunc returns advance count beyond input";
    /// `Read` returned a count that cannot be right.
    pub ErrBadReadCount: error       = "bufio.Scanner: Read returned impossible count";
}

// go: sdk 1.25.5 bufio/scan.go:128-128 ErrFinalToken
/// `bufio.ErrFinalToken` — a special sentinel a `SplitFunc` may return
/// to stop the `Scanner` after delivering one last token, with no error
/// reported from `Err`.
pub fn ErrFinalToken() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    return cached_error(&SLOT, || {
        return errors::New("final token");
    });
}
// ─── SplitFunc type ───────────────────────────────────────────────────

/// Boxed FnMut closure with the same signature as Go's SplitFunc:
/// `(data, atEOF) -> (advance, token, err)`.
///
/// `Option<slice<byte>>` carries Go's "nil vs empty" distinction:
///   * `None`           — "no token, read more or stop"
///   * `Some(empty)`    — "this is an empty token (e.g., a blank line)"
///   * `Some(non-empty)`— normal token
pub type SplitFunc = Box<dyn FnMut(&[byte], bool) -> (int, Option<slice<byte>>, error) + 'static>;

// ─── Scanner ──────────────────────────────────────────────────────────

pub struct Scanner<R: io::Reader> {
    r: R,
    split: SplitFunc,
    maxTokenSize: int,
    token: Option<slice<byte>>,
    buf: Vec<byte>,
    start: usize,
    end: usize,
    err: error,
    empties: int,
    scanCalled: bool,
    done: bool,
}

// go: sdk 1.25.5 bufio/scan.go:89-95 NewScanner
/// `bufio.NewScanner(r)` — defaults to ScanLines.
pub fn NewScanner<R: io::Reader>(r: R) -> Scanner<R> {
    return Scanner {
        r,
        split: Box::new(ScanLines),
        maxTokenSize: MaxScanTokenSize,
        token: None,
        buf: Vec::new(),
        start: 0,
        end: 0,
        err: nil,
        empties: 0,
        scanCalled: false,
        done: false,
    };
}

impl<R: io::Reader> Scanner<R> {
    // go: sdk 1.25.5 bufio/scan.go:108-110 Scanner.Bytes
    /// Most recent token's bytes (a fresh clone). Empty if no token yet.
    pub fn Bytes(&self) -> slice<byte> {
        return match &self.token {
            Some(t) => t.clone(),
            None => slice::new(),
        };
    }

    // go: sdk 1.25.5 bufio/scan.go:114-116 Scanner.Text
    /// Most recent token as a `string`.
    pub fn Text(&self) -> string {
        return match &self.token {
            Some(t) => string::from_bytes(t),
            None => string::new(),
        };
    }

    // go: sdk 1.25.5 bufio/scan.go:98-103 Scanner.Err
    /// First non-EOF error encountered. `nil` if scanning ended cleanly.
    pub fn Err(&self) -> error {
        if errors::Is(self.err.clone(), io::EOF) {
            return nil;
        }
        return self.err.clone();
    }

    // go: sdk 1.25.5 bufio/scan.go:287-292 Scanner.Split
    /// Override the split function. Panics if called after Scan.
    pub fn Split<F>(&mut self, split: F)
    where
        F: FnMut(&[byte], bool) -> (int, Option<slice<byte>>, error) + 'static,
    {
        if self.scanCalled {
            panic!("bufio.Scanner: Split called after Scan");
        }
        self.split = Box::new(split);
    }

    // go: sdk 1.25.5 bufio/scan.go:275-281 Scanner.Buffer
    /// Override the buffer and max token size. Panics if called after Scan.
    pub fn Buffer(&mut self, buf: slice<byte>, max: int) {
        if self.scanCalled {
            panic!("bufio.Scanner: Buffer called after Scan");
        }
        let mut v = buf.__into_vec();
        let cap = v.capacity();
        unsafe { v.set_len(cap) }
        self.buf = v;
        self.end = 0;
        self.start = 0;
        self.maxTokenSize = max;
    }

    // go: sdk 1.25.5 bufio/scan.go:257-261 Scanner.setErr
    fn setErr(&mut self, e: error) {
        if self.err == nil || errors::Is(self.err.clone(), io::EOF) {
            self.err = e;
        }
    }

    // go: sdk 1.25.5 bufio/scan.go:243-254 Scanner.advance
    fn advance(&mut self, n: int) -> bool {
        if n < 0 {
            self.setErr(ErrNegativeAdvance.into());
            return false;
        }
        if (n as usize) > self.end - self.start {
            self.setErr(ErrAdvanceTooFar.into());
            return false;
        }
        self.start += n as usize;
        return true;
    }

    // go: sdk 1.25.5 bufio/scan.go:139-240 Scanner.Scan
    // goishlint:ignore GOISH023 — the body ends in an infinite
    //     `loop` whose every exit is a `return` from inside it, so
    //     there is no tail expression to make explicit. Go writes the
    //     same shape: `for { … }` with returns in the body.
    /// Advance to the next token. Returns false at EOF or on error.
    pub fn Scan(&mut self) -> bool {
        if self.done {
            return false;
        }
        self.scanCalled = true;
        loop {
            // Try to extract a token from what we have.
            if self.end > self.start || self.err != nil {
                let at_eof = self.err != nil;
                let (advance, token, split_err) =
                    (self.split)(&self.buf[self.start..self.end], at_eof);
                if split_err != nil {
                    self.setErr(split_err);
                    return false;
                }
                if !self.advance(advance) {
                    return false;
                }
                self.token = token;
                if self.token.is_some() {
                    if self.err == nil || advance > 0 {
                        self.empties = 0;
                    } else {
                        self.empties += 1;
                        if self.empties > maxConsecutiveEmptyReads {
                            panic!("bufio.Scan: too many empty tokens without progressing");
                        }
                    }
                    return true;
                }
            }
            // No token from current data. If there's a pending error, stop.
            if self.err != nil {
                self.start = 0;
                self.end = 0;
                return false;
            }
            // Read more.
            //
            // Shift to start if buffer is full or more than half-consumed.
            if self.start > 0 && (self.end == self.buf.len() || self.start > self.buf.len() / 2) {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            // Grow if full.
            if self.end == self.buf.len() {
                if self.buf.len() >= self.maxTokenSize as usize {
                    self.setErr(ErrTooLong.into());
                    return false;
                }
                let mut new_size = self.buf.len() * 2;
                if new_size == 0 {
                    new_size = startBufSize;
                }
                if new_size > self.maxTokenSize as usize {
                    new_size = self.maxTokenSize as usize;
                }
                self.buf.resize(new_size, 0);
            }
            // Read into buf[end..].
            let mut loop_count = 0;
            loop {
                let want = self.buf.len() - self.end;
                let mut tmp: slice<byte> = slice::__from_vec({
                    let mut v: Vec<byte> = Vec::with_capacity(want);
                    v.resize(want, 0);
                    v
                });
                let (n_io, read_err) = self.r.Read(&mut tmp);
                if n_io < 0 || (n_io as usize) > want {
                    self.setErr(ErrBadReadCount.into());
                    break;
                }
                if n_io > 0 {
                    let src = tmp.__into_vec();
                    self.buf[self.end..self.end + n_io as usize]
                        .copy_from_slice(&src[..n_io as usize]);
                    self.end += n_io as usize;
                }
                if read_err != nil {
                    self.setErr(read_err);
                    break;
                }
                if n_io > 0 {
                    self.empties = 0;
                    break;
                }
                loop_count += 1;
                if loop_count > maxConsecutiveEmptyReads {
                    self.setErr(ErrNoProgress.into());
                    break;
                }
            }
        }
    }
}

// ─── Split functions ──────────────────────────────────────────────────

// go: sdk 1.25.5 bufio/scan.go:344-350 dropCR
/// Drops a terminal \r from the data.
fn dropCR(data: &[byte]) -> &[byte] {
    if !data.is_empty() && data[data.len() - 1] == b'\r' {
        return &data[..data.len() - 1];
    }
    return data;
}

// go: sdk 1.25.5 bufio/scan.go:352-375 ScanLines
/// A split function for a [`Scanner`] that returns each line of text,
/// stripped of any trailing end-of-line marker. The returned line may
/// be empty. The end-of-line marker is one optional carriage return
/// followed by one mandatory newline.
///
/// In regular expression notation, it is `\r?\n`. The last non-empty
/// line of input is returned even if it has no newline.
pub fn ScanLines(data: &[byte], at_eof: bool) -> (int, Option<slice<byte>>, error) {
    if at_eof && data.is_empty() {
        return (0, None, nil);
    }
    if let Some(i) = index_byte(data, b'\n') {
        // We have a full newline-terminated line.
        return (
            toint(i + 1),
            Some(slice::__from_vec(dropCR(&data[..i]).to_vec())),
            nil,
        );
    }
    // If we're at EOF, we have a final, non-terminated line. Return it.
    if at_eof {
        return (
            toint(data.len()),
            Some(slice::__from_vec(dropCR(data).to_vec())),
            nil,
        );
    }
    // Request more data.
    return (0, None, nil);
}

// go: sdk 1.25.5 bufio/scan.go:297-302 ScanBytes
/// `bufio.ScanBytes` — yields one byte per token.
pub fn ScanBytes(data: &[byte], at_eof: bool) -> (int, Option<slice<byte>>, error) {
    if at_eof && data.is_empty() {
        return (0, None, nil);
    }
    return (1, Some(slice::__from_vec(data[..1].to_vec())), nil);
}

// go: sdk 1.25.5 bufio/scan.go:312-342 ScanRunes
/// `bufio.ScanRunes` — yields one UTF-8-encoded rune per token. Invalid
/// encodings translate to U+FFFD (`"\xef\xbf\xbd"`).
pub fn ScanRunes(data: &[byte], at_eof: bool) -> (int, Option<slice<byte>>, error) {
    if at_eof && data.is_empty() {
        return (0, None, nil);
    }
    if data[0] < utf8::RuneSelf {
        return (1, Some(slice::__from_vec(data[..1].to_vec())), nil);
    }
    let (_, width) = utf8::DecodeRune(data);
    if width > 1 {
        return (
            width,
            Some(slice::__from_vec(data[..width as usize].to_vec())),
            nil,
        );
    }
    // width == 1 with implicit RuneError. Was the encoding incomplete?
    if !at_eof && !utf8::FullRune(data) {
        return (0, None, nil);
    }
    let mut tmp = [0u8; 4];
    let n = utf8::EncodeRune(&mut tmp, utf8::RuneError);
    return (1, Some(slice::__from_vec(tmp[..n as usize].to_vec())), nil);
}

// go: sdk 1.25.5 bufio/scan.go:403-427 ScanWords
/// A split function for a [`Scanner`] that returns each space-separated
/// word of text, with surrounding spaces deleted. It never returns an
/// empty token. The definition of space is [`isSpace`].
///
/// Both loops step by the *rune* width, not by one byte: a multi-byte
/// space has to be consumed whole, and the advance Go reports is
/// `i + width`.
pub fn ScanWords(data: &[byte], at_eof: bool) -> (int, Option<slice<byte>>, error) {
    // Skip leading spaces.
    let mut start = 0usize;
    while start < data.len() {
        let (r, width) = utf8::DecodeRune(&data[start..]);
        if !isSpace(r) {
            break;
        }
        start += width as usize;
    }
    // Scan until space, marking end of word.
    let mut i = start;
    while i < data.len() {
        let (r, width) = utf8::DecodeRune(&data[i..]);
        if isSpace(r) {
            return (
                toint(i + width as usize),
                Some(slice::__from_vec(data[start..i].to_vec())),
                nil,
            );
        }
        i += width as usize;
    }
    // If we're at EOF, we have a final, non-empty, non-terminated word.
    if at_eof && data.len() > start {
        return (
            toint(data.len()),
            Some(slice::__from_vec(data[start..].to_vec())),
            nil,
        );
    }
    // Request more data.
    return (toint(start), None, nil);
}

// ─── Helpers ──────────────────────────────────────────────────────────

// go: sdk 1.25.5 bufio/scan.go:377-397 isSpace
/// Go's own space table, not `unicode.IsSpace`: scan.go carries a copy
/// so the package does not pull in the unicode tables.
///
/// This had been an ASCII-only `matches!` over six bytes, so `ScanWords`
/// did not split on NBSP (U+00A0), NEL (U+0085), the U+2000..U+200A
/// run, or the ideographic space U+3000 — every one of which Go treats
/// as a space.
fn isSpace(r: rune) -> bool {
    if r <= 0x00FF {
        // Obvious ASCII ones: \t through \r plus space. Plus two
        // Latin-1 oddballs.
        if r == 0x20 || (0x09..=0x0D).contains(&r) {
            return true;
        }
        if r == 0x85 || r == 0xA0 {
            return true;
        }
        return false;
    }
    // High-valued ones.
    if (0x2000..=0x200A).contains(&r) {
        return true;
    }
    if r == 0x1680 || r == 0x2028 || r == 0x2029 || r == 0x202F || r == 0x205F || r == 0x3000 {
        return true;
    }
    return false;
}
