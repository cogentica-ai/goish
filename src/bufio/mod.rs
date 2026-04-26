// bufio — Go's `bufio` package, ported. M12.5 (Scanner only).
//
// Scanner provides line/byte/rune/word-tokenized reading from any
// `io.Reader`. The default split function is `ScanLines`, matching Go.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   sc := bufio.NewScanner(os.Stdin)     let mut sc = bufio::NewScanner(os::Stdin());
//   for sc.Scan() {                      while sc.Scan() {
//       fmt.Println(sc.Text())               Println!(sc.Text());
//   }                                    }
//   if err := sc.Err(); err != nil {     let err = sc.Err();
//       ...                              if err != nil { ... }
//   }
//
// Deferred (separate milestone):
//   * `bufio.Reader` / `bufio.Writer` — buffered I/O wrappers (~845 LOC
//     of port). Scanner alone covers the common line-reading case.
//   * `ErrFinalToken` — edge-case sentinel for early stop with a trailing
//     token. Add when there's demand.
//
// v1 deviations from Go:
//
//   * `Bytes()` returns a fresh `slice<byte>` (clone). Go returns a view
//     into the internal buffer that's invalidated on the next `Scan`.
//     Goish slices are owning (copy-on-subslice), so cloning is the
//     correct shape. Slightly more allocation, never invalidated.
//   * Split function token is `Option<slice<byte>>`. Go's `[]byte` can be
//     `nil` (signaling "no token, keep reading"); ours uses `Option`.
//     Empty token is `Some(slice::new())`, no token is `None`.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io::{self, Reader};
use crate::runtime::spin::SpinLock;
use crate::types::{byte, int};
use crate::unicode::utf8;

// ─── Constants ────────────────────────────────────────────────────────

pub const MaxScanTokenSize: int = 64 * 1024;
const startBufSize: usize = 4096;
const maxConsecutiveEmptyReads: int = 100;

// ─── Sentinels ────────────────────────────────────────────────────────

fn cached_error(slot: &SpinLock<Option<error>>, init: fn() -> error) -> error {
    let mut g = slot.lock();
    if g.is_none() {
        *g = Some(init());
    }
    g.as_ref().unwrap().clone()
}

pub fn ErrTooLong() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || errors::New("bufio.Scanner: token too long"))
}

pub fn ErrNegativeAdvance() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || {
        errors::New("bufio.Scanner: SplitFunc returns negative advance count")
    })
}

pub fn ErrAdvanceTooFar() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || {
        errors::New("bufio.Scanner: SplitFunc returns advance count beyond input")
    })
}

pub fn ErrBadReadCount() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || {
        errors::New("bufio.Scanner: Read returned impossible count")
    })
}

pub fn ErrNoProgress() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || {
        errors::New("multiple Read calls return no data or error")
    })
}

// ─── SplitFunc type ───────────────────────────────────────────────────

/// Boxed FnMut closure with the same signature as Go's SplitFunc:
/// `(data, atEOF) -> (advance, token, err)`.
///
/// `Option<slice<byte>>` carries Go's "nil vs empty" distinction:
///   * `None`           — "no token, read more or stop"
///   * `Some(empty)`    — "this is an empty token (e.g., a blank line)"
///   * `Some(non-empty)`— normal token
pub type SplitFunc =
    Box<dyn FnMut(&[byte], bool) -> (int, Option<slice<byte>>, error) + 'static>;

// ─── Scanner ──────────────────────────────────────────────────────────

pub struct Scanner<R: Reader> {
    r: R,
    split: SplitFunc,
    max_token_size: int,
    token: Option<slice<byte>>,
    buf: Vec<byte>,
    start: usize,
    end: usize,
    err: error,
    empties: int,
    scan_called: bool,
    done: bool,
}

/// `bufio.NewScanner(r)` — defaults to ScanLines.
pub fn NewScanner<R: Reader>(r: R) -> Scanner<R> {
    Scanner {
        r,
        split: Box::new(ScanLines),
        max_token_size: MaxScanTokenSize,
        token: None,
        buf: Vec::new(),
        start: 0,
        end: 0,
        err: nil,
        empties: 0,
        scan_called: false,
        done: false,
    }
}

impl<R: Reader> Scanner<R> {
    /// Most recent token's bytes (a fresh clone). Empty if no token yet.
    pub fn Bytes(&self) -> slice<byte> {
        match &self.token {
            Some(t) => t.clone(),
            None => slice::new(),
        }
    }

    /// Most recent token as a `string`.
    pub fn Text(&self) -> string {
        match &self.token {
            Some(t) => string::from_bytes(t),
            None => string::new(),
        }
    }

    /// First non-EOF error encountered. `nil` if scanning ended cleanly.
    pub fn Err(&self) -> error {
        if errors::Is(self.err.clone(), io::EOF()) {
            return nil;
        }
        self.err.clone()
    }

    /// Override the split function. Panics if called after Scan.
    pub fn Split<F>(&mut self, split: F)
    where
        F: FnMut(&[byte], bool) -> (int, Option<slice<byte>>, error) + 'static,
    {
        if self.scan_called {
            panic!("bufio.Scanner: Split called after Scan");
        }
        self.split = Box::new(split);
    }

    /// Override the buffer and max token size. Panics if called after Scan.
    pub fn Buffer(&mut self, buf: slice<byte>, max: int) {
        if self.scan_called {
            panic!("bufio.Scanner: Buffer called after Scan");
        }
        let mut v = buf.__into_vec();
        let cap = v.capacity();
        unsafe { v.set_len(cap) }
        self.buf = v;
        self.end = 0;
        self.start = 0;
        self.max_token_size = max;
    }

    fn set_err(&mut self, e: error) {
        if self.err == nil || errors::Is(self.err.clone(), io::EOF()) {
            self.err = e;
        }
    }

    fn advance(&mut self, n: int) -> bool {
        if n < 0 {
            self.set_err(ErrNegativeAdvance());
            return false;
        }
        if (n as usize) > self.end - self.start {
            self.set_err(ErrAdvanceTooFar());
            return false;
        }
        self.start += n as usize;
        true
    }

    /// Advance to the next token. Returns false at EOF or on error.
    pub fn Scan(&mut self) -> bool {
        if self.done {
            return false;
        }
        self.scan_called = true;
        loop {
            // Try to extract a token from what we have.
            if self.end > self.start || self.err != nil {
                let at_eof = self.err != nil;
                let (advance, token, split_err) =
                    (self.split)(&self.buf[self.start..self.end], at_eof);
                if split_err != nil {
                    self.set_err(split_err);
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
            if self.start > 0 && (self.end == self.buf.len() || self.start > self.buf.len() / 2)
            {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            // Grow if full.
            if self.end == self.buf.len() {
                if self.buf.len() >= self.max_token_size as usize {
                    self.set_err(ErrTooLong());
                    return false;
                }
                let mut new_size = self.buf.len() * 2;
                if new_size == 0 {
                    new_size = startBufSize;
                }
                if new_size > self.max_token_size as usize {
                    new_size = self.max_token_size as usize;
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
                    self.set_err(ErrBadReadCount());
                    break;
                }
                if n_io > 0 {
                    let src = tmp.__into_vec();
                    self.buf[self.end..self.end + n_io as usize]
                        .copy_from_slice(&src[..n_io as usize]);
                    self.end += n_io as usize;
                }
                if read_err != nil {
                    self.set_err(read_err);
                    break;
                }
                if n_io > 0 {
                    self.empties = 0;
                    break;
                }
                loop_count += 1;
                if loop_count > maxConsecutiveEmptyReads {
                    self.set_err(ErrNoProgress());
                    break;
                }
            }
        }
    }
}

// ─── Split functions ──────────────────────────────────────────────────

/// `bufio.ScanLines` — split on `\n`, stripping an optional trailing `\r`.
/// The final non-empty line is returned even without a terminating newline.
pub fn ScanLines(data: &[byte], at_eof: bool) -> (int, Option<slice<byte>>, error) {
    if at_eof && data.is_empty() {
        return (0, None, nil);
    }
    if let Some(i) = index_byte(data, b'\n') {
        let end = if i > 0 && data[i - 1] == b'\r' { i - 1 } else { i };
        return ((i + 1) as int, Some(slice::__from_vec(data[..end].to_vec())), nil);
    }
    if at_eof {
        let end = if !data.is_empty() && data[data.len() - 1] == b'\r' {
            data.len() - 1
        } else {
            data.len()
        };
        return (
            data.len() as int,
            Some(slice::__from_vec(data[..end].to_vec())),
            nil,
        );
    }
    (0, None, nil)
}

/// `bufio.ScanBytes` — yields one byte per token.
pub fn ScanBytes(data: &[byte], at_eof: bool) -> (int, Option<slice<byte>>, error) {
    if at_eof && data.is_empty() {
        return (0, None, nil);
    }
    (1, Some(slice::__from_vec(data[..1].to_vec())), nil)
}

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
    (1, Some(slice::__from_vec(tmp[..n as usize].to_vec())), nil)
}

/// `bufio.ScanWords` — split on whitespace runs, dropping empties.
pub fn ScanWords(data: &[byte], at_eof: bool) -> (int, Option<slice<byte>>, error) {
    // Skip leading whitespace.
    let mut start = 0usize;
    while start < data.len() {
        let r = data[start];
        if !is_ascii_space(r) {
            break;
        }
        start += 1;
    }
    if at_eof && start == data.len() {
        return (data.len() as int, None, nil);
    }
    // Scan until next whitespace.
    let mut i = start;
    while i < data.len() {
        if is_ascii_space(data[i]) {
            return (
                (i + 1) as int,
                Some(slice::__from_vec(data[start..i].to_vec())),
                nil,
            );
        }
        i += 1;
    }
    if at_eof && data.len() > start {
        return (
            data.len() as int,
            Some(slice::__from_vec(data[start..].to_vec())),
            nil,
        );
    }
    (start as int, None, nil)
}

// ─── Helpers ──────────────────────────────────────────────────────────

fn index_byte(data: &[byte], c: byte) -> Option<usize> {
    let mut i = 0;
    while i < data.len() {
        if data[i] == c {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[inline]
fn is_ascii_space(c: byte) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C)
}
