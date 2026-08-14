// bufio — Go's `bufio` package, ported.
//
// Three pieces, mirroring Go:
//
//   * `Scanner`     — line/byte/rune/word-tokenized reading.
//   * `Reader`      — buffered `io.Reader` wrapper with Peek/ReadByte/
//                     ReadRune/ReadSlice/ReadLine/ReadBytes/ReadString.
//   * `Writer`      — buffered `io.Writer` wrapper with Flush/Write/
//                     WriteByte/WriteRune/WriteString.
//   * `ReadWriter`  — pair of the above for Read+Write fds.
//
// Common Go idioms:
//
//   sc := bufio.NewScanner(os.Stdin)     let mut sc = bufio::NewScanner(os::Stdin());
//   for sc.Scan() {                      while sc.Scan() {
//       fmt.Println(sc.Text())               Println!(sc.Text());
//   }                                    }
//
//   r := bufio.NewReader(file)           let mut r = bufio::NewReader(file);
//   line, err := r.ReadString('\n')      let (line, err) = r.ReadString(b'\n');
//
//   w := bufio.NewWriter(os.Stdout)      let mut w = bufio::NewWriter(os::Stdout());
//   w.WriteString("hi\n")                w.WriteString(string("hi\n"));
//   w.Flush()                            let _ = w.Flush();
//
// Skipped (don't fit our trait shapes / no downcasting):
//   * `Reader.WriteTo` and `Writer.ReadFrom` — these dispatch on
//     `io.WriterTo`/`io.ReaderFrom` type assertions to skip a copy.
//     Add when goish gets a downcast story.
//   * `Writer.AvailableBuffer` — returns a view into Writer's backing
//     buffer for zero-copy fill-then-Write. Our `slice<byte>` is owning
//     (no shared backing), so the optimization can't be expressed.
//
// v1 deviations from Go:
//
//   * `Scanner.Bytes()`, `Reader.Peek/ReadSlice/ReadLine` return *fresh*
//     `slice<byte>` clones. Go returns views into the internal buffer
//     that get invalidated on the next read. Goish slices are owning
//     (copy-on-subslice), so cloning is the correct shape. Slightly more
//     allocation, never invalidated.
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
use crate::io;
use crate::runtime::spin::SpinLock;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// ─── Constants ────────────────────────────────────────────────────────

pub const MaxScanTokenSize: int = 64 * 1024;
pub const defaultBufSize: int = 4096;
const minReadBufferSize: usize = 16;
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

crate::var! {
    pub ErrTooLong: error            = "bufio.Scanner: token too long";
    pub ErrNegativeAdvance: error    = "bufio.Scanner: SplitFunc returns negative advance count";
    pub ErrAdvanceTooFar: error      = "bufio.Scanner: SplitFunc returns advance count beyond input";
    pub ErrBadReadCount: error       = "bufio.Scanner: Read returned impossible count";
    pub ErrNoProgress: error         = "multiple Read calls return no data or error";
    pub ErrInvalidUnreadByte: error  = "bufio: invalid use of UnreadByte";
    pub ErrInvalidUnreadRune: error  = "bufio: invalid use of UnreadRune";
    pub ErrBufferFull: error         = "bufio: buffer full";
    pub ErrNegativeCount: error      = "bufio: negative count";
}

fn err_negative_write() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    cached_error(&SLOT, || {
        errors::New("bufio: writer returned negative count from Write")
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

pub struct Scanner<R: io::Reader> {
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
pub fn NewScanner<R: io::Reader>(r: R) -> Scanner<R> {
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

impl<R: io::Reader> Scanner<R> {
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
        if errors::Is(self.err.clone(), io::EOF) {
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
        if self.err == nil || errors::Is(self.err.clone(), io::EOF) {
            self.err = e;
        }
    }

    fn advance(&mut self, n: int) -> bool {
        if n < 0 {
            self.set_err(ErrNegativeAdvance.into());
            return false;
        }
        if (n as usize) > self.end - self.start {
            self.set_err(ErrAdvanceTooFar.into());
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
                    self.set_err(ErrTooLong.into());
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
                    self.set_err(ErrBadReadCount.into());
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
                    self.set_err(ErrNoProgress.into());
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

// ─── Reader ───────────────────────────────────────────────────────────
//
// Buffered wrapper around any `io::Reader`. Mirrors `bufio.Reader` from
// Go 1.25, including UnreadByte/UnreadRune semantics.

pub struct Reader<R: io::Reader> {
    buf: Vec<byte>,
    rd: R,
    r: usize, // read position in buf
    w: usize, // write position in buf
    err: error,
    last_byte: int,      // last byte read, -1 if invalid for UnreadByte
    last_rune_size: int, // size of last rune, -1 if invalid for UnreadRune
    /// Recycled staging Vec for `fill()` — `io::Reader::Read` takes
    /// an owned `slice<byte>`, so reads can't land directly in
    /// `buf[w..]`; without recycling, every fill allocated and
    /// zeroed a fresh scratch Vec (once per HTTP request on the
    /// serve path).
    scratch: Vec<byte>,
}

/// `bufio.NewReader(rd)` — buffered reader with the default size.
pub fn NewReader<R: io::Reader>(rd: R) -> Reader<R> {
    NewReaderSize(rd, defaultBufSize)
}

impl<R: io::Reader> Reader<R> {
    /// Crate-internal: mutable access to the wrapped reader. The
    /// streaming `http::Body` owns its connection through a
    /// `bufio::Reader` (which may hold read-ahead response bytes) and
    /// closes the conn through here.
    pub(crate) fn __rd_mut(&mut self) -> &mut R {
        &mut self.rd
    }
}

/// `bufio.NewReaderSize(rd, size)` — buffered reader with the given
/// minimum buffer size (silently floored to `minReadBufferSize`).
pub fn NewReaderSize<R: io::Reader>(rd: R, size: int) -> Reader<R> {
    let sz = (size as usize).max(minReadBufferSize);
    let mut buf: Vec<byte> = Vec::with_capacity(sz);
    buf.resize(sz, 0);
    Reader {
        buf,
        rd,
        r: 0,
        w: 0,
        err: nil,
        last_byte: -1,
        last_rune_size: -1,
        scratch: Vec::new(),
    }
}

/// Crate-internal constructor reusing a caller-recycled backing
/// buffer — the analogue of Go's server-side pooled bufio.Reader
/// (`newBufioReader` + `putBufioReader`, net/http/server.go:840):
/// the HTTP keep-alive loop hands the same Vec back in every
/// request, so the per-request 4 KiB allocate-and-zero disappears.
/// An undersized (e.g. first-use empty) Vec is grown to
/// `defaultBufSize` once; the zeroing only touches the grown region.
// go: none — goish-only. The unit that crosses net/http's bufio and
// textproto pools. Go pools whole type-erased Reader/Writer structs;
// goish's are generic over the wrapped type, so the reusable
// ALLOCATION — the backing buffer — is what gets pooled, and this
// newtype is its name (a raw `Vec<byte>` in those signatures would
// also violate the no-Rust-containers rule, GOISH008).
#[doc(hidden)]
pub struct PoolBuf(pub(crate) Vec<byte>);

// go: none — goish-only: the get half of net/http's bufio reader
// pool (newBufioReader, server.go:866); sizes a recycled PoolBuf and
// builds a Reader around it.
pub(crate) fn __new_reader_with_buf<R: io::Reader>(rd: R, buf: PoolBuf) -> Reader<R> {
    let mut buf = buf.0;
    let sz = (defaultBufSize as usize).max(minReadBufferSize);
    if buf.len() < sz {
        buf.resize(sz, 0);
    }
    return Reader {
        buf,
        rd,
        r: 0,
        w: 0,
        err: nil,
        last_byte: -1,
        last_rune_size: -1,
        scratch: Vec::new(),
    };
}

impl<R: io::Reader> Reader<R> {
    /// `Size()` — buffer capacity in bytes.
    pub fn Size(&self) -> int {
        self.buf.len() as int
    }

    /// `Reset(rd)` — discard buffered data and switch to `rd`.
    pub fn Reset(&mut self, rd: R) {
        self.rd = rd;
        self.r = 0;
        self.w = 0;
        self.err = nil;
        self.last_byte = -1;
        self.last_rune_size = -1;
    }

    /// `Buffered()` — bytes available without reading from rd.
    pub fn Buffered(&self) -> int {
        (self.w - self.r) as int
    }

    // go: none — goish-only: the put half of Go's bufio reader pool
    // (putBufioReader, server.go:886).
    /// Crate-internal: recover the backing buffer for recycling into
    /// the next `__new_reader_with_buf`. Buffered-but-unconsumed
    /// bytes are discarded, matching the previous
    /// fresh-reader-per-request behavior.
    pub(crate) fn __into_buf(self) -> PoolBuf {
        return PoolBuf(self.buf);
    }

    // go: none — goish-only test hook.
    /// Identity of the backing buffer, for asserting pool reuse (a
    /// behavioural test cannot distinguish reuse from a silent fresh
    /// allocation).
    #[doc(hidden)]
    pub fn __buf_ptr(&self) -> *const u8 {
        return self.buf.as_ptr();
    }

    /// Crate-internal zero-copy line read for the HTTP parser: borrow
    /// the next `\n`-terminated line (with the trailing `\n` and any
    /// preceding `\r` stripped) directly from the internal buffer.
    ///
    ///   * `Ok(Some(line))` — full line was in (or read into) the
    ///     buffer; consumed. The borrow is valid until the next read
    ///     call on this reader — the same contract as Go's
    ///     `ReadSlice` view (bufio.go:345), which is exactly what
    ///     `textproto`-style parsing needs: copy out only the
    ///     substrings that outlive the line.
    ///   * `Ok(None)` — the line is longer than the whole buffer;
    ///     caller falls back to the allocating `ReadBytes` path.
    ///   * `Err(e)` — underlying read error before any delimiter.
    pub(crate) fn __read_line_view(&mut self) -> Result<Option<&[byte]>, error> {
        let (start, end, consume_to) = loop {
            if let Some(i) = index_byte(&self.buf[self.r..self.w], b'\n') {
                let start = self.r;
                let mut end = start + i;
                if end > start && self.buf[end - 1] == b'\r' {
                    end -= 1;
                }
                break (start, end, start + i + 1);
            }
            if self.err != nil {
                return Err(self.read_err());
            }
            if self.w - self.r >= self.buf.len() {
                return Ok(None); // line spans the whole buffer
            }
            self.fill();
        };
        self.r = consume_to;
        self.last_byte = b'\n' as int;
        self.last_rune_size = -1;
        Ok(Some(&self.buf[start..end]))
    }

    fn read_err(&mut self) -> error {
        let e = self.err.clone();
        self.err = nil;
        e
    }

    fn fill(&mut self) {
        if self.r > 0 {
            self.buf.copy_within(self.r..self.w, 0);
            self.w -= self.r;
            self.r = 0;
        }
        if self.w >= self.buf.len() {
            panic!("bufio: tried to fill full buffer");
        }
        let mut tries = maxConsecutiveEmptyReads;
        while tries > 0 {
            let want = self.buf.len() - self.w;
            // Stage through the recycled scratch Vec — resize only
            // zeroes newly-grown bytes, so the steady state is
            // alloc-free and memset-free.
            let mut sv = core::mem::take(&mut self.scratch);
            if sv.len() != want {
                sv.resize(want, 0);
            }
            let mut tmp: slice<byte> = slice::__from_vec(sv);
            let (n, err) = self.rd.Read(&mut tmp);
            if n < 0 {
                panic!("bufio: reader returned negative count from Read");
            }
            let src = tmp.__into_vec();
            if n > 0 {
                self.buf[self.w..self.w + n as usize]
                    .copy_from_slice(&src[..n as usize]);
                self.w += n as usize;
            }
            self.scratch = src;
            if err != nil {
                self.err = err;
                return;
            }
            if n > 0 {
                return;
            }
            tries -= 1;
        }
        // Go: b.err = io.ErrNoProgress (same string as bufio.ErrNoProgress).
        // Use the registered sentinel so errors::Is(err, bufio::ErrNoProgress) works.
        self.err = ErrNoProgress.into();
    }

    /// `Peek(n)` — next n bytes without advancing. Returns `(bytes, err)`.
    /// Err is `ErrBufferFull` if n exceeds buffer size.
    pub fn Peek(&mut self, n: int) -> (slice<byte>, error) {
        if n < 0 {
            return (slice::new(), ErrNegativeCount.into());
        }
        self.last_byte = -1;
        self.last_rune_size = -1;
        while (self.w - self.r) < n as usize
            && (self.w - self.r) < self.buf.len()
            && self.err == nil
        {
            self.fill();
        }
        if (n as usize) > self.buf.len() {
            return (
                slice::__from_vec(self.buf[self.r..self.w].to_vec()),
                ErrBufferFull.into(),
            );
        }
        let avail = self.w - self.r;
        let mut out_n = n as usize;
        let mut err = nil;
        if avail < n as usize {
            out_n = avail;
            err = self.read_err();
            if err == nil {
                err = ErrBufferFull.into();
            }
        }
        (
            slice::__from_vec(self.buf[self.r..self.r + out_n].to_vec()),
            err,
        )
    }

    /// `Discard(n)` — skip n bytes. Returns (skipped, err).
    pub fn Discard(&mut self, n: int) -> (int, error) {
        if n < 0 {
            return (0, ErrNegativeCount.into());
        }
        if n == 0 {
            return (0, nil);
        }
        self.last_byte = -1;
        self.last_rune_size = -1;
        let mut remain = n as usize;
        loop {
            let mut skip = self.w - self.r;
            if skip == 0 {
                self.fill();
                skip = self.w - self.r;
            }
            if skip > remain {
                skip = remain;
            }
            self.r += skip;
            remain -= skip;
            if remain == 0 {
                return (n, nil);
            }
            if self.err != nil {
                return ((n as usize - remain) as int, self.read_err());
            }
        }
    }

    /// `Read(p)` — fill `p` from the buffer (one rd.Read at most).
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let want = p.Len() as usize;
        if want == 0 {
            if self.Buffered() > 0 {
                return (0, nil);
            }
            return (0, self.read_err());
        }
        if self.r == self.w {
            if self.err != nil {
                return (0, self.read_err());
            }
            if want >= self.buf.len() {
                // Large read, empty buffer: read directly into p.
                let (n, err) = self.rd.Read(p);
                if n < 0 {
                    panic!("bufio: reader returned negative count from Read");
                }
                self.err = err;
                if n > 0 {
                    self.last_byte = p[(n - 1) as int] as int;
                    self.last_rune_size = -1;
                }
                return (n, self.read_err());
            }
            // Refill once.
            self.r = 0;
            self.w = 0;
            let cap = self.buf.len();
            let mut tmp: slice<byte> = slice::__from_vec({
                let mut v: Vec<byte> = Vec::with_capacity(cap);
                v.resize(cap, 0);
                v
            });
            let (n, err) = self.rd.Read(&mut tmp);
            if n < 0 {
                panic!("bufio: reader returned negative count from Read");
            }
            self.err = err;
            if n == 0 {
                return (0, self.read_err());
            }
            let src = tmp.__into_vec();
            self.buf[..n as usize].copy_from_slice(&src[..n as usize]);
            self.w += n as usize;
        }
        // Copy as much as we can.
        let n = (want).min(self.w - self.r);
        for i in 0..n {
            p[i as int] = self.buf[self.r + i];
        }
        self.r += n;
        self.last_byte = self.buf[self.r - 1] as int;
        self.last_rune_size = -1;
        (n as int, nil)
    }

    /// `ReadByte()` — single byte, blocking until one is available.
    pub fn ReadByte(&mut self) -> (byte, error) {
        self.last_rune_size = -1;
        while self.r == self.w {
            if self.err != nil {
                return (0, self.read_err());
            }
            self.fill();
        }
        let c = self.buf[self.r];
        self.r += 1;
        self.last_byte = c as int;
        (c, nil)
    }

    /// `UnreadByte()` — push back the most recently read byte.
    pub fn UnreadByte(&mut self) -> error {
        if self.last_byte < 0 || (self.r == 0 && self.w > 0) {
            return ErrInvalidUnreadByte.into();
        }
        if self.r > 0 {
            self.r -= 1;
        } else {
            self.w = 1;
        }
        self.buf[self.r] = self.last_byte as byte;
        self.last_byte = -1;
        self.last_rune_size = -1;
        nil
    }

    /// `ReadRune()` — single UTF-8 rune. Returns (rune, size, err).
    /// Invalid encoding consumes one byte and yields RuneError (U+FFFD).
    pub fn ReadRune(&mut self) -> (rune, int, error) {
        while (self.r as int + utf8::UTFMax) > self.w as int
            && !utf8::FullRune(&self.buf[self.r..self.w])
            && self.err == nil
            && (self.w - self.r) < self.buf.len()
        {
            self.fill();
        }
        self.last_rune_size = -1;
        if self.r == self.w {
            return (0, 0, self.read_err());
        }
        let mut r = self.buf[self.r] as rune;
        let mut size: int = 1;
        if r >= utf8::RuneSelf as rune {
            let (rr, sz) = utf8::DecodeRune(&self.buf[self.r..self.w]);
            r = rr;
            size = sz;
        }
        self.r += size as usize;
        self.last_byte = self.buf[self.r - 1] as int;
        self.last_rune_size = size;
        (r, size, nil)
    }

    /// `UnreadRune()` — push back the most recently read rune. Stricter
    /// than UnreadByte: only valid immediately after ReadRune.
    pub fn UnreadRune(&mut self) -> error {
        if self.last_rune_size < 0 || self.r < self.last_rune_size as usize {
            return ErrInvalidUnreadRune.into();
        }
        self.r -= self.last_rune_size as usize;
        self.last_byte = -1;
        self.last_rune_size = -1;
        nil
    }

    /// `ReadSlice(delim)` — bytes up to and including the delimiter.
    /// Goish: returns a fresh `slice<byte>` (not a view into buf).
    pub fn ReadSlice(&mut self, delim: byte) -> (slice<byte>, error) {
        let mut s: usize = 0; // search start within buf[r..w]
        loop {
            if let Some(i) = index_byte(&self.buf[self.r + s..self.w], delim) {
                let i = i + s;
                let line = self.buf[self.r..self.r + i + 1].to_vec();
                self.r += i + 1;
                if !line.is_empty() {
                    self.last_byte = line[line.len() - 1] as int;
                    self.last_rune_size = -1;
                }
                return (slice::__from_vec(line), nil);
            }
            if self.err != nil {
                let line = self.buf[self.r..self.w].to_vec();
                self.r = self.w;
                let err = self.read_err();
                if !line.is_empty() {
                    self.last_byte = line[line.len() - 1] as int;
                    self.last_rune_size = -1;
                }
                return (slice::__from_vec(line), err);
            }
            if (self.w - self.r) >= self.buf.len() {
                self.r = self.w;
                let line = self.buf.clone();
                // last_byte is already set by previous ReadByte/Read; keep it.
                return (slice::__from_vec(line), ErrBufferFull.into());
            }
            s = self.w - self.r;
            self.fill();
        }
    }

    /// `ReadLine()` — low-level line reader. Returns (line, isPrefix, err).
    /// Line excludes any trailing "\r\n" or "\n". On buffer-full mid-line,
    /// returns isPrefix=true and the line so far.
    pub fn ReadLine(&mut self) -> (slice<byte>, bool, error) {
        let (mut line, err) = self.ReadSlice(b'\n');
        if err != nil && errors::Is(err.clone(), ErrBufferFull) {
            // Handle the case where "\r\n" straddles the buffer.
            if line.Len() > 0 && line[line.Len() - 1] == b'\r' {
                if self.r == 0 {
                    panic!("bufio: tried to rewind past start of buffer");
                }
                self.r -= 1;
                line = line.slice(0, line.Len() - 1);
            }
            return (line, true, nil);
        }
        if line.Len() == 0 {
            if err != nil {
                return (slice::new(), false, err);
            }
            return (line, false, nil);
        }
        // strip trailing \n or \r\n
        if line[line.Len() - 1] == b'\n' {
            let mut drop: int = 1;
            if line.Len() > 1 && line[line.Len() - 2] == b'\r' {
                drop = 2;
            }
            line = line.slice(0, line.Len() - drop);
        }
        (line, false, nil)
    }

    /// `ReadBytes(delim)` — full payload up to and including the delimiter,
    /// crossing buffer boundaries.
    pub fn ReadBytes(&mut self, delim: byte) -> (slice<byte>, error) {
        let mut full: Vec<Vec<byte>> = Vec::new();
        let mut total: usize = 0;
        let frag: Vec<byte>;
        let mut err_final = nil;
        loop {
            let (s, e) = self.ReadSlice(delim);
            if e == nil {
                frag = s.__into_vec();
                break;
            }
            if !errors::Is(e.clone(), ErrBufferFull) {
                frag = s.__into_vec();
                err_final = e;
                break;
            }
            let buf = s.__into_vec();
            total += buf.len();
            full.push(buf);
        }
        total += frag.len();
        let mut out: Vec<byte> = Vec::with_capacity(total);
        for f in full {
            out.extend_from_slice(&f);
        }
        out.extend_from_slice(&frag);
        (slice::__from_vec(out), err_final)
    }

    /// `ReadString(delim)` — same as ReadBytes but returns a `string`.
    pub fn ReadString(&mut self, delim: byte) -> (string, error) {
        let (b, e) = self.ReadBytes(delim);
        (string::from_bytes(&b.__into_vec()), e)
    }

    /// Line-by-line port of `bufio.Reader.WriteTo` (bufio.go:518) —
    /// drain everything in the buffer and the underlying reader to `w`.
    /// Slim deviation: skip the `WriterTo` / `ReaderFrom` fast paths
    /// since goish doesn't expose those traits as `dyn`-castable.
    pub fn WriteTo(&mut self, w: &mut dyn io::Writer) -> (int, error) {
        // Go: b.lastByte = -1; b.lastRuneSize = -1
        self.last_byte = -1;
        self.last_rune_size = -1;

        let mut n: int = 0;

        // Go: if b.r < b.w { n, err = b.writeBuf(w); if err != nil { return } }
        if self.r < self.w {
            let (m, err) = self.write_buf(w);
            n += m;
            if err != nil {
                return (n, err);
            }
        }

        // Go: if b.w-b.r < len(b.buf) { b.fill() } — only fill when not full.
        if (self.w - self.r) < self.buf.len() {
            self.fill();
        }

        // Go: for b.r < b.w { m, err := b.writeBuf(w); n += m; if err != nil { return n, err }; b.fill() }
        while self.r < self.w {
            let (m, err) = self.write_buf(w);
            n += m;
            if err != nil {
                return (n, err);
            }
            self.fill();
        }

        // Go: if b.err == io.EOF { b.err = nil }
        if self.err != nil && errors::Is(self.err.clone(), io::EOF) {
            self.err = nil;
        }

        (n, self.read_err())
    }

    // Internal helper: port of bufio.Reader.writeBuf (bufio.go:565).
    fn write_buf(&mut self, w: &mut dyn io::Writer) -> (int, error) {
        // Go: n, err := w.Write(b.buf[b.r:b.w])
        let chunk: slice<byte> = slice::__from_vec(self.buf[self.r..self.w].to_vec());
        let (n, err) = w.Write(chunk);
        // Go: if n < 0 { panic(errNegativeWrite) }
        if n < 0 {
            panic!("bufio: writer returned negative count from Write");
        }
        // Go: b.r += n
        self.r += n as usize;
        (n, err)
    }
}

impl<R: io::Reader> io::Reader for Reader<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Reader::Read(self, p)
    }
}

impl<R: io::Reader> io::ByteReader for Reader<R> {
    fn ReadByte(&mut self) -> (byte, error) {
        Reader::ReadByte(self)
    }
}

// ─── Writer ───────────────────────────────────────────────────────────
//
// Buffered wrapper around any `io::Writer`. Call `Flush()` before
// dropping or after the last write to guarantee delivery.

pub struct Writer<W: io::Writer> {
    err: error,
    buf: Vec<byte>,
    n: usize,
    wr: W,
}

/// `bufio.NewWriter(wr)` — buffered writer with the default size.
pub fn NewWriter<W: io::Writer>(wr: W) -> Writer<W> {
    NewWriterSize(wr, defaultBufSize)
}

/// `bufio.NewWriterSize(wr, size)` — buffered writer with `size` bytes.
pub fn NewWriterSize<W: io::Writer>(wr: W, size: int) -> Writer<W> {
    let sz = if size <= 0 { defaultBufSize as usize } else { size as usize };
    let mut buf: Vec<byte> = Vec::with_capacity(sz);
    buf.resize(sz, 0);
    Writer {
        err: nil,
        buf,
        n: 0,
        wr,
    }
}

// go: none — goish-only: the get half of net/http's bufio writer
// pools (newBufioWriterSize, server.go:900). See `PoolBuf` for why
// the buffer, not the Writer, is the pooled unit.
/// Build a Writer around a recycled backing buffer, resized to
/// `size`. The put half is `__into_buf`.
pub(crate) fn __new_writer_with_buf<W: io::Writer>(
    wr: W,
    buf: PoolBuf,
    size: int,
) -> Writer<W> {
    let mut buf = buf.0;
    let sz = if size <= 0 { defaultBufSize as usize } else { size as usize };
    buf.resize(sz, 0);
    return Writer {
        err: nil,
        buf,
        n: 0,
        wr,
    };
}

impl<W: io::Writer> Writer<W> {
    // go: none — goish-only: the put half of Go's bufio writer pools
    // (putBufioWriter, server.go:921).
    /// Consume the writer, returning its backing buffer for pooling.
    /// Unflushed bytes are DISCARDED — same contract as Go's
    /// `bw.Reset(nil)` before the pool Put (putBufioWriter,
    /// server.go:922): callers flush first or forfeit the tail.
    pub(crate) fn __into_buf(self) -> PoolBuf {
        return PoolBuf(self.buf);
    }

    // go: none — goish-only test hook.
    /// Identity of the backing buffer (see Reader's `__buf_ptr`).
    #[doc(hidden)]
    pub fn __buf_ptr(&self) -> *const u8 {
        return self.buf.as_ptr();
    }

    /// `Size()` — buffer capacity in bytes.
    pub fn Size(&self) -> int {
        self.buf.len() as int
    }

    /// `Reset(wr)` — discard buffered data, clear error, switch to `wr`.
    pub fn Reset(&mut self, wr: W) {
        self.err = nil;
        self.n = 0;
        self.wr = wr;
    }

    /// `Buffered()` — bytes currently buffered (not yet flushed).
    pub fn Buffered(&self) -> int {
        self.n as int
    }

    /// `Available()` — bytes free in the buffer.
    pub fn Available(&self) -> int {
        (self.buf.len() - self.n) as int
    }

    /// `Writer.AvailableBuffer()` (bufio.go:668) — returns a `slice<byte>`
    /// with `len == 0` and `cap` equal to the writer's currently-available
    /// buffer space. Intended to be appended to and passed to a subsequent
    /// `Write`/`WriteString` call to avoid an intermediate allocation.
    ///
    /// Slim deviation: Go returns `b.buf[b.n:][:0]`, a sub-slice that
    /// aliases the underlying writer buffer so a follow-up
    /// `b.Write(buf[:m])` can be detected as in-place and skip the copy.
    /// goish slices are owned `Vec<byte>`, so we return a fresh empty
    /// slice with `Vec::with_capacity(self.Available())`. Callers see the
    /// same observable surface (an empty slice they can append to and
    /// pass to Write); only the zero-copy hand-off is lost — the
    /// follow-up Write performs a copy as it would for any other slice.
    pub fn AvailableBuffer(&self) -> slice<byte> {
        // Go: return b.buf[b.n:][:0]
        let avail = self.buf.len() - self.n;
        slice::__from_vec(Vec::with_capacity(avail))
    }

    /// `Flush()` — push buffered bytes to the underlying writer. Once an
    /// error is recorded, no further writes will be accepted until Reset.
    pub fn Flush(&mut self) -> error {
        if self.err != nil {
            return self.err.clone();
        }
        if self.n == 0 {
            return nil;
        }
        let chunk: slice<byte> = slice::__from_vec(self.buf[..self.n].to_vec());
        let want = self.n;
        let (n, err) = self.wr.Write(chunk);
        if n < 0 {
            self.err = err_negative_write();
            return self.err.clone();
        }
        let n = n as usize;
        let mut err = err;
        if n < want && err == nil {
            err = io::ErrShortWrite.into();
        }
        if err != nil {
            if n > 0 && n < want {
                self.buf.copy_within(n..want, 0);
            }
            self.n = want - n;
            self.err = err.clone();
            return err;
        }
        self.n = 0;
        nil
    }

    /// `Write(p)` — append `p` to the buffer, flushing as needed.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let mut p = p.__into_vec();
        let mut nn: usize = 0;
        while p.len() > self.Available() as usize && self.err == nil {
            let n;
            if self.Buffered() == 0 {
                // Large write, empty buffer: write directly to wr.
                let chunk: slice<byte> = slice::__from_vec(p.clone());
                let (m, err) = self.wr.Write(chunk);
                if m < 0 {
                    self.err = err_negative_write();
                    return (nn as int, self.err.clone());
                }
                n = m as usize;
                self.err = err;
            } else {
                let avail = self.buf.len() - self.n;
                let take = avail.min(p.len());
                self.buf[self.n..self.n + take].copy_from_slice(&p[..take]);
                self.n += take;
                n = take;
                let _ = self.Flush();
            }
            nn += n;
            p.drain(..n);
        }
        if self.err != nil {
            return (nn as int, self.err.clone());
        }
        let take = p.len();
        self.buf[self.n..self.n + take].copy_from_slice(&p[..]);
        self.n += take;
        nn += take;
        (nn as int, nil)
    }

    /// `WriteByte(c)` — append one byte.
    pub fn WriteByte(&mut self, c: byte) -> error {
        if self.err != nil {
            return self.err.clone();
        }
        if self.Available() <= 0 {
            let e = self.Flush();
            if e != nil {
                return e;
            }
        }
        self.buf[self.n] = c;
        self.n += 1;
        nil
    }

    /// `WriteRune(r)` — append a single UTF-8-encoded rune.
    pub fn WriteRune(&mut self, r: rune) -> (int, error) {
        if (r as u32) < utf8::RuneSelf as u32 {
            let e = self.WriteByte(r as byte);
            if e != nil {
                return (0, e);
            }
            return (1, nil);
        }
        if self.err != nil {
            return (0, self.err.clone());
        }
        let mut avail = self.Available() as int;
        if avail < utf8::UTFMax {
            let e = self.Flush();
            if e != nil {
                return (0, e);
            }
            avail = self.Available() as int;
            if avail < utf8::UTFMax {
                // Buffer is silly small; encode then write through WriteString.
                let mut tmp = [0u8; 4];
                let n = utf8::EncodeRune(&mut tmp, r) as usize;
                let v = tmp[..n].to_vec();
                let s = string::__from_vec(v);
                return self.WriteString(s);
            }
        }
        let n = utf8::EncodeRune(&mut self.buf[self.n..], r);
        self.n += n as usize;
        (n, nil)
    }

    /// `WriteString(s)` — append a string.
    pub fn WriteString<S: Into<string>>(&mut self, s: S) -> (int, error) {
        let s: string = s.into();
        let mut s = s.as_bytes().to_vec();
        let mut nn: usize = 0;
        while s.len() > self.Available() as usize && self.err == nil {
            let avail = self.buf.len() - self.n;
            let take = avail.min(s.len());
            self.buf[self.n..self.n + take].copy_from_slice(&s[..take]);
            self.n += take;
            let _ = self.Flush();
            nn += take;
            s.drain(..take);
        }
        if self.err != nil {
            return (nn as int, self.err.clone());
        }
        let take = s.len();
        self.buf[self.n..self.n + take].copy_from_slice(&s[..]);
        self.n += take;
        nn += take;
        (nn as int, nil)
    }

    /// Line-by-line port of `bufio.Writer.ReadFrom` (bufio.go:787) —
    /// pull bytes from `r` and buffer them, flushing as needed. Returns
    /// `(bytesRead, err)`. EOF is normalized to nil (Go behavior).
    /// Slim deviation: skip the `ReaderFrom` fast path on the underlying
    /// writer since goish doesn't expose that trait as `dyn`-castable.
    pub fn ReadFrom(&mut self, r: &mut dyn io::Reader) -> (int, error) {
        // Go: if b.err != nil { return 0, b.err }
        if self.err != nil {
            return (0, self.err.clone());
        }
        let mut n: int = 0;
        let mut err: error = nil;
        // Go: for { … }
        loop {
            // Go: if b.Available() == 0 { if err1 := b.Flush(); err1 != nil { return n, err1 } }
            if self.Available() == 0 {
                let err1 = self.Flush();
                if err1 != nil {
                    return (n, err1);
                }
            }
            // Slim: no ReaderFrom fast path.

            // Go: nr := 0; for nr < maxConsecutiveEmptyReads { m, err = r.Read(b.buf[b.n:]); ... }
            let mut nr = 0;
            let mut m: int = 0;
            while nr < maxConsecutiveEmptyReads {
                let avail = self.buf.len() - self.n;
                let mut tmp: slice<byte> = slice::__from_vec({
                    let mut v: Vec<byte> = Vec::with_capacity(avail);
                    v.resize(avail, 0);
                    v
                });
                let (mm, e) = r.Read(&mut tmp);
                m = mm;
                err = e;
                // Copy what we got back into our buffer.
                if mm > 0 {
                    let src = tmp.__into_vec();
                    self.buf[self.n..self.n + mm as usize]
                        .copy_from_slice(&src[..mm as usize]);
                }
                if mm != 0 || err != nil {
                    break;
                }
                nr += 1;
            }
            // Go: if nr == maxConsecutiveEmptyReads { return n, io.ErrNoProgress }
            if nr == maxConsecutiveEmptyReads {
                return (n, errors::New("multiple Read calls return no data or error"));
            }
            // Go: b.n += m; n += int64(m)
            self.n += m as usize;
            n += m;
            // Go: if err != nil { break }
            if err != nil {
                break;
            }
        }
        // Go: if err == io.EOF { … } — normalize EOF.
        if errors::Is(err.clone(), io::EOF) {
            // Go: if b.Available() == 0 { err = b.Flush() } else { err = nil }
            if self.Available() == 0 {
                err = self.Flush();
            } else {
                err = nil;
            }
        }
        (n, err)
    }
}

impl<W: io::Writer> io::Writer for Writer<W> {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        Writer::Write(self, p)
    }
}

// ─── ReadWriter ───────────────────────────────────────────────────────
//
// Aggregate: mirrors Go's `bufio.ReadWriter` (which uses struct embedding).
// Goish exposes the wrapped reader/writer as named fields; users call
// `rw.reader.ReadString(...)` / `rw.writer.WriteString(...)`.

pub struct ReadWriter<R: io::Reader, W: io::Writer> {
    pub reader: Reader<R>,
    pub writer: Writer<W>,
}

/// `bufio.NewReadWriter(r, w)` — pair of buffered Reader and Writer.
pub fn NewReadWriter<R: io::Reader, W: io::Writer>(
    r: Reader<R>,
    w: Writer<W>,
) -> ReadWriter<R, W> {
    ReadWriter { reader: r, writer: w }
}
