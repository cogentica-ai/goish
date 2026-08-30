// go: file bufio/bufio.go decls: errNegativeRead, errNegativeWrite, NewReaderSize, NewReader, Reader.Size, Reader.Reset, Reader.reset, Reader.fill, Reader.readErr, Reader.Peek, Reader.Discard, Reader.Read, Reader.ReadByte, Reader.UnreadByte, Reader.ReadRune, Reader.UnreadRune, Reader.Buffered, Reader.ReadSlice, Reader.ReadLine, Reader.collectFragments, Reader.ReadBytes, Reader.ReadString, Reader.WriteTo, Reader.writeBuf, NewWriterSize, NewWriter, Writer.Size, Writer.Reset, Writer.Flush, Writer.Available, Writer.AvailableBuffer, Writer.Buffered, Writer.Write, Writer.WriteByte, Writer.WriteRune, Writer.WriteString, Writer.ReadFrom, NewReadWriter
//
// `errNegativeRead` and `errNegativeWrite` are package-level `var`s in
// Go; they are named in the manifest because goish spells them as
// `fn`s — `errors::New` is not `const` — and GOISH017 matches a
// manifest entry against Rust `fn` items.
//
// bufio/bufio.go — the buffered `Reader`, `Writer` and `ReadWriter`.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{byte as tobyte, int as toint, rune as torune, uint32 as touint32};
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::runtime::spin::SpinLock;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// ─── Constants ────────────────────────────────────────────────────────

pub const defaultBufSize: int = 4096;
const minReadBufferSize: usize = 16;
const maxConsecutiveEmptyReads: int = 100;

// go: none — goish idiom: Go's `errors.New` runs at package
//     initialisation, in a `var` block. goish has no package init, so a
//     sentinel is built once behind a lock the first time it is asked
//     for. `crate::var!` below does the same thing; this is the raw
//     form, for the sentinels that predate it.
pub(crate) fn cached_error(slot: &SpinLock<Option<error>>, init: fn() -> error) -> error {
    let mut g = slot.lock();
    if g.is_none() {
        *g = Some(init());
    }
    return g.as_ref().unwrap().clone();
}

// go: none — goish idiom: Go calls `bytes.IndexByte`, which is an
//     assembly routine in internal/bytealg. goish's bufio has no
//     dependency on `bytes`, so the scan is spelled here; both files
//     use it.
pub(crate) fn index_byte(data: &[crate::types::byte], c: crate::types::byte) -> Option<usize> {
    let mut i = 0;
    while i < data.len() {
        if data[i] == c {
            return Some(i);
        }
        i += 1;
    }
    return None;
}

crate::var! {
    // go: none — goish idiom: Go's Scanner reads `io.ErrNoProgress`
    //     from the io package; goish keeps a local copy so bufio does
    //     not have to reach across for one string.
    pub ErrNoProgress: error         = "multiple Read calls return no data or error";
    // go: sdk 1.25.5 bufio/bufio.go:22-27 ErrInvalidUnreadByte
    pub ErrInvalidUnreadByte: error  = "bufio: invalid use of UnreadByte";
    // go: sdk 1.25.5 bufio/bufio.go:22-27 ErrInvalidUnreadRune
    pub ErrInvalidUnreadRune: error  = "bufio: invalid use of UnreadRune";
    // go: sdk 1.25.5 bufio/bufio.go:22-27 ErrBufferFull
    pub ErrBufferFull: error         = "bufio: buffer full";
    // go: sdk 1.25.5 bufio/bufio.go:22-27 ErrNegativeCount
    pub ErrNegativeCount: error      = "bufio: negative count";
}

// go: sdk 1.25.5 bufio/bufio.go:96-96 errNegativeRead
fn errNegativeRead() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    return cached_error(&SLOT, || {
        return errors::New("bufio: reader returned negative count from Read");
    });
}

// go: sdk 1.25.5 bufio/bufio.go:562-562 errNegativeWrite
fn errNegativeWrite() -> error {
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    return cached_error(&SLOT, || {
        return errors::New("bufio: writer returned negative count from Write");
    });
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
    lastByte: int,     // last byte read, -1 if invalid for UnreadByte
    lastRuneSize: int, // size of last rune, -1 if invalid for UnreadRune
    /// Recycled staging Vec for `fill()` — `io::Reader::Read` takes
    /// an owned `slice<byte>`, so reads can't land directly in
    /// `buf[w..]`; without recycling, every fill allocated and
    /// zeroed a fresh scratch Vec (once per HTTP request on the
    /// serve path).
    scratch: Vec<byte>,
}

// go: sdk 1.25.5 bufio/bufio.go:62-64 NewReader
/// `bufio.NewReader(rd)` — buffered reader with the default size.
pub fn NewReader<R: io::Reader>(rd: R) -> Reader<R> {
    return NewReaderSize(rd, defaultBufSize);
}

impl<R: io::Reader> Reader<R> {
    // go: none — goish idiom: Go's `http.body` keeps a `*bufio.Reader`
    //     and reaches its `rd` field directly, being in another package
    //     only by name. goish has no such reach, so the accessor is
    //     spelled here.
    /// Crate-internal: mutable access to the wrapped reader. The
    /// streaming `http::Body` owns its connection through a
    /// `bufio::Reader` (which may hold read-ahead response bytes) and
    /// closes the conn through here.
    pub(crate) fn __rd_mut(&mut self) -> &mut R {
        return &mut self.rd;
    }
}

// go: sdk 1.25.5 bufio/bufio.go:50-59 NewReaderSize
/// `bufio.NewReaderSize(rd, size)` — buffered reader with the given
/// minimum buffer size (silently floored to `minReadBufferSize`).
pub fn NewReaderSize<R: io::Reader>(rd: R, size: int) -> Reader<R> {
    let sz = (size as usize).max(minReadBufferSize);
    let mut buf: Vec<byte> = Vec::with_capacity(sz);
    buf.resize(sz, 0);
    return Reader {
        buf,
        rd,
        r: 0,
        w: 0,
        err: nil,
        lastByte: -1,
        lastRuneSize: -1,
        scratch: Vec::new(),
    };
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
        lastByte: -1,
        lastRuneSize: -1,
        scratch: Vec::new(),
    };
}

impl<R: io::Reader> Reader<R> {
    // go: sdk 1.25.5 bufio/bufio.go:67-67 Reader.Size
    /// `Size()` — buffer capacity in bytes.
    pub fn Size(&self) -> int {
        return toint(self.buf.len());
    }

    // go: sdk 1.25.5 bufio/bufio.go:74-85 Reader.Reset
    /// `Reset(rd)` — discard buffered data and switch to `rd`.
    pub fn Reset(&mut self, rd: R) {
        self.rd = rd;
        self.r = 0;
        self.w = 0;
        self.err = nil;
        self.lastByte = -1;
        self.lastRuneSize = -1;
    }

    // go: sdk 1.25.5 bufio/bufio.go:339-339 Reader.Buffered
    /// `Buffered()` — bytes available without reading from rd.
    pub fn Buffered(&self) -> int {
        return toint(self.w - self.r);
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
    // go: none — goish idiom: identity of the backing buffer, used by
    //     `net/http`'s reader pool to check a Reader still owns the
    //     buffer it was handed. Go compares the slice headers instead.
    #[doc(hidden)]
    pub fn __buf_ptr(&self) -> *const u8 {
        return self.buf.as_ptr();
    }

    // go: none — goish idiom: Go's `ReadSlice` already returns a view
    //     into the internal buffer, so `textproto` parses in place with
    //     no extra API. goish's `ReadSlice` returns an owning
    //     `slice<byte>` clone, so the zero-copy path the HTTP parser
    //     needs is a separate crate-internal borrow.
    /// Crate-internal zero-copy line read for the HTTP parser: borrow
    /// the next `\n`-terminated line (with the trailing `\n` and any
    /// preceding `\r` stripped) directly from the internal buffer.
    ///
    ///   * `(Some(line), nil)` — full line was in (or read into) the
    ///     buffer; consumed. The borrow is valid until the next read
    ///     call on this reader — the same contract as Go's
    ///     `ReadSlice` view (bufio.go:345), which is exactly what
    ///     `textproto`-style parsing needs: copy out only the
    ///     substrings that outlive the line.
    ///   * `(None, nil)` — the line is longer than the whole buffer;
    ///     caller falls back to the allocating `ReadBytes` path.
    ///   * `(None, err)` — underlying read error before any delimiter.
    pub(crate) fn __read_line_view(&mut self) -> (Option<&[byte]>, error) {
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
                return (None, self.readErr());
            }
            if self.w - self.r >= self.buf.len() {
                return (None, nil); // line spans the whole buffer
            }
            self.fill();
        };
        self.r = consume_to;
        self.lastByte = toint(b'\n');
        self.lastRuneSize = -1;
        return (Some(&self.buf[start..end]), nil);
    }

    // go: sdk 1.25.5 bufio/bufio.go:129-133 Reader.readErr
    fn readErr(&mut self) -> error {
        let e = self.err.clone();
        self.err = nil;
        return e;
    }

    // go: sdk 1.25.5 bufio/bufio.go:99-127 Reader.fill
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
                self.buf[self.w..self.w + n as usize].copy_from_slice(&src[..n as usize]);
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

    // go: sdk 1.25.5 bufio/bufio.go:143-170 Reader.Peek
    /// `Peek(n)` — next n bytes without advancing. Returns `(bytes, err)`.
    /// Err is `ErrBufferFull` if n exceeds buffer size.
    pub fn Peek(&mut self, n: int) -> (slice<byte>, error) {
        if n < 0 {
            return (slice::new(), ErrNegativeCount.into());
        }
        self.lastByte = -1;
        self.lastRuneSize = -1;
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
            err = self.readErr();
            if err == nil {
                err = ErrBufferFull.into();
            }
        }
        return (
            slice::__from_vec(self.buf[self.r..self.r + out_n].to_vec()),
            err,
        );
    }

    // go: sdk 1.25.5 bufio/bufio.go:177-207 Reader.Discard
    /// `Discard(n)` — skip n bytes. Returns (skipped, err).
    pub fn Discard(&mut self, n: int) -> (int, error) {
        if n < 0 {
            return (0, ErrNegativeCount.into());
        }
        if n == 0 {
            return (0, nil);
        }
        self.lastByte = -1;
        self.lastRuneSize = -1;
        let mut remain = n as usize;
        return loop {
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
                return (toint(n as usize - remain), self.readErr());
            }
        };
    }

    // go: sdk 1.25.5 bufio/bufio.go:216-263 Reader.Read
    /// `Read(p)` — fill `p` from the buffer (one rd.Read at most).
    pub fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let want = p.Len() as usize;
        if want == 0 {
            if self.Buffered() > 0 {
                return (0, nil);
            }
            return (0, self.readErr());
        }
        if self.r == self.w {
            if self.err != nil {
                return (0, self.readErr());
            }
            if want >= self.buf.len() {
                // Large read, empty buffer: read directly into p.
                let (n, err) = self.rd.Read(p);
                if n < 0 {
                    panic!("bufio: reader returned negative count from Read");
                }
                self.err = err;
                if n > 0 {
                    self.lastByte = toint(p[toint(n - 1)]);
                    self.lastRuneSize = -1;
                }
                return (n, self.readErr());
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
                return (0, self.readErr());
            }
            let src = tmp.__into_vec();
            self.buf[..n as usize].copy_from_slice(&src[..n as usize]);
            self.w += n as usize;
        }
        // Copy as much as we can.
        let n = (want).min(self.w - self.r);
        for i in 0..n {
            p[toint(i)] = self.buf[self.r + i];
        }
        self.r += n;
        self.lastByte = toint(self.buf[self.r - 1]);
        self.lastRuneSize = -1;
        return (toint(n), nil);
    }

    // go: sdk 1.25.5 bufio/bufio.go:267-279 Reader.ReadByte
    /// `ReadByte()` — single byte, blocking until one is available.
    pub fn ReadByte(&mut self) -> (byte, error) {
        self.lastRuneSize = -1;
        while self.r == self.w {
            if self.err != nil {
                return (0, self.readErr());
            }
            self.fill();
        }
        let c = self.buf[self.r];
        self.r += 1;
        self.lastByte = toint(c);
        return (c, nil);
    }

    // go: sdk 1.25.5 bufio/bufio.go:286-301 Reader.UnreadByte
    /// `UnreadByte()` — push back the most recently read byte.
    pub fn UnreadByte(&mut self) -> error {
        if self.lastByte < 0 || (self.r == 0 && self.w > 0) {
            return ErrInvalidUnreadByte.into();
        }
        if self.r > 0 {
            self.r -= 1;
        } else {
            self.w = 1;
        }
        self.buf[self.r] = tobyte(self.lastByte);
        self.lastByte = -1;
        self.lastRuneSize = -1;
        return nil;
    }

    // go: sdk 1.25.5 bufio/bufio.go:306-322 Reader.ReadRune
    /// `ReadRune()` — single UTF-8 rune. Returns (rune, size, err).
    /// Invalid encoding consumes one byte and yields RuneError (U+FFFD).
    pub fn ReadRune(&mut self) -> (rune, int, error) {
        while toint(self.r) + utf8::UTFMax > toint(self.w)
            && !utf8::FullRune(&self.buf[self.r..self.w])
            && self.err == nil
            && (self.w - self.r) < self.buf.len()
        {
            self.fill();
        }
        self.lastRuneSize = -1;
        if self.r == self.w {
            return (0, 0, self.readErr());
        }
        let mut r = torune(self.buf[self.r]);
        let mut size: int = 1;
        if r >= torune(utf8::RuneSelf) {
            let (rr, sz) = utf8::DecodeRune(&self.buf[self.r..self.w]);
            r = rr;
            size = sz;
        }
        self.r += size as usize;
        self.lastByte = toint(self.buf[self.r - 1]);
        self.lastRuneSize = size;
        return (r, size, nil);
    }

    // go: sdk 1.25.5 bufio/bufio.go:328-336 Reader.UnreadRune
    /// `UnreadRune()` — push back the most recently read rune. Stricter
    /// than UnreadByte: only valid immediately after ReadRune.
    pub fn UnreadRune(&mut self) -> error {
        if self.lastRuneSize < 0 || self.r < self.lastRuneSize as usize {
            return ErrInvalidUnreadRune.into();
        }
        self.r -= self.lastRuneSize as usize;
        self.lastByte = -1;
        self.lastRuneSize = -1;
        return nil;
    }

    // go: sdk 1.25.5 bufio/bufio.go:351-390 Reader.ReadSlice
    /// `ReadSlice(delim)` — bytes up to and including the delimiter.
    /// Goish: returns a fresh `slice<byte>` (not a view into buf).
    pub fn ReadSlice(&mut self, delim: byte) -> (slice<byte>, error) {
        let mut s: usize = 0; // search start within buf[r..w]
        return loop {
            if let Some(i) = index_byte(&self.buf[self.r + s..self.w], delim) {
                let i = i + s;
                let line = self.buf[self.r..self.r + i + 1].to_vec();
                self.r += i + 1;
                if !line.is_empty() {
                    self.lastByte = toint(line[line.len() - 1]);
                    self.lastRuneSize = -1;
                }
                return (slice::__from_vec(line), nil);
            }
            if self.err != nil {
                let line = self.buf[self.r..self.w].to_vec();
                self.r = self.w;
                let err = self.readErr();
                if !line.is_empty() {
                    self.lastByte = toint(line[line.len() - 1]);
                    self.lastRuneSize = -1;
                }
                return (slice::__from_vec(line), err);
            }
            if (self.w - self.r) >= self.buf.len() {
                self.r = self.w;
                let line = self.buf.clone();
                // lastByte is already set by previous ReadByte/Read; keep it.
                return (slice::__from_vec(line), ErrBufferFull.into());
            }
            s = self.w - self.r;
            self.fill();
        };
    }

    // go: sdk 1.25.5 bufio/bufio.go:408-441 Reader.ReadLine
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
        return (line, false, nil);
    }

    // go: sdk 1.25.5 bufio/bufio.go:441-479 Reader.collectFragments
    /// Reads until the first occurrence of `delim`, returning the full
    /// buffers that filled up on the way, the final fragment, the total
    /// length of all of them, and any error.
    ///
    /// Go returns `[][]byte` for the full buffers; goish returns a
    /// `Vec<Vec<byte>>`, which is the same shape — this is a private
    /// helper, so no public signature carries a Rust container.
    fn collectFragments(&mut self, delim: byte) -> (Vec<Vec<byte>>, Vec<byte>, usize, error) {
        let mut fullBuffers: Vec<Vec<byte>> = Vec::new();
        let mut totalLen: usize = 0;
        let frag: Vec<byte>;
        let mut err = nil;
        // Use ReadSlice to look for delim, accumulating full buffers.
        loop {
            let (s, e) = self.ReadSlice(delim);
            if e == nil {
                // Got the final fragment.
                frag = s.__into_vec();
                break;
            }
            if !errors::Is(e.clone(), ErrBufferFull) {
                // Unexpected error.
                frag = s.__into_vec();
                err = e;
                break;
            }
            // Make a copy of the buffer.
            let buf = s.__into_vec();
            totalLen += buf.len();
            fullBuffers.push(buf);
        }
        totalLen += frag.len();
        return (fullBuffers, frag, totalLen, err);
    }

    // go: sdk 1.25.5 bufio/bufio.go:481-490 Reader.ReadBytes
    /// Reads until the first occurrence of `delim`, returning a slice
    /// containing the data up to and including the delimiter.
    ///
    /// If it encounters an error before finding a delimiter, it returns
    /// the data read before the error and the error itself (often
    /// `io.EOF`). It returns an error iff the returned data does not
    /// end in `delim`.
    pub fn ReadBytes(&mut self, delim: byte) -> (slice<byte>, error) {
        let (full, frag, n, err) = self.collectFragments(delim);
        // Allocate new buffer to hold the full pieces and the fragment.
        let mut out: Vec<byte> = Vec::with_capacity(n);
        for f in full {
            out.extend_from_slice(&f);
        }
        out.extend_from_slice(&frag);
        return (slice::__from_vec(out), err);
    }

    // go: sdk 1.25.5 bufio/bufio.go:501-512 Reader.ReadString
    /// `ReadString(delim)` — same as ReadBytes but returns a `string`.
    pub fn ReadString(&mut self, delim: byte) -> (string, error) {
        let (b, e) = self.ReadBytes(delim);
        return (string::from_bytes(&b.__into_vec()), e);
    }

    // go: sdk 1.25.5 bufio/bufio.go:518-560 Reader.WriteTo
    /// Line-by-line port of `bufio.Reader.WriteTo` (bufio.go:518) —
    /// drain everything in the buffer and the underlying reader to `w`.
    /// Slim deviation: skip the `WriterTo` / `ReaderFrom` fast paths
    /// since goish doesn't expose those traits as `dyn`-castable.
    pub fn WriteTo(&mut self, w: &mut dyn io::Writer) -> (int, error) {
        // Go: b.lastByte = -1; b.lastRuneSize = -1
        self.lastByte = -1;
        self.lastRuneSize = -1;

        let mut n: int = 0;

        // Go: if b.r < b.w { n, err = b.writeBuf(w); if err != nil { return } }
        if self.r < self.w {
            let (m, err) = self.writeBuf(w);
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
            let (m, err) = self.writeBuf(w);
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

        return (n, self.readErr());
    }

    // go: sdk 1.25.5 bufio/bufio.go:565-572 Reader.writeBuf
    // Internal helper: port of bufio.Reader.writeBuf (bufio.go:565).
    fn writeBuf(&mut self, w: &mut dyn io::Writer) -> (int, error) {
        // Go: n, err := w.Write(b.buf[b.r:b.w])
        let chunk: slice<byte> = slice::__from_vec(self.buf[self.r..self.w].to_vec());
        let (n, err) = w.Write(chunk);
        // Go: if n < 0 { panic(errNegativeWrite) }
        if n < 0 {
            panic!("bufio: writer returned negative count from Write");
        }
        // Go: b.r += n
        self.r += n as usize;
        return (n, err);
    }
}

impl<R: io::Reader> io::Reader for Reader<R> {
    // go: sdk 1.25.5 bufio/bufio.go:216-263 Reader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Reader::Read(self, p);
    }
}

impl<R: io::Reader> io::ByteReader for Reader<R> {
    // go: sdk 1.25.5 bufio/bufio.go:267-279 Reader.ReadByte
    fn ReadByte(&mut self) -> (byte, error) {
        return Reader::ReadByte(self);
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

// go: sdk 1.25.5 bufio/bufio.go:610-612 NewWriter
/// `bufio.NewWriter(wr)` — buffered writer with the default size.
pub fn NewWriter<W: io::Writer>(wr: W) -> Writer<W> {
    return NewWriterSize(wr, defaultBufSize);
}

// go: sdk 1.25.5 bufio/bufio.go:592-605 NewWriterSize
/// `bufio.NewWriterSize(wr, size)` — buffered writer with `size` bytes.
pub fn NewWriterSize<W: io::Writer>(wr: W, size: int) -> Writer<W> {
    let sz = if size <= 0 {
        defaultBufSize as usize
    } else {
        size as usize
    };
    let mut buf: Vec<byte> = Vec::with_capacity(sz);
    buf.resize(sz, 0);
    return Writer {
        err: nil,
        buf,
        n: 0,
        wr,
    };
}

// go: none — goish-only: the get half of net/http's bufio writer
// pools (newBufioWriterSize, server.go:900). See `PoolBuf` for why
// the buffer, not the Writer, is the pooled unit.
/// Build a Writer around a recycled backing buffer, resized to
/// `size`. The put half is `__into_buf`.
pub(crate) fn __new_writer_with_buf<W: io::Writer>(wr: W, buf: PoolBuf, size: int) -> Writer<W> {
    let mut buf = buf.0;
    let sz = if size <= 0 {
        defaultBufSize as usize
    } else {
        size as usize
    };
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
    // go: none — goish idiom: identity of the backing buffer, used by
    //     `net/http`'s reader pool to check a Reader still owns the
    //     buffer it was handed. Go compares the slice headers instead.
    #[doc(hidden)]
    pub fn __buf_ptr(&self) -> *const u8 {
        return self.buf.as_ptr();
    }

    // go: sdk 1.25.5 bufio/bufio.go:615-615 Writer.Size
    /// `Size()` — buffer capacity in bytes.
    pub fn Size(&self) -> int {
        return toint(self.buf.len());
    }

    // go: sdk 1.25.5 bufio/bufio.go:622-635 Writer.Reset
    /// `Reset(wr)` — discard buffered data, clear error, switch to `wr`.
    pub fn Reset(&mut self, wr: W) {
        self.err = nil;
        self.n = 0;
        self.wr = wr;
    }

    // go: sdk 1.25.5 bufio/bufio.go:673-673 Writer.Buffered
    /// `Buffered()` — bytes currently buffered (not yet flushed).
    pub fn Buffered(&self) -> int {
        return toint(self.n);
    }

    // go: sdk 1.25.5 bufio/bufio.go:662-662 Writer.Available
    /// `Available()` — bytes free in the buffer.
    pub fn Available(&self) -> int {
        return toint(self.buf.len() - self.n);
    }

    // go: sdk 1.25.5 bufio/bufio.go:668-670 Writer.AvailableBuffer
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
        return slice::__from_vec(Vec::with_capacity(avail));
    }

    // go: sdk 1.25.5 bufio/bufio.go:638-659 Writer.Flush
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
            self.err = errNegativeWrite();
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
        return nil;
    }

    // go: sdk 1.25.5 bufio/bufio.go:679-701 Writer.Write
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
                    self.err = errNegativeWrite();
                    return (toint(nn), self.err.clone());
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
            return (toint(nn), self.err.clone());
        }
        let take = p.len();
        self.buf[self.n..self.n + take].copy_from_slice(&p[..]);
        self.n += take;
        nn += take;
        return (toint(nn), nil);
    }

    // go: sdk 1.25.5 bufio/bufio.go:704-714 Writer.WriteByte
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
        return nil;
    }

    // go: sdk 1.25.5 bufio/bufio.go:718-744 Writer.WriteRune
    /// `WriteRune(r)` — append a single UTF-8-encoded rune.
    pub fn WriteRune(&mut self, r: rune) -> (int, error) {
        if touint32(r) < touint32(utf8::RuneSelf) {
            let e = self.WriteByte(tobyte(r));
            if e != nil {
                return (0, e);
            }
            return (1, nil);
        }
        if self.err != nil {
            return (0, self.err.clone());
        }
        let mut avail = self.Available();
        if avail < utf8::UTFMax {
            let e = self.Flush();
            if e != nil {
                return (0, e);
            }
            avail = self.Available();
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
        return (n, nil);
    }

    // go: sdk 1.25.5 bufio/bufio.go:750-781 Writer.WriteString
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
            return (toint(nn), self.err.clone());
        }
        let take = s.len();
        self.buf[self.n..self.n + take].copy_from_slice(&s[..]);
        self.n += take;
        nn += take;
        return (toint(nn), nil);
    }

    // go: sdk 1.25.5 bufio/bufio.go:787-831 Writer.ReadFrom
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
                    self.buf[self.n..self.n + mm as usize].copy_from_slice(&src[..mm as usize]);
                }
                if mm != 0 || err != nil {
                    break;
                }
                nr += 1;
            }
            // Go: if nr == maxConsecutiveEmptyReads { return n, io.ErrNoProgress }
            if nr == maxConsecutiveEmptyReads {
                return (
                    n,
                    errors::New("multiple Read calls return no data or error"),
                );
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
        return (n, err);
    }
}

impl<W: io::Writer> io::Writer for Writer<W> {
    // go: sdk 1.25.5 bufio/bufio.go:679-701 Writer.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return Writer::Write(self, p);
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

// go: sdk 1.25.5 bufio/bufio.go:843-845 NewReadWriter
/// `bufio.NewReadWriter(r, w)` — pair of buffered Reader and Writer.
pub fn NewReadWriter<R: io::Reader, W: io::Writer>(r: Reader<R>, w: Writer<W>) -> ReadWriter<R, W> {
    return ReadWriter {
        reader: r,
        writer: w,
    };
}
