// compress/lzw — Lempel-Ziv-Welch (GIF/PDF flavor).
//
// Line-by-line port of Go 1.25 `/share/go/src/compress/lzw/reader.go`.
// LZW with variable-width codes up to 12 bits; the first 1<<litWidth
// codes are literals, then a `clear` and `eof` code, then learned
// dictionary entries up to 4096 codes total.
//
// Slim deviations:
//   * Go's `*Reader` chooses readLSB / readMSB via a function-pointer
//     field (`r.read`). Goish dispatches via the `order` enum match
//     inside `read_code()` — functionally identical.
//   * Go embeds `suffix [4096]uint8`, `prefix [4096]uint16`, and
//     `output [8192]uint8` directly in the struct (~20 KiB stack
//     footprint). Goish boxes those tables (`Box<[T; N]>`) so the
//     Reader fits inside default-sized goroutine stacks (2 KiB) without
//     opt-up. The user-visible `Reader` type is otherwise byte-identical
//     to Go's.
//   * Go does `src.(io.ByteReader)` then falls back to bufio.NewReader.
//     Goish unconditionally wraps in `bufio::Reader` (the ByteReader
//     impl was added for that purpose). Slight extra allocation on
//     already-buffered sources; behavior identical.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::boxed::Box;

use crate::bufio;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int, uint};
use crate::nil;

// Go: const ( LSB Order = iota; MSB )
//
// `Order` specifies the bit ordering in an LZW data stream.
// Go's `Order` is a typed `int`. We mirror as a tiny tuple struct that
// supports `==` against itself and the two constants.

/// `lzw.Order` — LSB or MSB ordering. (reader.go:29)
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Order(pub int);

/// LSB — Least Significant Bits first (GIF). (reader.go:33)
pub const LSB: Order = Order(0);
/// MSB — Most Significant Bits first (TIFF, PDF). (reader.go:36)
pub const MSB: Order = Order(1);

// Go: const ( maxWidth = 12; decoderInvalidCode = 0xffff; flushBuffer = 1<<maxWidth )
const MAX_WIDTH: uint = 12;
const DECODER_INVALID_CODE: u16 = 0xffff;
const FLUSH_BUFFER: usize = 1 << 12; // 4096

// ─── Reader ────────────────────────────────────────────────────────────

/// `lzw.Reader` (reader.go:47) — io.Reader for LZW-compressed bytes.
/// Read returns decompressed plaintext; Close releases the reader.
pub struct Reader<R: io::Reader> {
    // Go: r io.ByteReader
    r: bufio::Reader<R>,
    // Go: bits uint32; nBits uint; width uint
    bits: u32,
    nBits: uint,
    width: uint,
    // Go: read func(*Reader) (uint16, error) — see slim deviation
    order: Order,
    // Go: litWidth int
    litWidth: int,
    // Go: err error
    err: error,

    // Go: clear, eof, hi, overflow, last uint16
    clear: u16,
    eof_: u16,
    hi: u16,
    overflow: u16,
    last: u16,

    // Go: suffix [1<<maxWidth]uint8; prefix [1<<maxWidth]uint16
    suffix: Box<[byte; FLUSH_BUFFER]>,
    prefix: Box<[u16; FLUSH_BUFFER]>,

    // Go: output [2*1<<maxWidth]byte; o int; toRead []byte
    output: Box<[byte; 2 * FLUSH_BUFFER]>,
    o: int,
    toRead: slice<byte>,
}

impl<R: io::Reader> Reader<R> {
    // Go: func (r *Reader) readLSB() (uint16, error)  (reader.go:90)
    fn readLSB(&mut self) -> (u16, error) {
        // Go: for r.nBits < r.width
        while self.nBits < self.width {
            let (x, err) = self.r.ReadByte();
            if !err.IsNil() {
                return (0, err);
            }
            // Go: r.bits |= uint32(x) << r.nBits
            self.bits |= (x as u32) << self.nBits;
            self.nBits += 8;
        }
        // Go: code := uint16(r.bits & (1<<r.width - 1))
        let code = (self.bits & ((1u32 << self.width) - 1)) as u16;
        self.bits >>= self.width;
        self.nBits -= self.width;
        (code, nil)
    }

    // Go: func (r *Reader) readMSB() (uint16, error)  (reader.go:106)
    fn readMSB(&mut self) -> (u16, error) {
        while self.nBits < self.width {
            let (x, err) = self.r.ReadByte();
            if !err.IsNil() {
                return (0, err);
            }
            // Go: r.bits |= uint32(x) << (24 - r.nBits)
            self.bits |= (x as u32) << (24 - self.nBits);
            self.nBits += 8;
        }
        // Go: code := uint16(r.bits >> (32 - r.width))
        let code = (self.bits >> (32 - self.width)) as u16;
        self.bits <<= self.width;
        self.nBits -= self.width;
        (code, nil)
    }

    // Slim-deviation dispatcher for the order-dependent reader fn.
    fn read_code(&mut self) -> (u16, error) {
        if self.order == LSB {
            self.readLSB()
        } else {
            self.readMSB()
        }
    }

    /// `(r *Reader).Read(b)` (reader.go:122) — io.Reader.
    pub fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        // Go: for { ... }
        loop {
            // Go: if len(r.toRead) > 0 { n := copy(b, r.toRead); r.toRead = r.toRead[n:]; return n, nil }
            if self.toRead.Len() > 0 {
                let n = copy_into(b, &self.toRead);
                self.toRead = self.toRead.slice(n, self.toRead.Len());
                return (n, nil);
            }
            // Go: if r.err != nil { return 0, r.err }
            if !self.err.IsNil() {
                return (0, self.err.clone());
            }
            self.decode();
        }
    }

    // Go: func (r *Reader) decode()  (reader.go:139)
    fn decode(&mut self) {
        // Go: loop:  for { ... break loop ... }
        // Goish: model the labeled break with a sentinel `done` flag.
        let mut done = false;
        while !done {
            // Go: code, err := r.read(r)
            let (code, err) = self.read_code();
            if !err.IsNil() {
                // Go: if err == io.EOF { err = io.ErrUnexpectedEOF }
                self.err = if errors::Is(err.clone(), io::EOF()) {
                    io::ErrUnexpectedEOF()
                } else {
                    err
                };
                break;
            }

            // Go: switch { ... }
            if code < self.clear {
                // case code < r.clear: literal code (reader.go:152-160)
                self.output[self.o as usize] = code as byte;
                self.o += 1;
                if self.last != DECODER_INVALID_CODE {
                    self.suffix[self.hi as usize] = code as byte;
                    self.prefix[self.hi as usize] = self.last;
                }
            } else if code == self.clear {
                // case code == r.clear (reader.go:161-166)
                self.width = 1 + self.litWidth as uint;
                self.hi = self.eof_;
                self.overflow = 1u16 << self.width;
                self.last = DECODER_INVALID_CODE;
                continue;
            } else if code == self.eof_ {
                // case code == r.eof (reader.go:167-169)
                self.err = io::EOF();
                done = true;
                break;
            } else if code <= self.hi {
                // case code <= r.hi (reader.go:170-196)
                let mut c = code;
                let mut i = (self.output.len() as int) - 1;
                if code == self.hi && self.last != DECODER_INVALID_CODE {
                    // hi-special: walk prefix chain to find the head.
                    c = self.last;
                    while c >= self.clear {
                        c = self.prefix[c as usize];
                    }
                    self.output[i as usize] = c as byte;
                    i -= 1;
                    c = self.last;
                }
                // Go: for c >= r.clear { r.output[i] = r.suffix[c]; i--; c = r.prefix[c] }
                while c >= self.clear {
                    self.output[i as usize] = self.suffix[c as usize];
                    i -= 1;
                    c = self.prefix[c as usize];
                }
                self.output[i as usize] = c as byte;
                // Go: r.o += copy(r.output[r.o:], r.output[i:])
                let n = copy_within_output(
                    &mut self.output[..],
                    self.o as usize,
                    i as usize,
                );
                self.o += n;
                if self.last != DECODER_INVALID_CODE {
                    self.suffix[self.hi as usize] = c as byte;
                    self.prefix[self.hi as usize] = self.last;
                }
            } else {
                // default: invalid code (reader.go:197-200)
                self.err = errors::New("lzw: invalid code");
                done = true;
                break;
            }

            // Go: r.last, r.hi = code, r.hi+1
            self.last = code;
            self.hi += 1;
            // Go: if r.hi >= r.overflow { ... }
            if self.hi >= self.overflow {
                if self.hi > self.overflow {
                    panic!("unreachable");
                }
                if self.width as uint == MAX_WIDTH {
                    self.last = DECODER_INVALID_CODE;
                    self.hi -= 1;
                } else {
                    self.width += 1;
                    self.overflow = 1u16 << self.width;
                }
            }
            // Go: if r.o >= flushBuffer { break }
            if self.o as usize >= FLUSH_BUFFER {
                break;
            }
        }
        // Go: r.toRead = r.output[:r.o]
        let mut buf: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(self.o as usize);
        for i in 0..(self.o as usize) {
            buf.push(self.output[i]);
        }
        self.toRead = slice::__from_vec(buf);
        self.o = 0;
    }

    /// `(r *Reader).Close()` (reader.go:230) — marks the reader closed
    /// without touching the underlying source.
    pub fn Close(&mut self) -> error {
        // Go: r.err = errClosed
        self.err = errClosed();
        nil
    }

    /// `(r *Reader).Reset(src, order, litWidth)` (reader.go:237).
    pub fn Reset(&mut self, src: R, order: Order, lit_width: int) {
        // Go: *r = Reader{}; r.init(src, order, litWidth)
        // Goish: zero state in-place then call init().
        self.bits = 0;
        self.nBits = 0;
        self.width = 0;
        self.litWidth = 0;
        self.err = nil;
        self.clear = 0;
        self.eof_ = 0;
        self.hi = 0;
        self.overflow = 0;
        self.last = 0;
        // suffix/prefix/output are scratch — no need to clear.
        self.o = 0;
        self.toRead = slice::new();
        // Replace the wrapped source.
        self.r = bufio::NewReader(src);
        self.init(order, lit_width);
    }

    // Go: func (r *Reader) init(src io.Reader, order Order, litWidth int)
    fn init(&mut self, order: Order, lit_width: int) {
        // Go: switch order { case LSB: r.read = readLSB; ... default: invalid }
        if order != LSB && order != MSB {
            self.err = errors::New("lzw: unknown order");
            return;
        }
        self.order = order;
        // Go: if litWidth < 2 || 8 < litWidth { r.err = ... return }
        if lit_width < 2 || 8 < lit_width {
            self.err = crate::Sprintf!("lzw: litWidth %d out of range", lit_width).into_error();
            return;
        }
        self.litWidth = lit_width;
        // Go: r.width = 1 + uint(litWidth)
        self.width = 1 + lit_width as uint;
        // Go: r.clear = uint16(1) << uint(litWidth)
        self.clear = 1u16 << lit_width as uint;
        // Go: r.eof, r.hi = r.clear+1, r.clear+1
        self.eof_ = self.clear + 1;
        self.hi = self.clear + 1;
        // Go: r.overflow = uint16(1) << r.width
        self.overflow = 1u16 << self.width;
        self.last = DECODER_INVALID_CODE;
    }
}

// Go: var errClosed = errors.New("lzw: reader/writer is closed")
fn errClosed() -> error {
    errors::New("lzw: reader/writer is closed")
}

// Go: copy(dst, src)  (built-in)
fn copy_into(dst: &mut slice<byte>, src: &slice<byte>) -> int {
    let n = dst.Len().min(src.Len());
    for k in 0..(n as usize) {
        dst[k as int] = src[k as int];
    }
    n
}

// Go: copy(r.output[r.o:], r.output[i:])  (within-array copy)
fn copy_within_output(out: &mut [byte], dst_off: usize, src_off: usize) -> int {
    let n = (out.len() - dst_off).min(out.len() - src_off);
    if dst_off <= src_off {
        // Forward copy is safe.
        for k in 0..n {
            out[dst_off + k] = out[src_off + k];
        }
    } else {
        // Source precedes destination — copy backwards (rare in this code path).
        for k in (0..n).rev() {
            out[dst_off + k] = out[src_off + k];
        }
    }
    n as int
}

/// `lzw.NewReader(src, order, litWidth)` (reader.go:254).
///
/// Returns a Reader<R> instead of `io.ReadCloser`. Goish has no
/// trait-object form for ReadCloser; the concrete type implements both
/// `io::Reader` and `io::Closer`.
pub fn NewReader<R: io::Reader>(src: R, order: Order, lit_width: int) -> Reader<R> {
    new_reader(src, order, lit_width)
}

// Go: func newReader(src io.Reader, order Order, litWidth int) *Reader  (reader.go:258)
fn new_reader<R: io::Reader>(src: R, order: Order, lit_width: int) -> Reader<R> {
    let mut r = Reader {
        r: bufio::NewReader(src),
        bits: 0,
        nBits: 0,
        width: 0,
        order: LSB,
        litWidth: 0,
        err: nil,
        clear: 0,
        eof_: 0,
        hi: 0,
        overflow: 0,
        last: 0,
        suffix: Box::new([0u8; FLUSH_BUFFER]),
        prefix: Box::new([0u16; FLUSH_BUFFER]),
        output: Box::new([0u8; 2 * FLUSH_BUFFER]),
        o: 0,
        toRead: slice::new(),
    };
    r.init(order, lit_width);
    r
}

// ─── trait impls ───────────────────────────────────────────────────────

impl<R: io::Reader> io::Reader for Reader<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Reader::Read(self, p)
    }
}

impl<R: io::Reader> io::Closer for Reader<R> {
    fn Close(&mut self) -> error {
        Reader::Close(self)
    }
}

// `string` returned by `Sprintf!` doesn't implement `into_error`
// directly elsewhere; provide a private extension trait used only in
// this module to mirror Go's `fmt.Errorf(...)` shape.
trait IntoErrorExt {
    fn into_error(self) -> error;
}
impl IntoErrorExt for string {
    fn into_error(self) -> error {
        errors::New(self)
    }
}
