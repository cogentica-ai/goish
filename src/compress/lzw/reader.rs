// go: file compress/lzw/reader.go decls: errClosed, newReader, Reader.readLSB, Reader.readMSB, Reader.Read, Reader.decode, Reader.Close, Reader.Reset, NewReader, Reader.init
//
// The `decls:` manifest above lists reader.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// `Order`, `Reader` or the width constants there would report them as
// dropped ports. They are not dropped - each carries its own
// `// go: sdk` anchor below.
//
// compress/lzw/reader.go - the LZW decompressor (GIF/TIFF/PDF variant).
//
// LZW builds its dictionary as it decodes, so the decoder and encoder
// have to grow the code width at exactly the same moment or they
// desynchronise silently. That moment is `hi == overflow`, and the
// off-by-one it invites is the whole reason `decode` is written the way
// it is: `hi` is the highest code assigned so far, `overflow` is
// `1 << width`, and the width grows *before* the next code is read.
//
// The other subtlety is the KwKwK case. A code can refer to the entry
// the decoder is about to create - the classic "cScSc" pattern - so
// `decode` special-cases `code == hi + 1` by emitting the previous
// entry plus its own first byte.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::boxed::Box;

use crate::bufio;
use crate::convert::{
    byte as tobyte, int as toint, uint as touint, uint16 as touint16, uint32 as touint32,
};
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int, uint};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Order(pub int);

/// LSB — Least Significant Bits first (GIF).
pub const LSB: Order = Order(0);
/// MSB — Most Significant Bits first (TIFF, PDF).
pub const MSB: Order = Order(1);

// Go: const ( maxWidth = 12; decoderInvalidCode = 0xffff; flushBuffer = 1<<maxWidth )
pub(super) const MAX_WIDTH: uint = 12;
pub(super) const DECODER_INVALID_CODE: u16 = 0xffff;
pub(super) const FLUSH_BUFFER: usize = 1 << 12; // 4096

// ─── Reader ────────────────────────────────────────────────────────────

/// `lzw.Reader` — io.Reader for LZW-compressed bytes.
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
    // go: sdk 1.25.5 compress/lzw/reader.go:90-103 Reader.readLSB
    // Go: func (r *Reader) readLSB() (uint16, error)
    fn readLSB(&mut self) -> (u16, error) {
        // Go: for r.nBits < r.width
        while self.nBits < self.width {
            let (x, err) = self.r.ReadByte();
            if !err.IsNil() {
                return (0, err);
            }
            // Go: r.bits |= uint32(x) << r.nBits
            self.bits |= touint32(x) << self.nBits;
            self.nBits += 8;
        }
        // Go: code := uint16(r.bits & (1<<r.width - 1))
        let code = touint16(self.bits & ((1u32 << self.width) - 1));
        self.bits >>= self.width;
        self.nBits -= self.width;
        return (code, nil);
    }

    // go: sdk 1.25.5 compress/lzw/reader.go:106-119 Reader.readMSB
    // Go: func (r *Reader) readMSB() (uint16, error)
    fn readMSB(&mut self) -> (u16, error) {
        while self.nBits < self.width {
            let (x, err) = self.r.ReadByte();
            if !err.IsNil() {
                return (0, err);
            }
            // Go: r.bits |= uint32(x) << (24 - r.nBits)
            self.bits |= touint32(x) << (24 - self.nBits);
            self.nBits += 8;
        }
        // Go: code := uint16(r.bits >> (32 - r.width))
        let code = touint16(self.bits >> (32 - self.width));
        self.bits <<= self.width;
        self.nBits -= self.width;
        return (code, nil);
    }

    // go: none — goish idiom: Go stores the order-dependent reader in a
    //     `read func(*Reader) (uint16, error)` field; goish dispatches
    //     on `order`, since a function-valued field would need the
    //     `dyn Fn` this project bans (§5 rule 3).
    fn read_code(&mut self) -> (u16, error) {
        return if self.order == LSB {
            self.readLSB()
        } else {
            self.readMSB()
        };
    }

    // go: sdk 1.25.5 compress/lzw/reader.go:122-134 Reader.Read
    // goishlint:ignore GOISH023 - Go's `for { … return … }`; the Rust
    //     `loop` below never breaks, so every exit is already an
    //     explicit `return`.
    /// `(r *Reader).Read(b)` — io.Reader.
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

    // go: sdk 1.25.5 compress/lzw/reader.go:139-224 Reader.decode
    // Go: func (r *Reader) decode()
    fn decode(&mut self) {
        // Go: loop:  for { ... break loop ... }
        // Goish: model the labeled break with a sentinel `done` flag.
        let done = false;
        while !done {
            // Go: code, err := r.read(r)
            let (code, err) = self.read_code();
            if !err.IsNil() {
                // Go: if err == io.EOF { err = io.ErrUnexpectedEOF }
                self.err = if errors::Is(err.clone(), io::EOF) {
                    io::ErrUnexpectedEOF.into()
                } else {
                    err
                };
                break;
            }

            // Go: switch { ... }
            if code < self.clear {
                // case code < r.clear: literal code (reader.go:152-160)
                self.output[self.o as usize] = tobyte(code);
                self.o += 1;
                if self.last != DECODER_INVALID_CODE {
                    self.suffix[self.hi as usize] = tobyte(code);
                    self.prefix[self.hi as usize] = self.last;
                }
            } else if code == self.clear {
                // case code == r.clear (reader.go:161-166)
                self.width = 1 + touint(self.litWidth);
                self.hi = self.eof_;
                self.overflow = 1u16 << self.width;
                self.last = DECODER_INVALID_CODE;
                continue;
            } else if code == self.eof_ {
                // case code == r.eof (reader.go:167-169)
                self.err = io::EOF.into();
                break;
            } else if code <= self.hi {
                // case code <= r.hi (reader.go:170-196)
                let mut c = code;
                let mut i = toint(self.output.len()) - 1;
                if code == self.hi && self.last != DECODER_INVALID_CODE {
                    // hi-special: walk prefix chain to find the head.
                    c = self.last;
                    while c >= self.clear {
                        c = self.prefix[c as usize];
                    }
                    self.output[i as usize] = tobyte(c);
                    i -= 1;
                    c = self.last;
                }
                // Go: for c >= r.clear { r.output[i] = r.suffix[c]; i--; c = r.prefix[c] }
                while c >= self.clear {
                    self.output[i as usize] = self.suffix[c as usize];
                    i -= 1;
                    c = self.prefix[c as usize];
                }
                self.output[i as usize] = tobyte(c);
                // Go: r.o += copy(r.output[r.o:], r.output[i:])
                let n = copy_within_output(&mut self.output[..], self.o as usize, i as usize);
                self.o += n;
                if self.last != DECODER_INVALID_CODE {
                    self.suffix[self.hi as usize] = tobyte(c);
                    self.prefix[self.hi as usize] = self.last;
                }
            } else {
                // default: invalid code (reader.go:197-200)
                self.err = errors::New("lzw: invalid code");
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
                if touint(self.width) == MAX_WIDTH {
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

    // go: sdk 1.25.5 compress/lzw/reader.go:230-233 Reader.Close
    /// `(r *Reader).Close()` — marks the reader closed
    /// without touching the underlying source.
    pub fn Close(&mut self) -> error {
        // Go: r.err = errClosed
        self.err = errClosed();
        return nil;
    }

    // go: sdk 1.25.5 compress/lzw/reader.go:237-240 Reader.Reset
    /// `(r *Reader).Reset(src, order, litWidth)`.
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

    // go: sdk 1.25.5 compress/lzw/reader.go:264-290 Reader.init
    // goishlint:ignore GOISH020 — Go's `init(src, order, litWidth)`
    //     takes the source because it is also the reset path; goish
    //     assigns `self.r` in `Reset` before calling this, so only the
    //     two configuration arguments are left.
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
        self.width = 1 + touint(lit_width);
        // Go: r.clear = uint16(1) << uint(litWidth)
        self.clear = 1u16 << touint(lit_width);
        // Go: r.eof, r.hi = r.clear+1, r.clear+1
        self.eof_ = self.clear + 1;
        self.hi = self.clear + 1;
        // Go: r.overflow = uint16(1) << r.width
        self.overflow = 1u16 << self.width;
        self.last = DECODER_INVALID_CODE;
    }
}

// go: sdk 1.25.5 compress/lzw/reader.go:226-226 errClosed
/// `lzw.errClosed` — the sentinel a closed reader or writer returns.
///
/// Go declares it as a package-level `var`; goish caches it behind a
/// lock so repeated calls return pointer-identical errors, which is
/// what `errors::Is` compares.
pub(super) fn errClosed() -> error {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(errors::New("lzw: reader/writer is closed"));
    }
    return g.as_ref().unwrap().clone();
}

// go: none — goish idiom: Go's builtin `copy(dst, src)`, which copies
//     min(len(dst), len(src)) bytes and returns the count.
pub(super) fn copy_into(dst: &mut slice<byte>, src: &slice<byte>) -> int {
    let n = dst.Len().min(src.Len());
    for k in 0..(n as usize) {
        dst[toint(k)] = src[toint(k)];
    }
    return n;
}

// go: none — goish idiom: Go's builtin `copy` over two overlapping
//     ranges of one array; Rust cannot take two borrows of one buffer.
pub(super) fn copy_within_output(out: &mut [byte], dst_off: usize, src_off: usize) -> int {
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
    return toint(n);
}

// go: sdk 1.25.5 compress/lzw/reader.go:254-256 NewReader
/// `lzw.NewReader(src, order, litWidth)`.
///
/// Returns a Reader<R> instead of `io.ReadCloser`. Goish has no
/// trait-object form for ReadCloser; the concrete type implements both
/// `io::Reader` and `io::Closer`.
pub fn NewReader<R: io::Reader>(src: R, order: Order, lit_width: int) -> Reader<R> {
    return new_reader(src, order, lit_width);
}

// go: sdk 1.25.5 compress/lzw/reader.go:258-262 newReader
/// `lzw.newReader(src, order, litWidth)` — build a `Reader` directly,
/// without the `io.ReadCloser` boxing `NewReader` does in Go.
pub(super) fn new_reader<R: io::Reader>(src: R, order: Order, lit_width: int) -> Reader<R> {
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
    return r;
}

// ─── trait impls ───────────────────────────────────────────────────────

impl<R: io::Reader> io::Reader for Reader<R> {
    // go: sdk 1.25.5 compress/lzw/reader.go:122-134 Reader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Reader::Read(self, p);
    }
}

impl<R: io::Reader> io::Closer for Reader<R> {
    // go: sdk 1.25.5 compress/lzw/reader.go:230-233 Reader.Close
    fn Close(&mut self) -> error {
        return Reader::Close(self);
    }
}

// `string` returned by `Sprintf!` doesn't implement `into_error`
// directly elsewhere; provide a private extension trait used only in
// this module to mirror Go's `fmt.Errorf(...)` shape.
pub(super) trait IntoErrorExt {
    // go: none — goish idiom: lifts a formatted `string` into an
    //     `error`. Go writes `errors.New(fmt.Sprintf(...))` inline.
    fn into_error(self) -> error;
}
impl IntoErrorExt for string {
    // go: none — goish idiom: see the trait declaration.
    fn into_error(self) -> error {
        return errors::New(self);
    }
}
