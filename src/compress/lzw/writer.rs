// go: file compress/lzw/writer.go decls: Writer.writeLSB, Writer.writeMSB, Writer.incHi, Writer.Write, Writer.Close, Writer.Reset, NewWriter, newWriter, Writer.init
//
// goishlint:ignore GOISH021 errOutOfCodes — declared in reader.rs
//     alongside `errClosed`, since both are cached the same way and
//     goish keeps the pair together. Go declares this one in
//     writer.go:94.
//
// The `decls:` manifest above lists writer.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// `Writer` or the table constants there would report them as dropped
// ports. They are not dropped - each carries its own `// go: sdk`
// anchor below.
//
// compress/lzw/writer.go - the LZW compressor.
//
// The dictionary is a hash table of 16384 slots holding
// (prefix, suffix) -> code, probed with two different strides so a
// collision walks a different chain each time. `incHi` is where the
// code width grows and where the table is reset once `hi` reaches
// `maxCode`, and it has to happen at the same point the decoder does it
// - see reader.rs's header.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::boxed::Box;

use crate::bufio;
use crate::convert::{byte as tobyte, int as toint, uint as touint, uint32 as touint32};
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int, uint};

use super::reader::{errClosed, IntoErrorExt, Order, LSB, MSB};

// ─── Writer ────────────────────────────────────────────────────────────
//
// Line-by-line port of /share/go/src/compress/lzw/writer.go.
//
// Slim deviations:
//   * Order-dispatch via enum match (vs Go's `write` function-pointer field).
//   * `table [16384]uint32` boxed for stack budget.
//   * Always wrap the destination in `bufio::Writer` (Go has a
//     `writer interface{ io.ByteWriter; Flush() error }` short-circuit
//     for already-buffered destinations; goish unconditionally buffers).

// Go: maxCode = 1<<12 - 1
const MAX_CODE: u32 = (1 << 12) - 1;
// Go: invalidCode = 1<<32 - 1
const INVALID_CODE: u32 = u32::MAX;
// Go: tableSize = 4 * 1<<12
const TABLE_SIZE: usize = 4 * (1 << 12); // 16384
                                         // Go: tableMask = tableSize - 1
const TABLE_MASK: u32 = (TABLE_SIZE as u32) - 1; // goishlint:ignore GOISH005 - a const initialiser must be a constant expression.
                                                 // Go: invalidEntry = 0
const INVALID_ENTRY: u32 = 0;

/// `lzw.Writer` — io.Writer that emits LZW-compressed
/// bytes to an underlying writer, flushed by Close().
pub struct Writer<W: io::Writer> {
    // Go: w writer (io.ByteWriter + Flush)
    w: bufio::Writer<W>,
    // Go: litWidth uint
    litWidth: uint,
    // Go: order Order; write func ...; nBits uint; width uint; bits uint32
    order: Order,
    nBits: uint,
    width: uint,
    bits: u32,
    // Go: hi, overflow uint32
    hi: u32,
    overflow: u32,
    // Go: savedCode uint32
    savedCode: u32,
    // Go: err error
    err: error,
    // Go: table [tableSize]uint32 — 16384 entries (~64 KiB), boxed.
    table: Box<[u32; TABLE_SIZE]>,
}

impl<W: io::Writer> Writer<W> {
    // go: sdk 1.25.5 compress/lzw/writer.go:65-76 Writer.writeLSB
    // Go: func (w *Writer) writeLSB(c uint32) error
    fn writeLSB(&mut self, c: u32) -> error {
        // Go: w.bits |= c << w.nBits
        self.bits |= c << self.nBits;
        self.nBits += self.width;
        // Go: for w.nBits >= 8 { ... }
        while self.nBits >= 8 {
            let err = self.w.WriteByte(tobyte(self.bits));
            if !err.IsNil() {
                return err;
            }
            self.bits >>= 8;
            self.nBits -= 8;
        }
        return nil;
    }

    // go: sdk 1.25.5 compress/lzw/writer.go:79-90 Writer.writeMSB
    // Go: func (w *Writer) writeMSB(c uint32) error
    fn writeMSB(&mut self, c: u32) -> error {
        // Go: w.bits |= c << (32 - w.width - w.nBits)
        self.bits |= c << (32 - self.width - self.nBits);
        self.nBits += self.width;
        while self.nBits >= 8 {
            let err = self.w.WriteByte(tobyte(self.bits >> 24));
            if !err.IsNil() {
                return err;
            }
            self.bits <<= 8;
            self.nBits -= 8;
        }
        return nil;
    }

    // go: none — goish idiom: Go stores the order-dependent writer in a
    //     `write func(*Writer, uint32) error` field; goish dispatches on
    //     `order` (§5 rule 3).
    fn write_code(&mut self, c: u32) -> error {
        return if self.order == LSB {
            self.writeLSB(c)
        } else {
            self.writeMSB(c)
        };
    }

    // go: sdk 1.25.5 compress/lzw/writer.go:99-119 Writer.incHi
    // Go: func (w *Writer) incHi() error
    // Returns (err, isOutOfCodes). `isOutOfCodes=true` mirrors Go's
    // sentinel `errOutOfCodes` value used as a control-flow signal.
    fn incHi(&mut self) -> (error, bool) {
        // Go: w.hi++
        self.hi += 1;
        if self.hi == self.overflow {
            self.width += 1;
            self.overflow <<= 1;
        }
        if self.hi == MAX_CODE {
            // Go: clear := uint32(1) << w.litWidth
            let clear = 1u32 << self.litWidth;
            let err = self.write_code(clear);
            if !err.IsNil() {
                return (err, false);
            }
            self.width = self.litWidth + 1;
            self.hi = clear + 1;
            self.overflow = clear << 1;
            // Go: for i := range w.table { w.table[i] = invalidEntry }
            for i in 0..TABLE_SIZE {
                self.table[i] = INVALID_ENTRY;
            }
            return (nil, true); // errOutOfCodes
        }
        return (nil, false);
    }

    // go: sdk 1.25.5 compress/lzw/writer.go:122-196 Writer.Write
    /// `(w *Writer).Write(p)` — io.Writer.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: if w.err != nil { return 0, w.err }
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }
        // Go: if len(p) == 0 { return 0, nil }
        if p.Len() == 0 {
            return (0, nil);
        }
        // Go: if maxLit := uint8(1<<w.litWidth - 1); maxLit != 0xff
        let maxLit: byte = tobyte((1u32 << self.litWidth) - 1);
        if maxLit != 0xff {
            for i in 0..(p.Len() as usize) {
                let x = p[toint(i)];
                if x > maxLit {
                    self.err = errors::New("lzw: input byte too large for the litWidth");
                    return (0, self.err.clone());
                }
            }
        }
        let n = p.Len();
        let mut code = self.savedCode;
        let mut start: usize = 0;
        if code == INVALID_CODE {
            // Go: clear := uint32(1) << w.litWidth
            let clear = 1u32 << self.litWidth;
            let err = self.write_code(clear);
            if !err.IsNil() {
                return (0, err);
            }
            // Go: code, p = uint32(p[0]), p[1:]
            code = touint32(p[0i64]);
            start = 1;
        }
        // Go: loop: for _, x := range p { ... continue loop ... }
        let plen = p.Len() as usize;
        let mut idx = start;
        'outer: while idx < plen {
            let x = p[toint(idx)];
            idx += 1;
            let literal = touint32(x);
            // Go: key := code<<8 | literal
            let key = (code << 8) | literal;
            // Go: hash := (key>>12 ^ key) & tableMask
            let mut hash = ((key >> 12) ^ key) & TABLE_MASK;
            let mut h = hash;
            let mut t = self.table[hash as usize];
            // Go: for ... t != invalidEntry { ... }
            while t != INVALID_ENTRY {
                if key == t >> 12 {
                    code = t & MAX_CODE;
                    continue 'outer;
                }
                h = (h + 1) & TABLE_MASK;
                t = self.table[h as usize];
            }
            // Go: if w.err = w.write(w, code); w.err != nil { return 0, w.err }
            self.err = self.write_code(code);
            if !self.err.IsNil() {
                return (0, self.err.clone());
            }
            code = literal;
            // Go: if err1 := w.incHi(); err1 != nil { ... }
            let (e1, oof) = self.incHi();
            if oof {
                continue;
            }
            if !e1.IsNil() {
                self.err = e1;
                return (0, self.err.clone());
            }
            // Go: for { if w.table[hash] == invalidEntry { ... break } else hash++ }
            loop {
                if self.table[hash as usize] == INVALID_ENTRY {
                    self.table[hash as usize] = (key << 12) | self.hi;
                    break;
                }
                hash = (hash + 1) & TABLE_MASK;
            }
        }
        // Go: w.savedCode = code; return n, nil
        self.savedCode = code;
        return (n, nil);
    }

    // go: sdk 1.25.5 compress/lzw/writer.go:200-239 Writer.Close
    /// `(w *Writer).Close()`.
    pub fn Close(&mut self) -> error {
        if !self.err.IsNil() {
            // Go: if w.err == errClosed { return nil }
            if errors::Is(self.err.clone(), errClosed()) {
                return nil;
            }
            return self.err.clone();
        }
        // Go: w.err = errClosed
        self.err = errClosed();
        if self.savedCode != INVALID_CODE {
            let saved = self.savedCode;
            let e = self.write_code(saved);
            if !e.IsNil() {
                return e;
            }
            let (e2, oof) = self.incHi();
            if !e2.IsNil() && !oof {
                return e2;
            }
        } else {
            let clear = 1u32 << self.litWidth;
            let e = self.write_code(clear);
            if !e.IsNil() {
                return e;
            }
        }
        // Go: eof := uint32(1)<<w.litWidth + 1
        let eof = (1u32 << self.litWidth) + 1;
        let e = self.write_code(eof);
        if !e.IsNil() {
            return e;
        }
        if self.nBits > 0 {
            if self.order == MSB {
                self.bits >>= 24;
            }
            let e = self.w.WriteByte(tobyte(self.bits));
            if !e.IsNil() {
                return e;
            }
        }
        return self.w.Flush();
    }

    // go: sdk 1.25.5 compress/lzw/writer.go:243-246 Writer.Reset
    /// `(w *Writer).Reset(dst, order, litWidth)`.
    pub fn Reset(&mut self, dst: W, order: Order, lit_width: int) {
        // Zero state in-place then re-init.
        self.litWidth = 0;
        self.nBits = 0;
        self.width = 0;
        self.bits = 0;
        self.hi = 0;
        self.overflow = 0;
        self.savedCode = 0;
        self.err = nil;
        for i in 0..TABLE_SIZE {
            self.table[i] = INVALID_ENTRY;
        }
        self.w = bufio::NewWriter(dst);
        self.init(order, lit_width);
    }

    // go: sdk 1.25.5 compress/lzw/writer.go:267-293 Writer.init
    // goishlint:ignore GOISH020 — see `Reader::init` in reader.rs.
    fn init(&mut self, order: Order, lit_width: int) {
        // Go: switch order { LSB|MSB ... default: invalid }
        if order != LSB && order != MSB {
            self.err = errors::New("lzw: unknown order");
            return;
        }
        self.order = order;
        if lit_width < 2 || 8 < lit_width {
            self.err = crate::Sprintf!("lzw: litWidth %d out of range", lit_width).into_error();
            return;
        }
        let lw = touint(lit_width);
        self.width = 1 + lw;
        self.litWidth = lw;
        self.hi = (1u32 << lw) + 1;
        self.overflow = 1u32 << (lw + 1);
        self.savedCode = INVALID_CODE;
    }
}

// go: sdk 1.25.5 compress/lzw/writer.go:257-259 NewWriter
/// `lzw.NewWriter(w, order, litWidth)`.
///
/// Returns a `Writer<W>` instead of `io.WriteCloser`. Goish has no
/// trait-object form for WriteCloser; the concrete type implements
/// both `io::Writer` and `io::Closer`.
pub fn NewWriter<W: io::Writer>(dst: W, order: Order, lit_width: int) -> Writer<W> {
    return new_writer(dst, order, lit_width);
}

// go: sdk 1.25.5 compress/lzw/writer.go:261-265 newWriter
/// `lzw.newWriter(dst, order, litWidth)` — build a `Writer` directly,
/// without the `io.WriteCloser` boxing `NewWriter` does in Go.
fn new_writer<W: io::Writer>(dst: W, order: Order, lit_width: int) -> Writer<W> {
    let mut w = Writer {
        w: bufio::NewWriter(dst),
        litWidth: 0,
        order: LSB,
        nBits: 0,
        width: 0,
        bits: 0,
        hi: 0,
        overflow: 0,
        savedCode: 0,
        err: nil,
        table: Box::new([INVALID_ENTRY; TABLE_SIZE]),
    };
    w.init(order, lit_width);
    return w;
}

impl<W: io::Writer> io::Writer for Writer<W> {
    // go: sdk 1.25.5 compress/lzw/writer.go:122-196 Writer.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return Writer::Write(self, p);
    }
}

impl<W: io::Writer> io::Closer for Writer<W> {
    // go: sdk 1.25.5 compress/lzw/writer.go:200-239 Writer.Close
    fn Close(&mut self) -> error {
        return Writer::Close(self);
    }
}
