// compress/flate — DEFLATE compressed data format (RFC 1951).
//
// Line-by-line port of Go 1.25 `/share/go/src/compress/flate/`.
// This file currently carries the **decompressor** (the inflate side):
// `inflate.go` + `dict_decoder.go`. The Huffman encoder, the
// compressor, and the zlib wrapper are appended by later tasks.
//
// Slim deviations from Go:
//   * Go's `decompressor.step` is a `func(*decompressor)` field.
//     Goish dispatches via the `Step` enum inside `Read` — functionally
//     identical (no function-pointer field, AGENTS.md §5).
//   * Go's `makeReader` does `r.(Reader)` to detect a source that already
//     implements `io.ByteReader`, else wraps it in `bufio.NewReader`. Goish
//     mirrors this with TWO entry points: `NewReader` wraps a plain
//     `io::Reader` in `bufio::Reader` (the else-branch), while `NewReaderByte`
//     takes a source that already implements `io::ByteReader` and uses it
//     DIRECTLY (the `r.(Reader)` branch) — no extra buffering, so the source
//     is left positioned exactly at the byte past the DEFLATE stream.
//     Proven by examples/zlib_offset_smoke.rs (consumed == exact stream len).
//   * Go's `NewReader` returns `io.ReadCloser`; goish has no
//     trait-object ReadCloser, so we return the concrete
//     `Decompressor<R>` which implements `io::Reader` + `io::Closer`
//     (and carries `Reset`, mirroring the `Resetter` interface).
//   * Go's `huffmanDecoder.bits`/`codebits` are `*[N]int` heap arrays.
//     Goish stores them inline (boxed where the stack budget matters).

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::error;
use crate::errors::nil;
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int, uint};

// ─── inflate.go lives in its own file ────────────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. inflate.go's half has moved to `inflate.rs`.

pub mod inflate;

pub(crate) use inflate::new_decompressor_buffered;
pub use inflate::{
    CorruptInputError, Decompressor, InternalError, NewReader, NewReaderByte, NewReaderByteDict,
    NewReaderDict,
};

use inflate::{endBlockMarker, internal, maxMatchOffset, maxNumLit};

// ─── dict_decoder.go lives in its own file ───────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. dict_decoder.go's half has moved to
// `dict_decoder.rs` and is anchored; the other six Go files of this
// package are still here and still unanchored.

mod dict_decoder;

// ─── token.go lives in its own file ──────────────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. token.go's half has moved to `token.rs`.

#[path = "token.rs"]
mod token_go;

use token_go::{lengthCode, literalToken, matchToken, matchType, offsetCode, token};

// ─── huffman_code.go lives in its own file ───────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. huffman_code.go's half has moved to
// `huffman_code.rs` and is anchored. `huffOffset` below stays here: it
// is huffman_bit_writer.go:600, not huffman_code.go.

mod huffman_code;

use huffman_code::{
    clone_encoder, fixedLiteralEncoding, fixedOffsetEncoding, hcode, huffmanEncoder, math_MaxInt32,
    newHuffmanEncoder,
};

// `huffOffset` (huffman_bit_writer.go:600) — a static offset encoder
// used for huffman-only encoding. Built once, cloned in.
fn huffOffset() -> huffmanEncoder {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<Vec<hcode>>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        let mut offsetFreq = [0i32; offsetCodeCount as usize];
        offsetFreq[0] = 1;
        let mut h = newHuffmanEncoder(offsetCodeCount);
        h.generate(&offsetFreq, 15);
        *g = Some(h.codes);
    }
    return huffman_code::__from_codes(g.as_ref().unwrap());
}

// ─── huffmanBitWriter constants (huffman_bit_writer.go:11) ─────────────

// The largest offset code.
const offsetCodeCount: int = 30;

// The first length code.
const lengthCodesStart: int = 257;

// The number of codegen codes.
const codegenCodeCount: int = 19;
const badCode: u8 = 255;

// bufferFlushSize — buffer size after which bytes are flushed to the
// writer. A multiple of 6 (we accumulate 6 bytes between writes).
const bufferFlushSize: int = 240;

// bufferSize — actual output byte buffer size. Has headroom for a
// flush (up to 8 bytes).
const bufferSize: int = bufferFlushSize + 8;

// maxStoreBlockSize — defined in deflate.go (the compressor task);
// referenced here by `storedSize`. RFC 1951 stored-block max payload.
const maxStoreBlockSize: int = 65535;

// The number of extra bits needed by length code X - LENGTH_CODES_START.
static lengthExtraBits: [i8; 29] = [
    /* 257 */ 0, 0, 0, /* 260 */ 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, /* 270 */ 2, 2, 2, 3,
    3, 3, 3, 4, 4, 4, /* 280 */ 4, 5, 5, 5, 5, 0,
];

// The length indicated by length code X - LENGTH_CODES_START.
static lengthBase: [u32; 29] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224, 255,
];

// Offset code word extra bits.
static offsetExtraBits: [i8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

static offsetBase: [u32; 30] = [
    0x000000, 0x000001, 0x000002, 0x000003, 0x000004, 0x000006, 0x000008, 0x00000c, 0x000010,
    0x000018, 0x000020, 0x000030, 0x000040, 0x000060, 0x000080, 0x0000c0, 0x000100, 0x000180,
    0x000200, 0x000300, 0x000400, 0x000600, 0x000800, 0x000c00, 0x001000, 0x001800, 0x002000,
    0x003000, 0x004000, 0x006000,
];

// The odd order in which the codegen code sizes are written.
static codegenOrder: [u32; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

// ─── huffmanBitWriter (huffman_bit_writer.go:71) ───────────────────────

/// `flate.huffmanBitWriter` — accumulates Huffman-coded bits and flushes
/// whole bytes to the underlying `io::Writer`.
///
/// Go's `huffmanBitWriter.writer` is a plain `io.Writer`; the bit writer
/// owns ALL its buffering via the `bytes` array (no `bufio`). Goish
/// holds the writer directly, generic over `W`.
pub(crate) struct huffmanBitWriter<W: io::Writer> {
    // The underlying writer. Do not use directly; use `write`, which
    // makes Write errors sticky.
    writer: W,

    // Data waiting to be written is bytes[0:nbytes] and then the low
    // nbits of bits. Data is always written sequentially into `bytes`.
    bits: u64,
    nbits: uint,
    bytes: [byte; bufferSize as usize],
    codegenFreq: [i32; codegenCodeCount as usize],
    nbytes: int,
    // Internal scratch buffers — module-private, stay `Vec`.
    literalFreq: Vec<i32>,
    offsetFreq: Vec<i32>,
    codegen: Vec<u8>,
    literalEncoding: huffmanEncoder,
    offsetEncoding: huffmanEncoder,
    codegenEncoding: huffmanEncoder,
    pub(crate) err: error,
}

/// `newHuffmanBitWriter(w)` (huffman_bit_writer.go:94).
pub(crate) fn newHuffmanBitWriter<W: io::Writer>(w: W) -> huffmanBitWriter<W> {
    let mut literalFreq: Vec<i32> = Vec::with_capacity(maxNumLit as usize);
    literalFreq.resize(maxNumLit as usize, 0);
    let mut offsetFreq: Vec<i32> = Vec::with_capacity(offsetCodeCount as usize);
    offsetFreq.resize(offsetCodeCount as usize, 0);
    let mut codegen: Vec<u8> = Vec::with_capacity((maxNumLit + offsetCodeCount + 1) as usize);
    codegen.resize((maxNumLit + offsetCodeCount + 1) as usize, 0);
    huffmanBitWriter {
        writer: w,
        bits: 0,
        nbits: 0,
        bytes: [0u8; bufferSize as usize],
        codegenFreq: [0i32; codegenCodeCount as usize],
        nbytes: 0,
        literalFreq,
        offsetFreq,
        codegen,
        literalEncoding: newHuffmanEncoder(maxNumLit),
        offsetEncoding: newHuffmanEncoder(offsetCodeCount),
        codegenEncoding: newHuffmanEncoder(codegenCodeCount),
        err: nil,
    }
}

impl<W: io::Writer> huffmanBitWriter<W> {
    /// `(w *huffmanBitWriter).reset(writer)` (huffman_bit_writer.go:106).
    ///
    /// Goish takes the new writer by value (Go reassigns the interface
    /// pointer; goish owns `W`).
    pub(crate) fn reset(&mut self, writer: W) {
        self.writer = writer;
        self.bits = 0;
        self.nbits = 0;
        self.nbytes = 0;
        self.err = nil;
    }

    /// `(w *huffmanBitWriter).flush()` (huffman_bit_writer.go:111).
    pub(crate) fn flush(&mut self) {
        if !self.err.IsNil() {
            self.nbits = 0;
            return;
        }
        let mut n = self.nbytes;
        while self.nbits != 0 {
            self.bytes[n as usize] = self.bits as byte;
            self.bits >>= 8;
            if self.nbits > 8 {
                // Avoid underflow.
                self.nbits -= 8;
            } else {
                self.nbits = 0;
            }
            n += 1;
        }
        self.bits = 0;
        self.write_buf(n);
        self.nbytes = 0;
    }

    // `(w *huffmanBitWriter).write(b)` — emits `bytes[0:n]` to the
    // underlying writer with sticky errors. Go passes `w.bytes[:n]`;
    // goish converts the internal scratch into a `slice<byte>` here.
    fn write_buf(&mut self, n: int) {
        if !self.err.IsNil() {
            return;
        }
        let mut v: Vec<byte> = Vec::with_capacity(n as usize);
        v.extend_from_slice(&self.bytes[..n as usize]);
        let (_, e) = self.writer.Write(slice::__from_vec(v));
        self.err = e;
    }

    // `write` for an arbitrary external buffer (used by `writeBytes`).
    fn write_slice(&mut self, b: &[byte]) {
        if !self.err.IsNil() {
            return;
        }
        let mut v: Vec<byte> = Vec::with_capacity(b.len());
        v.extend_from_slice(b);
        let (_, e) = self.writer.Write(slice::__from_vec(v));
        self.err = e;
    }

    /// `(w *huffmanBitWriter).writeBits(b, nb)` (huffman_bit_writer.go:139).
    pub(crate) fn writeBits(&mut self, b: i32, nb: uint) {
        if !self.err.IsNil() {
            return;
        }
        // uint64(b) — Go converts an int32; sign-extend then truncate to
        // the bit pattern of a u64 the same way Go's conversion does.
        self.bits |= ((b as i64) as u64) << self.nbits;
        self.nbits += nb;
        if self.nbits >= 48 {
            let bits_ = self.bits;
            self.bits >>= 48;
            self.nbits -= 48;
            let mut n = self.nbytes;
            self.bytes[n as usize] = bits_ as byte;
            self.bytes[(n + 1) as usize] = (bits_ >> 8) as byte;
            self.bytes[(n + 2) as usize] = (bits_ >> 16) as byte;
            self.bytes[(n + 3) as usize] = (bits_ >> 24) as byte;
            self.bytes[(n + 4) as usize] = (bits_ >> 32) as byte;
            self.bytes[(n + 5) as usize] = (bits_ >> 40) as byte;
            n += 6;
            if n >= bufferFlushSize {
                self.write_buf(n);
                n = 0;
            }
            self.nbytes = n;
        }
    }

    /// `(w *huffmanBitWriter).writeBytes(bytes)` (huffman_bit_writer.go:166).
    pub(crate) fn writeBytes(&mut self, bytes_in: &[byte]) {
        if !self.err.IsNil() {
            return;
        }
        let mut n = self.nbytes;
        if self.nbits & 7 != 0 {
            self.err = internal("writeBytes with unfinished bits");
            return;
        }
        while self.nbits != 0 {
            self.bytes[n as usize] = self.bits as byte;
            self.bits >>= 8;
            self.nbits -= 8;
            n += 1;
        }
        if n != 0 {
            self.write_buf(n);
        }
        self.nbytes = 0;
        self.write_slice(bytes_in);
    }

    // `(w *huffmanBitWriter).generateCodegen(...)`
    // (huffman_bit_writer.go:200).
    //
    // RFC 1951 3.2.7 run-length encoding of the concatenated literal +
    // offset length arrays. Result is written into `codegen`; per-code
    // frequencies into `codegenFreq`.
    fn generateCodegen(
        &mut self,
        numLiterals: int,
        numOffsets: int,
        litEnc: &huffmanEncoder,
        offEnc: &huffmanEncoder,
    ) {
        for f in self.codegenFreq.iter_mut() {
            *f = 0;
        }
        // codegen is used both as a temporary copy of the lengths and as
        // the output — fine because output is always shorter.
        {
            // Copy the concatenated code sizes to codegen.
            for i in 0..(numLiterals as usize) {
                self.codegen[i] = litEnc.codes[i].len as u8;
            }
            for i in 0..(numOffsets as usize) {
                self.codegen[(numLiterals as usize) + i] = offEnc.codes[i].len as u8;
            }
            self.codegen[(numLiterals + numOffsets) as usize] = badCode;
        }

        let mut size: u8 = self.codegen[0];
        let mut count: int = 1;
        let mut outIndex: int = 0;
        let mut inIndex: int = 1;
        while size != badCode {
            // INVARIANT: we have seen "count" copies of size not yet
            // output.
            let nextSize: u8 = self.codegen[inIndex as usize];
            if nextSize == size {
                count += 1;
                inIndex += 1;
                continue;
            }
            // Generate codegen indicating "count" of size.
            if size != 0 {
                self.codegen[outIndex as usize] = size;
                outIndex += 1;
                self.codegenFreq[size as usize] += 1;
                count -= 1;
                while count >= 3 {
                    let mut n: int = 6;
                    if n > count {
                        n = count;
                    }
                    self.codegen[outIndex as usize] = 16;
                    outIndex += 1;
                    self.codegen[outIndex as usize] = (n - 3) as u8;
                    outIndex += 1;
                    self.codegenFreq[16] += 1;
                    count -= n;
                }
            } else {
                while count >= 11 {
                    let mut n: int = 138;
                    if n > count {
                        n = count;
                    }
                    self.codegen[outIndex as usize] = 18;
                    outIndex += 1;
                    self.codegen[outIndex as usize] = (n - 11) as u8;
                    outIndex += 1;
                    self.codegenFreq[18] += 1;
                    count -= n;
                }
                if count >= 3 {
                    // count >= 3 && count <= 10
                    self.codegen[outIndex as usize] = 17;
                    outIndex += 1;
                    self.codegen[outIndex as usize] = (count - 3) as u8;
                    outIndex += 1;
                    self.codegenFreq[17] += 1;
                    count = 0;
                }
            }
            count -= 1;
            while count >= 0 {
                self.codegen[outIndex as usize] = size;
                outIndex += 1;
                self.codegenFreq[size as usize] += 1;
                count -= 1;
            }
            // Set up invariant for next iteration.
            size = nextSize;
            count = 1;
            inIndex += 1;
        }
        // Marker for the end of the codegen.
        self.codegen[outIndex as usize] = badCode;
    }

    // `(w *huffmanBitWriter).dynamicSize(...)` (huffman_bit_writer.go:286).
    fn dynamicSize(
        &self,
        litEnc: &huffmanEncoder,
        offEnc: &huffmanEncoder,
        extraBits: int,
    ) -> (int, int) {
        let mut numCodegens: int = self.codegenFreq.len() as int;
        while numCodegens > 4
            && self.codegenFreq[codegenOrder[(numCodegens - 1) as usize] as usize] == 0
        {
            numCodegens -= 1;
        }
        let header: int = 3
            + 5
            + 5
            + 4
            + (3 * numCodegens)
            + self.codegenEncoding.bitLength(&self.codegenFreq[..])
            + (self.codegenFreq[16] as int) * 2
            + (self.codegenFreq[17] as int) * 3
            + (self.codegenFreq[18] as int) * 7;
        let size: int = header
            + litEnc.bitLength(&self.literalFreq)
            + offEnc.bitLength(&self.offsetFreq)
            + extraBits;
        (size, numCodegens)
    }

    // `(w *huffmanBitWriter).fixedSize(extraBits)`
    // (huffman_bit_writer.go:305).
    fn fixedSize(&self, extraBits: int) -> int {
        3 + fixedLiteralEncoding().bitLength(&self.literalFreq)
            + fixedOffsetEncoding().bitLength(&self.offsetFreq)
            + extraBits
    }

    // `(w *huffmanBitWriter).storedSize(in)` (huffman_bit_writer.go:315).
    //
    // Returns the size in bits and whether the block fits in a single
    // stored block. `None` mirrors Go's `in == nil`.
    fn storedSize(&self, in_: Option<&[byte]>) -> (int, bool) {
        match in_ {
            None => (0, false),
            Some(b) => {
                if (b.len() as int) <= maxStoreBlockSize {
                    return (((b.len() as int) + 5) * 8, true);
                }
                (0, false)
            }
        }
    }

    /// `(w *huffmanBitWriter).writeCode(c)` (huffman_bit_writer.go:325).
    fn writeCode(&mut self, c: hcode) {
        if !self.err.IsNil() {
            return;
        }
        self.bits |= (c.code as u64) << self.nbits;
        self.nbits += c.len as uint;
        if self.nbits >= 48 {
            let bits_ = self.bits;
            self.bits >>= 48;
            self.nbits -= 48;
            let mut n = self.nbytes;
            self.bytes[n as usize] = bits_ as byte;
            self.bytes[(n + 1) as usize] = (bits_ >> 8) as byte;
            self.bytes[(n + 2) as usize] = (bits_ >> 16) as byte;
            self.bytes[(n + 3) as usize] = (bits_ >> 24) as byte;
            self.bytes[(n + 4) as usize] = (bits_ >> 32) as byte;
            self.bytes[(n + 5) as usize] = (bits_ >> 40) as byte;
            n += 6;
            if n >= bufferFlushSize {
                self.write_buf(n);
                n = 0;
            }
            self.nbytes = n;
        }
    }

    // `(w *huffmanBitWriter).writeDynamicHeader(...)`
    // (huffman_bit_writer.go:357).
    fn writeDynamicHeader(
        &mut self,
        numLiterals: int,
        numOffsets: int,
        numCodegens: int,
        isEof: bool,
    ) {
        if !self.err.IsNil() {
            return;
        }
        let mut firstBits: i32 = 4;
        if isEof {
            firstBits = 5;
        }
        self.writeBits(firstBits, 3);
        self.writeBits((numLiterals - 257) as i32, 5);
        self.writeBits((numOffsets - 1) as i32, 5);
        self.writeBits((numCodegens - 4) as i32, 4);

        {
            let mut i: int = 0;
            while i < numCodegens {
                let value =
                    self.codegenEncoding.codes[codegenOrder[i as usize] as usize].len as uint;
                self.writeBits(value as i32, 3);
                i += 1;
            }
        }

        let mut i: int = 0;
        loop {
            let codeWord: int = self.codegen[i as usize] as int;
            i += 1;
            if codeWord == (badCode as int) {
                break;
            }
            self.writeCode(self.codegenEncoding.codes[codeWord as usize]);

            match codeWord {
                16 => {
                    self.writeBits(self.codegen[i as usize] as i32, 2);
                    i += 1;
                }
                17 => {
                    self.writeBits(self.codegen[i as usize] as i32, 3);
                    i += 1;
                }
                18 => {
                    self.writeBits(self.codegen[i as usize] as i32, 7);
                    i += 1;
                }
                _ => {}
            }
        }
    }

    /// `(w *huffmanBitWriter).writeStoredHeader(length, isEof)`
    /// (huffman_bit_writer.go:398).
    pub(crate) fn writeStoredHeader(&mut self, length: int, isEof: bool) {
        if !self.err.IsNil() {
            return;
        }
        let mut flag: i32 = 0;
        if isEof {
            flag = 1;
        }
        self.writeBits(flag, 3);
        self.flush();
        self.writeBits(length as i32, 16);
        // int32(^uint16(length)) — ones-complement of the low 16 bits.
        self.writeBits((!(length as u16)) as i32, 16);
    }

    /// `(w *huffmanBitWriter).writeFixedHeader(isEof)`
    /// (huffman_bit_writer.go:412).
    pub(crate) fn writeFixedHeader(&mut self, isEof: bool) {
        if !self.err.IsNil() {
            return;
        }
        // Indicate that we are a fixed Huffman block.
        let mut value: i32 = 2;
        if isEof {
            value = 3;
        }
        self.writeBits(value, 3);
    }

    /// `(w *huffmanBitWriter).writeBlock(tokens, eof, input)`
    /// (huffman_bit_writer.go:429).
    ///
    /// Writes a block of tokens with the smallest encoding. If `input`
    /// is supplied and the Huffman-encoded data is larger than the raw
    /// bytes, a stored block is written instead. `None` input forces
    /// Huffman encoding (Go's `input == nil`).
    pub(crate) fn writeBlock(&mut self, tokens: &[token], eof: bool, input: Option<&[byte]>) {
        if !self.err.IsNil() {
            return;
        }

        // tokens = append(tokens, endBlockMarker)
        let mut toks: Vec<token> = tokens.to_vec();
        toks.push(token(endBlockMarker as u32));
        let (numLiterals, numOffsets) = self.indexTokens(&toks);

        let mut extraBits: int = 0;
        let (storedSize_, storable) = self.storedSize(input);
        if storable {
            // Cost of the extra bits required by length/offset fields
            // (same for fixed and dynamic) — only computed when needed.
            {
                let mut lengthCode: int = lengthCodesStart + 8;
                while lengthCode < numLiterals {
                    // First eight length codes have extra size = 0.
                    extraBits += (self.literalFreq[lengthCode as usize] as int)
                        * (lengthExtraBits[(lengthCode - lengthCodesStart) as usize] as int);
                    lengthCode += 1;
                }
            }
            {
                let mut offsetCode: int = 4;
                while offsetCode < numOffsets {
                    // First four offset codes have extra size = 0.
                    extraBits += (self.offsetFreq[offsetCode as usize] as int)
                        * (offsetExtraBits[offsetCode as usize] as int);
                    offsetCode += 1;
                }
            }
        }

        // Figure out the smallest code. Fixed Huffman baseline.
        let mut useFixed = true;
        let mut size = self.fixedSize(extraBits);

        // Generate codegen + codegenFreq describing how to encode the
        // dynamic literal/offset encodings.
        self.generateCodegen(
            numLiterals,
            numOffsets,
            &clone_encoder(&self.literalEncoding),
            &clone_encoder(&self.offsetEncoding),
        );
        let cf = self.codegenFreq;
        self.codegenEncoding.generate(&cf, 7);
        let (dynamicSize_, numCodegens) = self.dynamicSize(
            &clone_encoder(&self.literalEncoding),
            &clone_encoder(&self.offsetEncoding),
            extraBits,
        );

        if dynamicSize_ < size {
            size = dynamicSize_;
            useFixed = false;
        }

        // Stored bytes?
        if storable && storedSize_ < size {
            self.writeStoredHeader(input.unwrap().len() as int, eof);
            self.writeBytes(input.unwrap());
            return;
        }

        // Huffman.
        if useFixed {
            self.writeFixedHeader(eof);
            let le = fixedLiteralEncoding();
            let oe = fixedOffsetEncoding();
            self.writeTokens(&toks, &le.codes, &oe.codes);
        } else {
            self.writeDynamicHeader(numLiterals, numOffsets, numCodegens, eof);
            let le = clone_encoder(&self.literalEncoding);
            let oe = clone_encoder(&self.offsetEncoding);
            self.writeTokens(&toks, &le.codes, &oe.codes);
        }
    }

    /// `(w *huffmanBitWriter).writeBlockDynamic(tokens, eof, input)`
    /// (huffman_bit_writer.go:498).
    ///
    /// Encodes a block using a dynamic Huffman table. If `input` is
    /// supplied and the savings are below 1/16th of the input size, the
    /// block is stored.
    pub(crate) fn writeBlockDynamic(
        &mut self,
        tokens: &[token],
        eof: bool,
        input: Option<&[byte]>,
    ) {
        if !self.err.IsNil() {
            return;
        }

        let mut toks: Vec<token> = tokens.to_vec();
        toks.push(token(endBlockMarker as u32));
        let (numLiterals, numOffsets) = self.indexTokens(&toks);

        // Generate codegen + codegenFreq.
        self.generateCodegen(
            numLiterals,
            numOffsets,
            &clone_encoder(&self.literalEncoding),
            &clone_encoder(&self.offsetEncoding),
        );
        let cf = self.codegenFreq;
        self.codegenEncoding.generate(&cf, 7);
        let (size, numCodegens) = self.dynamicSize(
            &clone_encoder(&self.literalEncoding),
            &clone_encoder(&self.offsetEncoding),
            0,
        );

        // Store bytes if we don't get a reasonable improvement.
        let (ssize, storable) = self.storedSize(input);
        if storable && ssize < (size + (size >> 4)) {
            self.writeStoredHeader(input.unwrap().len() as int, eof);
            self.writeBytes(input.unwrap());
            return;
        }

        // Write Huffman table.
        self.writeDynamicHeader(numLiterals, numOffsets, numCodegens, eof);

        // Write the tokens.
        let le = clone_encoder(&self.literalEncoding);
        let oe = clone_encoder(&self.offsetEncoding);
        self.writeTokens(&toks, &le.codes, &oe.codes);
    }

    // `(w *huffmanBitWriter).indexTokens(tokens)`
    // (huffman_bit_writer.go:530).
    //
    // Indexes a slice of tokens, updates literalFreq/offsetFreq, and
    // generates literalEncoding/offsetEncoding. Returns the number of
    // literal and offset codes used.
    fn indexTokens(&mut self, tokens: &[token]) -> (int, int) {
        for f in self.literalFreq.iter_mut() {
            *f = 0;
        }
        for f in self.offsetFreq.iter_mut() {
            *f = 0;
        }

        for &t in tokens.iter() {
            if t.0 < matchType {
                self.literalFreq[t.literal() as usize] += 1;
                continue;
            }
            let length = t.length();
            let offset = t.offset();
            self.literalFreq[(lengthCodesStart as usize) + (lengthCode(length) as usize)] += 1;
            self.offsetFreq[offsetCode(offset) as usize] += 1;
        }

        // Number of literals.
        let mut numLiterals: int = self.literalFreq.len() as int;
        while self.literalFreq[(numLiterals - 1) as usize] == 0 {
            numLiterals -= 1;
        }
        // Number of offsets.
        let mut numOffsets: int = self.offsetFreq.len() as int;
        while numOffsets > 0 && self.offsetFreq[(numOffsets - 1) as usize] == 0 {
            numOffsets -= 1;
        }
        if numOffsets == 0 {
            // No match found. To use dynamic encoding we must count at
            // least one offset so the offset tree can be encoded.
            self.offsetFreq[0] = 1;
            numOffsets = 1;
        }
        let lf = self.literalFreq.clone();
        self.literalEncoding.generate(&lf, 15);
        let of = self.offsetFreq.clone();
        self.offsetEncoding.generate(&of, 15);
        (numLiterals, numOffsets)
    }

    // `(w *huffmanBitWriter).writeTokens(tokens, leCodes, oeCodes)`
    // (huffman_bit_writer.go:568).
    fn writeTokens(&mut self, tokens: &[token], leCodes: &[hcode], oeCodes: &[hcode]) {
        if !self.err.IsNil() {
            return;
        }
        for &t in tokens.iter() {
            if t.0 < matchType {
                self.writeCode(leCodes[t.literal() as usize]);
                continue;
            }
            // Write the length.
            let length = t.length();
            let lengthCode_ = lengthCode(length);
            self.writeCode(leCodes[(lengthCode_ as usize) + (lengthCodesStart as usize)]);
            let extraLengthBits = lengthExtraBits[lengthCode_ as usize] as uint;
            if extraLengthBits > 0 {
                let extraLength = (length - lengthBase[lengthCode_ as usize]) as i32;
                self.writeBits(extraLength, extraLengthBits);
            }
            // Write the offset.
            let offset = t.offset();
            let offsetCode_ = offsetCode(offset);
            self.writeCode(oeCodes[offsetCode_ as usize]);
            let extraOffsetBits = offsetExtraBits[offsetCode_ as usize] as uint;
            if extraOffsetBits > 0 {
                let extraOffset = (offset - offsetBase[offsetCode_ as usize]) as i32;
                self.writeBits(extraOffset, extraOffsetBits);
            }
        }
    }

    /// `(w *huffmanBitWriter).writeBlockHuff(eof, input)`
    /// (huffman_bit_writer.go:612).
    ///
    /// Encodes a block of bytes as Huffman-coded literals, or as an
    /// uncompressed stored block if compression barely helps.
    pub(crate) fn writeBlockHuff(&mut self, eof: bool, input: &[byte]) {
        if !self.err.IsNil() {
            return;
        }

        // Clear histogram.
        for f in self.literalFreq.iter_mut() {
            *f = 0;
        }

        // Add everything as literals.
        histogram(input, &mut self.literalFreq);

        self.literalFreq[endBlockMarker] = 1;

        const numLiterals: int = (endBlockMarker as int) + 1;
        self.offsetFreq[0] = 1;
        const numOffsets: int = 1;

        let lf = self.literalFreq.clone();
        self.literalEncoding.generate(&lf, 15);

        // Always use dynamic Huffman or Store.
        // Generate codegen + codegenFreq.
        self.generateCodegen(
            numLiterals,
            numOffsets,
            &clone_encoder(&self.literalEncoding),
            &huffOffset(),
        );
        let cf = self.codegenFreq;
        self.codegenEncoding.generate(&cf, 7);
        let (size, numCodegens) =
            self.dynamicSize(&clone_encoder(&self.literalEncoding), &huffOffset(), 0);

        // Store bytes if we don't get a reasonable improvement.
        let (ssize, storable) = self.storedSize(Some(input));
        if storable && ssize < (size + (size >> 4)) {
            self.writeStoredHeader(input.len() as int, eof);
            self.writeBytes(input);
            return;
        }

        // Huffman.
        self.writeDynamicHeader(numLiterals, numOffsets, numCodegens, eof);
        let encoding: Vec<hcode> = self.literalEncoding.codes[..257].to_vec();
        let mut n = self.nbytes;
        for &t in input.iter() {
            // Bit-writing inlined (~30% speedup in Go).
            let c = encoding[t as usize];
            self.bits |= (c.code as u64) << self.nbits;
            self.nbits += c.len as uint;
            if self.nbits < 48 {
                continue;
            }
            // Store 6 bytes.
            let bits_ = self.bits;
            self.bits >>= 48;
            self.nbits -= 48;
            self.bytes[n as usize] = bits_ as byte;
            self.bytes[(n + 1) as usize] = (bits_ >> 8) as byte;
            self.bytes[(n + 2) as usize] = (bits_ >> 16) as byte;
            self.bytes[(n + 3) as usize] = (bits_ >> 24) as byte;
            self.bytes[(n + 4) as usize] = (bits_ >> 32) as byte;
            self.bytes[(n + 5) as usize] = (bits_ >> 40) as byte;
            n += 6;
            if n < bufferFlushSize {
                continue;
            }
            self.write_buf(n);
            if !self.err.IsNil() {
                return; // Return early on write failure.
            }
            n = 0;
        }
        self.nbytes = n;
        self.writeCode(encoding[endBlockMarker]);
    }
}

// `histogram(b, h)` (huffman_bit_writer.go:688) — accumulate a histogram
// of `b` into `h`. `h.len()` must be >= 256 and all-zero.
fn histogram(b: &[byte], h: &mut [i32]) {
    for &t in b.iter() {
        h[t as usize] += 1;
    }
}

// ─── round-trip test shim ──────────────────────────────────────────────
//
// `huffmanBitWriter`, `token` etc. are module-internal (`pub(crate)`),
// so an example crate cannot drive them directly. This `#[doc(hidden)]`
// shim builds DEFLATE streams with the encoder above and decodes them
// back through the already-ported `NewReader` decompressor, returning a
// per-case status word so an example can assert the encoder is faithful.

/// Drive the Huffman bit writer over three block kinds and inflate the
/// result back. Returns `(cases_passed, cases_total)`.
///
/// `#[doc(hidden)]` — for the `flate_huffman_smoke` example only; not a
/// stable API.
#[doc(hidden)]
pub fn __huffman_writer_roundtrip() -> (int, int) {
    use crate::bytes;

    let mut passed: int = 0;
    let total: int = 3;

    // Helper: inflate a DEFLATE byte stream.
    fn inflate(compressed: slice<byte>) -> Vec<byte> {
        let src = bytes::NewBuffer(compressed);
        let mut r = NewReader(src);
        let mut out: Vec<byte> = Vec::new();
        let mut buf: slice<byte> = {
            let mut v: Vec<byte> = Vec::with_capacity(512);
            v.resize(512, 0u8);
            slice::__from_vec(v)
        };
        loop {
            let (n, e) = r.Read(&mut buf);
            let mut k: int = 0;
            while k < n {
                out.push(buf[k]);
                k += 1;
            }
            if !e.IsNil() {
                break;
            }
        }
        out
    }

    // Case 1 — stored block (writeStoredHeader + writeBytes).
    {
        let payload: &[byte] = b"the quick brown fox stored verbatim";
        let mut w = newHuffmanBitWriter(bytes::NewBuffer(slice::new()));
        w.writeStoredHeader(payload.len() as int, true);
        w.writeBytes(payload);
        w.flush();
        if w.err.IsNil() {
            let compressed = w.writer.Bytes();
            let got = inflate(compressed);
            if got.as_slice() == payload {
                passed += 1;
            }
        }
    }

    // Case 2 — literal-only Huffman block via writeBlock (input=None
    // forces Huffman; fixed or dynamic chosen by size).
    {
        let payload: &[byte] = b"aaaaaabbbbbbccccccddddddeeeeeeffffffhuffman literals";
        let mut toks: Vec<token> = Vec::with_capacity(payload.len());
        for &c in payload.iter() {
            toks.push(literalToken(c as u32));
        }
        let mut w = newHuffmanBitWriter(bytes::NewBuffer(slice::new()));
        w.writeBlock(&toks, true, None);
        w.flush();
        if w.err.IsNil() {
            let compressed = w.writer.Bytes();
            let got = inflate(compressed);
            if got.as_slice() == payload {
                passed += 1;
            }
        }
    }

    // Case 3 — a block with a back-reference match token via writeBlock.
    // Emit "abcabcabc": 6 literals then a match (length 3, offset 3).
    // matchToken xlength = length-3, xoffset = offset-1.
    {
        let expected: &[byte] = b"abcabc";
        let mut toks: Vec<token> = Vec::new();
        toks.push(literalToken(b'a' as u32));
        toks.push(literalToken(b'b' as u32));
        toks.push(literalToken(b'c' as u32));
        // copy 3 bytes from 3 back -> "abc" again.
        toks.push(matchToken(0, 2));
        let mut w = newHuffmanBitWriter(bytes::NewBuffer(slice::new()));
        w.writeBlock(&toks, true, None);
        w.flush();
        if w.err.IsNil() {
            let compressed = w.writer.Bytes();
            let got = inflate(compressed);
            if got.as_slice() == expected {
                passed += 1;
            }
        }
    }

    (passed, total)
}

// ═══════════════════════════════════════════════════════════════════════
// LZ77 compressor + Writer — port of Go 1.25 `deflate.go` + `deflatefast.go`.
//
// Both files are `package flate`; the types here (`compressor`,
// `deflateFast`, `dictWriter`) are Go-unexported and stay `pub(crate)` /
// private. The public surface is `Writer`, `NewWriter`, `NewWriterDict`,
// and the level constants.
//
// Slim deviations from Go:
//   * Go's `compressor.fill` (`func(*compressor,[]byte) int`) and
//     `compressor.step` (`func(*compressor)`) are function-pointer
//     fields. AGENTS.md §5 forbids fn-pointer struct fields, so goish
//     models each with an enum (`Fill`, `CStep`) dispatched by a method
//     — the same shape the decompressor's `Step` enum uses.
//   * Go's `compressor.bulkHasher` is also a `func` field; it always
//     holds `bulkHash4`, so goish drops the field and calls `bulkHash4`
//     directly.
//   * Go's `Writer` holds a `compressor` whose `huffmanBitWriter.writer`
//     is an `io.Writer` interface; `NewWriterDict` wraps the destination
//     in a `*dictWriter`. goish has no trait-object writer, so `Writer`
//     and `compressor` are generic over `W: io::Writer`. `NewWriter`
//     returns `Writer<W>`; `NewWriterDict` returns `Writer<dictWriter<W>>`.
//   * Go's `Writer.Reset` does a `dictWriter` type assertion to decide
//     whether to re-`fillWindow`. goish carries the `dict` bytes on the
//     `Writer` and re-fills the window iff `dict` is non-empty.
//   * Go's `NewWriter` returns `(*Writer, error)`; goish returns
//     `(Writer<W>, error)` by value.
// ═══════════════════════════════════════════════════════════════════════

// ─── compressor constants (deflate.go:14) ──────────────────────────────

/// No compression — only DEFLATE framing.
pub const NoCompression: int = 0;
/// Fastest compression (custom `deflateFast` encoder).
pub const BestSpeed: int = 1;
/// Best compression ratio.
pub const BestCompression: int = 9;
/// The default compression level.
pub const DefaultCompression: int = -1;

/// `HuffmanOnly` disables Lempel-Ziv match searching and only performs
/// Huffman entropy encoding. Useful for data already compressed with an
/// LZ-style algorithm that lacks an entropy encoder. The output is still
/// RFC 1951 compliant.
pub const HuffmanOnly: int = -2;

const logWindowSize: int = 15;
const windowSize: int = 1 << logWindowSize;
const windowMask: int = windowSize - 1;

const baseMatchLength: int = 3; // smallest match length per the RFC
const minMatchLength: int = 4; // smallest match length the compressor emits
const maxMatchLength: int = 258; // largest match length
const baseMatchOffset: int = 1; // smallest match offset
                                // maxMatchOffset is shared with the decompressor (defined above as 1<<15).

const maxFlateBlockTokens: int = 1 << 14;
const hashBits: int = 17; // after 17, performance degrades
const hashSize: int = 1 << hashBits;
const hashMask: u32 = (1 << hashBits) - 1;
const maxHashOffset: int = 1 << 24;

const skipNever: int = math_MaxInt32 as int;

// ─── compressionLevel (deflate.go:61) ──────────────────────────────────

#[derive(Clone, Copy, Default)]
struct compressionLevel {
    level: int,
    good: int,
    lazy: int,
    nice: int,
    chain: int,
    fastSkipHashing: int,
}

const fn cl(level: int, good: int, lazy: int, nice: int, chain: int, fsh: int) -> compressionLevel {
    compressionLevel {
        level,
        good,
        lazy,
        nice,
        chain,
        fastSkipHashing: fsh,
    }
}

// Go's package-level `var levels []compressionLevel`. Renamed to
// `levelTable` here — the Huffman-encoder port already has a function-
// local `levels` (`huffmanEncoder::bitCounts`). Index 0/1 are
// placeholders (Store / BestSpeed use custom paths); 2..=9 drive `deflate`.
static levelTable: [compressionLevel; 10] = [
    cl(0, 0, 0, 0, 0, 0), // NoCompression.
    cl(1, 0, 0, 0, 0, 0), // BestSpeed — see deflatefast.
    cl(2, 4, 0, 16, 8, 5),
    cl(3, 4, 0, 32, 32, 6),
    cl(4, 4, 4, 16, 16, skipNever),
    cl(5, 8, 16, 32, 32, skipNever),
    cl(6, 8, 16, 128, 128, skipNever),
    cl(7, 8, 32, 128, 256, skipNever),
    cl(8, 32, 128, 258, 1024, skipNever),
    cl(9, 32, 258, 258, 4096, skipNever),
];

// ─── compressor fill/step dispatch (deflate.go:88-90) ──────────────────

/// Models Go's `compressor.fill func(*compressor, []byte) int`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fill {
    Store,   // fillStore
    Deflate, // fillDeflate
}

/// Models Go's `compressor.step func(*compressor)`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CStep {
    Store,     // store
    StoreHuff, // storeHuff
    EncSpeed,  // encSpeed
    Deflate,   // deflate
}

// ─── deflateFast constants (deflatefast.go:12) ─────────────────────────

const tableBits: int = 14;
const tableSize: int = 1 << tableBits;
const tableMask: u32 = (tableSize as u32) - 1;
const tableShift: u32 = 32 - (tableBits as u32);

// Reset the buffer offset when reaching this.
const bufferReset: i32 = math_MaxInt32 - (maxStoreBlockSize as i32) * 2;

const inputMargin: int = 16 - 1;
const minNonLiteralBlockSize: int = 1 + 1 + inputMargin;

fn load32(b: &[byte], i: i32) -> u32 {
    let i = i as usize;
    (b[i] as u32) | ((b[i + 1] as u32) << 8) | ((b[i + 2] as u32) << 16) | ((b[i + 3] as u32) << 24)
}

fn load64(b: &[byte], i: i32) -> u64 {
    let i = i as usize;
    (b[i] as u64)
        | ((b[i + 1] as u64) << 8)
        | ((b[i + 2] as u64) << 16)
        | ((b[i + 3] as u64) << 24)
        | ((b[i + 4] as u64) << 32)
        | ((b[i + 5] as u64) << 40)
        | ((b[i + 6] as u64) << 48)
        | ((b[i + 7] as u64) << 56)
}

fn hash(u: u32) -> u32 {
    u.wrapping_mul(0x1e35a7bd) >> tableShift
}

/// `flate.tableEntry` — a hash-table slot.
#[derive(Clone, Copy, Default)]
struct tableEntry {
    val: u32,
    offset: i32,
}

/// `flate.deflateFast` — the BestSpeed match table + previous block.
pub(crate) struct deflateFast {
    table: Vec<tableEntry>, // tableSize entries; internal scratch.
    prev: Vec<byte>,        // previous block, empty if unknown.
    cur: i32,               // current match offset.
}

/// `newDeflateFast()` (deflatefast.go:63).
fn newDeflateFast() -> deflateFast {
    deflateFast {
        table: alloc::vec![tableEntry::default(); tableSize as usize],
        prev: Vec::with_capacity(maxStoreBlockSize as usize),
        cur: maxStoreBlockSize as i32,
    }
}

impl deflateFast {
    /// `(e *deflateFast).encode(dst, src)` (deflatefast.go:69) — encode a
    /// block from `src`, appending tokens to `dst`.
    fn encode(&mut self, mut dst: Vec<token>, src: &[byte]) -> Vec<token> {
        // Ensure that e.cur doesn't wrap.
        if self.cur >= bufferReset {
            self.shiftOffsets();
        }

        // Fast path for very small inputs.
        if (src.len() as int) < minNonLiteralBlockSize {
            self.cur += maxStoreBlockSize as i32;
            self.prev.clear();
            return emitLiteral(dst, src);
        }

        let sLimit: i32 = (src.len() as i32) - (inputMargin as i32);

        let mut nextEmit: i32 = 0;
        let mut s: i32 = 0;
        let mut cv: u32 = load32(src, s);
        let mut nextHash: u32 = hash(cv);

        'outer: loop {
            let mut skip: i32 = 32;

            let mut nextS: i32 = s;
            let mut candidate: tableEntry;
            loop {
                s = nextS;
                let bytesBetweenHashLookups = skip >> 5;
                nextS = s + bytesBetweenHashLookups;
                skip += bytesBetweenHashLookups;
                if nextS > sLimit {
                    // goto emitRemainder
                    if (nextEmit as int) < (src.len() as int) {
                        dst = emitLiteral(dst, &src[nextEmit as usize..]);
                    }
                    self.cur += src.len() as i32;
                    let n = src.len();
                    self.prev.clear();
                    self.prev.extend_from_slice(&src[..n]);
                    return dst;
                }
                candidate = self.table[(nextHash & tableMask) as usize];
                let now = load32(src, nextS);
                self.table[(nextHash & tableMask) as usize] = tableEntry {
                    offset: s + self.cur,
                    val: cv,
                };
                nextHash = hash(now);

                let offset = s - (candidate.offset - self.cur);
                if (offset as int) > maxMatchOffset || cv != candidate.val {
                    cv = now;
                    continue;
                }
                break;
            }

            // A 4-byte match has been found. src[nextEmit:s] are unmatched.
            dst = emitLiteral(dst, &src[nextEmit as usize..s as usize]);

            loop {
                // Extend the 4-byte match as long as possible.
                s += 4;
                let t = candidate.offset - self.cur + 4;
                let l = self.matchLen(s, t, src);

                dst.push(matchToken(
                    (l + 4 - (baseMatchLength as i32)) as u32,
                    (s - t - (baseMatchOffset as i32)) as u32,
                ));
                s += l;
                nextEmit = s;
                if s >= sLimit {
                    // goto emitRemainder
                    if (nextEmit as int) < (src.len() as int) {
                        dst = emitLiteral(dst, &src[nextEmit as usize..]);
                    }
                    self.cur += src.len() as i32;
                    let n = src.len();
                    self.prev.clear();
                    self.prev.extend_from_slice(&src[..n]);
                    return dst;
                }

                let x = load64(src, s - 1);
                let prevHash = hash(x as u32);
                self.table[(prevHash & tableMask) as usize] = tableEntry {
                    offset: self.cur + s - 1,
                    val: x as u32,
                };
                let x = x >> 8;
                let currHash = hash(x as u32);
                candidate = self.table[(currHash & tableMask) as usize];
                self.table[(currHash & tableMask) as usize] = tableEntry {
                    offset: self.cur + s,
                    val: x as u32,
                };

                let offset = s - (candidate.offset - self.cur);
                if (offset as int) > maxMatchOffset || (x as u32) != candidate.val {
                    cv = (x >> 8) as u32;
                    nextHash = hash(cv);
                    s += 1;
                    continue 'outer;
                }
            }
        }
    }

    /// `(e *deflateFast).matchLen(s, t, src)` (deflatefast.go:211) — match
    /// length between `src[s:]` and `src[t:]`; `t` may be negative to
    /// indicate a match starting in `e.prev`.
    fn matchLen(&self, s: i32, t: i32, src: &[byte]) -> i32 {
        let mut s1 = (s as int) + maxMatchLength - 4;
        if s1 > (src.len() as int) {
            s1 = src.len() as int;
        }
        let s1 = s1 as usize;

        // Inside the current block.
        if t >= 0 {
            let a = &src[s as usize..s1];
            let b = &src[t as usize..t as usize + a.len()];
            for i in 0..a.len() {
                if a[i] != b[i] {
                    return i as i32;
                }
            }
            return a.len() as i32;
        }

        // A match in the previous block.
        let tp = (self.prev.len() as i32) + t;
        if tp < 0 {
            return 0;
        }
        let tp = tp as usize;

        let a = &src[s as usize..s1];
        let mut b: &[byte] = &self.prev[tp..];
        if b.len() > a.len() {
            b = &b[..a.len()];
        }
        let a2 = &a[..b.len()];
        for i in 0..b.len() {
            if a2[i] != b[i] {
                return i as i32;
            }
        }

        let n = b.len() as i32;
        if ((s + n) as usize) == s1 {
            return n;
        }

        // Continue looking for more matches in the current block.
        let a = &src[(s + n) as usize..s1];
        let b = &src[..a.len()];
        for i in 0..a.len() {
            if a[i] != b[i] {
                return (i as i32) + n;
            }
        }
        (a.len() as i32) + n
    }

    /// `(e *deflateFast).reset()` (deflatefast.go:270).
    fn reset(&mut self) {
        self.prev.clear();
        self.cur += maxMatchOffset as i32;
        if self.cur >= bufferReset {
            self.shiftOffsets();
        }
    }

    /// `(e *deflateFast).shiftOffsets()` (deflatefast.go:286).
    fn shiftOffsets(&mut self) {
        if self.prev.is_empty() {
            for e in self.table.iter_mut() {
                *e = tableEntry::default();
            }
            self.cur = (maxMatchOffset as i32) + 1;
            return;
        }
        for i in 0..self.table.len() {
            let mut v = self.table[i].offset - self.cur + (maxMatchOffset as i32) + 1;
            if v < 0 {
                v = 0;
            }
            self.table[i].offset = v;
        }
        self.cur = (maxMatchOffset as i32) + 1;
    }
}

/// `emitLiteral(dst, lit)` (deflatefast.go:201).
fn emitLiteral(mut dst: Vec<token>, lit: &[byte]) -> Vec<token> {
    for &v in lit {
        dst.push(literalToken(v as u32));
    }
    dst
}

// ─── hash helpers (deflate.go:291) ─────────────────────────────────────

const hashmul: u32 = 0x1e35a7bd;

/// `hash4(b)` — hash of the first 4 bytes; caller ensures `len(b) >= 4`.
fn hash4(b: &[byte]) -> u32 {
    (((b[3] as u32) | ((b[2] as u32) << 8) | ((b[1] as u32) << 16) | ((b[0] as u32) << 24))
        .wrapping_mul(hashmul))
        >> (32 - (hashBits as u32))
}

/// `bulkHash4(b, dst)` — bulk hashes using the same algorithm as `hash4`.
fn bulkHash4(b: &[byte], dst: &mut [u32]) {
    if (b.len() as int) < minMatchLength {
        return;
    }
    let mut hb =
        (b[3] as u32) | ((b[2] as u32) << 8) | ((b[1] as u32) << 16) | ((b[0] as u32) << 24);
    dst[0] = hb.wrapping_mul(hashmul) >> (32 - (hashBits as u32));
    let end = (b.len() as int) - minMatchLength + 1;
    let mut i: int = 1;
    while i < end {
        hb = (hb << 8) | (b[(i + 3) as usize] as u32);
        dst[i as usize] = hb.wrapping_mul(hashmul) >> (32 - (hashBits as u32));
        i += 1;
    }
}

/// `matchLen(a, b, max)` (deflate.go:318) — matching-byte count up to `max`.
fn matchLen(a: &[byte], b: &[byte], max: int) -> int {
    let a = &a[..max as usize];
    let b = &b[..a.len()];
    for i in 0..a.len() {
        if b[i] != a[i] {
            return i as int;
        }
    }
    max
}

// ─── compressor (deflate.go:81) ────────────────────────────────────────

/// `flate.compressor` — the LZ77 match finder + block writer.
pub(crate) struct compressor<W: io::Writer> {
    compressionLevel: compressionLevel,

    w: huffmanBitWriter<W>,

    // compression algorithm dispatch (Go: `fill`/`step` func fields).
    fill: Fill,
    step: CStep,
    bestSpeed: deflateFast, // Encoder for BestSpeed.

    // Input hash chains.
    chainHead: int,
    hashHead: Vec<u32>, // hashSize entries.
    hashPrev: Vec<u32>, // windowSize entries.
    hashOffset: int,

    // input window: unprocessed data is window[index:windowEnd].
    index: int,
    window: Vec<byte>,
    windowEnd: int,
    blockStart: int,
    byteAvailable: bool,

    sync: bool, // requesting flush

    tokens: Vec<token>, // queued output tokens

    // deflate state.
    length: int,
    offset: int,
    maxInsertIndex: int,
    err: error,

    // hashMatch must hold hashes for the maximum match length.
    hashMatch: [u32; (maxMatchLength - 1) as usize],
}

fn new_compressor<W: io::Writer>(w: W) -> compressor<W> {
    compressor {
        compressionLevel: compressionLevel::default(),
        w: newHuffmanBitWriter(w),
        fill: Fill::Store,
        step: CStep::Store,
        bestSpeed: newDeflateFast(),
        chainHead: 0,
        hashHead: Vec::new(),
        hashPrev: Vec::new(),
        hashOffset: 0,
        index: 0,
        window: Vec::new(),
        windowEnd: 0,
        blockStart: 0,
        byteAvailable: false,
        sync: false,
        tokens: Vec::new(),
        length: 0,
        offset: 0,
        maxInsertIndex: 0,
        err: nil,
        hashMatch: [0u32; (maxMatchLength - 1) as usize],
    }
}

impl<W: io::Writer> compressor<W> {
    /// `(d *compressor).fillDeflate(b)` (deflate.go:124).
    fn fillDeflate(&mut self, b: &[byte]) -> int {
        if self.index >= 2 * windowSize - (minMatchLength + maxMatchLength) {
            // Shift the window by windowSize.
            self.window
                .copy_within(windowSize as usize..2 * windowSize as usize, 0);
            self.index -= windowSize;
            self.windowEnd -= windowSize;
            if self.blockStart >= windowSize {
                self.blockStart -= windowSize;
            } else {
                self.blockStart = math_MaxInt32 as int;
            }
            self.hashOffset += windowSize;
            if self.hashOffset > maxHashOffset {
                let delta = self.hashOffset - 1;
                self.hashOffset -= delta;
                self.chainHead -= delta;

                for i in 0..self.hashPrev.len() {
                    let v = self.hashPrev[i] as int;
                    if v > delta {
                        self.hashPrev[i] = (v - delta) as u32;
                    } else {
                        self.hashPrev[i] = 0;
                    }
                }
                for i in 0..self.hashHead.len() {
                    let v = self.hashHead[i] as int;
                    if v > delta {
                        self.hashHead[i] = (v - delta) as u32;
                    } else {
                        self.hashHead[i] = 0;
                    }
                }
            }
        }
        let n = copy_slice(&mut self.window[self.windowEnd as usize..], b);
        self.windowEnd += n;
        n
    }

    /// `(d *compressor).writeBlock(tokens, index)` (deflate.go:164).
    fn writeBlock(&mut self, tokens: &[token], index: int) -> error {
        if index > 0 {
            let mut window: Option<Vec<byte>> = None;
            if self.blockStart <= index {
                window = Some(self.window[self.blockStart as usize..index as usize].to_vec());
            }
            self.blockStart = index;
            match &window {
                Some(w) => self.w.writeBlock(tokens, false, Some(w.as_slice())),
                None => self.w.writeBlock(tokens, false, None),
            }
            return self.w.err.clone();
        }
        nil
    }

    /// `(d *compressor).fillWindow(b)` (deflate.go:181) — fill the window
    /// with a dictionary and precompute all hashes (faster than a full
    /// encode). Only valid right after a reset.
    fn fillWindow(&mut self, b: &[byte]) {
        if self.compressionLevel.level < 2 {
            return;
        }
        if self.index != 0 || self.windowEnd != 0 {
            panic!("internal error: fillWindow called with stale data");
        }

        // If we are given too much, cut it.
        let mut b = b;
        if (b.len() as int) > windowSize {
            b = &b[b.len() - windowSize as usize..];
        }
        let n = copy_slice(&mut self.window, b);

        // Calculate 256 hashes at a time (more L1 cache hits).
        let loops = (n + 256 - minMatchLength) / 256;
        let mut j: int = 0;
        while j < loops {
            let index = j * 256;
            let mut end = index + 256 + minMatchLength - 1;
            if end > n {
                end = n;
            }
            let dstSize = (end - index) - minMatchLength + 1;
            if dstSize <= 0 {
                j += 1;
                continue;
            }
            // bulkHash4 over window[index:end] into hashMatch[:dstSize].
            {
                let toCheck = &self.window[index as usize..end as usize];
                bulkHash4(toCheck, &mut self.hashMatch[..dstSize as usize]);
            }
            for i in 0..(dstSize as usize) {
                let val = self.hashMatch[i];
                let di = (i as int) + index;
                let hh = (val & hashMask) as usize;
                self.hashPrev[(di & windowMask) as usize] = self.hashHead[hh];
                self.hashHead[hh] = (di + self.hashOffset) as u32;
            }
            j += 1;
        }
        self.windowEnd = n;
        self.index = n;
    }

    /// `(d *compressor).findMatch(pos, prevHead, prevLength, lookahead)`
    /// (deflate.go:231) — chained-hash match finder.
    fn findMatch(
        &self,
        pos: int,
        prevHead: int,
        prevLength: int,
        lookahead: int,
    ) -> (int, int, bool) {
        let mut minMatchLook = maxMatchLength;
        if lookahead < minMatchLook {
            minMatchLook = lookahead;
        }

        let win = &self.window[0..(pos + minMatchLook) as usize];

        // We quit when we get a match at least `nice` long.
        let mut nice = (win.len() as int) - pos;
        if self.compressionLevel.nice < nice {
            nice = self.compressionLevel.nice;
        }

        let mut tries = self.compressionLevel.chain;
        let mut length = prevLength;
        let mut offset: int = 0;
        let mut ok = false;
        if length >= self.compressionLevel.good {
            tries >>= 2;
        }

        let mut wEnd = win[(pos + length) as usize];
        let wPos = &win[pos as usize..];
        let minIndex = pos - windowSize;

        let mut i = prevHead;
        while tries > 0 {
            if wEnd == win[(i + length) as usize] {
                let n = matchLen(&win[i as usize..], wPos, minMatchLook);
                if n > length && (n > minMatchLength || pos - i <= 4096) {
                    length = n;
                    offset = pos - i;
                    ok = true;
                    if n >= nice {
                        break;
                    }
                    wEnd = win[(pos + n) as usize];
                }
            }
            if i == minIndex {
                break;
            }
            i = (self.hashPrev[(i & windowMask) as usize] as int) - self.hashOffset;
            if i < minIndex || i < 0 {
                break;
            }
            tries -= 1;
        }
        (length, offset, ok)
    }

    /// `(d *compressor).writeStoredBlock(buf)` (deflate.go:283).
    fn writeStoredBlock(&mut self, buf: &[byte]) -> error {
        self.w.writeStoredHeader(buf.len() as int, false);
        if !self.w.err.IsNil() {
            return self.w.err.clone();
        }
        self.w.writeBytes(buf);
        self.w.err.clone()
    }

    /// `(d *compressor).encSpeed()` (deflate.go:332) — BestSpeed step.
    fn encSpeed(&mut self) {
        if self.windowEnd < maxStoreBlockSize {
            if !self.sync {
                return;
            }
            // Handle small sizes.
            if self.windowEnd < 128 {
                if self.windowEnd == 0 {
                    return;
                } else if self.windowEnd <= 16 {
                    let buf = self.window[..self.windowEnd as usize].to_vec();
                    self.err = self.writeStoredBlock(&buf);
                } else {
                    let input = self.window[..self.windowEnd as usize].to_vec();
                    self.w.writeBlockHuff(false, &input);
                    self.err = self.w.err.clone();
                }
                self.windowEnd = 0;
                self.bestSpeed.reset();
                return;
            }
        }
        // Encode the block.
        let input = self.window[..self.windowEnd as usize].to_vec();
        let mut toks = core::mem::take(&mut self.tokens);
        toks.clear(); // Go: d.tokens[:0] — keep capacity.
        self.tokens = self.bestSpeed.encode(toks, &input);

        // If we removed less than 1/16th, Huffman-compress the block.
        if (self.tokens.len() as int) > self.windowEnd - (self.windowEnd >> 4) {
            self.w.writeBlockHuff(false, &input);
        } else {
            self.w
                .writeBlockDynamic(&self.tokens.clone(), false, Some(&input));
        }
        self.err = self.w.err.clone();
        self.windowEnd = 0;
    }

    /// `(d *compressor).initDeflate()` (deflate.go:369).
    fn initDeflate(&mut self) {
        self.window = alloc::vec![0u8; 2 * windowSize as usize];
        self.hashHead = alloc::vec![0u32; hashSize as usize];
        self.hashPrev = alloc::vec![0u32; windowSize as usize];
        self.hashOffset = 1;
        self.tokens = Vec::with_capacity((maxFlateBlockTokens + 1) as usize);
        self.length = minMatchLength - 1;
        self.offset = 0;
        self.byteAvailable = false;
        self.index = 0;
        self.chainHead = -1;
    }

    /// `(d *compressor).deflate()` (deflate.go:381) — the main LZ77 step.
    fn deflate(&mut self) {
        if self.windowEnd - self.index < minMatchLength + maxMatchLength && !self.sync {
            return;
        }

        self.maxInsertIndex = self.windowEnd - (minMatchLength - 1);

        loop {
            if self.index > self.windowEnd {
                panic!("index > windowEnd");
            }
            let lookahead = self.windowEnd - self.index;
            if lookahead < minMatchLength + maxMatchLength {
                if !self.sync {
                    break;
                }
                if self.index > self.windowEnd {
                    panic!("index > windowEnd");
                }
                if lookahead == 0 {
                    // Flush current output block if any.
                    if self.byteAvailable {
                        let lit = self.window[(self.index - 1) as usize];
                        self.tokens.push(literalToken(lit as u32));
                        self.byteAvailable = false;
                    }
                    if self.tokens.len() > 0 {
                        let toks = self.tokens.clone();
                        let idx = self.index;
                        self.err = self.writeBlock(&toks, idx);
                        if !self.err.IsNil() {
                            return;
                        }
                        self.tokens.clear();
                    }
                    break;
                }
            }
            if self.index < self.maxInsertIndex {
                // Update the hash.
                let hash = hash4(
                    &self.window[self.index as usize..(self.index + minMatchLength) as usize],
                );
                let hh = (hash & hashMask) as usize;
                self.chainHead = self.hashHead[hh] as int;
                self.hashPrev[(self.index & windowMask) as usize] = self.chainHead as u32;
                self.hashHead[hh] = (self.index + self.hashOffset) as u32;
            }
            let prevLength = self.length;
            let prevOffset = self.offset;
            self.length = minMatchLength - 1;
            self.offset = 0;
            let mut minIndex = self.index - windowSize;
            if minIndex < 0 {
                minIndex = 0;
            }

            // Level fields (Go reaches these via struct embedding).
            let fastSkipHashing = self.compressionLevel.fastSkipHashing;
            let lazy = self.compressionLevel.lazy;

            if self.chainHead - self.hashOffset >= minIndex
                && (fastSkipHashing != skipNever && lookahead > minMatchLength - 1
                    || fastSkipHashing == skipNever && lookahead > prevLength && prevLength < lazy)
            {
                let (newLength, newOffset, ok) = self.findMatch(
                    self.index,
                    self.chainHead - self.hashOffset,
                    minMatchLength - 1,
                    lookahead,
                );
                if ok {
                    self.length = newLength;
                    self.offset = newOffset;
                }
            }
            if fastSkipHashing != skipNever && self.length >= minMatchLength
                || fastSkipHashing == skipNever
                    && prevLength >= minMatchLength
                    && self.length <= prevLength
            {
                // Output a match — the current one if fastSkipHashing,
                // else the previous (lazy) one.
                if fastSkipHashing != skipNever {
                    self.tokens.push(matchToken(
                        (self.length - baseMatchLength) as u32,
                        (self.offset - baseMatchOffset) as u32,
                    ));
                } else {
                    self.tokens.push(matchToken(
                        (prevLength - baseMatchLength) as u32,
                        (prevOffset - baseMatchOffset) as u32,
                    ));
                }
                // Insert in the hash table all strings up to the end of
                // the match (index and index-1 are already inserted).
                if self.length <= fastSkipHashing {
                    let newIndex = if fastSkipHashing != skipNever {
                        self.index + self.length
                    } else {
                        self.index + prevLength - 1
                    };
                    let mut index = self.index;
                    index += 1;
                    while index < newIndex {
                        if index < self.maxInsertIndex {
                            let hash = hash4(
                                &self.window[index as usize..(index + minMatchLength) as usize],
                            );
                            let hh = (hash & hashMask) as usize;
                            self.hashPrev[(index & windowMask) as usize] = self.hashHead[hh];
                            self.hashHead[hh] = (index + self.hashOffset) as u32;
                        }
                        index += 1;
                    }
                    self.index = index;

                    if fastSkipHashing == skipNever {
                        self.byteAvailable = false;
                        self.length = minMatchLength - 1;
                    }
                } else {
                    // For long matches, don't insert each item.
                    self.index += self.length;
                }
                if (self.tokens.len() as int) == maxFlateBlockTokens {
                    let toks = self.tokens.clone();
                    let idx = self.index;
                    self.err = self.writeBlock(&toks, idx);
                    if !self.err.IsNil() {
                        return;
                    }
                    self.tokens.clear();
                }
            } else {
                if fastSkipHashing != skipNever || self.byteAvailable {
                    let i = if fastSkipHashing != skipNever {
                        self.index
                    } else {
                        self.index - 1
                    };
                    let lit = self.window[i as usize];
                    self.tokens.push(literalToken(lit as u32));
                    if (self.tokens.len() as int) == maxFlateBlockTokens {
                        let toks = self.tokens.clone();
                        self.err = self.writeBlock(&toks, i + 1);
                        if !self.err.IsNil() {
                            return;
                        }
                        self.tokens.clear();
                    }
                }
                self.index += 1;
                if fastSkipHashing == skipNever {
                    self.byteAvailable = true;
                }
            }
        }
    }

    /// `(d *compressor).fillStore(b)` (deflate.go:514).
    fn fillStore(&mut self, b: &[byte]) -> int {
        let n = copy_slice(&mut self.window[self.windowEnd as usize..], b);
        self.windowEnd += n;
        n
    }

    /// `(d *compressor).store()` (deflate.go:520).
    fn store(&mut self) {
        if self.windowEnd > 0 && (self.windowEnd == maxStoreBlockSize || self.sync) {
            let buf = self.window[..self.windowEnd as usize].to_vec();
            self.err = self.writeStoredBlock(&buf);
            self.windowEnd = 0;
        }
    }

    /// `(d *compressor).storeHuff()` (deflate.go:530) — HuffmanOnly step.
    fn storeHuff(&mut self) {
        if self.windowEnd < (self.window.len() as int) && !self.sync || self.windowEnd == 0 {
            return;
        }
        let input = self.window[..self.windowEnd as usize].to_vec();
        self.w.writeBlockHuff(false, &input);
        self.err = self.w.err.clone();
        self.windowEnd = 0;
    }

    // Dispatch `step` (Go's `d.step(d)`).
    fn run_step(&mut self) {
        match self.step {
            CStep::Store => self.store(),
            CStep::StoreHuff => self.storeHuff(),
            CStep::EncSpeed => self.encSpeed(),
            CStep::Deflate => self.deflate(),
        }
    }

    // Dispatch `fill` (Go's `d.fill(d, b)`).
    fn run_fill(&mut self, b: &[byte]) -> int {
        match self.fill {
            Fill::Store => self.fillStore(b),
            Fill::Deflate => self.fillDeflate(b),
        }
    }

    /// `(d *compressor).write(b)` (deflate.go:539).
    fn write(&mut self, b: &[byte]) -> (int, error) {
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }
        let n = b.len() as int;
        let mut b = b;
        while b.len() > 0 {
            self.run_step();
            let consumed = self.run_fill(b);
            b = &b[consumed as usize..];
            if !self.err.IsNil() {
                return (0, self.err.clone());
            }
        }
        (n, nil)
    }

    /// `(d *compressor).syncFlush()` (deflate.go:554).
    fn syncFlush(&mut self) -> error {
        if !self.err.IsNil() {
            return self.err.clone();
        }
        self.sync = true;
        self.run_step();
        if self.err.IsNil() {
            self.w.writeStoredHeader(0, false);
            self.w.flush();
            self.err = self.w.err.clone();
        }
        self.sync = false;
        self.err.clone()
    }

    /// `(d *compressor).init(w, level)` (deflate.go:569).
    fn init(&mut self, level: int) -> error {
        if level == NoCompression {
            self.window = alloc::vec![0u8; maxStoreBlockSize as usize];
            self.fill = Fill::Store;
            self.step = CStep::Store;
        } else if level == HuffmanOnly {
            self.window = alloc::vec![0u8; maxStoreBlockSize as usize];
            self.fill = Fill::Store;
            self.step = CStep::StoreHuff;
        } else if level == BestSpeed {
            self.compressionLevel = levelTable[level as usize];
            self.window = alloc::vec![0u8; maxStoreBlockSize as usize];
            self.fill = Fill::Store;
            self.step = CStep::EncSpeed;
            self.bestSpeed = newDeflateFast();
            self.tokens = alloc::vec![token(0); maxStoreBlockSize as usize];
        } else {
            let mut level = level;
            if level == DefaultCompression {
                level = 6;
            }
            if 2 <= level && level <= 9 {
                self.compressionLevel = levelTable[level as usize];
                self.initDeflate();
                self.fill = Fill::Deflate;
                self.step = CStep::Deflate;
            } else {
                return crate::fmt::Errorf!(
                    "flate: invalid compression level %d: want value in range [-2, 9]",
                    level
                );
            }
        }
        nil
    }

    /// `(d *compressor).reset(w)` (deflate.go:602).
    fn reset(&mut self, w: W) {
        self.w.reset(w);
        self.sync = false;
        self.err = nil;
        match self.compressionLevel.level {
            NoCompression => {
                self.windowEnd = 0;
            }
            BestSpeed => {
                self.windowEnd = 0;
                self.tokens.clear();
                self.bestSpeed.reset();
            }
            _ => {
                self.chainHead = -1;
                for v in self.hashHead.iter_mut() {
                    *v = 0;
                }
                for v in self.hashPrev.iter_mut() {
                    *v = 0;
                }
                self.hashOffset = 1;
                self.index = 0;
                self.windowEnd = 0;
                self.blockStart = 0;
                self.byteAvailable = false;
                self.tokens.clear();
                self.length = minMatchLength - 1;
                self.offset = 0;
                self.maxInsertIndex = 0;
            }
        }
    }

    /// `(d *compressor).close()` (deflate.go:627).
    fn close(&mut self) -> error {
        if self.err == errWriterClosed {
            return nil;
        }
        if !self.err.IsNil() {
            return self.err.clone();
        }
        self.sync = true;
        self.run_step();
        if !self.err.IsNil() {
            return self.err.clone();
        }
        self.w.writeStoredHeader(0, true);
        if !self.w.err.IsNil() {
            return self.w.err.clone();
        }
        self.w.flush();
        if !self.w.err.IsNil() {
            return self.w.err.clone();
        }
        self.err = errWriterClosed.into();
        nil
    }
}

// `errWriterClosed` (deflate.go:695) — Go's package-level sentinel.
crate::var! {
    errWriterClosed: error = "flate: closed writer";
}

// `copy_slice` — Go's builtin `copy(dst, src)`: copies min(len) bytes.
fn copy_slice(dst: &mut [byte], src: &[byte]) -> int {
    let n = core::cmp::min(dst.len(), src.len());
    dst[..n].copy_from_slice(&src[..n]);
    n as int
}

// ─── dictWriter (deflate.go:687) ───────────────────────────────────────

/// `flate.dictWriter` — transparently forwards `Write` to `w`. Used by
/// `NewWriterDict` so `Writer.Reset` can detect a dictionary writer.
pub struct dictWriter<W: io::Writer> {
    w: W,
}

impl<W: io::Writer> io::Writer for dictWriter<W> {
    fn Write(&mut self, b: slice<byte>) -> (int, error) {
        self.w.Write(b)
    }
}

// ─── Writer (deflate.go:699) ───────────────────────────────────────────

/// A `Writer` takes data written to it and writes the compressed form of
/// that data to an underlying writer (see [`NewWriter`]).
pub struct Writer<W: io::Writer> {
    d: compressor<W>,
    dict: Vec<byte>, // duplicated dictionary for `Reset`.
}

impl<W: io::Writer> Writer<W> {
    /// `(w *Writer).Write(data)` (deflate.go:706) — writes `data`, which
    /// is eventually emitted to the underlying writer in compressed form.
    pub fn Write(&mut self, data: slice<byte>) -> (int, error) {
        let v: &[byte] = &data;
        self.d.write(&v)
    }

    /// `(w *Writer).Flush()` (deflate.go:719) — flush pending data to the
    /// underlying writer (Z_SYNC_FLUSH).
    pub fn Flush(&mut self) -> error {
        self.d.syncFlush()
    }

    /// `(w *Writer).Close()` (deflate.go:726) — flush and close.
    pub fn Close(&mut self) -> error {
        self.d.close()
    }

    /// `(w *Writer).Reset(dst)` (deflate.go:733) — discard state and make
    /// the writer equivalent to a fresh [`NewWriter`] / [`NewWriterDict`]
    /// targeting `dst` with the same level and dictionary.
    pub fn Reset(&mut self, dst: W) {
        self.d.reset(dst);
        if !self.dict.is_empty() {
            let dict = self.dict.clone();
            self.d.fillWindow(&dict);
        }
    }

    /// Consume the `Writer` and return the underlying writer.
    ///
    /// goish-specific (Go callers keep their own reference to the
    /// destination `io.Writer`; a goish `Writer` *owns* `W` by value, so
    /// this hands it back after [`Close`](Self::Close)).
    pub fn into_writer(self) -> W {
        self.d.w.into_writer()
    }
}

impl<W: io::Writer> huffmanBitWriter<W> {
    /// Consume the bit writer and yield the underlying `io::Writer`.
    pub(crate) fn into_writer(self) -> W {
        self.writer
    }
}

impl<W: io::Writer> dictWriter<W> {
    /// Consume the `dictWriter` and yield the wrapped writer.
    pub fn into_writer(self) -> W {
        self.w
    }
}

impl<W: io::Writer> io::Writer for Writer<W> {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        Writer::Write(self, p)
    }
}

impl<W: io::Writer> io::Closer for Writer<W> {
    fn Close(&mut self) -> error {
        Writer::Close(self)
    }
}

/// `flate.NewWriter(w, level)` (deflate.go:662) — a new [`Writer`]
/// compressing at `level`. Levels range from 1 ([`BestSpeed`]) to 9
/// ([`BestCompression`]); 0 ([`NoCompression`]) only adds DEFLATE
/// framing, -1 ([`DefaultCompression`]) uses the default level, and -2
/// ([`HuffmanOnly`]) does Huffman entropy coding only.
///
/// If `level` is in `[-2, 9]` the error is `nil`; otherwise it is non-nil.
pub fn NewWriter<W: io::Writer>(w: W, level: int) -> (Writer<W>, error) {
    let mut dw = Writer {
        d: new_compressor(w),
        dict: Vec::new(),
    };
    let err = dw.d.init(level);
    if !err.IsNil() {
        return (dw, err);
    }
    (dw, nil)
}

/// `flate.NewWriterDict(w, level, dict)` (deflate.go:676) — like
/// [`NewWriter`] but initializes the [`Writer`] with a preset dictionary.
/// The returned writer behaves as if `dict` had been written without
/// producing output; the compressed data can only be decompressed by a
/// reader initialized with the same dictionary (see [`NewReaderDict`]).
pub fn NewWriterDict<W: io::Writer>(
    w: W,
    level: int,
    dict: slice<byte>,
) -> (Writer<dictWriter<W>>, error) {
    let dw = dictWriter { w };
    let (mut zw, err) = NewWriter(dw, level);
    if !err.IsNil() {
        return (zw, err);
    }
    let d: &[byte] = &dict;
    zw.d.fillWindow(&d);
    zw.dict.extend_from_slice(&d); // duplicate dictionary for Reset.
    (zw, nil)
}
