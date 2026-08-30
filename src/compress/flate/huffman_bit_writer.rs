// go: file compress/flate/huffman_bit_writer.go decls: huffOffset, newHuffmanBitWriter, huffmanBitWriter.reset, huffmanBitWriter.flush, huffmanBitWriter.write, huffmanBitWriter.writeBits, huffmanBitWriter.writeBytes, huffmanBitWriter.generateCodegen, huffmanBitWriter.dynamicSize, huffmanBitWriter.fixedSize, huffmanBitWriter.storedSize, huffmanBitWriter.writeCode, huffmanBitWriter.writeDynamicHeader, huffmanBitWriter.writeStoredHeader, huffmanBitWriter.writeFixedHeader, huffmanBitWriter.writeBlock, huffmanBitWriter.writeBlockDynamic, huffmanBitWriter.indexTokens, huffmanBitWriter.writeTokens, huffmanBitWriter.writeBlockHuff, histogram
//
// goishlint:ignore GOISH018 init — Go's `huffmanBitWriter` has no
//     `init`; the name belongs to `huffmanEncoder.init`, which lives in
//     huffman_code.rs, and to `huffmanDecoder.init` in inflate.rs.
//     goishlint matches by bare name across the cited file.
// goishlint:ignore GOISH021 endBlockMarker — declared in inflate.rs,
//     which is where Go's `endBlockMarker` const lives too
//     (inflate.go:24). huffman_bit_writer.go re-declares nothing; it
//     is goishlint that resolves the name against both files.
//
// The `decls:` manifest above lists huffman_bit_writer.go's funcs and
// methods only. GOISH017 matches a manifest entry against Rust `fn`
// items, so naming the file's consts, types and vars there would
// report every one as a dropped port. They are not dropped — each
// carries its own `// go: sdk` anchor below.
//
// compress/flate/huffman_bit_writer.go — the DEFLATE block writer.
//
// This is where a run of `token`s becomes bits. The writer buffers up
// to 64 bits in a single word and drains six bytes at a time, which is
// why `bufferFlushSize` is a multiple of six and `bufferSize` carries
// eight bytes of headroom: a single `writeBits` can never overflow the
// buffer between flushes.
//
// The block-type decision is the other half. For each block the writer
// computes three sizes — `dynamicSize` (with the cost of the code-length
// header included), `fixedSize`, and `storedSize` — and emits whichever
// is smallest, which is why `generateCodegen` runs before anything is
// written. `storedSize` returning `ok == false` for a block that cannot
// be stored (no input retained, or over 65535 bytes) is load-bearing:
// without it the writer would compare against a size it cannot use.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{
    byte as tobyte, int as toint, int32 as toint32, uint as touint, uint16 as touint16,
    uint32 as touint32, uint64 as touint64,
};
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int, uint};

use super::huffman_code;
use super::huffman_code::{
    clone_encoder, fixedLiteralEncoding, fixedOffsetEncoding, hcode, huffmanEncoder,
    newHuffmanEncoder,
};
use super::inflate::{endBlockMarker, internal, maxNumLit};
use super::token_go::{lengthCode, matchType, offsetCode, token};

// go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:600-600 huffOffset
/// `flate.huffOffset` — the static offset encoder used for
/// huffman-only encoding. Go initialises it as a package-level var at
/// program start; goish builds it once behind a `SpinLock` and clones
/// the code table in.
pub(super) fn huffOffset() -> huffmanEncoder {
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
pub(super) const offsetCodeCount: int = 30;

// The first length code.
pub(super) const lengthCodesStart: int = 257;

// The number of codegen codes.
pub(super) const codegenCodeCount: int = 19;
pub(super) const badCode: u8 = 255;

// bufferFlushSize — buffer size after which bytes are flushed to the
// writer. A multiple of 6 (we accumulate 6 bytes between writes).
pub(super) const bufferFlushSize: int = 240;

// bufferSize — actual output byte buffer size. Has headroom for a
// flush (up to 8 bytes).
pub(super) const bufferSize: int = bufferFlushSize + 8;

// maxStoreBlockSize — defined in deflate.go (the compressor task);
// referenced here by `storedSize`. RFC 1951 stored-block max payload.
pub(super) const maxStoreBlockSize: int = 65535;

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
pub(super) struct huffmanBitWriter<W: io::Writer> {
    // The underlying writer. Do not use directly; use `write`, which
    // makes Write errors sticky.
    pub(super) writer: W,

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

// go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:94-104 newHuffmanBitWriter
/// `newHuffmanBitWriter(w)` (huffman_bit_writer.go:94).
pub(crate) fn newHuffmanBitWriter<W: io::Writer>(w: W) -> huffmanBitWriter<W> {
    let mut literalFreq: Vec<i32> = Vec::with_capacity(maxNumLit as usize);
    literalFreq.resize(maxNumLit as usize, 0);
    let mut offsetFreq: Vec<i32> = Vec::with_capacity(offsetCodeCount as usize);
    offsetFreq.resize(offsetCodeCount as usize, 0);
    let mut codegen: Vec<u8> = Vec::with_capacity((maxNumLit + offsetCodeCount + 1) as usize);
    codegen.resize((maxNumLit + offsetCodeCount + 1) as usize, 0);
    return huffmanBitWriter {
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
    };
}

impl<W: io::Writer> huffmanBitWriter<W> {
    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:106-109 huffmanBitWriter.reset
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

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:111-130 huffmanBitWriter.flush
    /// `(w *huffmanBitWriter).flush()` (huffman_bit_writer.go:111).
    pub(crate) fn flush(&mut self) {
        if !self.err.IsNil() {
            self.nbits = 0;
            return;
        }
        let mut n = self.nbytes;
        while self.nbits != 0 {
            self.bytes[n as usize] = tobyte(self.bits);
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

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:132-137 huffmanBitWriter.write
    // goishlint:ignore GOISH014 — Go's one `write(b []byte)` splits in
    //     two here, because a goish `slice<byte>` owns its buffer where
    //     Go's `[]byte` is a view. `write_buf` is the `w.bytes[:n]`
    //     call shape and carries the anchor; `write_slice` is the
    //     external-buffer one and is marked `// go: none`.
    /// `(w *huffmanBitWriter).write(b)` — emit `bytes[0:n]` to the
    /// underlying writer, sticky on error.
    ///
    /// Go passes `w.bytes[:n]`, a view of the scratch array. goish's
    /// `slice<byte>` owns its buffer, so the two call shapes split:
    /// this one takes a length into the scratch, and `write_slice`
    /// takes an external buffer.
    fn write_buf(&mut self, n: int) {
        if !self.err.IsNil() {
            return;
        }
        let mut v: Vec<byte> = Vec::with_capacity(n as usize);
        v.extend_from_slice(&self.bytes[..n as usize]);
        let (_, e) = self.writer.Write(slice::__from_vec(v));
        self.err = e;
    }

    // go: none — goish idiom: the external-buffer half of `write_buf`;
    //     see there. Go needs only one `write` because a `[]byte` view
    //     is the same type either way.
    fn write_slice(&mut self, b: &[byte]) {
        if !self.err.IsNil() {
            return;
        }
        let mut v: Vec<byte> = Vec::with_capacity(b.len());
        v.extend_from_slice(b);
        let (_, e) = self.writer.Write(slice::__from_vec(v));
        self.err = e;
    }

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:139-164 huffmanBitWriter.writeBits
    /// `(w *huffmanBitWriter).writeBits(b, nb)` (huffman_bit_writer.go:139).
    pub(crate) fn writeBits(&mut self, b: i32, nb: uint) {
        if !self.err.IsNil() {
            return;
        }
        // uint64(b) — Go converts an int32; sign-extend then truncate to
        // the bit pattern of a u64 the same way Go's conversion does.
        self.bits |= touint64(b) << self.nbits;
        self.nbits += nb;
        if self.nbits >= 48 {
            let bits_ = self.bits;
            self.bits >>= 48;
            self.nbits -= 48;
            let mut n = self.nbytes;
            self.bytes[n as usize] = tobyte(bits_);
            self.bytes[(n + 1) as usize] = tobyte(bits_ >> 8);
            self.bytes[(n + 2) as usize] = tobyte(bits_ >> 16);
            self.bytes[(n + 3) as usize] = tobyte(bits_ >> 24);
            self.bytes[(n + 4) as usize] = tobyte(bits_ >> 32);
            self.bytes[(n + 5) as usize] = tobyte(bits_ >> 40);
            n += 6;
            if n >= bufferFlushSize {
                self.write_buf(n);
                n = 0;
            }
            self.nbytes = n;
        }
    }

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:166-186 huffmanBitWriter.writeBytes
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
            self.bytes[n as usize] = tobyte(self.bits);
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

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:200-283 huffmanBitWriter.generateCodegen
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
                self.codegen[i] = tobyte(litEnc.codes[i].len);
            }
            for i in 0..(numOffsets as usize) {
                self.codegen[(numLiterals as usize) + i] = tobyte(offEnc.codes[i].len);
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
                    self.codegen[outIndex as usize] = tobyte(n - 3);
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
                    self.codegen[outIndex as usize] = tobyte(n - 11);
                    outIndex += 1;
                    self.codegenFreq[18] += 1;
                    count -= n;
                }
                if count >= 3 {
                    // count >= 3 && count <= 10
                    self.codegen[outIndex as usize] = 17;
                    outIndex += 1;
                    self.codegen[outIndex as usize] = tobyte(count - 3);
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

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:286-302 huffmanBitWriter.dynamicSize
    // `(w *huffmanBitWriter).dynamicSize(...)` (huffman_bit_writer.go:286).
    fn dynamicSize(
        &self,
        litEnc: &huffmanEncoder,
        offEnc: &huffmanEncoder,
        extraBits: int,
    ) -> (int, int) {
        let mut numCodegens: int = toint(self.codegenFreq.len());
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
            + toint(self.codegenFreq[16]) * 2
            + toint(self.codegenFreq[17]) * 3
            + toint(self.codegenFreq[18]) * 7;
        let size: int = header
            + litEnc.bitLength(&self.literalFreq)
            + offEnc.bitLength(&self.offsetFreq)
            + extraBits;
        return (size, numCodegens);
    }

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:305-310 huffmanBitWriter.fixedSize
    // `(w *huffmanBitWriter).fixedSize(extraBits)`
    // (huffman_bit_writer.go:305).
    fn fixedSize(&self, extraBits: int) -> int {
        return 3
            + fixedLiteralEncoding().bitLength(&self.literalFreq)
            + fixedOffsetEncoding().bitLength(&self.offsetFreq)
            + extraBits;
    }

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:315-323 huffmanBitWriter.storedSize
    // `(w *huffmanBitWriter).storedSize(in)` (huffman_bit_writer.go:315).
    //
    // Returns the size in bits and whether the block fits in a single
    // stored block. `None` mirrors Go's `in == nil`.
    fn storedSize(&self, in_: Option<&[byte]>) -> (int, bool) {
        return match in_ {
            None => (0, false),
            Some(b) => {
                if toint(b.len()) <= maxStoreBlockSize {
                    return ((toint(b.len()) + 5) * 8, true);
                }
                (0, false)
            }
        };
    }

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:325-350 huffmanBitWriter.writeCode
    /// `(w *huffmanBitWriter).writeCode(c)` (huffman_bit_writer.go:325).
    fn writeCode(&mut self, c: hcode) {
        if !self.err.IsNil() {
            return;
        }
        self.bits |= touint64(c.code) << self.nbits;
        self.nbits += touint(c.len);
        if self.nbits >= 48 {
            let bits_ = self.bits;
            self.bits >>= 48;
            self.nbits -= 48;
            let mut n = self.nbytes;
            self.bytes[n as usize] = tobyte(bits_);
            self.bytes[(n + 1) as usize] = tobyte(bits_ >> 8);
            self.bytes[(n + 2) as usize] = tobyte(bits_ >> 16);
            self.bytes[(n + 3) as usize] = tobyte(bits_ >> 24);
            self.bytes[(n + 4) as usize] = tobyte(bits_ >> 32);
            self.bytes[(n + 5) as usize] = tobyte(bits_ >> 40);
            n += 6;
            if n >= bufferFlushSize {
                self.write_buf(n);
                n = 0;
            }
            self.nbytes = n;
        }
    }

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:357-396 huffmanBitWriter.writeDynamicHeader
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
        self.writeBits(toint32(numLiterals - 257), 5);
        self.writeBits(toint32(numOffsets - 1), 5);
        self.writeBits(toint32(numCodegens - 4), 4);

        {
            let mut i: int = 0;
            while i < numCodegens {
                let value =
                    touint(self.codegenEncoding.codes[codegenOrder[i as usize] as usize].len);
                self.writeBits(toint32(value), 3);
                i += 1;
            }
        }

        let mut i: int = 0;
        loop {
            let codeWord: int = toint(self.codegen[i as usize]);
            i += 1;
            if codeWord == toint(badCode) {
                break;
            }
            self.writeCode(self.codegenEncoding.codes[codeWord as usize]);

            match codeWord {
                16 => {
                    self.writeBits(toint32(self.codegen[i as usize]), 2);
                    i += 1;
                }
                17 => {
                    self.writeBits(toint32(self.codegen[i as usize]), 3);
                    i += 1;
                }
                18 => {
                    self.writeBits(toint32(self.codegen[i as usize]), 7);
                    i += 1;
                }
                _ => {}
            }
        }
    }

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:398-410 huffmanBitWriter.writeStoredHeader
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
        self.writeBits(toint32(length), 16);
        // int32(^uint16(length)) — ones-complement of the low 16 bits.
        self.writeBits(toint32(!touint16(length)), 16);
    }

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:412-422 huffmanBitWriter.writeFixedHeader
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

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:429-491 huffmanBitWriter.writeBlock
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
        toks.push(token(touint32(endBlockMarker)));
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
                    extraBits += toint(self.literalFreq[lengthCode as usize])
                        * toint(lengthExtraBits[(lengthCode - lengthCodesStart) as usize]);
                    lengthCode += 1;
                }
            }
            {
                let mut offsetCode: int = 4;
                while offsetCode < numOffsets {
                    // First four offset codes have extra size = 0.
                    extraBits += toint(self.offsetFreq[offsetCode as usize])
                        * toint(offsetExtraBits[offsetCode as usize]);
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
            self.writeStoredHeader(toint(input.unwrap().len()), eof);
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

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:498-524 huffmanBitWriter.writeBlockDynamic
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
        toks.push(token(touint32(endBlockMarker)));
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
            self.writeStoredHeader(toint(input.unwrap().len()), eof);
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

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:530-564 huffmanBitWriter.indexTokens
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
        let mut numLiterals: int = toint(self.literalFreq.len());
        while self.literalFreq[(numLiterals - 1) as usize] == 0 {
            numLiterals -= 1;
        }
        // Number of offsets.
        let mut numOffsets: int = toint(self.offsetFreq.len());
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
        return (numLiterals, numOffsets);
    }

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:568-596 huffmanBitWriter.writeTokens
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
            let extraLengthBits: uint = touint(lengthExtraBits[lengthCode_ as usize]);
            if extraLengthBits > 0 {
                let extraLength = toint32(length - lengthBase[lengthCode_ as usize]);
                self.writeBits(extraLength, extraLengthBits);
            }
            // Write the offset.
            let offset = t.offset();
            let offsetCode_ = offsetCode(offset);
            self.writeCode(oeCodes[offsetCode_ as usize]);
            let extraOffsetBits: uint = touint(offsetExtraBits[offsetCode_ as usize]);
            if extraOffsetBits > 0 {
                let extraOffset = toint32(offset - offsetBase[offsetCode_ as usize]);
                self.writeBits(extraOffset, extraOffsetBits);
            }
        }
    }

    // go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:612-683 huffmanBitWriter.writeBlockHuff
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

        const numLiterals: int = (endBlockMarker as int) + 1; // goishlint:ignore GOISH005 - a const initialiser must be a constant expression; `int(...)` is a call.

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
            self.writeStoredHeader(toint(input.len()), eof);
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
            self.bits |= touint64(c.code) << self.nbits;
            self.nbits += touint(c.len);
            if self.nbits < 48 {
                continue;
            }
            // Store 6 bytes.
            let bits_ = self.bits;
            self.bits >>= 48;
            self.nbits -= 48;
            self.bytes[n as usize] = tobyte(bits_);
            self.bytes[(n + 1) as usize] = tobyte(bits_ >> 8);
            self.bytes[(n + 2) as usize] = tobyte(bits_ >> 16);
            self.bytes[(n + 3) as usize] = tobyte(bits_ >> 24);
            self.bytes[(n + 4) as usize] = tobyte(bits_ >> 32);
            self.bytes[(n + 5) as usize] = tobyte(bits_ >> 40);
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

// go: sdk 1.25.5 compress/flate/huffman_bit_writer.go:688-693 histogram
// `histogram(b, h)` (huffman_bit_writer.go:688) — accumulate a histogram
// of `b` into `h`. `h.len()` must be >= 256 and all-zero.
pub(super) fn histogram(b: &[byte], h: &mut [i32]) {
    for &t in b.iter() {
        h[t as usize] += 1;
    }
}
