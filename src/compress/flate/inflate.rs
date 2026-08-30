// go: file compress/flate/inflate.go decls: CorruptInputError.Error, InternalError.Error, huffmanDecoder.init, decompressor.nextBlock, decompressor.Read, decompressor.Close, decompressor.readHuffman, decompressor.huffmanBlock, decompressor.dataBlock, decompressor.copyData, decompressor.finishBlock, noEOF, decompressor.moreBits, decompressor.huffSym, fixedHuffmanDecoderInit, decompressor.Reset, NewReader, NewReaderDict
//
// goishlint:ignore GOISH018 ReadError.Error, WriteError.Error — Go's
//     `ReadError` and `WriteError` are documented as "no longer
//     returned"; nothing in the package
//     constructs either. goish does not carry a type it can never
//     produce, so their `Error` methods have no counterpart.
// goishlint:ignore GOISH021 ReadError, WriteError — see above.
// goishlint:ignore GOISH021 maxCodeLen — Go sizes two scratch arrays in
//     `huffmanDecoder.init` with it; goish sizes the same two as
//     `[int; 17]` literals, because a Rust array length must be a
//     constant expression of type usize and the Go constant is an int.
// goishlint:ignore GOISH021 fixedOnce — the `sync.Once` guarding Go's
//     package-level `fixedHuffmanDecoder` var. goish has no
//     package-level mutable statics under `no_std`; the table lives in
//     a `SpinLock` slot, which is its own guard.
// goishlint:ignore GOISH021 Reader, Resetter — Go's `flate.Reader` is
//     `io.Reader + io.ByteReader` and `Resetter` is a one-method
//     interface, both used only to type-assert a value at run time.
//     goish spells the first as a generic bound on `Decompressor<R>`
//     and the second as an inherent `Reset` method, so neither has a
//     nominal counterpart to declare.
//
// The `decls:` manifest above lists inflate.go's funcs and methods
// only. GOISH017 matches a manifest entry against Rust `fn` items, so
// naming the file's consts, types and vars there would report every
// one of them as a dropped port. They are not dropped — each carries
// its own `// go: sdk` anchor below.
//
// compress/flate/inflate.go — the DEFLATE decompressor (RFC 1951).
//
// The decoder is a table-driven Huffman reader over a bit stream, and
// the tables are the interesting part. `huffmanDecoder.init` builds a
// single-level lookup of 512 entries covering every code up to 9 bits,
// plus a second level of link tables for the longer ones; `huffSym`
// therefore resolves most symbols in one array index and only chases a
// link for a long code. The `chunk & huffmanCountMask == 0` case is
// what makes an empty or degenerate tree an error rather than an
// infinite loop, which is a real corrupt-input path, not a paranoia
// check.
//
// Deviations from Go, all forced:
//
//   * `Decompressor<R>` is generic over `R: io::Reader + io::ByteReader`
//     — Go's `flate.Reader` — so `makeReader`'s run-time type assertion
//     becomes a choice of constructor. See its waiver below.
//   * Go's `decompressor.step` is a `func(*decompressor)` field; goish
//     enumerates the three possible next steps, since a function-valued
//     field would need the `dyn Fn` this project bans (§5 rule 3).
//   * `huffSym` names its decoder instead of taking a pointer to one;
//     see the note at its definition.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bufio;
use crate::convert::{
    byte as tobyte, int as toint, uint as touint, uint16 as touint16, uint32 as touint32,
};
use crate::errors::nil;
use crate::errors::{self, error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int, uint};

use crate::math::bits;

use super::dict_decoder::dictDecoder;

// ─── constants ─────────────────────────────────────────

// maxCodeLen = 16 — max length of a Huffman code (sizes the `count`
// and `nextcode` scratch arrays in `huffmanDecoder::init`).
pub(super) const maxNumLit: int = 286;
pub(super) const maxNumDist: int = 30;
pub(super) const numCodes: int = 19; // number of codes in Huffman meta-code

// chunk & 15 is number of bits; chunk >> 4 is value, incl. table link.
pub(super) const huffmanChunkBits: uint = 9;
pub(super) const huffmanNumChunks: usize = 1 << 9; // 512
pub(super) const huffmanCountMask: u32 = 15;
pub(super) const huffmanValueShift: u32 = 4;

// deflate.go line 47 / huffman_bit_writer.go line 16 — referenced by inflate.
pub(super) const maxMatchOffset: int = 1 << 15; // 32768
pub(super) const endBlockMarker: usize = 256;

// ─── CorruptInputError / InternalError ─────────────────

/// `flate.CorruptInputError` — reports corrupt input at a byte offset.
#[derive(Clone, Copy, Debug, Default)]
pub struct CorruptInputError(pub int);

impl ErrorTrait for CorruptInputError {
    // go: sdk 1.25.5 compress/flate/inflate.go:35-37 CorruptInputError.Error
    fn Error(&self) -> string {
        let mut s = string::from("flate: corrupt input before offset ");
        s = s + crate::strconv::FormatInt(self.0, 10);
        return s;
    }
}

/// `flate.InternalError` — reports an error in the flate code itself.
#[derive(Clone, Debug, Default)]
pub struct InternalError(pub string);

impl ErrorTrait for InternalError {
    // go: sdk 1.25.5 compress/flate/inflate.go:42-42 InternalError.Error
    fn Error(&self) -> string {
        return string::from("flate: internal error: ") + self.0.clone();
    }
}

// ─── huffmanDecoder ───────────────────────────────────

/// Huffman decoding tables — a fixed-width lookup table plus overflow
/// link tables for codes longer than `huffmanChunkBits`.
struct huffmanDecoder {
    // the minimum code length
    min: int,
    // chunks as described in the inflate.go comment
    chunks: Box<[u32; huffmanNumChunks]>,
    // overflow links
    links: Vec<Vec<u32>>,
    // mask the width of the link table
    linkMask: u32,
}

impl huffmanDecoder {
    // go: none — goish idiom: Go's zero `huffmanDecoder` is usable and
    //     `init` fills it; goish needs a constructor because the chunk
    //     table is a boxed array.
    fn new() -> huffmanDecoder {
        return huffmanDecoder {
            min: 0,
            chunks: Box::new([0u32; huffmanNumChunks]),
            links: Vec::new(),
            linkMask: 0,
        };
    }

    // go: sdk 1.25.5 compress/flate/inflate.go:116-256 huffmanDecoder.init
    // Go: func (h *huffmanDecoder) init(lengths []int) bool
    //
    // Initialize Huffman decoding tables from an array of code lengths.
    // Returns false on an over/under-subscribed tree (degenerate
    // single-symbol length-1 trees and empty trees are accepted).
    fn init(&mut self, lengths: &[int]) -> bool {
        // Go: if h.min != 0 { *h = huffmanDecoder{} }
        if self.min != 0 {
            self.min = 0;
            for c in self.chunks.iter_mut() {
                *c = 0;
            }
            self.links = Vec::new();
            self.linkMask = 0;
        }

        // Count number of codes of each length, compute min and max.
        let mut count = [0i64; 16]; // maxCodeLen
        let mut min: int = 0;
        let mut max: int = 0;
        for &n in lengths.iter() {
            if n == 0 {
                continue;
            }
            if min == 0 || n < min {
                min = n;
            }
            if n > max {
                max = n;
            }
            count[n as usize] += 1;
        }

        // Empty tree — valid; huffSym will fail later if it is used.
        if max == 0 {
            return true;
        }

        let mut code: int = 0;
        let mut nextcode = [0i64; 16]; // maxCodeLen
        {
            let mut i = min;
            while i <= max {
                code <<= 1;
                nextcode[i as usize] = code;
                code += count[i as usize];
                i += 1;
            }
        }

        // Check that the coding is complete. Exception: accept the
        // degenerate single-code coding (code == 1 && max == 1).
        if code != (1i64 << touint(max)) && !(code == 1 && max == 1) {
            return false;
        }

        self.min = min;
        if max > toint(huffmanChunkBits) {
            let numLinks: int = 1i64 << (touint(max) - huffmanChunkBits);
            self.linkMask = touint32(numLinks - 1);

            // create link tables
            let link: int = nextcode[(huffmanChunkBits as usize) + 1] >> 1;
            let nlinks = toint(huffmanNumChunks) - link;
            self.links = Vec::with_capacity(nlinks as usize);
            for _ in 0..nlinks {
                self.links.push(Vec::new());
            }
            let mut j: int = link;
            while j < toint(huffmanNumChunks) {
                let mut reverse: int = toint(bits::Reverse16(touint16(j)));
                reverse >>= 16 - toint(huffmanChunkBits);
                let off: int = j - link;
                self.chunks[reverse as usize] =
                    (touint32(off) << huffmanValueShift) | (touint32(huffmanChunkBits) + 1);
                let mut lt: Vec<u32> = Vec::with_capacity(numLinks as usize);
                lt.resize(numLinks as usize, 0u32);
                self.links[off as usize] = lt;
                j += 1;
            }
        }

        for (i, &n) in lengths.iter().enumerate() {
            if n == 0 {
                continue;
            }
            let code: int = nextcode[n as usize];
            nextcode[n as usize] += 1;
            let chunk: u32 = (touint32(i) << huffmanValueShift) | touint32(n);
            let mut reverse: int = toint(bits::Reverse16(touint16(code)));
            reverse >>= 16 - toint(n);
            if n <= toint(huffmanChunkBits) {
                let mut off: int = reverse;
                let step: int = 1i64 << touint(n);
                while off < toint(self.chunks.len()) {
                    self.chunks[off as usize] = chunk;
                    off += step;
                }
            } else {
                let j: usize = (reverse as usize) & (huffmanNumChunks - 1);
                let value: u32 = self.chunks[j] >> huffmanValueShift;
                reverse >>= huffmanChunkBits;
                let linktab = &mut self.links[value as usize];
                let mut off: int = reverse;
                let step: int = 1i64 << (touint(n) - huffmanChunkBits);
                while off < toint(linktab.len()) {
                    linktab[off as usize] = chunk;
                    off += step;
                }
            }
        }

        return true;
    }
}

// ─── fixed Huffman decoder ────────────────────────────
//
// Go uses `sync.Once`; goish builds the table once behind a SpinLock
// and clones the Arc-shared chunks/links on demand. The table is small
// and immutable after init, so a per-decompressor clone is cheap.

// go: sdk 1.25.5 compress/flate/inflate.go:766-784 fixedHuffmanDecoderInit
/// `flate.fixedHuffmanDecoderInit()` — build the fixed Huffman decoder
/// once, from the code lengths in RFC 1951 section 3.2.6.
///
/// Go fills the package-level `fixedHuffmanDecoder` var behind a
/// `sync.Once`; goish has no package-level mutable statics under
/// `no_std`, so the table lives in the `SpinLock` slot that
/// [`fixedHuffmanDecoder`] reads. This forces that slot to be filled,
/// which is the whole of what Go's function does.
fn fixedHuffmanDecoderInit() {
    let _ = fixedHuffmanDecoder();
}

// go: none — goish idiom: Go's package-level `fixedHuffmanDecoder` var,
//     read directly once `fixedHuffmanDecoderInit` has run. goish hands
//     back an independent decoder sharing the same immutable table.
fn fixedHuffmanDecoder() -> huffmanDecoder {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<(Box<[u32; huffmanNumChunks]>, int)>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        // RFC section 3.2.6.
        let mut b = [0i64; 288];
        for x in b.iter_mut().take(144) {
            *x = 8;
        }
        for x in b.iter_mut().take(256).skip(144) {
            *x = 9;
        }
        for x in b.iter_mut().take(280).skip(256) {
            *x = 7;
        }
        for x in b.iter_mut().take(288).skip(280) {
            *x = 8;
        }
        let mut h = huffmanDecoder::new();
        h.init(&b);
        *g = Some((h.chunks, h.min));
    }
    let (chunks, min) = g.as_ref().unwrap();
    return huffmanDecoder {
        min: *min,
        chunks: chunks.clone(),
        links: Vec::new(),
        linkMask: 0,
    };
}

// go: none — goish idiom: Go's `huffSym` takes the decoder as a
//     `*huffmanDecoder` argument; goish names it, because a `&mut self`
//     and a `&self.h1` cannot both be live. The three variants are
//     exactly Go's three call sites.
#[derive(Clone, Copy)]
enum whichHuff {
    H1,
    HL,
    HD,
}

// RFC 1951 section 3.2.7 — code-length code order.
const codeOrder: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

// ─── decompression step state ──────────────────────────────────────────

// Go's `decompressor.step` is a `func(*decompressor)`. Goish enumerates
// the four possible next steps.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    NextBlock,
    HuffmanBlock,
    CopyData,
}

// huffmanBlock sub-state (Go's local `stateInit`/`stateDict` iota).
const stateInit: int = 0;
const stateDict: int = 1;

// ─── decompressor ─────────────────────────────────────

/// `flate.decompressor` — DEFLATE decompression state. Returned by
/// [`NewReader`] / [`NewReaderDict`]; implements `io::Reader` +
/// `io::Closer`, and carries `Reset` (Go's `Resetter`).
pub struct Decompressor<R: io::Reader + io::ByteReader> {
    // Input source. Go's `flate.Reader` = io.Reader + io.ByteReader.
    // The decompressor's bit reader pulls bytes via `ReadByte()`, so it
    // consumes EXACTLY the compressed bytes of the stream and no more —
    // matching Go's `makeReader`, which uses an already-ByteReader source
    // directly (no extra buffering). `NewReader` wraps a plain `io::Reader`
    // in `bufio::Reader` (Go's else-branch); `NewReaderByte` uses a source
    // that already implements `io::ByteReader` directly (Go's
    // `r.(flate.Reader)` branch), leaving the source positioned precisely
    // at the stream end so callers can read a following trailer/next object.
    r: R,
    roffset: int,

    // Input bits, in top of b.
    b: u32,
    nb: uint,

    // Huffman decoders for literal/length, distance.
    h1: huffmanDecoder,
    h2: huffmanDecoder,
    // Fixed-Huffman literal/length decoder (built once, cloned in).
    hfixed: huffmanDecoder,

    // Length arrays used to define Huffman codes.
    bitsArr: Box<[int; (maxNumLit + maxNumDist) as usize]>,
    codebits: [int; numCodes as usize],

    // Output history buffer.
    dict: dictDecoder,

    // Temporary buffer (avoids repeated allocation).
    buf: [byte; 4],

    // Next step in the decompression, and decompression state.
    step: Step,
    stepState: int,
    final_: bool,
    err: error,
    toRead: slice<byte>,
    // hl/hd select which decoder a huffmanBlock uses: a flag for the
    // lit/len decoder (fixed vs dynamic) and whether a dist decoder
    // exists (None == fixed distance encoding).
    hlFixed: bool,
    hdValid: bool,
    copyLen: int,
    copyDist: int,
}

impl<R: io::Reader + io::ByteReader> Decompressor<R> {
    // go: sdk 1.25.5 compress/flate/inflate.go:302-333 nextBlock
    // Go: func (f *decompressor) nextBlock()
    fn nextBlock(&mut self) {
        while self.nb < 1 + 2 {
            let e = self.moreBits();
            if !e.IsNil() {
                self.err = e;
                return;
            }
        }
        self.final_ = self.b & 1 == 1;
        self.b >>= 1;
        let typ = self.b & 3;
        self.b >>= 2;
        self.nb -= 1 + 2;
        match typ {
            0 => self.dataBlock(),
            1 => {
                // compressed, fixed Huffman tables
                self.hlFixed = true;
                self.hdValid = false;
                self.huffmanBlock();
            }
            2 => {
                // compressed, dynamic Huffman tables
                let e = self.readHuffman();
                if !e.IsNil() {
                    self.err = e;
                    return;
                }
                self.hlFixed = false;
                self.hdValid = true;
                self.huffmanBlock();
            }
            _ => {
                // 3 is reserved.
                self.err = corrupt(self.roffset);
            }
        }
    }

    // go: sdk 1.25.5 compress/flate/inflate.go:335-353 Read
    /// `(f *decompressor).Read(b)` — io.Reader.
    pub fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        return loop {
            if self.toRead.Len() > 0 {
                let n = copy_into(b, &self.toRead);
                self.toRead = self.toRead.slice(n, self.toRead.Len());
                if self.toRead.Len() == 0 {
                    return (n, self.err.clone());
                }
                return (n, nil);
            }
            if !self.err.IsNil() {
                return (0, self.err.clone());
            }
            // Go: f.step(f)
            match self.step {
                Step::NextBlock => self.nextBlock(),
                Step::HuffmanBlock => self.huffmanBlock(),
                Step::CopyData => self.copyData(),
            }
            if !self.err.IsNil() && self.toRead.Len() == 0 {
                // Flush what's left in case of error.
                self.toRead = self.dict.readFlush();
            }
        };
    }

    // go: sdk 1.25.5 compress/flate/inflate.go:355-360 Close
    /// `(f *decompressor).Close()`.
    pub fn Close(&mut self) -> error {
        if self.err == io::EOF {
            return nil;
        }
        return self.err.clone();
    }

    // go: none — goish idiom: Go hands the caller the `io.Reader` it
    //     passed in, so `compress/gzip` can keep reading the trailer
    //     from it. goish's decompressor owns its source, so it lends it
    //     back instead.
    /// Borrow the underlying buffered source. The DEFLATE decoder stops
    /// on a byte boundary at the end of the compressed stream, so once
    /// `Read` has returned `io.EOF` this reader is positioned exactly at
    /// the first trailing byte. Used by `compress/zlib` (and would be
    /// used by `compress/gzip`) to read the format trailer that follows
    /// the DEFLATE payload — Go's `zlib.reader` keeps its own
    /// `flate.Reader` handle for the same purpose.
    pub(crate) fn reader_mut(&mut self) -> &mut R {
        return &mut self.r;
    }

    // go: none — goish idiom: the by-value half of `reader_mut`.
    /// Consume the decompressor and return its buffered source. Like
    /// [`reader_mut`](Self::reader_mut) but takes the reader by value —
    /// used by `compress/gzip`, whose multistream support must re-parse
    /// a fresh header from the source after one gzip member's trailer
    /// and then `Reset` a flate decoder back onto it.
    pub(crate) fn into_reader(self) -> R {
        return self.r;
    }

    // go: sdk 1.25.5 compress/flate/inflate.go:367-473 readHuffman
    // Go: func (f *decompressor) readHuffman() error
    fn readHuffman(&mut self) -> error {
        // HLIT[5], HDIST[5], HCLEN[4].
        while self.nb < 5 + 5 + 4 {
            let e = self.moreBits();
            if !e.IsNil() {
                return e;
            }
        }
        let nlit: int = toint(self.b & 0x1F) + 257;
        if nlit > maxNumLit {
            return corrupt(self.roffset);
        }
        self.b >>= 5;
        let ndist: int = toint(self.b & 0x1F) + 1;
        if ndist > maxNumDist {
            return corrupt(self.roffset);
        }
        self.b >>= 5;
        let nclen: int = toint(self.b & 0xF) + 4;
        // numCodes is 19, so nclen is always valid.
        self.b >>= 4;
        self.nb -= 5 + 5 + 4;

        // (HCLEN+4)*3 bits: code lengths in the magic codeOrder order.
        {
            let mut i: int = 0;
            while i < nclen {
                while self.nb < 3 {
                    let e = self.moreBits();
                    if !e.IsNil() {
                        return e;
                    }
                }
                self.codebits[codeOrder[i as usize]] = toint(self.b & 0x7);
                self.b >>= 3;
                self.nb -= 3;
                i += 1;
            }
        }
        {
            let mut i = nclen;
            while i < toint(codeOrder.len()) {
                self.codebits[codeOrder[i as usize]] = 0;
                i += 1;
            }
        }
        if !self.h1.init(&self.codebits[..]) {
            return corrupt(self.roffset);
        }

        // HLIT+257 + HDIST+1 code lengths, using the meta Huffman code.
        {
            let n: int = nlit + ndist;
            let mut i: int = 0;
            while i < n {
                let (x, err) = self.huffSym(whichHuff::H1);
                if !err.IsNil() {
                    return err;
                }
                if x < 16 {
                    // Actual length.
                    self.bitsArr[i as usize] = x;
                    i += 1;
                    continue;
                }
                // Repeat previous length or zero.
                let mut rep: int;
                let nb: uint;
                let b: int;
                match x {
                    16 => {
                        rep = 3;
                        nb = 2;
                        if i == 0 {
                            return corrupt(self.roffset);
                        }
                        b = self.bitsArr[(i - 1) as usize];
                    }
                    17 => {
                        rep = 3;
                        nb = 3;
                        b = 0;
                    }
                    18 => {
                        rep = 11;
                        nb = 7;
                        b = 0;
                    }
                    _ => {
                        return internal("unexpected length code");
                    }
                }
                while self.nb < nb {
                    let e = self.moreBits();
                    if !e.IsNil() {
                        return e;
                    }
                }
                rep += toint(self.b & ((1u32 << nb) - 1));
                self.b >>= nb;
                self.nb -= nb;
                if i + rep > n {
                    return corrupt(self.roffset);
                }
                let mut j: int = 0;
                while j < rep {
                    self.bitsArr[i as usize] = b;
                    i += 1;
                    j += 1;
                }
            }
        }

        let lit_ok = {
            let lits: &[int] = &self.bitsArr[..nlit as usize];
            self.h1.init(lits)
        };
        let dist_ok = {
            let dists: &[int] = &self.bitsArr[nlit as usize..(nlit + ndist) as usize];
            self.h2.init(dists)
        };
        if !lit_ok || !dist_ok {
            return corrupt(self.roffset);
        }

        // Initialize the min-bits-to-read for the HLIT tree to the EOB
        // marker length — every block terminates with one, so this
        // never reads past the end of the DEFLATE stream.
        if self.h1.min < self.bitsArr[endBlockMarker] {
            self.h1.min = self.bitsArr[endBlockMarker];
        }

        return nil;
    }

    // go: sdk 1.25.5 compress/flate/inflate.go:479-620 huffmanBlock
    // Go: func (f *decompressor) huffmanBlock()
    //
    // Decode a single Huffman block. The Go original uses `goto` between
    // `readLiteral` and `copyHistory`; goish models that with a loop +
    // a `Phase` selector.
    fn huffmanBlock(&mut self) {
        // Initial phase: stepState picks the entry point.
        let mut copying = self.stepState == stateDict;

        loop {
            if !copying {
                // ── readLiteral ──────────────────────────────────────
                let (v, err) = self.huffSym(whichHuff::HL);
                if !err.IsNil() {
                    self.err = err;
                    return;
                }
                let n: uint; // number of extra bits
                let mut length: int;
                if v < 256 {
                    self.dict.writeByte(tobyte(v));
                    if self.dict.availWrite() == 0 {
                        self.toRead = self.dict.readFlush();
                        self.step = Step::HuffmanBlock;
                        self.stepState = stateInit;
                        return;
                    }
                    continue; // goto readLiteral
                } else if v == 256 {
                    self.finishBlock();
                    return;
                } else if v < 265 {
                    length = v - (257 - 3);
                    n = 0;
                } else if v < 269 {
                    length = v * 2 - (265 * 2 - 11);
                    n = 1;
                } else if v < 273 {
                    length = v * 4 - (269 * 4 - 19);
                    n = 2;
                } else if v < 277 {
                    length = v * 8 - (273 * 8 - 35);
                    n = 3;
                } else if v < 281 {
                    length = v * 16 - (277 * 16 - 67);
                    n = 4;
                } else if v < 285 {
                    length = v * 32 - (281 * 32 - 131);
                    n = 5;
                } else if v < maxNumLit {
                    length = 258;
                    n = 0;
                } else {
                    self.err = corrupt(self.roffset);
                    return;
                }
                if n > 0 {
                    while self.nb < n {
                        let e = self.moreBits();
                        if !e.IsNil() {
                            self.err = e;
                            return;
                        }
                    }
                    length += toint(self.b & ((1u32 << n) - 1));
                    self.b >>= n;
                    self.nb -= n;
                }

                let mut dist: int;
                if !self.hdValid {
                    while self.nb < 5 {
                        let e = self.moreBits();
                        if !e.IsNil() {
                            self.err = e;
                            return;
                        }
                    }
                    // dist = Reverse8(uint8(b & 0x1F << 3))
                    dist = toint(bits::Reverse8(tobyte((self.b & 0x1F) << 3)));
                    self.b >>= 5;
                    self.nb -= 5;
                } else {
                    let (d, e) = self.huffSym(whichHuff::HD);
                    if !e.IsNil() {
                        self.err = e;
                        return;
                    }
                    dist = d;
                }

                if dist < 4 {
                    dist += 1;
                } else if dist < maxNumDist {
                    let nbe: uint = touint(dist - 2) >> 1;
                    // have 1 bit in bottom of dist, need nbe more.
                    let mut extra: int = (dist & 1) << nbe;
                    while self.nb < nbe {
                        let e = self.moreBits();
                        if !e.IsNil() {
                            self.err = e;
                            return;
                        }
                    }
                    extra |= toint(self.b & ((1u32 << nbe) - 1));
                    self.b >>= nbe;
                    self.nb -= nbe;
                    dist = (1i64 << (nbe + 1)) + 1 + extra;
                } else {
                    self.err = corrupt(self.roffset);
                    return;
                }

                // No check on length; encoding can be prescient.
                if dist > self.dict.histSize() {
                    self.err = corrupt(self.roffset);
                    return;
                }

                self.copyLen = length;
                self.copyDist = dist;
                copying = true; // goto copyHistory
            } else {
                // ── copyHistory ──────────────────────────────────────
                let mut cnt = self.dict.tryWriteCopy(self.copyDist, self.copyLen);
                if cnt == 0 {
                    cnt = self.dict.writeCopy(self.copyDist, self.copyLen);
                }
                self.copyLen -= cnt;

                if self.dict.availWrite() == 0 || self.copyLen > 0 {
                    self.toRead = self.dict.readFlush();
                    self.step = Step::HuffmanBlock; // continue this work
                    self.stepState = stateDict;
                    return;
                }
                copying = false; // goto readLiteral
            }
        }
    }

    // go: sdk 1.25.5 compress/flate/inflate.go:623-651 dataBlock
    // Go: func (f *decompressor) dataBlock()
    fn dataBlock(&mut self) {
        // Uncompressed. Discard current half-byte.
        self.nb = 0;
        self.b = 0;

        // Length then ones-complement of length.
        let mut buf4: slice<byte> = {
            let mut v: Vec<byte> = Vec::with_capacity(4);
            v.resize(4, 0u8);
            slice::__from_vec(v)
        };
        let (nr, err) = io::ReadFull(&mut self.r, &mut buf4);
        self.roffset += nr;
        for k in 0..4usize {
            self.buf[k] = buf4[toint(k)];
        }
        if !err.IsNil() {
            self.err = noEOF(err);
            return;
        }
        let n: int = toint(self.buf[0]) | (toint(self.buf[1]) << 8);
        let nn: int = toint(self.buf[2]) | (toint(self.buf[3]) << 8);
        if touint16(nn) != (!touint16(n)) {
            self.err = corrupt(self.roffset);
            return;
        }

        if n == 0 {
            self.toRead = self.dict.readFlush();
            self.finishBlock();
            return;
        }

        self.copyLen = n;
        self.copyData();
    }

    // go: sdk 1.25.5 compress/flate/inflate.go:655-676 copyData
    // Go: func (f *decompressor) copyData()
    fn copyData(&mut self) {
        // Copy f.copyLen bytes from the reader into f.dict.hist.
        let avail = self.dict.availWrite();
        let want = if avail > self.copyLen {
            self.copyLen
        } else {
            avail
        };
        let mut tmp: slice<byte> = {
            let mut v: Vec<byte> = Vec::with_capacity(want as usize);
            v.resize(want as usize, 0u8);
            slice::__from_vec(v)
        };
        let (cnt, err) = io::ReadFull(&mut self.r, &mut tmp);
        self.roffset += cnt;
        self.copyLen -= cnt;
        // Go: f.dict.writeMark(cnt)
        //
        // Go reads straight into `f.dict.writeSlice()`; goish's
        // `io::ReadFull` needs an owned `slice<byte>` and cannot fill a
        // borrowed window, so the bytes land in `tmp` first and are
        // copied into the same view here. `writeSlice`/`writeMark` are
        // still the only things that touch the cursor.
        {
            let buf = self.dict.writeSlice();
            let n = usize::try_from(cnt).unwrap_or(0);
            let mut k: usize = 0;
            while k < n {
                buf[k] = tmp[toint(k)];
                k += 1;
            }
        }
        self.dict.writeMark(cnt);
        if !err.IsNil() {
            self.err = noEOF(err);
            return;
        }

        if self.dict.availWrite() == 0 || self.copyLen > 0 {
            self.toRead = self.dict.readFlush();
            self.step = Step::CopyData;
            return;
        }
        self.finishBlock();
    }

    // go: sdk 1.25.5 compress/flate/inflate.go:678-686 finishBlock
    // Go: func (f *decompressor) finishBlock()
    fn finishBlock(&mut self) {
        if self.final_ {
            if self.dict.availRead() > 0 {
                self.toRead = self.dict.readFlush();
            }
            self.err = io::EOF.into();
        }
        self.step = Step::NextBlock;
    }

    // go: sdk 1.25.5 compress/flate/inflate.go:696-705 moreBits
    // Go: func (f *decompressor) moreBits() error
    fn moreBits(&mut self) -> error {
        let (c, err) = self.r.ReadByte();
        if !err.IsNil() {
            return noEOF(err);
        }
        self.roffset += 1;
        self.b |= touint32(c) << self.nb;
        self.nb += 8;
        return nil;
    }

    // go: sdk 1.25.5 compress/flate/inflate.go:708-747 decompressor.huffSym
    /// `(f *decompressor).huffSym(h)` — read the next Huffman-encoded
    /// symbol from `f` according to `h`.
    ///
    /// Go passes the decoder by pointer: `f.huffSym(&f.h1)`. That is a
    /// `&mut self` and a `&self.h1` alive at once, which the borrow
    /// checker refuses, so goish names the decoder instead of passing
    /// it — same arity, and the three call sites read the same way.
    /// The bit-reading loop itself is hoisted into `huff_sym_step`,
    /// which borrows only the fields it needs.
    fn huffSym(&mut self, h: whichHuff) -> (int, error) {
        return match h {
            whichHuff::H1 => return self.huffSym_h1(),
            whichHuff::HL => return self.huffSym_hl(),
            whichHuff::HD => return self.huffSym_hd(),
        };
    }

    // go: none — goish idiom: the `h1` arm of `huffSym`, split out so
    //     each borrows exactly one decoder's fields.
    fn huffSym_h1(&mut self) -> (int, error) {
        return huff_sym_step(
            &mut self.r,
            &mut self.b,
            &mut self.nb,
            &mut self.roffset,
            &mut self.err,
            &HuffTables {
                min: self.h1.min,
                chunks: &self.h1.chunks,
                links: &self.h1.links,
                linkMask: self.h1.linkMask,
            },
        );
    }

    // go: none — goish idiom: the `hl` arm of `huffSym`; see `huffSym_h1`.
    //     Go reaches the fixed table through the same pointer parameter.
    fn huffSym_hl(&mut self) -> (int, error) {
        return if self.hlFixed {
            let tables = HuffTables {
                min: self.hfixed.min,
                chunks: &self.hfixed.chunks,
                links: &self.hfixed.links,
                linkMask: self.hfixed.linkMask,
            };
            huff_sym_step(
                &mut self.r,
                &mut self.b,
                &mut self.nb,
                &mut self.roffset,
                &mut self.err,
                &tables,
            )
        } else {
            self.huffSym_h1()
        };
    }

    // go: none — goish idiom: the `hd` arm of `huffSym`; see `huffSym_h1`.
    fn huffSym_hd(&mut self) -> (int, error) {
        return huff_sym_step(
            &mut self.r,
            &mut self.b,
            &mut self.nb,
            &mut self.roffset,
            &mut self.err,
            &HuffTables {
                min: self.h2.min,
                chunks: &self.h2.chunks,
                links: &self.h2.links,
                linkMask: self.h2.linkMask,
            },
        );
    }

    // go: sdk 1.25.5 compress/flate/inflate.go:786-797 Reset
    /// `(f *decompressor).Reset(r, dict)` — Go's
    /// `Resetter`. Discards buffered data and reinitializes for a new
    /// source. `dict` is a preset dictionary (pass `slice::new()` /
    /// `nil` for none).
    pub fn Reset(&mut self, r: R, dict: slice<byte>) -> error {
        // `R` is already the `flate.Reader` (io::Reader + io::ByteReader);
        // assign directly — no re-wrapping (mirrors makeReader being a
        // no-op when the source already implements the interface).
        self.r = r;
        self.roffset = 0;
        self.b = 0;
        self.nb = 0;
        self.h1 = huffmanDecoder::new();
        self.h2 = huffmanDecoder::new();
        self.buf = [0u8; 4];
        self.step = Step::NextBlock;
        self.stepState = stateInit;
        self.final_ = false;
        self.err = nil;
        self.toRead = slice::new();
        self.hlFixed = false;
        self.hdValid = false;
        self.copyLen = 0;
        self.copyDist = 0;
        for x in self.codebits.iter_mut() {
            *x = 0;
        }
        for x in self.bitsArr.iter_mut() {
            *x = 0;
        }
        let d: &[byte] = &dict;
        self.dict.init(maxMatchOffset, &d);
        return nil;
    }
}

// Borrowed view of a huffmanDecoder for the free-function huffSym.
struct HuffTables<'a> {
    min: int,
    chunks: &'a [u32; huffmanNumChunks],
    links: &'a Vec<Vec<u32>>,
    linkMask: u32,
}

// go: none — goish idiom: the table-lookup core of `huffSym`, lifted
//     out of the impl so it borrows only the fields it needs instead of
//     aliasing `&mut self` against one of the decoders.
//
// Go: func (f *decompressor) huffSym(...)
fn huff_sym_step<R: io::Reader + io::ByteReader>(
    r: &mut R,
    fb: &mut u32,
    fnb: &mut uint,
    roffset: &mut int,
    ferr: &mut error,
    h: &HuffTables<'_>,
) -> (int, error) {
    let mut n: uint = touint(h.min);
    let mut nb: uint = *fnb;
    let mut b: u32 = *fb;
    return loop {
        while nb < n {
            let (c, err) = r.ReadByte();
            if !err.IsNil() {
                *fb = b;
                *fnb = nb;
                return (0, noEOF(err));
            }
            *roffset += 1;
            b |= touint32(c) << (nb & 31);
            nb += 8;
        }
        let mut chunk: u32 = h.chunks[(b & (touint32(huffmanNumChunks) - 1)) as usize];
        n = touint(chunk & huffmanCountMask);
        if n > huffmanChunkBits {
            chunk = h.links[(chunk >> huffmanValueShift) as usize]
                [((b >> huffmanChunkBits) & h.linkMask) as usize];
            n = touint(chunk & huffmanCountMask);
        }
        if n <= nb {
            if n == 0 {
                *fb = b;
                *fnb = nb;
                *ferr = corrupt(*roffset);
                return (0, ferr.clone());
            }
            *fb = b >> (n & 31);
            *fnb = nb - n;
            return (toint(chunk >> huffmanValueShift), nil);
        }
    };
}

// go: sdk 1.25.5 compress/flate/inflate.go:689-694 noEOF
// Go: func noEOF(e error) error
fn noEOF(e: error) -> error {
    if e == io::EOF {
        return io::ErrUnexpectedEOF.into();
    }
    return e;
}

// go: none — goish idiom: Go writes `CorruptInputError(f.roffset)`
//     and assigns it to an `error` directly; goish wraps the concrete
//     type into the `error` carrier.
/// Construct a `CorruptInputError` lifted into `error`.
fn corrupt(offset: int) -> error {
    return errors::Wrap(CorruptInputError(offset));
}

// go: none — goish idiom: see `corrupt`.
/// Construct an `InternalError` lifted into `error`.
pub(super) fn internal(msg: &str) -> error {
    return errors::Wrap(InternalError(string::from(msg)));
}

// go: none — goish idiom: Go's builtin `copy(dst, src)` over two
//     distinct slices, which clamps to the shorter length.
/// Go's `copy(dst, src)` built-in for two distinct slices.
fn copy_into(dst: &mut slice<byte>, src: &slice<byte>) -> int {
    let n = dst.Len().min(src.Len());
    for k in 0..n {
        dst[k] = src[k];
    }
    return n;
}

// go: waived makeReader — Go's decides at *run time* whether the source
//     already satisfies `flate.Reader` (io.Reader + io.ByteReader) and
//     wraps it in a `bufio.Reader` only when it does not. goish's
//     `Decompressor<R>` is generic over that bound, so the decision is
//     made at compile time by which constructor is called: `NewReader`
//     wraps a plain `io::Reader` in `bufio::Reader` — Go's else branch
//     — and `NewReaderByte` takes a source that already implements
//     `io::ByteReader` — Go's `r.(Reader)` branch. There is no run-time
//     assertion left to port, and no place to put one.
// goishlint:ignore GOISH018 makeReader — see the waiver above.

// ─── constructors ─────────────────────────────────────

// go: none — goish idiom: the shared body of `NewReader`/`NewReaderDict`.
fn new_decompressor<R: io::Reader + io::ByteReader>(r: R, dict: &[byte]) -> Decompressor<R> {
    // Go: fixedHuffmanDecoderInit() runs inside huffmanBlock's first
    // fixed-Huffman block; goish forces it here, since the decoder is
    // a field rather than a package var.
    fixedHuffmanDecoderInit();
    let mut f = Decompressor {
        r,
        roffset: 0,
        b: 0,
        nb: 0,
        h1: huffmanDecoder::new(),
        h2: huffmanDecoder::new(),
        hfixed: fixedHuffmanDecoder(),
        bitsArr: Box::new([0i64; (maxNumLit + maxNumDist) as usize]),
        codebits: [0i64; numCodes as usize],
        dict: dictDecoder::new(),
        buf: [0u8; 4],
        step: Step::NextBlock,
        stepState: stateInit,
        final_: false,
        err: nil,
        toRead: slice::new(),
        hlFixed: false,
        hdValid: false,
        copyLen: 0,
        copyDist: 0,
    };
    f.dict.init(maxMatchOffset, dict);
    return f;
}

// go: none — goish idiom: `compress/gzip` restarts inflation on a
//     buffered source it already owns. Go passes the `io.Reader` and
//     lets `makeReader` decide; goish has no run-time assertion, so the
//     buffered case gets its own constructor.
/// Build a `Decompressor` whose source *is* the given `bufio::Reader<R>`
/// — no extra wrapping. `compress/gzip` uses this to restart inflation on
/// the next gzip member while reusing the buffered reader it has already
/// positioned past the previous member's trailer.
///
/// `bufio::Reader<R>` already implements `io::ByteReader`, so this is just
/// `new_decompressor` specialised to that source type.
pub(crate) fn new_decompressor_buffered<R: io::Reader>(
    r: bufio::Reader<R>,
    dict: &[byte],
) -> Decompressor<bufio::Reader<R>> {
    return new_decompressor(r, dict);
}

// go: sdk 1.25.5 compress/flate/inflate.go:807-817 NewReader
/// `flate.NewReader(r)` — a new ReadCloser reading the
/// uncompressed version of `r`. Returns `io.EOF` after the final block.
///
/// Mirrors Go's `makeReader` ELSE-branch: a plain `io::Reader` is wrapped
/// in `bufio::Reader` (which supplies `io::ByteReader`). For a source that
/// already implements `io::ByteReader`, use [`NewReaderByte`] to avoid the
/// extra buffering and keep the source positioned exactly at the stream
/// end. Returns the concrete `Decompressor` (Go returns `io.ReadCloser`).
pub fn NewReader<R: io::Reader>(r: R) -> Decompressor<bufio::Reader<R>> {
    return new_decompressor(bufio::NewReader(r), &[]);
}

// go: sdk 1.25.5 compress/flate/inflate.go:826-836 NewReaderDict
/// `flate.NewReaderDict(r, dict)` — like [`NewReader`]
/// but initializes the reader with a preset dictionary `dict`.
pub fn NewReaderDict<R: io::Reader>(r: R, dict: slice<byte>) -> Decompressor<bufio::Reader<R>> {
    let d: &[byte] = &dict;
    return new_decompressor(bufio::NewReader(r), &d);
}

// go: none — goish idiom: the `r.(Reader)` branch of `makeReader`,
//     chosen at compile time by calling this constructor instead of
//     `NewReader`. See the `makeReader` waiver above.
/// Like [`NewReader`] but for a source that ALREADY implements
/// `io::ByteReader` (Go's `flate.Reader`). Mirrors `makeReader`'s
/// `r.(flate.Reader)` branch: the source is used directly with no extra
/// buffering, so after `Read` returns `io.EOF` the source is positioned
/// exactly at the first byte past the DEFLATE stream. This is what
/// offset-tracking consumers (e.g. git packfile scanners reading
/// sequential zlib streams) require.
pub fn NewReaderByte<R: io::Reader + io::ByteReader>(r: R) -> Decompressor<R> {
    return new_decompressor(r, &[]);
}

// go: none — goish idiom: the dictionary form of `NewReaderByte`; see
//     the `makeReader` waiver above.
/// Like [`NewReaderDict`] but for an already-`io::ByteReader` source.
pub fn NewReaderByteDict<R: io::Reader + io::ByteReader>(
    r: R,
    dict: slice<byte>,
) -> Decompressor<R> {
    let d: &[byte] = &dict;
    return new_decompressor(r, &d);
}

// ─── trait impls ───────────────────────────────────────────────────────

impl<R: io::Reader + io::ByteReader> io::Reader for Decompressor<R> {
    // go: sdk 1.25.5 compress/flate/inflate.go:335-353 Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        return Decompressor::Read(self, p);
    }
}

impl<R: io::Reader + io::ByteReader> io::Closer for Decompressor<R> {
    // go: sdk 1.25.5 compress/flate/inflate.go:355-360 Close
    fn Close(&mut self) -> error {
        return Decompressor::Close(self);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Huffman encoder + bit writer — port of Go 1.25 `token.go`,
// `huffman_code.go`, `huffman_bit_writer.go`.
//
// These types are all `package flate` unexported in Go (`token`,
// `huffmanEncoder`, `huffmanBitWriter`); they stay module-internal
// (`pub(crate)` / private) — the compressor (`deflate.go`, next task)
// consumes them from within this same module.
//
// Slim deviations from Go:
//   * Go's `huffmanBitWriter.writer` is an `io.Writer`. Go's
//     `newHuffmanBitWriter` takes a raw `io.Writer` and the bit writer
//     does ALL its own buffering via the inline `bytes [bufferSize]byte`
//     array — no `bufio` layer. Goish mirrors this: `huffmanBitWriter`
//     is generic over `W: io::Writer` and holds it directly.
//   * Go's package-level `fixedLiteralEncoding` / `fixedOffsetEncoding`
//     / `huffOffset` are built by package `init()`. Goish builds them
//     lazily behind a `SpinLock` (no `no_std` package-init) and clones
//     the small immutable tables on demand — same pattern the inflate
//     side uses for `fixedHuffmanDecoder`.
//   * Go's `InternalError("...")` constructs the error directly from a
//     string; goish wraps via `internal(...)`.
// ═══════════════════════════════════════════════════════════════════════
