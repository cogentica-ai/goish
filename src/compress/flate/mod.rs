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

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::bufio;
use crate::errors::nil;
use crate::errors::{self, error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::math::bits;
use crate::types::{byte, int, uint};

// ─── constants (inflate.go:18) ─────────────────────────────────────────

// maxCodeLen = 16 — max length of a Huffman code (sizes the `count`
// and `nextcode` scratch arrays in `huffmanDecoder::init`).
const maxNumLit: int = 286;
const maxNumDist: int = 30;
const numCodes: int = 19; // number of codes in Huffman meta-code

// chunk & 15 is number of bits; chunk >> 4 is value, incl. table link.
const huffmanChunkBits: uint = 9;
const huffmanNumChunks: usize = 1 << 9; // 512
const huffmanCountMask: u32 = 15;
const huffmanValueShift: u32 = 4;

// deflate.go:47 / huffman_bit_writer.go:16 — referenced by inflate.
const maxMatchOffset: int = 1 << 15; // 32768
const endBlockMarker: usize = 256;

// ─── CorruptInputError / InternalError (inflate.go:32) ─────────────────

/// `flate.CorruptInputError` — reports corrupt input at a byte offset.
#[derive(Clone, Copy, Debug, Default)]
pub struct CorruptInputError(pub int);

impl ErrorTrait for CorruptInputError {
    fn Error(&self) -> string {
        let mut s = string::from("flate: corrupt input before offset ");
        s = s + crate::strconv::FormatInt(self.0, 10);
        s
    }
}

/// `flate.InternalError` — reports an error in the flate code itself.
#[derive(Clone, Debug, Default)]
pub struct InternalError(pub string);

impl ErrorTrait for InternalError {
    fn Error(&self) -> string {
        string::from("flate: internal error: ") + self.0.clone()
    }
}

// ─── huffmanDecoder (inflate.go:104) ───────────────────────────────────

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
    fn new() -> huffmanDecoder {
        huffmanDecoder {
            min: 0,
            chunks: Box::new([0u32; huffmanNumChunks]),
            links: Vec::new(),
            linkMask: 0,
        }
    }

    // Go: func (h *huffmanDecoder) init(lengths []int) bool  (inflate.go:116)
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
        if code != (1i64 << (max as uint)) && !(code == 1 && max == 1) {
            return false;
        }

        self.min = min;
        if max > huffmanChunkBits as int {
            let numLinks: int = 1i64 << ((max as uint) - huffmanChunkBits);
            self.linkMask = (numLinks - 1) as u32;

            // create link tables
            let link: int = nextcode[(huffmanChunkBits as usize) + 1] >> 1;
            let nlinks = (huffmanNumChunks as int) - link;
            self.links = Vec::with_capacity(nlinks as usize);
            for _ in 0..nlinks {
                self.links.push(Vec::new());
            }
            let mut j: int = link;
            while j < huffmanNumChunks as int {
                let mut reverse: int = bits::Reverse16(j as u16) as int;
                reverse >>= 16 - (huffmanChunkBits as int);
                let off: int = j - link;
                self.chunks[reverse as usize] =
                    ((off as u32) << huffmanValueShift) | ((huffmanChunkBits as u32) + 1);
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
            let chunk: u32 = ((i as u32) << huffmanValueShift) | (n as u32);
            let mut reverse: int = bits::Reverse16(code as u16) as int;
            reverse >>= 16 - (n as int);
            if n <= huffmanChunkBits as int {
                let mut off: int = reverse;
                let step: int = 1i64 << (n as uint);
                while off < self.chunks.len() as int {
                    self.chunks[off as usize] = chunk;
                    off += step;
                }
            } else {
                let j: usize = (reverse as usize) & (huffmanNumChunks - 1);
                let value: u32 = self.chunks[j] >> huffmanValueShift;
                reverse >>= huffmanChunkBits;
                let linktab = &mut self.links[value as usize];
                let mut off: int = reverse;
                let step: int = 1i64 << ((n as uint) - huffmanChunkBits);
                while off < linktab.len() as int {
                    linktab[off as usize] = chunk;
                    off += step;
                }
            }
        }

        true
    }
}

// ─── fixed Huffman decoder (inflate.go:766) ────────────────────────────
//
// Go uses `sync.Once`; goish builds the table once behind a SpinLock
// and clones the Arc-shared chunks/links on demand. The table is small
// and immutable after init, so a per-decompressor clone is cheap.

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
    huffmanDecoder {
        min: *min,
        chunks: chunks.clone(),
        links: Vec::new(),
        linkMask: 0,
    }
}

// RFC 1951 section 3.2.7 — code-length code order.
const codeOrder: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

// ─── dictDecoder (dict_decoder.go:27) ──────────────────────────────────

/// LZ77 sliding-window history buffer used by the decompressor.
struct dictDecoder {
    // Sliding window history (internal scratch buffer — stays Vec).
    hist: Vec<byte>,
    // Invariant: 0 <= rdPos <= wrPos <= len(hist)
    wrPos: int,
    rdPos: int,
    full: bool,
}

impl dictDecoder {
    fn new() -> dictDecoder {
        dictDecoder {
            hist: Vec::new(),
            wrPos: 0,
            rdPos: 0,
            full: false,
        }
    }

    // Go: func (dd *dictDecoder) init(size int, dict []byte)  (dict_decoder.go:39)
    fn init(&mut self, size: int, dict: &[byte]) {
        // *dd = dictDecoder{hist: dd.hist}
        self.wrPos = 0;
        self.rdPos = 0;
        self.full = false;

        if (self.hist.capacity() as int) < size {
            self.hist = Vec::with_capacity(size as usize);
        }
        self.hist.resize(size as usize, 0u8);

        // if len(dict) > len(hist) { dict = dict[len(dict)-len(hist):] }
        let mut d: &[byte] = dict;
        if (d.len() as int) > (self.hist.len() as int) {
            d = &d[d.len() - self.hist.len()..];
        }
        // dd.wrPos = copy(dd.hist, dict)
        let n = d.len().min(self.hist.len());
        self.hist[..n].copy_from_slice(&d[..n]);
        self.wrPos = n as int;
        if self.wrPos == self.hist.len() as int {
            self.wrPos = 0;
            self.full = true;
        }
        self.rdPos = self.wrPos;
    }

    // Go: histSize  (dict_decoder.go:59)
    fn histSize(&self) -> int {
        if self.full {
            return self.hist.len() as int;
        }
        self.wrPos
    }

    // Go: availRead  (dict_decoder.go:67)
    fn availRead(&self) -> int {
        self.wrPos - self.rdPos
    }

    // Go: availWrite  (dict_decoder.go:72)
    fn availWrite(&self) -> int {
        (self.hist.len() as int) - self.wrPos
    }

    // Go: writeByte  (dict_decoder.go:93)
    fn writeByte(&mut self, c: byte) {
        self.hist[self.wrPos as usize] = c;
        self.wrPos += 1;
    }

    // Go: writeCopy  (dict_decoder.go:103) — copy (dist,length) to output.
    fn writeCopy(&mut self, dist: int, length: int) -> int {
        let dstBase: int = self.wrPos;
        let mut dstPos: int = dstBase;
        let mut srcPos: int = dstPos - dist;
        let mut endPos: int = dstPos + length;
        if endPos > self.hist.len() as int {
            endPos = self.hist.len() as int;
        }

        // Copy non-overlapping section after destination position.
        if srcPos < 0 {
            srcPos += self.hist.len() as int;
            let hlen = self.hist.len();
            let n = copy_within(
                &mut self.hist,
                dstPos as usize,
                endPos as usize,
                srcPos as usize,
                hlen,
            );
            dstPos += n;
            srcPos = 0;
        }

        // Copy possibly overlapping section before destination position.
        while dstPos < endPos {
            let n = copy_within(
                &mut self.hist,
                dstPos as usize,
                endPos as usize,
                srcPos as usize,
                dstPos as usize,
            );
            dstPos += n;
        }

        self.wrPos = dstPos;
        dstPos - dstBase
    }

    // Go: tryWriteCopy  (dict_decoder.go:153) — fast path for short dist.
    fn tryWriteCopy(&mut self, dist: int, length: int) -> int {
        let mut dstPos: int = self.wrPos;
        let endPos: int = dstPos + length;
        if dstPos < dist || endPos > self.hist.len() as int {
            return 0;
        }
        let dstBase: int = dstPos;
        let srcPos: int = dstPos - dist;

        while dstPos < endPos {
            let n = copy_within(
                &mut self.hist,
                dstPos as usize,
                endPos as usize,
                srcPos as usize,
                dstPos as usize,
            );
            dstPos += n;
        }

        self.wrPos = dstPos;
        dstPos - dstBase
    }

    // Go: readFlush  (dict_decoder.go:174) — slice ready to emit.
    // Goish returns an owned `slice<byte>` copy (Go aliases the buffer;
    // goish's slice cannot safely alias `hist` across mutation).
    fn readFlush(&mut self) -> slice<byte> {
        let lo = self.rdPos as usize;
        let hi = self.wrPos as usize;
        let mut v: Vec<byte> = Vec::with_capacity(hi - lo);
        v.extend_from_slice(&self.hist[lo..hi]);
        self.rdPos = self.wrPos;
        if self.wrPos == self.hist.len() as int {
            self.wrPos = 0;
            self.rdPos = 0;
            self.full = true;
        }
        slice::__from_vec(v)
    }
}

// Go's `copy(dst, src)` on overlapping ranges of the SAME buffer.
// `copy` is forward + clamps to min length; overlap with dst > src
// performs the run-length-style forward propagation flate relies on.
fn copy_within(buf: &mut [byte], dst: usize, dst_end: usize, src: usize, src_end: usize) -> int {
    let n = (dst_end - dst).min(src_end - src);
    for k in 0..n {
        buf[dst + k] = buf[src + k];
    }
    n as int
}

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

// ─── decompressor (inflate.go:267) ─────────────────────────────────────

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
    // Go: func (f *decompressor) nextBlock()  (inflate.go:302)
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

    /// `(f *decompressor).Read(b)` (inflate.go:335) — io.Reader.
    pub fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        loop {
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
        }
    }

    /// `(f *decompressor).Close()` (inflate.go:355).
    pub fn Close(&mut self) -> error {
        if self.err == io::EOF {
            return nil;
        }
        self.err.clone()
    }

    /// Borrow the underlying buffered source. The DEFLATE decoder stops
    /// on a byte boundary at the end of the compressed stream, so once
    /// `Read` has returned `io.EOF` this reader is positioned exactly at
    /// the first trailing byte. Used by `compress/zlib` (and would be
    /// used by `compress/gzip`) to read the format trailer that follows
    /// the DEFLATE payload — Go's `zlib.reader` keeps its own
    /// `flate.Reader` handle for the same purpose.
    pub(crate) fn reader_mut(&mut self) -> &mut R {
        &mut self.r
    }

    /// Consume the decompressor and return its buffered source. Like
    /// [`reader_mut`](Self::reader_mut) but takes the reader by value —
    /// used by `compress/gzip`, whose multistream support must re-parse
    /// a fresh header from the source after one gzip member's trailer
    /// and then `Reset` a flate decoder back onto it.
    pub(crate) fn into_reader(self) -> R {
        self.r
    }

    // Go: func (f *decompressor) readHuffman() error  (inflate.go:367)
    fn readHuffman(&mut self) -> error {
        // HLIT[5], HDIST[5], HCLEN[4].
        while self.nb < 5 + 5 + 4 {
            let e = self.moreBits();
            if !e.IsNil() {
                return e;
            }
        }
        let nlit: int = ((self.b & 0x1F) as int) + 257;
        if nlit > maxNumLit {
            return corrupt(self.roffset);
        }
        self.b >>= 5;
        let ndist: int = ((self.b & 0x1F) as int) + 1;
        if ndist > maxNumDist {
            return corrupt(self.roffset);
        }
        self.b >>= 5;
        let nclen: int = ((self.b & 0xF) as int) + 4;
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
                self.codebits[codeOrder[i as usize]] = (self.b & 0x7) as int;
                self.b >>= 3;
                self.nb -= 3;
                i += 1;
            }
        }
        {
            let mut i = nclen;
            while i < codeOrder.len() as int {
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
                let (x, err) = self.huffSym_h1();
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
                rep += (self.b & ((1u32 << nb) - 1)) as int;
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

        nil
    }

    // Go: func (f *decompressor) huffmanBlock()  (inflate.go:479)
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
                let (v, err) = self.huffSym_hl();
                if !err.IsNil() {
                    self.err = err;
                    return;
                }
                let n: uint; // number of extra bits
                let mut length: int;
                if v < 256 {
                    self.dict.writeByte(v as byte);
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
                    length += (self.b & ((1u32 << n) - 1)) as int;
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
                    dist = bits::Reverse8(((self.b & 0x1F) << 3) as u8) as int;
                    self.b >>= 5;
                    self.nb -= 5;
                } else {
                    let (d, e) = self.huffSym_hd();
                    if !e.IsNil() {
                        self.err = e;
                        return;
                    }
                    dist = d;
                }

                if dist < 4 {
                    dist += 1;
                } else if dist < maxNumDist {
                    let nbe: uint = ((dist - 2) as uint) >> 1;
                    // have 1 bit in bottom of dist, need nbe more.
                    let mut extra: int = (dist & 1) << nbe;
                    while self.nb < nbe {
                        let e = self.moreBits();
                        if !e.IsNil() {
                            self.err = e;
                            return;
                        }
                    }
                    extra |= (self.b & ((1u32 << nbe) - 1)) as int;
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

    // Go: func (f *decompressor) dataBlock()  (inflate.go:623)
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
            self.buf[k] = buf4[k as int];
        }
        if !err.IsNil() {
            self.err = noEOF(err);
            return;
        }
        let n: int = (self.buf[0] as int) | ((self.buf[1] as int) << 8);
        let nn: int = (self.buf[2] as int) | ((self.buf[3] as int) << 8);
        if (nn as u16) != ((!n) as u16) {
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

    // Go: func (f *decompressor) copyData()  (inflate.go:655)
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
        // writeSlice + writeMark: copy the bytes read into the window.
        {
            let wr = self.dict.wrPos as usize;
            for k in 0..(cnt as usize) {
                self.dict.hist[wr + k] = tmp[k as int];
            }
            self.dict.wrPos += cnt;
        }
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

    // Go: func (f *decompressor) finishBlock()  (inflate.go:678)
    fn finishBlock(&mut self) {
        if self.final_ {
            if self.dict.availRead() > 0 {
                self.toRead = self.dict.readFlush();
            }
            self.err = io::EOF.into();
        }
        self.step = Step::NextBlock;
    }

    // Go: func (f *decompressor) moreBits() error  (inflate.go:696)
    fn moreBits(&mut self) -> error {
        let (c, err) = self.r.ReadByte();
        if !err.IsNil() {
            return noEOF(err);
        }
        self.roffset += 1;
        self.b |= (c as u32) << self.nb;
        self.nb += 8;
        nil
    }

    // Go: func (f *decompressor) huffSym(h *huffmanDecoder) (int, error)
    // (inflate.go:708). The borrow checker forbids `&mut self` + `&h`
    // aliasing, so the table lookup is hoisted into a free function and
    // three thin wrappers select the decoder.

    fn huffSym_h1(&mut self) -> (int, error) {
        huff_sym_step(
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
        )
    }

    fn huffSym_hl(&mut self) -> (int, error) {
        if self.hlFixed {
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
        }
    }

    fn huffSym_hd(&mut self) -> (int, error) {
        huff_sym_step(
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
        )
    }

    /// `(f *decompressor).Reset(r, dict)` (inflate.go:786) — Go's
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
        let d = slice_bytes(&dict);
        self.dict.init(maxMatchOffset, &d);
        nil
    }
}

// Borrowed view of a huffmanDecoder for the free-function huffSym.
struct HuffTables<'a> {
    min: int,
    chunks: &'a [u32; huffmanNumChunks],
    links: &'a Vec<Vec<u32>>,
    linkMask: u32,
}

// Go: func (f *decompressor) huffSym(...)  — table-lookup core lifted out
// of the impl so it does not alias `&mut self` against the decoder.
fn huff_sym_step<R: io::Reader + io::ByteReader>(
    r: &mut R,
    fb: &mut u32,
    fnb: &mut uint,
    roffset: &mut int,
    ferr: &mut error,
    h: &HuffTables<'_>,
) -> (int, error) {
    let mut n: uint = h.min as uint;
    let mut nb: uint = *fnb;
    let mut b: u32 = *fb;
    loop {
        while nb < n {
            let (c, err) = r.ReadByte();
            if !err.IsNil() {
                *fb = b;
                *fnb = nb;
                return (0, noEOF(err));
            }
            *roffset += 1;
            b |= (c as u32) << (nb & 31);
            nb += 8;
        }
        let mut chunk: u32 = h.chunks[(b & ((huffmanNumChunks as u32) - 1)) as usize];
        n = (chunk & huffmanCountMask) as uint;
        if n > huffmanChunkBits {
            chunk = h.links[(chunk >> huffmanValueShift) as usize]
                [((b >> huffmanChunkBits) & h.linkMask) as usize];
            n = (chunk & huffmanCountMask) as uint;
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
            return ((chunk >> huffmanValueShift) as int, nil);
        }
    }
}

// Go: func noEOF(e error) error  (inflate.go:689)
fn noEOF(e: error) -> error {
    if e == io::EOF {
        return io::ErrUnexpectedEOF.into();
    }
    e
}

// Construct a `CorruptInputError` lifted into `error`.
fn corrupt(offset: int) -> error {
    errors::Wrap(CorruptInputError(offset))
}

// Construct an `InternalError` lifted into `error`.
fn internal(msg: &str) -> error {
    errors::Wrap(InternalError(string::from(msg)))
}

// Go's `copy(dst, src)` built-in for two distinct slices.
fn copy_into(dst: &mut slice<byte>, src: &slice<byte>) -> int {
    let n = dst.Len().min(src.Len());
    for k in 0..n {
        dst[k] = src[k];
    }
    n
}

// Snapshot a `slice<byte>` into a Rust `Vec` (internal scratch path).
fn slice_bytes(s: &slice<byte>) -> Vec<byte> {
    let n = s.Len();
    let mut v: Vec<byte> = Vec::with_capacity(n as usize);
    let mut i: int = 0;
    while i < n {
        v.push(s[i]);
        i += 1;
    }
    v
}

// ─── constructors (inflate.go:807) ─────────────────────────────────────

fn new_decompressor<R: io::Reader + io::ByteReader>(r: R, dict: &[byte]) -> Decompressor<R> {
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
    f
}

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
    new_decompressor(r, dict)
}

/// `flate.NewReader(r)` (inflate.go:807) — a new ReadCloser reading the
/// uncompressed version of `r`. Returns `io.EOF` after the final block.
///
/// Mirrors Go's `makeReader` ELSE-branch: a plain `io::Reader` is wrapped
/// in `bufio::Reader` (which supplies `io::ByteReader`). For a source that
/// already implements `io::ByteReader`, use [`NewReaderByte`] to avoid the
/// extra buffering and keep the source positioned exactly at the stream
/// end. Returns the concrete `Decompressor` (Go returns `io.ReadCloser`).
pub fn NewReader<R: io::Reader>(r: R) -> Decompressor<bufio::Reader<R>> {
    new_decompressor(bufio::NewReader(r), &[])
}

/// `flate.NewReaderDict(r, dict)` (inflate.go:826) — like [`NewReader`]
/// but initializes the reader with a preset dictionary `dict`.
pub fn NewReaderDict<R: io::Reader>(r: R, dict: slice<byte>) -> Decompressor<bufio::Reader<R>> {
    let d = slice_bytes(&dict);
    new_decompressor(bufio::NewReader(r), &d)
}

/// Like [`NewReader`] but for a source that ALREADY implements
/// `io::ByteReader` (Go's `flate.Reader`). Mirrors `makeReader`'s
/// `r.(flate.Reader)` branch: the source is used directly with no extra
/// buffering, so after `Read` returns `io.EOF` the source is positioned
/// exactly at the first byte past the DEFLATE stream. This is what
/// offset-tracking consumers (e.g. git packfile scanners reading
/// sequential zlib streams) require.
pub fn NewReaderByte<R: io::Reader + io::ByteReader>(r: R) -> Decompressor<R> {
    new_decompressor(r, &[])
}

/// Like [`NewReaderDict`] but for an already-`io::ByteReader` source.
pub fn NewReaderByteDict<R: io::Reader + io::ByteReader>(
    r: R,
    dict: slice<byte>,
) -> Decompressor<R> {
    let d = slice_bytes(&dict);
    new_decompressor(r, &d)
}

// ─── trait impls ───────────────────────────────────────────────────────

impl<R: io::Reader + io::ByteReader> io::Reader for Decompressor<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Decompressor::Read(self, p)
    }
}

impl<R: io::Reader + io::ByteReader> io::Closer for Decompressor<R> {
    fn Close(&mut self) -> error {
        Decompressor::Close(self)
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

// ─── token (token.go:7) ────────────────────────────────────────────────

// 2 bits:   type   0 = literal  1=EOF  2=Match   3=Unused
// 8 bits:   xlength = length - MIN_MATCH_LENGTH
// 22 bits   xoffset = offset - MIN_OFFSET_SIZE, or literal
const lengthShift: u32 = 22;
const offsetMask: u32 = (1 << lengthShift) - 1;
#[allow(dead_code)]
const typeMask: u32 = 3 << 30;
const literalType: u32 = 0 << 30;
const matchType: u32 = 1 << 30;

// The length code for length X (MIN_MATCH_LENGTH <= X <= MAX_MATCH_LENGTH)
// is lengthCodes[length - MIN_MATCH_LENGTH].
static lengthCodes: [u32; 256] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14,
    14, 15, 15, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 18, 18, 18,
    18, 18, 18, 18, 18, 19, 19, 19, 19, 19, 19, 19, 19, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20, 20,
    20, 20, 20, 20, 20, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 21, 22, 22, 22,
    22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 22, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23, 23,
    23, 23, 23, 23, 23, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25,
    25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 25, 26, 26, 26,
    26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26, 26,
    26, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
    27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 27, 28,
];

static offsetCodes: [u32; 256] = [
    0, 1, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
    12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
    14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
    15, 15, 15, 15, 15, 15, 15, 15,
];

/// `flate.token` — a packed `uint32` encoding a literal or a
/// length+offset match.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) struct token(pub u32);

/// Convert a literal into a literal token.
pub(crate) fn literalToken(literal: u32) -> token {
    token(literalType + literal)
}

/// Convert a < xlength, xoffset > pair into a match token.
pub(crate) fn matchToken(xlength: u32, xoffset: u32) -> token {
    token(matchType + (xlength << lengthShift) + xoffset)
}

impl token {
    /// Returns the literal of a literal token.
    pub(crate) fn literal(self) -> u32 {
        self.0.wrapping_sub(literalType)
    }

    /// Returns the extra offset of a match token.
    pub(crate) fn offset(self) -> u32 {
        self.0 & offsetMask
    }

    /// Returns the length of a match token.
    pub(crate) fn length(self) -> u32 {
        self.0.wrapping_sub(matchType) >> lengthShift
    }
}

/// `lengthCode(len)` — length code for `len`.
fn lengthCode(len: u32) -> u32 {
    lengthCodes[len as usize]
}

/// `offsetCode(off)` — offset code corresponding to a specific offset.
fn offsetCode(off: u32) -> u32 {
    if off < (offsetCodes.len() as u32) {
        return offsetCodes[off as usize];
    }
    if (off >> 7) < (offsetCodes.len() as u32) {
        return offsetCodes[(off >> 7) as usize] + 14;
    }
    offsetCodes[(off >> 14) as usize] + 28
}

// ─── huffmanEncoder (huffman_code.go) ──────────────────────────────────

const math_MaxUint16: u16 = 0xFFFF;
const math_MaxInt32: i32 = 0x7FFF_FFFF;

/// `flate.hcode` — a Huffman code with a bit code and bit length.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct hcode {
    pub(crate) code: u16,
    pub(crate) len: u16,
}

impl hcode {
    /// `(h *hcode).set(code, length)` — set code and length.
    fn set(&mut self, code: u16, length: u16) {
        self.len = length;
        self.code = code;
    }
}

/// `flate.literalNode` — a literal value and its frequency.
#[derive(Clone, Copy, Debug)]
struct literalNode {
    literal: u16,
    freq: i32,
}

/// `flate.levelInfo` — state of the constructed tree for a given depth.
#[derive(Clone, Copy, Default)]
struct levelInfo {
    // Our level. for better printing.
    level: i32,
    // The frequency of the last node at this level.
    lastFreq: i32,
    // The frequency of the next character to add to this level.
    nextCharFreq: i32,
    // The frequency of the next pair (from level below) to add to this
    // level. Only valid if the "needed" value of the next lower level is 0.
    nextPairFreq: i32,
    // The number of chains remaining to generate for this level before
    // moving up to the next level.
    needed: i32,
}

/// `flate.huffmanEncoder` — a bit-length-limited Huffman code generator.
pub(crate) struct huffmanEncoder {
    // Internal scratch buffers — module-private, stay `Vec`.
    pub(crate) codes: Vec<hcode>,
    freqcache: Vec<literalNode>,
    bitCount: [i32; 17],
}

fn maxNode() -> literalNode {
    literalNode {
        literal: math_MaxUint16,
        freq: math_MaxInt32,
    }
}

/// `newHuffmanEncoder(size)`.
pub(crate) fn newHuffmanEncoder(size: int) -> huffmanEncoder {
    let mut codes: Vec<hcode> = Vec::with_capacity(size as usize);
    codes.resize(size as usize, hcode::default());
    huffmanEncoder {
        codes,
        freqcache: Vec::new(),
        bitCount: [0i32; 17],
    }
}

// `reverseBits(number, bitLength)` (huffman_code.go:343).
fn reverseBits(number: u16, bitLength: byte) -> u16 {
    bits::Reverse16(number << (16 - (bitLength as u32)))
}

/// Generates a HuffmanCode corresponding to the fixed literal table.
fn generateFixedLiteralEncoding() -> huffmanEncoder {
    let mut h = newHuffmanEncoder(maxNumLit);
    let mut ch: u16 = 0;
    while ch < (maxNumLit as u16) {
        let bits_: u16;
        let size: u16;
        if ch < 144 {
            // size 8, 000110000 .. 10111111
            bits_ = ch + 48;
            size = 8;
        } else if ch < 256 {
            // size 9, 110010000 .. 111111111
            bits_ = ch + 400 - 144;
            size = 9;
        } else if ch < 280 {
            // size 7, 0000000 .. 0010111
            bits_ = ch - 256;
            size = 7;
        } else {
            // size 8, 11000000 .. 11000111
            bits_ = ch + 192 - 280;
            size = 8;
        }
        h.codes[ch as usize] = hcode {
            code: reverseBits(bits_, size as byte),
            len: size,
        };
        ch += 1;
    }
    h
}

fn generateFixedOffsetEncoding() -> huffmanEncoder {
    let mut h = newHuffmanEncoder(30);
    let n = h.codes.len();
    for ch in 0..n {
        h.codes[ch] = hcode {
            code: reverseBits(ch as u16, 5),
            len: 5,
        };
    }
    h
}

impl huffmanEncoder {
    /// `(h *huffmanEncoder).bitLength(freq)`.
    fn bitLength(&self, freq: &[i32]) -> int {
        let mut total: int = 0;
        for (i, &f) in freq.iter().enumerate() {
            if f != 0 {
                total += (f as int) * (self.codes[i].len as int);
            }
        }
        total
    }

    // `(h *huffmanEncoder).bitCounts(list, maxBits)` (huffman_code.go:132).
    //
    // Computes the number of literals assigned to each bit size. Only
    // called when `list.len() >= 3`. `list` must have a spare slot at
    // index `len` (the caller passes a sub-slice one short of capacity);
    // here `list` is the live working slice and we append `maxNode()`.
    fn bitCounts(&mut self, list: &mut Vec<literalNode>, mut maxBits: i32) -> &[i32] {
        if maxBits >= maxBitsLimit {
            panic!("flate: maxBits too large");
        }
        let n: i32 = list.len() as i32;
        // list = list[0:n+1]; list[n] = maxNode()
        list.push(maxNode());

        // The tree can't have greater depth than n - 1.
        if maxBits > n - 1 {
            maxBits = n - 1;
        }

        // Create information about each of the levels.
        let mut levels = [levelInfo::default(); maxBitsLimit as usize];
        // leafCounts[i][j] is the number of literals at the left of the
        // level j ancestor.
        let mut leafCounts = [[0i32; maxBitsLimit as usize]; maxBitsLimit as usize];

        {
            let mut level: i32 = 1;
            while level <= maxBits {
                levels[level as usize] = levelInfo {
                    level,
                    lastFreq: list[1].freq,
                    nextCharFreq: list[2].freq,
                    nextPairFreq: list[0].freq + list[1].freq,
                    needed: 0,
                };
                leafCounts[level as usize][level as usize] = 2;
                if level == 1 {
                    levels[level as usize].nextPairFreq = math_MaxInt32;
                }
                level += 1;
            }
        }

        // We need a total of 2*n - 2 items at top level and have
        // already generated 2.
        levels[maxBits as usize].needed = 2 * n - 4;

        let mut level: i32 = maxBits;
        loop {
            let nextPairFreq = levels[level as usize].nextPairFreq;
            let nextCharFreq = levels[level as usize].nextCharFreq;
            if nextPairFreq == math_MaxInt32 && nextCharFreq == math_MaxInt32 {
                // We've run out of both leaves and pairs.
                levels[level as usize].needed = 0;
                levels[(level + 1) as usize].nextPairFreq = math_MaxInt32;
                level += 1;
                continue;
            }

            let prevFreq = levels[level as usize].lastFreq;
            if nextCharFreq < nextPairFreq {
                // The next item on this row is a leaf node.
                let nn = leafCounts[level as usize][level as usize] + 1;
                levels[level as usize].lastFreq = nextCharFreq;
                // Lower leafCounts are the same as the previous node.
                leafCounts[level as usize][level as usize] = nn;
                levels[level as usize].nextCharFreq = list[nn as usize].freq;
            } else {
                // The next item on this row is a pair from the prev row.
                levels[level as usize].lastFreq = nextPairFreq;
                // copy(leafCounts[level][:level], leafCounts[level-1][:level])
                for k in 0..(level as usize) {
                    leafCounts[level as usize][k] = leafCounts[(level - 1) as usize][k];
                }
                let lvl = levels[level as usize].level;
                levels[(lvl - 1) as usize].needed = 2;
            }

            levels[level as usize].needed -= 1;
            if levels[level as usize].needed == 0 {
                // We've done everything we need to do for this level.
                if levels[level as usize].level == maxBits {
                    // All done!
                    break;
                }
                let lvl = levels[level as usize].level;
                let lastFreq = levels[level as usize].lastFreq;
                levels[(lvl + 1) as usize].nextPairFreq = prevFreq + lastFreq;
                level += 1;
            } else {
                // If we stole from below, move down temporarily to
                // replenish it.
                while levels[(level - 1) as usize].needed > 0 {
                    level -= 1;
                }
            }
        }

        // Sanity check.
        if leafCounts[maxBits as usize][maxBits as usize] != n {
            panic!("leafCounts[maxBits][maxBits] != n");
        }

        let mut bits_: usize = 1;
        {
            let mut level: i32 = maxBits;
            while level > 0 {
                // counts[level] - counts[level-1]
                self.bitCount[bits_] = leafCounts[maxBits as usize][level as usize]
                    - leafCounts[maxBits as usize][(level - 1) as usize];
                bits_ += 1;
                level -= 1;
            }
        }
        &self.bitCount[..(maxBits as usize) + 1]
    }

    // `(h *huffmanEncoder).assignEncodingAndSize(bitCount, list)`
    // (huffman_code.go:246). Assigns each leaf a bit count and an
    // encoding per RFC 1951 3.2.2.
    fn assignEncodingAndSize(&mut self, bitCount: &[i32], list: &mut [literalNode]) {
        let mut code: u16 = 0;
        let mut list_len: usize = list.len();
        for (n, &bits_) in bitCount.iter().enumerate() {
            code <<= 1;
            if n == 0 || bits_ == 0 {
                continue;
            }
            // The literals list[len-bits .. len] are encoded using "bits"
            // bits, and get the values code, code+1, ... in literal order.
            let lo = list_len - (bits_ as usize);
            let chunk = &mut list[lo..list_len];

            byLiteral_sort(chunk);
            for node in chunk.iter() {
                self.codes[node.literal as usize] = hcode {
                    code: reverseBits(code, n as byte),
                    len: n as u16,
                };
                code += 1;
            }
            list_len = lo;
        }
    }

    /// `(h *huffmanEncoder).generate(freq, maxBits)` (huffman_code.go:272).
    ///
    /// Updates this Huffman code to be the minimum code for the
    /// specified frequency count.
    pub(crate) fn generate(&mut self, freq: &[i32], maxBits: i32) {
        if self.freqcache.is_empty() {
            // Reusable buffer with the longest possible frequency table.
            self.freqcache = Vec::with_capacity((maxNumLit + 1) as usize);
            self.freqcache.resize(
                (maxNumLit + 1) as usize,
                literalNode {
                    literal: 0,
                    freq: 0,
                },
            );
        }
        // list = h.freqcache[:len(freq)+1]
        let mut count: usize = 0;
        // Set list to the set of all non-zero literals and their freqs.
        for (i, &f) in freq.iter().enumerate() {
            if f != 0 {
                self.freqcache[count] = literalNode {
                    literal: i as u16,
                    freq: f,
                };
                count += 1;
            } else {
                self.codes[i].len = 0;
            }
        }

        // list = list[:count]
        let mut list: Vec<literalNode> = self.freqcache[..count].to_vec();
        if count <= 2 {
            // Two or fewer literals — everything has bit length 1.
            for (i, node) in list.iter().enumerate() {
                self.codes[node.literal as usize].set(i as u16, 1);
            }
            return;
        }
        byFreq_sort(&mut list);

        // Number of literals for each bit count, then the assignment.
        // bitCounts appends maxNode() to `list`; assignEncodingAndSize
        // operates on the original count, so slice it back.
        let bc = self.bitCounts(&mut list, maxBits).to_vec();
        list.truncate(count);
        self.assignEncodingAndSize(&bc, &mut list);
    }
}

// `byLiteral.sort` — sort.Sort over byLiteral.Less (literal ascending).
fn byLiteral_sort(a: &mut [literalNode]) {
    a.sort_by(|x, y| x.literal.cmp(&y.literal));
}

// `byFreq.sort` — sort.Sort over byFreq.Less (freq asc, literal tiebreak).
fn byFreq_sort(a: &mut [literalNode]) {
    a.sort_by(|x, y| {
        if x.freq == y.freq {
            x.literal.cmp(&y.literal)
        } else {
            x.freq.cmp(&y.freq)
        }
    });
}

// ─── fixed encoders (huffman_code.go:103 / huffman_bit_writer.go:600) ──
//
// Go builds `fixedLiteralEncoding`, `fixedOffsetEncoding` and
// `huffOffset` in package `init()`. Goish has no package init under
// `no_std`, so they are built once behind a `SpinLock` and cloned in.

fn clone_encoder(h: &huffmanEncoder) -> huffmanEncoder {
    huffmanEncoder {
        codes: h.codes.clone(),
        freqcache: Vec::new(),
        bitCount: [0i32; 17],
    }
}

fn fixedLiteralEncoding() -> huffmanEncoder {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<Vec<hcode>>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(generateFixedLiteralEncoding().codes);
    }
    huffmanEncoder {
        codes: g.as_ref().unwrap().clone(),
        freqcache: Vec::new(),
        bitCount: [0i32; 17],
    }
}

fn fixedOffsetEncoding() -> huffmanEncoder {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<Vec<hcode>>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(generateFixedOffsetEncoding().codes);
    }
    huffmanEncoder {
        codes: g.as_ref().unwrap().clone(),
        freqcache: Vec::new(),
        bitCount: [0i32; 17],
    }
}

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
    huffmanEncoder {
        codes: g.as_ref().unwrap().clone(),
        freqcache: Vec::new(),
        bitCount: [0i32; 17],
    }
}

// ─── huffmanBitWriter constants (huffman_bit_writer.go:11) ─────────────

// The largest offset code.
const offsetCodeCount: int = 30;

// The first length code.
const lengthCodesStart: int = 257;

// The number of codegen codes.
const codegenCodeCount: int = 19;
const badCode: u8 = 255;

const maxBitsLimit: i32 = 16;

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
        let v = slice_bytes(&data);
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
    let d = slice_bytes(&dict);
    zw.d.fillWindow(&d);
    zw.dict.extend_from_slice(&d); // duplicate dictionary for Reset.
    (zw, nil)
}
