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
//   * Go does `r.(Reader)` to detect a source that already implements
//     `io.ByteReader`, else wraps in `bufio.NewReader`. Goish
//     unconditionally wraps the source in `bufio::Reader<R>` (which
//     implements both `io::Reader` and `io::ByteReader` — Go's
//     `flate.Reader`). Slight extra buffering on already-buffered
//     sources; behavior identical. The lzw port does the same.
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
use crate::errors::{self, error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::math::bits;
use crate::types::{byte, int, uint};
use crate::errors::nil;

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
pub struct Decompressor<R: io::Reader> {
    // Input source. Go's `flate.Reader` = io.Reader + io.ByteReader;
    // `bufio::Reader<R>` provides exactly that.
    r: bufio::Reader<R>,
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

impl<R: io::Reader> Decompressor<R> {
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
        self.r = bufio::NewReader(r);
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
fn huff_sym_step<R: io::Reader>(
    r: &mut bufio::Reader<R>,
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

fn new_decompressor<R: io::Reader>(r: R, dict: &[byte]) -> Decompressor<R> {
    let mut f = Decompressor {
        r: bufio::NewReader(r),
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

/// `flate.NewReader(r)` (inflate.go:807) — a new ReadCloser reading the
/// uncompressed version of `r`. Returns `io.EOF` after the final block.
///
/// Returns the concrete `Decompressor<R>` (Go returns `io.ReadCloser`);
/// it implements `io::Reader` + `io::Closer` and carries `Reset`.
pub fn NewReader<R: io::Reader>(r: R) -> Decompressor<R> {
    new_decompressor(r, &[])
}

/// `flate.NewReaderDict(r, dict)` (inflate.go:826) — like [`NewReader`]
/// but initializes the reader with a preset dictionary `dict`.
pub fn NewReaderDict<R: io::Reader>(r: R, dict: slice<byte>) -> Decompressor<R> {
    let d = slice_bytes(&dict);
    new_decompressor(r, &d)
}

// ─── trait impls ───────────────────────────────────────────────────────

impl<R: io::Reader> io::Reader for Decompressor<R> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Decompressor::Read(self, p)
    }
}

impl<R: io::Reader> io::Closer for Decompressor<R> {
    fn Close(&mut self) -> error {
        Decompressor::Close(self)
    }
}
