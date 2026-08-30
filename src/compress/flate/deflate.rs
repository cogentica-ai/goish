// go: file compress/flate/deflate.go decls: compressor.fillDeflate, compressor.writeBlock, compressor.fillWindow, compressor.findMatch, compressor.writeStoredBlock, hash4, bulkHash4, matchLen, compressor.encSpeed, compressor.initDeflate, compressor.deflate, compressor.fillStore, compressor.store, compressor.storeHuff, compressor.write, compressor.syncFlush, compressor.init, compressor.reset, compressor.close, NewWriter, NewWriterDict, dictWriter.Write, Writer.Write, Writer.Flush, Writer.Close, Writer.Reset
//
// goishlint:ignore GOISH021 maxMatchOffset, levels — `maxMatchOffset`
//     is declared in inflate.rs, which is where Go declares it too
//     (inflate.go:25); goishlint resolves the name against both files.
//     `levels` is the compression-level table, built here through the
//     `cl` const fn — goishlint sees the `const fn`, not the array.
//
// The `decls:` manifest above lists deflate.go's funcs and methods
// only. GOISH017 matches a manifest entry against Rust `fn` items, so
// naming the file's consts, types and vars there would report every
// one as a dropped port. They are not dropped — each carries its own
// `// go: sdk` anchor below.
//
// compress/flate/deflate.go — the compressor and the public `Writer`.
//
// Levels 2..9 share one match finder: a hash of four bytes into a
// chained table, walked back through `chainHead`/`hashPrev` for at most
// `maxChainLength` links. What the level actually selects is the four
// numbers in `levels` — how good a match has to be before the search
// stops (`goodLength`, `niceLength`), how many links to walk, and how
// far to skip when nothing matches (`fastSkipHashing`). Level 1 does
// not appear there at all; it goes to deflatefast.rs.
//
// The window is the other half. `fillWindow` slides the second half of
// the buffer down to the first and subtracts `windowSize` from every
// stored offset, which is why `hashOffset` exists and why an offset of
// zero means "empty" rather than "position zero".

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{int as toint, uint32 as touint32};
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int};

use super::deflatefast::{deflateFast, newDeflateFast};
use super::huffman_bit_writer::{huffmanBitWriter, maxStoreBlockSize, newHuffmanBitWriter};
use super::huffman_code::math_MaxInt32;
use super::token_go::{literalToken, matchToken, token};

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

pub(super) const baseMatchLength: int = 3; // smallest match length per the RFC
const minMatchLength: int = 4; // smallest match length the compressor emits
pub(super) const maxMatchLength: int = 258; // largest match length
pub(super) const baseMatchOffset: int = 1; // smallest match offset
                                           // maxMatchOffset is shared with the decompressor (defined above as 1<<15).

const maxFlateBlockTokens: int = 1 << 14;
const hashBits: int = 17; // after 17, performance degrades
const hashSize: int = 1 << hashBits;
const hashMask: u32 = (1 << hashBits) - 1;
const maxHashOffset: int = 1 << 24;

const skipNever: int = math_MaxInt32 as int; // goishlint:ignore GOISH005 - a const initialiser must be a constant expression.

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

// go: none — goish idiom: Go writes the `levels` table as a slice of
//     struct literals; a Rust `const` array needs a `const fn` to build
//     each row, since struct-literal field init is not shorter here.
const fn cl(level: int, good: int, lazy: int, nice: int, chain: int, fsh: int) -> compressionLevel {
    return compressionLevel {
        level,
        good,
        lazy,
        nice,
        chain,
        fastSkipHashing: fsh,
    };
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

// ─── hash helpers (deflate.go:291) ─────────────────────────────────────

const hashmul: u32 = 0x1e35a7bd;

// go: sdk 1.25.5 compress/flate/deflate.go:296-298 hash4
/// `hash4(b)` — hash of the first 4 bytes; caller ensures `len(b) >= 4`.
fn hash4(b: &[byte]) -> u32 {
    return ((touint32(b[3])
        | (touint32(b[2]) << 8)
        | (touint32(b[1]) << 16)
        | (touint32(b[0]) << 24))
        .wrapping_mul(hashmul))
        >> (32 - touint32(hashBits));
}

// go: sdk 1.25.5 compress/flate/deflate.go:302-313 bulkHash4
/// `bulkHash4(b, dst)` — bulk hashes using the same algorithm as `hash4`.
fn bulkHash4(b: &[byte], dst: &mut [u32]) {
    if toint(b.len()) < minMatchLength {
        return;
    }
    let mut hb =
        touint32(b[3]) | (touint32(b[2]) << 8) | (touint32(b[1]) << 16) | (touint32(b[0]) << 24);
    dst[0] = hb.wrapping_mul(hashmul) >> (32 - touint32(hashBits));
    let end = toint(b.len()) - minMatchLength + 1;
    let mut i: int = 1;
    while i < end {
        hb = (hb << 8) | touint32(b[(i + 3) as usize]);
        dst[i as usize] = hb.wrapping_mul(hashmul) >> (32 - touint32(hashBits));
        i += 1;
    }
}

// go: sdk 1.25.5 compress/flate/deflate.go:318-327 matchLen
/// `matchLen(a, b, max)` (deflate.go:318) — matching-byte count up to `max`.
fn matchLen(a: &[byte], b: &[byte], max: int) -> int {
    let a = &a[..max as usize];
    let b = &b[..a.len()];
    for i in 0..a.len() {
        if b[i] != a[i] {
            return toint(i);
        }
    }
    return max;
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

// go: none — goish idiom: Go's zero `compressor` is usable and `init`
//     fills it; goish needs a constructor because the window and hash
//     tables are owned buffers.
fn new_compressor<W: io::Writer>(w: W) -> compressor<W> {
    return compressor {
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
    };
}

impl<W: io::Writer> compressor<W> {
    // go: sdk 1.25.5 compress/flate/deflate.go:124-162 compressor.fillDeflate
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
                self.blockStart = toint(math_MaxInt32);
            }
            self.hashOffset += windowSize;
            if self.hashOffset > maxHashOffset {
                let delta = self.hashOffset - 1;
                self.hashOffset -= delta;
                self.chainHead -= delta;

                for i in 0..self.hashPrev.len() {
                    let v = toint(self.hashPrev[i]);
                    if v > delta {
                        self.hashPrev[i] = touint32(v - delta);
                    } else {
                        self.hashPrev[i] = 0;
                    }
                }
                for i in 0..self.hashHead.len() {
                    let v = toint(self.hashHead[i]);
                    if v > delta {
                        self.hashHead[i] = touint32(v - delta);
                    } else {
                        self.hashHead[i] = 0;
                    }
                }
            }
        }
        let n = copy_slice(&mut self.window[self.windowEnd as usize..], b);
        self.windowEnd += n;
        return n;
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:164-175 compressor.writeBlock
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
        return nil;
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:181-227 compressor.fillWindow
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
        if toint(b.len()) > windowSize {
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
                let di = toint(i) + index;
                let hh = (val & hashMask) as usize;
                self.hashPrev[(di & windowMask) as usize] = self.hashHead[hh];
                self.hashHead[hh] = touint32(di + self.hashOffset);
            }
            j += 1;
        }
        self.windowEnd = n;
        self.index = n;
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:231-281 compressor.findMatch
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
        let mut nice = toint(win.len()) - pos;
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
            i = toint(self.hashPrev[(i & windowMask) as usize]) - self.hashOffset;
            if i < minIndex || i < 0 {
                break;
            }
            tries -= 1;
        }
        return (length, offset, ok);
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:283-289 compressor.writeStoredBlock
    /// `(d *compressor).writeStoredBlock(buf)` (deflate.go:283).
    fn writeStoredBlock(&mut self, buf: &[byte]) -> error {
        self.w.writeStoredHeader(toint(buf.len()), false);
        if !self.w.err.IsNil() {
            return self.w.err.clone();
        }
        self.w.writeBytes(buf);
        return self.w.err.clone();
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:332-367 compressor.encSpeed
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
        self.tokens = self
            .bestSpeed
            .encode(slice::__from_vec(toks), &input)
            .__into_vec();

        // If we removed less than 1/16th, Huffman-compress the block.
        if toint(self.tokens.len()) > self.windowEnd - (self.windowEnd >> 4) {
            self.w.writeBlockHuff(false, &input);
        } else {
            self.w
                .writeBlockDynamic(&self.tokens.clone(), false, Some(&input));
        }
        self.err = self.w.err.clone();
        self.windowEnd = 0;
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:369-379 compressor.initDeflate
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

    // go: sdk 1.25.5 compress/flate/deflate.go:381-512 compressor.deflate
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
                        self.tokens.push(literalToken(touint32(lit)));
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
                self.chainHead = toint(self.hashHead[hh]);
                self.hashPrev[(self.index & windowMask) as usize] = touint32(self.chainHead);
                self.hashHead[hh] = touint32(self.index + self.hashOffset);
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
                        touint32(self.length - baseMatchLength),
                        touint32(self.offset - baseMatchOffset),
                    ));
                } else {
                    self.tokens.push(matchToken(
                        touint32(prevLength - baseMatchLength),
                        touint32(prevOffset - baseMatchOffset),
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
                            self.hashHead[hh] = touint32(index + self.hashOffset);
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
                if toint(self.tokens.len()) == maxFlateBlockTokens {
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
                    self.tokens.push(literalToken(touint32(lit)));
                    if toint(self.tokens.len()) == maxFlateBlockTokens {
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

    // go: sdk 1.25.5 compress/flate/deflate.go:514-518 compressor.fillStore
    /// `(d *compressor).fillStore(b)` (deflate.go:514).
    fn fillStore(&mut self, b: &[byte]) -> int {
        let n = copy_slice(&mut self.window[self.windowEnd as usize..], b);
        self.windowEnd += n;
        return n;
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:520-525 compressor.store
    /// `(d *compressor).store()` (deflate.go:520).
    fn store(&mut self) {
        if self.windowEnd > 0 && (self.windowEnd == maxStoreBlockSize || self.sync) {
            let buf = self.window[..self.windowEnd as usize].to_vec();
            self.err = self.writeStoredBlock(&buf);
            self.windowEnd = 0;
        }
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:530-537 compressor.storeHuff
    /// `(d *compressor).storeHuff()` (deflate.go:530) — HuffmanOnly step.
    fn storeHuff(&mut self) {
        if self.windowEnd < toint(self.window.len()) && !self.sync || self.windowEnd == 0 {
            return;
        }
        let input = self.window[..self.windowEnd as usize].to_vec();
        self.w.writeBlockHuff(false, &input);
        self.err = self.w.err.clone();
        self.windowEnd = 0;
    }

    // go: none — goish idiom: Go's `d.step` is a `func(*compressor)`
    //     field reassigned by `init`; goish enumerates the four steps,
    //     since a function-valued field would need the `dyn Fn` this
    //     project bans (§5 rule 3).
    fn run_step(&mut self) {
        match self.step {
            CStep::Store => self.store(),
            CStep::StoreHuff => self.storeHuff(),
            CStep::EncSpeed => self.encSpeed(),
            CStep::Deflate => self.deflate(),
        }
    }

    // go: none — goish idiom: the `d.fill` half of `run_step`; see there.
    fn run_fill(&mut self, b: &[byte]) -> int {
        return match self.fill {
            Fill::Store => self.fillStore(b),
            Fill::Deflate => self.fillDeflate(b),
        };
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:539-552 compressor.write
    /// `(d *compressor).write(b)` (deflate.go:539).
    fn write(&mut self, b: &[byte]) -> (int, error) {
        if !self.err.IsNil() {
            return (0, self.err.clone());
        }
        let n = toint(b.len());
        let mut b = b;
        while b.len() > 0 {
            self.run_step();
            let consumed = self.run_fill(b);
            b = &b[consumed as usize..];
            if !self.err.IsNil() {
                return (0, self.err.clone());
            }
        }
        return (n, nil);
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:554-567 compressor.syncFlush
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
        return self.err.clone();
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:569-600 compressor.init
    // goishlint:ignore GOISH020 — Go's `init(w io.Writer, level int)`
    //     takes the destination writer because a zero `compressor` has
    //     none; goish's `new_compressor` has already moved `w` in, so
    //     only `level` is left to pass.
    /// `(d *compressor).init(level)` — configure for `level`.
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
        return nil;
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:602-625 compressor.reset
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

    // go: sdk 1.25.5 compress/flate/deflate.go:627-648 compressor.close
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
        return nil;
    }
}

// `errWriterClosed` (deflate.go:695) — Go's package-level sentinel.
crate::var! {
    errWriterClosed: error = "flate: closed writer";
}

// go: none — goish idiom: Go's builtin `copy(dst, src)`, which copies
//     min(len(dst), len(src)) bytes and returns the count.
fn copy_slice(dst: &mut [byte], src: &[byte]) -> int {
    let n = core::cmp::min(dst.len(), src.len());
    dst[..n].copy_from_slice(&src[..n]);
    return toint(n);
}

// ─── dictWriter (deflate.go:687) ───────────────────────────────────────

/// `flate.dictWriter` — transparently forwards `Write` to `w`. Used by
/// `NewWriterDict` so `Writer.Reset` can detect a dictionary writer.
pub struct dictWriter<W: io::Writer> {
    w: W,
}

impl<W: io::Writer> io::Writer for dictWriter<W> {
    // go: sdk 1.25.5 compress/flate/deflate.go:691-693 dictWriter.Write
    fn Write(&mut self, b: slice<byte>) -> (int, error) {
        return self.w.Write(b);
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
    // go: sdk 1.25.5 compress/flate/deflate.go:706-708 Writer.Write
    /// `(w *Writer).Write(data)` (deflate.go:706) — writes `data`, which
    /// is eventually emitted to the underlying writer in compressed form.
    pub fn Write(&mut self, data: slice<byte>) -> (int, error) {
        let v: &[byte] = &data;
        return self.d.write(&v);
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:719-723 Writer.Flush
    /// `(w *Writer).Flush()` (deflate.go:719) — flush pending data to the
    /// underlying writer (Z_SYNC_FLUSH).
    pub fn Flush(&mut self) -> error {
        return self.d.syncFlush();
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:726-728 Writer.Close
    /// `(w *Writer).Close()` (deflate.go:726) — flush and close.
    pub fn Close(&mut self) -> error {
        return self.d.close();
    }

    // go: sdk 1.25.5 compress/flate/deflate.go:733-743 Writer.Reset
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

    // go: none — goish idiom: Go callers keep their own reference to
    //     the destination `io.Writer`; a goish `Writer` owns `W` by
    //     value, so it has to hand it back after `Close`.
    /// Consume the `Writer` and return the underlying writer.
    pub fn into_writer(self) -> W {
        return self.d.w.into_writer();
    }
}

impl<W: io::Writer> huffmanBitWriter<W> {
    // go: none — goish idiom: see `Writer::into_writer`.
    /// Consume the bit writer and yield the underlying `io::Writer`.
    pub(crate) fn into_writer(self) -> W {
        return self.writer;
    }
}

impl<W: io::Writer> dictWriter<W> {
    // go: none — goish idiom: see `Writer::into_writer`.
    /// Consume the `dictWriter` and yield the wrapped writer.
    pub fn into_writer(self) -> W {
        return self.w;
    }
}

impl<W: io::Writer> io::Writer for Writer<W> {
    // go: sdk 1.25.5 compress/flate/deflate.go:706-708 Writer.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return Writer::Write(self, p);
    }
}

impl<W: io::Writer> io::Closer for Writer<W> {
    // go: sdk 1.25.5 compress/flate/deflate.go:726-728 Writer.Close
    fn Close(&mut self) -> error {
        return Writer::Close(self);
    }
}

// go: sdk 1.25.5 compress/flate/deflate.go:662-668 NewWriter
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
    return (dw, nil);
}

// go: sdk 1.25.5 compress/flate/deflate.go:676-685 NewWriterDict
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
    return (zw, nil);
}
