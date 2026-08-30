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
use crate::types::{byte, int};

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

use inflate::maxMatchOffset;

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

use token_go::{literalToken, matchToken, token};

// ─── huffman_code.go lives in its own file ───────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. huffman_code.go's half has moved to
// `huffman_code.rs` and is anchored. `huffOffset` below stays here: it
// is huffman_bit_writer.go:600, not huffman_code.go.

mod huffman_code;

use huffman_code::math_MaxInt32;

// ─── huffman_bit_writer.go lives in its own file ─────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. huffman_bit_writer.go's half has moved to
// `huffman_bit_writer.rs`.

mod huffman_bit_writer;

use huffman_bit_writer::{huffmanBitWriter, maxStoreBlockSize, newHuffmanBitWriter};

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
