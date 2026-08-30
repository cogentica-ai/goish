// go: file compress/flate/dict_decoder.go decls: dictDecoder.init, dictDecoder.histSize, dictDecoder.availRead, dictDecoder.availWrite, dictDecoder.writeSlice, dictDecoder.writeMark, dictDecoder.writeByte, dictDecoder.writeCopy, dictDecoder.tryWriteCopy, dictDecoder.readFlush
//
// The `decls:` manifest above lists dict_decoder.go's methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the `dictDecoder` type there would report it as a dropped port. It is
// not dropped — it carries its own `// go: sdk` anchor below.
//
// compress/flate/dict_decoder.go — the LZ77 sliding-window history
// buffer the decompressor writes into.
//
// The window is a single flat buffer with a read and a write cursor,
// not a ring: `readFlush` drains it and, when the write cursor reaches
// the end, resets both to zero and records that the history is now
// full. That is what lets `writeCopy` treat a back-reference as a
// plain forward copy inside one buffer, and it is why the "copy" it
// does is deliberately *not* `copy_from_slice`: for `dist < length`
// the source and destination overlap and the forward, byte-at-a-time
// propagation is the run-length expansion DEFLATE depends on. Go gets
// this from `copy`'s forward semantics on overlapping slices of the
// same array; goish spells it out in `copy_within`.
//
// Deviations from Go:
//
//   * `readFlush` returns an owned `slice<byte>`. Go returns
//     `dd.hist[dd.rdPos:dd.wrPos]`, aliasing the window, and the
//     caller is expected to consume it before the next write; a goish
//     `slice<byte>` owns its buffer and cannot alias `hist` across the
//     mutation that follows.
//   * `writeSlice` returns `&mut [byte]` rather than `slice<byte>`,
//     for the same reason inverted: its entire purpose is to be a
//     writable view *into* the window. It is unexported, so no goish
//     API surface sees the borrow.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use crate::convert::int as toint;
use crate::goslice::slice;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

// go: sdk 1.25.5 compress/flate/dict_decoder.go:27-37 dictDecoder
/// `flate.dictDecoder` — the LZ77 sliding-window history buffer.
///
/// Invariant: `0 <= rdPos <= wrPos <= len(hist)`.
pub(super) struct dictDecoder {
    // Go: hist []byte — sliding window history. An internal scratch
    // buffer, so it stays a `Vec` (AGENTS.md §3 covers API surface).
    hist: Vec<byte>,
    // Go: wrPos int — current output position in buffer.
    wrPos: int,
    // Go: rdPos int — have emitted hist[:rdPos] already.
    rdPos: int,
    // Go: full bool — has a full window length been written yet?
    full: bool,
}

impl dictDecoder {
    // go: none — goish idiom: Go's zero `dictDecoder` is usable and
    //     `init` fills it; goish needs a constructor because `hist` is
    //     private to this module.
    pub(super) fn new() -> dictDecoder {
        return dictDecoder {
            hist: Vec::new(),
            wrPos: 0,
            rdPos: 0,
            full: false,
        };
    }

    // go: sdk 1.25.5 compress/flate/dict_decoder.go:39-57 dictDecoder.init
    /// `(*dictDecoder).init(size, dict)` — initialize the history
    /// buffer to `size` bytes, pre-seeded with the tail of `dict`.
    pub(super) fn init(&mut self, size: int, dict: &[byte]) {
        // Go: *dd = dictDecoder{hist: dd.hist}
        self.wrPos = 0;
        self.rdPos = 0;
        self.full = false;

        // Go: if cap(dd.hist) < size { dd.hist = make([]byte, size) }
        //     dd.hist = dd.hist[:size]
        if toint(self.hist.capacity()) < size {
            self.hist = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        }
        self.hist.resize(usize::try_from(size).unwrap_or(0), 0);

        // Go: if len(dict) > len(dd.hist) { dict = dict[len(dict)-len(dd.hist):] }
        let mut d: &[byte] = dict;
        if d.len() > self.hist.len() {
            d = &d[d.len() - self.hist.len()..];
        }
        // Go: dd.wrPos = copy(dd.hist, dict)
        let n = core::cmp::min(d.len(), self.hist.len());
        self.hist[..n].copy_from_slice(&d[..n]);
        self.wrPos = toint(n);
        // Go: if dd.wrPos == len(dd.hist) { dd.wrPos = 0; dd.full = true }
        if self.wrPos == toint(self.hist.len()) {
            self.wrPos = 0;
            self.full = true;
        }
        // Go: dd.rdPos = dd.wrPos
        self.rdPos = self.wrPos;
    }

    // go: sdk 1.25.5 compress/flate/dict_decoder.go:59-65 dictDecoder.histSize
    /// `(*dictDecoder).histSize()` — the number of bytes of history
    /// available, which is the whole window once it has been filled.
    pub(super) fn histSize(&self) -> int {
        // Go: if dd.full { return len(dd.hist) }; return dd.wrPos
        if self.full {
            return toint(self.hist.len());
        }
        return self.wrPos;
    }

    // go: sdk 1.25.5 compress/flate/dict_decoder.go:67-70 dictDecoder.availRead
    /// `(*dictDecoder).availRead()` — bytes that can be flushed.
    pub(super) fn availRead(&self) -> int {
        // Go: return dd.wrPos - dd.rdPos
        return self.wrPos - self.rdPos;
    }

    // go: sdk 1.25.5 compress/flate/dict_decoder.go:72-77 dictDecoder.availWrite
    /// `(*dictDecoder).availWrite()` — bytes that can still be written
    /// before the window must be flushed.
    pub(super) fn availWrite(&self) -> int {
        // Go: return len(dd.hist) - dd.wrPos
        return toint(self.hist.len()) - self.wrPos;
    }

    // go: sdk 1.25.5 compress/flate/dict_decoder.go:79-81 dictDecoder.writeSlice
    /// `(*dictDecoder).writeSlice()` — a writable view of the buffer
    /// from the write cursor on. The invariant `len(s) <= availWrite()`
    /// is kept by construction.
    pub(super) fn writeSlice(&mut self) -> &mut [byte] {
        // Go: return dd.hist[dd.wrPos:]
        let lo = usize::try_from(self.wrPos).unwrap_or(0);
        return &mut self.hist[lo..];
    }

    // go: sdk 1.25.5 compress/flate/dict_decoder.go:86-88 dictDecoder.writeMark
    /// `(*dictDecoder).writeMark(cnt)` — advance the write cursor by
    /// `cnt`. The caller must keep `0 <= cnt <= availWrite()`.
    pub(super) fn writeMark(&mut self, cnt: int) {
        // Go: dd.wrPos += cnt
        self.wrPos += cnt;
    }

    // go: sdk 1.25.5 compress/flate/dict_decoder.go:93-96 dictDecoder.writeByte
    /// `(*dictDecoder).writeByte(c)` — write a single byte. The caller
    /// must keep `0 < availWrite()`.
    pub(super) fn writeByte(&mut self, c: byte) {
        // Go: dd.hist[dd.wrPos] = c; dd.wrPos++
        self.hist[usize::try_from(self.wrPos).unwrap_or(0)] = c;
        self.wrPos += 1;
    }

    // go: sdk 1.25.5 compress/flate/dict_decoder.go:103-151 dictDecoder.writeCopy
    /// `(*dictDecoder).writeCopy(dist, length)` — copy a string at
    /// `(dist, length)` to the output, returning the number of bytes
    /// copied. That may be less than `length` if the window filled.
    pub(super) fn writeCopy(&mut self, dist: int, length: int) -> int {
        // Go: dstBase := dd.wrPos; dstPos := dstBase; srcPos := dstPos - dist
        let dstBase: int = self.wrPos;
        let mut dstPos: int = dstBase;
        let mut srcPos: int = dstPos - dist;
        // Go: endPos := dstPos + length; if endPos > len(dd.hist) { endPos = len(dd.hist) }
        let mut endPos: int = dstPos + length;
        if endPos > toint(self.hist.len()) {
            endPos = toint(self.hist.len());
        }

        // Go: copy the non-overlapping section after the destination,
        // where the source wraps back around the end of the window.
        if srcPos < 0 {
            srcPos += toint(self.hist.len());
            let hlen = self.hist.len();
            let n = copy_within(
                &mut self.hist,
                usize::try_from(dstPos).unwrap_or(0),
                usize::try_from(endPos).unwrap_or(0),
                usize::try_from(srcPos).unwrap_or(0),
                hlen,
            );
            dstPos += n;
            srcPos = 0;
        }

        // Go: copy the possibly overlapping section before the
        // destination. Each round can only advance by `dist`, so a
        // short distance expands run-length style.
        while dstPos < endPos {
            let n = copy_within(
                &mut self.hist,
                usize::try_from(dstPos).unwrap_or(0),
                usize::try_from(endPos).unwrap_or(0),
                usize::try_from(srcPos).unwrap_or(0),
                usize::try_from(dstPos).unwrap_or(0),
            );
            dstPos += n;
        }

        // Go: dd.wrPos = dstPos; return dstPos - dstBase
        self.wrPos = dstPos;
        return dstPos - dstBase;
    }

    // go: sdk 1.25.5 compress/flate/dict_decoder.go:153-172 dictDecoder.tryWriteCopy
    /// `(*dictDecoder).tryWriteCopy(dist, length)` — the fast path for
    /// a copy that neither wraps nor fills the window. Returns 0 if
    /// either condition fails, so the caller falls back to
    /// [`dictDecoder::writeCopy`].
    pub(super) fn tryWriteCopy(&mut self, dist: int, length: int) -> int {
        // Go: dstPos := dd.wrPos; endPos := dstPos + length
        let mut dstPos: int = self.wrPos;
        let endPos: int = dstPos + length;
        // Go: if dstPos < dist || endPos > len(dd.hist) { return 0 }
        if dstPos < dist || endPos > toint(self.hist.len()) {
            return 0;
        }
        // Go: dstBase := dstPos; srcPos := dstPos - dist
        let dstBase: int = dstPos;
        let srcPos: int = dstPos - dist;

        // Go: for dstPos < endPos { dstPos += copy(...) }
        while dstPos < endPos {
            let n = copy_within(
                &mut self.hist,
                usize::try_from(dstPos).unwrap_or(0),
                usize::try_from(endPos).unwrap_or(0),
                usize::try_from(srcPos).unwrap_or(0),
                usize::try_from(dstPos).unwrap_or(0),
            );
            dstPos += n;
        }

        // Go: dd.wrPos = dstPos; return dstPos - dstBase
        self.wrPos = dstPos;
        return dstPos - dstBase;
    }

    // go: sdk 1.25.5 compress/flate/dict_decoder.go:174-182 dictDecoder.readFlush
    /// `(*dictDecoder).readFlush()` — the bytes written since the last
    /// flush. When the window is exhausted both cursors reset and the
    /// history is marked full.
    ///
    /// Go returns `dd.hist[dd.rdPos:dd.wrPos]`, aliasing the window;
    /// goish returns an owned copy, since a `slice<byte>` cannot alias
    /// `hist` across the mutation that follows.
    pub(super) fn readFlush(&mut self) -> slice<byte> {
        // Go: toRead := dd.hist[dd.rdPos:dd.wrPos]
        let lo = usize::try_from(self.rdPos).unwrap_or(0);
        let hi = usize::try_from(self.wrPos).unwrap_or(0);
        let mut v: Vec<byte> = Vec::with_capacity(hi - lo);
        v.extend_from_slice(&self.hist[lo..hi]);
        // Go: dd.rdPos = dd.wrPos
        self.rdPos = self.wrPos;
        // Go: if dd.wrPos == len(dd.hist) { dd.wrPos = 0; dd.rdPos = 0; dd.full = true }
        if self.wrPos == toint(self.hist.len()) {
            self.wrPos = 0;
            self.rdPos = 0;
            self.full = true;
        }
        return slice::__from_vec(v);
    }
}

// go: none — goish idiom: Go's builtin `copy(dst, src)` over two
//     overlapping ranges of the same array. `copy` is forward and
//     clamps to the shorter length, and the forward direction is
//     load-bearing here: with `dst > src` it propagates bytes it has
//     just written, which is how DEFLATE expands a run. Rust's
//     `copy_from_slice` cannot take two borrows of one buffer, and
//     `slice::copy_within` would be the wrong shape for the clamping.
fn copy_within(buf: &mut [byte], dst: usize, dst_end: usize, src: usize, src_end: usize) -> int {
    let n = core::cmp::min(dst_end - dst, src_end - src);
    let mut k: usize = 0;
    while k < n {
        buf[dst + k] = buf[src + k];
        k += 1;
    }
    return toint(n);
}
