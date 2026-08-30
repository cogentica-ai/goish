// go: file compress/flate/deflatefast.go decls: load32, load64, hash, newDeflateFast, deflateFast.encode, emitLiteral, deflateFast.matchLen, deflateFast.reset, deflateFast.shiftOffsets
//
// The `decls:` manifest above lists deflatefast.go's funcs and methods
// only. GOISH017 matches a manifest entry against Rust `fn` items, so
// naming `tableEntry`, `deflateFast` or the eight constants there would
// report them as dropped ports. They are not dropped — each carries its
// own `// go: sdk` anchor below.
//
// compress/flate/deflatefast.go — the BestSpeed match finder.
//
// One hash table, one candidate per slot, no chaining: `encode` hashes
// four bytes, looks up the single previous position with that hash, and
// takes the match if it is in range and actually matches. That is the
// whole of level 1, and it is why the table is `[tableSize]tableEntry`
// rather than a chain of buckets.
//
// The offsets in that table are absolute across `Reset` calls, which is
// what `shiftOffsets` and `bufferReset` are for: rather than clearing
// 16384 entries on every block, the encoder keeps counting and only
// rebases when the offset would overflow int32. `reset` therefore does
// *not* zero the table — it shifts it — and an entry older than the
// current window is rejected by the `> maxMatchOffset` distance check
// instead of by having been cleared.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::{int as toint, int32 as toint32, uint32 as touint32, uint64 as touint64};
use crate::goslice::slice;
use crate::types::{byte, int};

use super::deflate::{baseMatchLength, baseMatchOffset, maxMatchLength};
use super::huffman_bit_writer::maxStoreBlockSize;
use super::huffman_code::math_MaxInt32;
use super::inflate::maxMatchOffset;
use super::token_go::{literalToken, matchToken, token};

// ─── deflateFast constants (deflatefast.go:12) ─────────────────────────

pub(super) const tableBits: int = 14;
pub(super) const tableSize: int = 1 << tableBits;
pub(super) const tableMask: u32 = (tableSize as u32) - 1; // goishlint:ignore GOISH005 - a const initialiser must be a constant expression.
pub(super) const tableShift: u32 = 32 - (tableBits as u32); // goishlint:ignore GOISH005 - a const initialiser must be a constant expression.

// Reset the buffer offset when reaching this.
pub(super) const bufferReset: i32 = math_MaxInt32 - (maxStoreBlockSize as i32) * 2; // goishlint:ignore GOISH005 - a const initialiser must be a constant expression.

pub(super) const inputMargin: int = 16 - 1;
pub(super) const minNonLiteralBlockSize: int = 1 + 1 + inputMargin;

// go: sdk 1.25.5 compress/flate/deflatefast.go:26-29 load32
pub(super) fn load32(b: &[byte], i: i32) -> u32 {
    let i = i as usize;
    return touint32(b[i])
        | (touint32(b[i + 1]) << 8)
        | (touint32(b[i + 2]) << 16)
        | (touint32(b[i + 3]) << 24);
}

// go: sdk 1.25.5 compress/flate/deflatefast.go:31-35 load64
pub(super) fn load64(b: &[byte], i: i32) -> u64 {
    let i = i as usize;
    return touint64(b[i])
        | (touint64(b[i + 1]) << 8)
        | (touint64(b[i + 2]) << 16)
        | (touint64(b[i + 3]) << 24)
        | (touint64(b[i + 4]) << 32)
        | (touint64(b[i + 5]) << 40)
        | (touint64(b[i + 6]) << 48)
        | (touint64(b[i + 7]) << 56);
}

// go: sdk 1.25.5 compress/flate/deflatefast.go:37-39 hash
pub(super) fn hash(u: u32) -> u32 {
    return u.wrapping_mul(0x1e35a7bd) >> tableShift;
}

/// `flate.tableEntry` — a hash-table slot.
#[derive(Clone, Copy, Default)]
struct tableEntry {
    val: u32,
    offset: i32,
}

/// `flate.deflateFast` — the BestSpeed match table + previous block.
pub(super) struct deflateFast {
    table: Vec<tableEntry>, // tableSize entries; internal scratch.
    prev: Vec<byte>,        // previous block, empty if unknown.
    cur: i32,               // current match offset.
}

// go: sdk 1.25.5 compress/flate/deflatefast.go:63-65 newDeflateFast
/// `newDeflateFast()` (deflatefast.go:63).
pub(super) fn newDeflateFast() -> deflateFast {
    return deflateFast {
        table: alloc::vec![tableEntry::default(); tableSize as usize],
        prev: Vec::with_capacity(maxStoreBlockSize as usize),
        cur: toint32(maxStoreBlockSize),
    };
}

impl deflateFast {
    // go: sdk 1.25.5 compress/flate/deflatefast.go:69-199 deflateFast.encode
    /// `(e *deflateFast).encode(dst, src)` — encode a block from `src`,
    /// appending tokens to `dst`.
    ///
    /// Takes and returns `slice<token>` — Go's `[]token` — and unwraps
    /// to a `Vec` for the append-heavy inner loop, converting back at
    /// the return site (§3).
    pub(super) fn encode(&mut self, dst: slice<token>, src: &[byte]) -> slice<token> {
        let dst: Vec<token> = dst.__into_vec();
        return slice::__from_vec(self.encode_vec(dst, src));
    }

    // go: none — goish idiom: the body of `encode`, over the unwrapped
    //     `Vec`. Splitting it keeps the conversion at the boundary
    //     instead of in the middle of the match loop.
    // goishlint:ignore GOISH023 - Go's `for { … return … }`; the Rust
    //     `loop` below never breaks, so every exit is already an
    //     explicit `return`.
    fn encode_vec(&mut self, mut dst: Vec<token>, src: &[byte]) -> Vec<token> {
        // Ensure that e.cur doesn't wrap.
        if self.cur >= bufferReset {
            self.shiftOffsets();
        }

        // Fast path for very small inputs.
        if toint(src.len()) < minNonLiteralBlockSize {
            self.cur += toint32(maxStoreBlockSize);
            self.prev.clear();
            return emitLiteral(dst, src);
        }

        let sLimit: i32 = toint32(src.len()) - toint32(inputMargin);

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
                    if toint(nextEmit) < toint(src.len()) {
                        dst = emitLiteral(dst, &src[nextEmit as usize..]);
                    }
                    self.cur += toint32(src.len());
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
                if toint(offset) > maxMatchOffset || cv != candidate.val {
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
                    touint32(l + 4 - toint32(baseMatchLength)),
                    touint32(s - t - toint32(baseMatchOffset)),
                ));
                s += l;
                nextEmit = s;
                if s >= sLimit {
                    // goto emitRemainder
                    if toint(nextEmit) < toint(src.len()) {
                        dst = emitLiteral(dst, &src[nextEmit as usize..]);
                    }
                    self.cur += toint32(src.len());
                    let n = src.len();
                    self.prev.clear();
                    self.prev.extend_from_slice(&src[..n]);
                    return dst;
                }

                let x = load64(src, s - 1);
                let prevHash = hash(touint32(x));
                self.table[(prevHash & tableMask) as usize] = tableEntry {
                    offset: self.cur + s - 1,
                    val: touint32(x),
                };
                let x = x >> 8;
                let currHash = hash(touint32(x));
                candidate = self.table[(currHash & tableMask) as usize];
                self.table[(currHash & tableMask) as usize] = tableEntry {
                    offset: self.cur + s,
                    val: touint32(x),
                };

                let offset = s - (candidate.offset - self.cur);
                if toint(offset) > maxMatchOffset || touint32(x) != candidate.val {
                    cv = touint32(x >> 8);
                    nextHash = hash(cv);
                    s += 1;
                    continue 'outer;
                }
            }
        }
    }

    // go: sdk 1.25.5 compress/flate/deflatefast.go:211-266 deflateFast.matchLen
    /// `(e *deflateFast).matchLen(s, t, src)` (deflatefast.go:211) — match
    /// length between `src[s:]` and `src[t:]`; `t` may be negative to
    /// indicate a match starting in `e.prev`.
    pub(super) fn matchLen(&self, s: i32, t: i32, src: &[byte]) -> i32 {
        let mut s1 = toint(s) + maxMatchLength - 4;
        if s1 > toint(src.len()) {
            s1 = toint(src.len());
        }
        let s1 = s1 as usize;

        // Inside the current block.
        if t >= 0 {
            let a = &src[s as usize..s1];
            let b = &src[t as usize..t as usize + a.len()];
            for i in 0..a.len() {
                if a[i] != b[i] {
                    return toint32(i);
                }
            }
            return toint32(a.len());
        }

        // A match in the previous block.
        let tp = toint32(self.prev.len()) + t;
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
                return toint32(i);
            }
        }

        let n = toint32(b.len());
        if ((s + n) as usize) == s1 {
            return n;
        }

        // Continue looking for more matches in the current block.
        let a = &src[(s + n) as usize..s1];
        let b = &src[..a.len()];
        for i in 0..a.len() {
            if a[i] != b[i] {
                return toint32(i) + n;
            }
        }
        return toint32(a.len()) + n;
    }

    // go: sdk 1.25.5 compress/flate/deflatefast.go:270-280 deflateFast.reset
    /// `(e *deflateFast).reset()` (deflatefast.go:270).
    pub(super) fn reset(&mut self) {
        self.prev.clear();
        self.cur += toint32(maxMatchOffset);
        if self.cur >= bufferReset {
            self.shiftOffsets();
        }
    }

    // go: sdk 1.25.5 compress/flate/deflatefast.go:286-307 deflateFast.shiftOffsets
    /// `(e *deflateFast).shiftOffsets()` (deflatefast.go:286).
    pub(super) fn shiftOffsets(&mut self) {
        if self.prev.is_empty() {
            for e in self.table.iter_mut() {
                *e = tableEntry::default();
            }
            self.cur = toint32(maxMatchOffset) + 1;
            return;
        }
        for i in 0..self.table.len() {
            let mut v = self.table[i].offset - self.cur + toint32(maxMatchOffset) + 1;
            if v < 0 {
                v = 0;
            }
            self.table[i].offset = v;
        }
        self.cur = toint32(maxMatchOffset) + 1;
    }
}

// go: sdk 1.25.5 compress/flate/deflatefast.go:201-206 emitLiteral
/// `emitLiteral(dst, lit)` (deflatefast.go:201).
fn emitLiteral(mut dst: Vec<token>, lit: &[byte]) -> Vec<token> {
    for &v in lit {
        dst.push(literalToken(touint32(v)));
    }
    return dst;
}
