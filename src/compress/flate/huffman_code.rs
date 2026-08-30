// go: file compress/flate/huffman_code.go decls: hcode.set, maxNode, newHuffmanEncoder, generateFixedLiteralEncoding, generateFixedOffsetEncoding, fixedLiteralEncoding, fixedOffsetEncoding, huffmanEncoder.bitLength, huffmanEncoder.bitCounts, huffmanEncoder.assignEncodingAndSize, huffmanEncoder.generate, byLiteral.sort, byLiteral.Len, byLiteral.Less, byLiteral.Swap, byFreq.sort, byFreq.Len, byFreq.Less, byFreq.Swap, reverseBits
//
// The `decls:` manifest above lists huffman_code.go's funcs and
// methods only. GOISH017 matches a manifest entry against Rust `fn`
// items, so naming `hcode`, `huffmanEncoder`, `literalNode`,
// `levelInfo`, `maxBitsLimit`, `byLiteral` or `byFreq` there would
// report all seven as dropped ports. `fixedLiteralEncoding` and
// `fixedOffsetEncoding` are Go *vars* that goish ports as functions,
// so they are listed — a Rust `fn` is what GOISH017 sees. They are not dropped — each carries its
// own `// go: sdk` anchor below.
//
// compress/flate/huffman_code.go — the bit-length-limited Huffman code
// generator.
//
// `bitCounts` is the load-bearing piece and is the reason this is not
// a textbook Huffman implementation. DEFLATE caps a code at 15 bits,
// so the tree cannot simply be built by repeated merging; instead the
// package runs the package-merge algorithm over `levelInfo` records,
// one per bit depth, and computes how many literals end up at each
// length. Go's comment calls it "the same as the algorithm in the
// zlib source", and the port keeps its structure — including the
// `maxNode()` sentinel appended past the end of the working list,
// which is what lets the inner loops compare against a value that
// always loses.
//
// Deviations from Go:
//
//   * `byLiteral` and `byFreq` are Go slice types with methods; goish
//     spells each as a newtype over `&mut [literalNode]` so it can
//     implement `sort::Interface` without owning a copy. Their `sort`
//     is an associated function rather than a pointer method, since
//     Go's `func (s *byLiteral) sort(a []literalNode)` reassigns the
//     receiver, which a borrow cannot do.
//   * goish's `sort::Sort` is a heapsort where Go's is pdqsort. Both
//     `Less` here are total orders — `byLiteral` on a unique literal,
//     `byFreq` breaking a frequency tie by literal — so the result is
//     identical, not merely equivalent.
//   * Go builds `fixedLiteralEncoding` and `fixedOffsetEncoding` as
//     package-level vars at init. goish has no package init under
//     `no_std`, so each is a function that builds once behind a
//     `SpinLock` and clones the code table in.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use crate::convert::{
    byte as tobyte, int as toint, int32 as toint32, uint16 as touint16, uint32 as touint32,
};
use crate::math::bits;
use crate::sort;
use crate::types::{byte, int};

extern crate alloc;
use alloc::vec::Vec;

use super::inflate::maxNumLit;

// ─── huffmanEncoder (huffman_code.go) ──────────────────────────────────

// go: sdk 1.25.5 compress/flate/huffman_code.go:116-116 maxBitsLimit
/// `flate.maxBitsLimit` — the largest number of bits a DEFLATE code may
/// use. The whole package-merge construction below exists to respect it.
pub(super) const maxBitsLimit: i32 = 16;

const math_MaxUint16: u16 = 0xFFFF;
pub(super) const math_MaxInt32: i32 = 0x7FFF_FFFF;

/// `flate.hcode` — a Huffman code with a bit code and bit length.
#[derive(Clone, Copy, Default, Debug)]
pub(crate) struct hcode {
    pub(crate) code: u16,
    pub(crate) len: u16,
}

impl hcode {
    // go: sdk 1.25.5 compress/flate/huffman_code.go:52-55 hcode.set
    /// `(h *hcode).set(code, length)` — set code and length.
    fn set(&mut self, code: u16, length: u16) {
        self.len = length;
        self.code = code;
    }
}

/// `flate.literalNode` — a literal value and its frequency.
#[derive(Clone, Copy, Debug)]
pub(super) struct literalNode {
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

// go: sdk 1.25.5 compress/flate/huffman_code.go:57-57 maxNode
pub(super) fn maxNode() -> literalNode {
    return literalNode {
        literal: math_MaxUint16,
        freq: math_MaxInt32,
    };
}

// go: sdk 1.25.5 compress/flate/huffman_code.go:59-61 newHuffmanEncoder
/// `newHuffmanEncoder(size)`.
pub(crate) fn newHuffmanEncoder(size: int) -> huffmanEncoder {
    let mut codes: Vec<hcode> = Vec::with_capacity(size as usize);
    codes.resize(size as usize, hcode::default());
    return huffmanEncoder {
        codes,
        freqcache: Vec::new(),
        bitCount: [0i32; 17],
    };
}

// go: sdk 1.25.5 compress/flate/huffman_code.go:343-345 reverseBits
// `reverseBits(number, bitLength)` (huffman_code.go:343).
pub(super) fn reverseBits(number: u16, bitLength: byte) -> u16 {
    return bits::Reverse16(number << (16 - touint32(bitLength)));
}

// go: sdk 1.25.5 compress/flate/huffman_code.go:64-92 generateFixedLiteralEncoding
/// Generates a HuffmanCode corresponding to the fixed literal table.
pub(super) fn generateFixedLiteralEncoding() -> huffmanEncoder {
    let mut h = newHuffmanEncoder(maxNumLit);
    let mut ch: u16 = 0;
    while ch < touint16(maxNumLit) {
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
            code: reverseBits(bits_, tobyte(size)),
            len: size,
        };
        ch += 1;
    }
    return h;
}

// go: sdk 1.25.5 compress/flate/huffman_code.go:94-101 generateFixedOffsetEncoding
pub(super) fn generateFixedOffsetEncoding() -> huffmanEncoder {
    let mut h = newHuffmanEncoder(30);
    let n = h.codes.len();
    for ch in 0..n {
        h.codes[ch] = hcode {
            code: reverseBits(touint16(ch), 5),
            len: 5,
        };
    }
    return h;
}

impl huffmanEncoder {
    // go: sdk 1.25.5 compress/flate/huffman_code.go:106-114 huffmanEncoder.bitLength
    /// `(h *huffmanEncoder).bitLength(freq)`.
    pub(super) fn bitLength(&self, freq: &[i32]) -> int {
        let mut total: int = 0;
        for (i, &f) in freq.iter().enumerate() {
            if f != 0 {
                total += toint(f) * toint(self.codes[i].len);
            }
        }
        return total;
    }

    // go: sdk 1.25.5 compress/flate/huffman_code.go:132-242 huffmanEncoder.bitCounts
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
        let n: i32 = toint32(list.len());
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
        return &self.bitCount[..(maxBits as usize) + 1];
    }

    // go: sdk 1.25.5 compress/flate/huffman_code.go:246-266 huffmanEncoder.assignEncodingAndSize
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

            byLiteral::sort(chunk);
            for node in chunk.iter() {
                self.codes[node.literal as usize] = hcode {
                    code: reverseBits(code, tobyte(n)),
                    len: touint16(n),
                };
                code += 1;
            }
            list_len = lo;
        }
    }

    // go: sdk 1.25.5 compress/flate/huffman_code.go:272-308 huffmanEncoder.generate
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
                    literal: touint16(i),
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
                self.codes[node.literal as usize].set(touint16(i), 1);
            }
            return;
        }
        byFreq::sort(&mut list);

        // Number of literals for each bit count, then the assignment.
        // bitCounts appends maxNode() to `list`; assignEncodingAndSize
        // operates on the original count, so slice it back.
        let bc = self.bitCounts(&mut list, maxBits).to_vec();
        list.truncate(count);
        self.assignEncodingAndSize(&bc, &mut list);
    }
}

// go: sdk 1.25.5 compress/flate/huffman_code.go:310-310 byLiteral
/// `flate.byLiteral` — a `sort.Interface` over literal nodes, ordered
/// by literal value.
///
/// Go's is a slice type and its `sort` method reassigns the receiver;
/// a Rust borrow cannot, so this is a newtype over `&mut [literalNode]`
/// and `sort` is an associated function.
pub(super) struct byLiteral<'a>(&'a mut [literalNode]);

impl<'a> byLiteral<'a> {
    // go: sdk 1.25.5 compress/flate/huffman_code.go:312-315 byLiteral.sort
    /// `(*byLiteral).sort(a)` — sort `a` by literal value.
    fn sort(a: &mut [literalNode]) {
        // Go: *s = byLiteral(a); sort.Sort(s)
        let mut s = byLiteral(a);
        sort::Sort(&mut s);
    }
}

impl<'a> sort::Interface for byLiteral<'a> {
    // go: sdk 1.25.5 compress/flate/huffman_code.go:317-317 byLiteral.Len
    fn Len(&self) -> int {
        return toint(self.0.len());
    }
    // go: sdk 1.25.5 compress/flate/huffman_code.go:319-321 byLiteral.Less
    fn Less(&self, i: int, j: int) -> bool {
        // Go: return s[i].literal < s[j].literal
        return self.0[touidx(i)].literal < self.0[touidx(j)].literal;
    }
    // go: sdk 1.25.5 compress/flate/huffman_code.go:323-323 byLiteral.Swap
    fn Swap(&mut self, i: int, j: int) {
        // Go: s[i], s[j] = s[j], s[i]
        self.0.swap(touidx(i), touidx(j));
    }
}

// go: sdk 1.25.5 compress/flate/huffman_code.go:325-325 byFreq
/// `flate.byFreq` — a `sort.Interface` over literal nodes, ordered by
/// frequency with the literal value breaking ties. The tiebreak is what
/// makes the order total, so the heapsort goish uses lands on the same
/// permutation Go's pdqsort does.
pub(super) struct byFreq<'a>(&'a mut [literalNode]);

impl<'a> byFreq<'a> {
    // go: sdk 1.25.5 compress/flate/huffman_code.go:327-330 byFreq.sort
    /// `(*byFreq).sort(a)` — sort `a` by frequency, then literal.
    fn sort(a: &mut [literalNode]) {
        // Go: *s = byFreq(a); sort.Sort(s)
        let mut s = byFreq(a);
        sort::Sort(&mut s);
    }
}

impl<'a> sort::Interface for byFreq<'a> {
    // go: sdk 1.25.5 compress/flate/huffman_code.go:332-332 byFreq.Len
    fn Len(&self) -> int {
        return toint(self.0.len());
    }
    // go: sdk 1.25.5 compress/flate/huffman_code.go:334-339 byFreq.Less
    fn Less(&self, i: int, j: int) -> bool {
        // Go: if s[i].freq == s[j].freq { return s[i].literal < s[j].literal }
        if self.0[touidx(i)].freq == self.0[touidx(j)].freq {
            return self.0[touidx(i)].literal < self.0[touidx(j)].literal;
        }
        // Go: return s[i].freq < s[j].freq
        return self.0[touidx(i)].freq < self.0[touidx(j)].freq;
    }
    // go: sdk 1.25.5 compress/flate/huffman_code.go:341-341 byFreq.Swap
    fn Swap(&mut self, i: int, j: int) {
        // Go: s[i], s[j] = s[j], s[i]
        self.0.swap(touidx(i), touidx(j));
    }
}

// go: none — goish idiom: `sort::Interface` indexes with goish's `int`;
//     a Rust slice indexes with `usize`.
fn touidx(i: int) -> usize {
    return usize::try_from(i).unwrap_or(0);
}
// ─── fixed encoders (huffman_code.go:103 / huffman_bit_writer.go:600) ──
//
// Go builds `fixedLiteralEncoding`, `fixedOffsetEncoding` and
// `huffOffset` in package `init()`. Goish has no package init under
// `no_std`, so they are built once behind a `SpinLock` and cloned in.

// go: none — goish idiom: Go's fixed encoders are package-level `var`s
//     initialised once at program start and shared by pointer. goish
//     builds each behind a `SpinLock` and hands out a clone, so every
//     accessor needs a way to rebuild the struct from a code table.
pub(super) fn __from_codes(codes: &[hcode]) -> huffmanEncoder {
    return huffmanEncoder {
        codes: codes.to_vec(),
        freqcache: Vec::new(),
        bitCount: [0i32; 17],
    };
}

// go: none — goish idiom: Go shares one `*huffmanEncoder` by pointer;
//     goish hands out an independent encoder with the same code table,
//     since the `freqcache` scratch buffer must not be shared.
pub(super) fn clone_encoder(h: &huffmanEncoder) -> huffmanEncoder {
    return __from_codes(&h.codes);
}

// go: sdk 1.25.5 compress/flate/huffman_code.go:103-103 fixedLiteralEncoding
/// `flate.fixedLiteralEncoding` — the fixed literal code table. Go
/// initialises it as a package-level var at program start; goish builds
/// it once behind a `SpinLock` and clones the table in.
pub(super) fn fixedLiteralEncoding() -> huffmanEncoder {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<Vec<hcode>>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(generateFixedLiteralEncoding().codes);
    }
    return __from_codes(g.as_ref().unwrap());
}

// go: sdk 1.25.5 compress/flate/huffman_code.go:104-104 fixedOffsetEncoding
/// `flate.fixedOffsetEncoding` — the fixed offset code table; see
/// [`fixedLiteralEncoding`].
pub(super) fn fixedOffsetEncoding() -> huffmanEncoder {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<Vec<hcode>>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(generateFixedOffsetEncoding().codes);
    }
    return __from_codes(g.as_ref().unwrap());
}
