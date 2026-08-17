// go: file compress/bzip2/huffman.go decls: huffmanTree, huffmanNode, invalidNodeValue, huffmanTree.Decode, newHuffmanTree, huffmanSymbolLengthPair, huffmanCode, buildHuffmanNode
//
// compress/bzip2/huffman.go — the canonical Huffman decoder.
//
// bzip2 transmits only the code LENGTH of each symbol; the codes
// themselves are reconstructed canonically (sort by length, then by
// symbol value, then assign increasing codes packed at the MSB end of
// a uint32). Sorting the finished codes groups each branch's left half
// together, which is what lets `buildHuffmanNode` split the list
// recursively instead of walking bit-by-bit.
//
// Slim deviation:
//   * Go's `Decode` holds `node := &t.nodes[nodeIndex]`, a pointer into
//     the node table. goish copies the node (8 bytes, `Copy`) instead —
//     the loop only ever reads it, and a live `&` into `t.nodes` would
//     collide with nothing here but reads worse.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use crate::cmp;
use crate::convert::uint16 as touint16;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::io::ByteReader;
use crate::slices;
use crate::types::{int, uint16, uint32, uint8};

use super::bit_reader::bitReader;
use super::bzip2::structuralError;

// go: sdk 1.25.5 compress/bzip2/huffman.go:12-19 huffmanTree
/// `bzip2.huffmanTree` — a binary tree navigated bit-by-bit to reach a
/// symbol. `nodes[0]` is the root; `nextNode` is the bump allocator
/// index used while the tree is under construction.
#[derive(Clone, Default)]
pub(super) struct huffmanTree {
    // Go: nodes []huffmanNode
    pub(super) nodes: slice<huffmanNode>,
    // Go: nextNode int
    pub(super) nextNode: int,
}

// go: sdk 1.25.5 compress/bzip2/huffman.go:22-31 huffmanNode
/// `bzip2.huffmanNode` — one non-leaf node. `left`/`right` index into
/// the tree's `nodes`; [`invalidNodeValue`] there marks a leaf whose
/// symbol is in `leftValue`/`rightValue`.
///
/// The symbols are `uint16` because bzip2 encodes MTF indexes plus two
/// run-length metasymbols and an EOF symbol — more than 256 in all.
#[derive(Clone, Copy, Default)]
pub(super) struct huffmanNode {
    // Go: left, right uint16
    pub(super) left: uint16,
    pub(super) right: uint16,
    // Go: leftValue, rightValue uint16
    pub(super) leftValue: uint16,
    pub(super) rightValue: uint16,
}

// go: sdk 1.25.5 compress/bzip2/huffman.go:34-35 invalidNodeValue
/// `bzip2.invalidNodeValue` — an invalid index which marks a leaf node
/// in the tree.
pub(super) const invalidNodeValue: uint16 = 0xffff;

impl huffmanTree {
    // go: sdk 1.25.5 compress/bzip2/huffman.go:37-78 huffmanTree.Decode
    /// `(t *huffmanTree).Decode(br)` — read bits from `br` and navigate
    /// the tree until a symbol is found.
    pub(super) fn Decode<R: ByteReader>(&self, br: &mut bitReader<R>) -> uint16 {
        // Go: nodeIndex := uint16(0) // node 0 is the root of the tree.
        let mut nodeIndex: uint16 = 0;

        loop {
            // Go: node := &t.nodes[nodeIndex]
            let node = self.nodes[nodeIndex];

            // Go: var bit uint16
            let bit: uint16;
            if br.bits > 0 {
                // Get next bit - fast path.
                // Go: br.bits--; bit = uint16(br.n>>(br.bits&63)) & 1
                br.bits -= 1;
                bit = touint16(br.n >> (br.bits & 63)) & 1;
            } else {
                // Get next bit - slow path.
                // Use ReadBits to retrieve a single bit
                // from the underling io.ByteReader.
                // Go: bit = uint16(br.ReadBits(1))
                bit = touint16(br.ReadBits(1));
            }

            // Trick a compiler into generating conditional move instead of branch,
            // by making both loads unconditional.
            // Go: l, r := node.left, node.right
            let (l, r) = (node.left, node.right);

            // Go: if bit == 1 { nodeIndex = l } else { nodeIndex = r }
            if bit == 1 {
                nodeIndex = l;
            } else {
                nodeIndex = r;
            }

            // Go: if nodeIndex == invalidNodeValue
            if nodeIndex == invalidNodeValue {
                // We found a leaf. Use the value of bit to decide
                // whether is a left or a right value.
                // Go: l, r := node.leftValue, node.rightValue
                let (l, r) = (node.leftValue, node.rightValue);
                if bit == 1 {
                    return l;
                }
                return r;
            }
        }
    }
}

// go: sdk 1.25.5 compress/bzip2/huffman.go:81-141 newHuffmanTree
/// `bzip2.newHuffmanTree(lengths)` — build a tree from the code length
/// of each symbol. The maximum code length is 32 bits.
pub(super) fn newHuffmanTree(lengths: &slice<uint8>) -> (huffmanTree, error) {
    // There are many possible trees that assign the same code length to
    // each symbol (consider reflecting a tree down the middle, for
    // example). Since the code length assignments determine the
    // efficiency of the tree, each of these trees is equally good. In
    // order to minimize the amount of information needed to build a tree
    // bzip2 uses a canonical tree so that it can be reconstructed given
    // only the code length assignments.

    // Go: if len(lengths) < 2 { panic("newHuffmanTree: too few symbols") }
    if lengths.Len() < 2 {
        panic!("newHuffmanTree: too few symbols");
    }

    // Go: var t huffmanTree
    let mut t = huffmanTree::default();

    // First we sort the code length assignments by ascending code length,
    // using the symbol value to break ties.
    // Go: pairs := make([]huffmanSymbolLengthPair, len(lengths))
    let mut pairs = crate::make!([]huffmanSymbolLengthPair, lengths.Len());
    // Go: for i, length := range lengths
    for (i, length) in crate::range!(lengths) {
        pairs[i].value = touint16(i);
        pairs[i].length = *length;
    }

    // Go: slices.SortFunc(pairs, func(a, b huffmanSymbolLengthPair) int { … })
    slices::SortFunc!(pairs, |a: &huffmanSymbolLengthPair, b: &huffmanSymbolLengthPair| {
        let c = cmp::Compare(&a.length, &b.length);
        if c != 0 {
            return c;
        }
        return cmp::Compare(&a.value, &b.value);
    });

    // Now we assign codes to the symbols, starting with the longest code.
    // We keep the codes packed into a uint32, at the most-significant end.
    // So branches are taken from the MSB downwards. This makes it easy to
    // sort them later.
    // Go: code := uint32(0); length := uint8(32)
    let mut code: uint32 = 0;
    let mut length: uint8 = 32;

    // Go: codes := make([]huffmanCode, len(lengths))
    let mut codes = crate::make!([]huffmanCode, lengths.Len());
    // Go: for i := len(pairs) - 1; i >= 0; i--
    let mut i = pairs.Len() - 1;
    while i >= 0 {
        if length > pairs[i].length {
            length = pairs[i].length;
        }
        codes[i].code = code;
        codes[i].codeLen = length;
        codes[i].value = pairs[i].value;
        // We need to 'increment' the code, which means treating |code|
        // like a |length| bit number.
        //
        // Go: code += 1 << (32 - length)
        //
        // `length` is at least 1 here (readBlock rejects 0), so the
        // shift is at most 31 and cannot reach Rust's overflow panic.
        // The add wraps: Go's uint32 arithmetic does, and a code list
        // whose Kraft sum exceeds 1 relies on it.
        code = code.wrapping_add(1u32 << (32 - length));
        i -= 1;
    }

    // Now we can sort by the code so that the left half of each branch are
    // grouped together, recursively.
    // Go: slices.SortFunc(codes, func(a, b huffmanCode) int { return cmp.Compare(a.code, b.code) })
    slices::SortFunc!(codes, |a: &huffmanCode, b: &huffmanCode| {
        return cmp::Compare(&a.code, &b.code);
    });

    // Go: t.nodes = make([]huffmanNode, len(codes))
    t.nodes = crate::make!([]huffmanNode, codes.Len());
    // Go: _, err := buildHuffmanNode(&t, codes, 0); return t, err
    let (_, err) = buildHuffmanNode(&mut t, &codes, 0);
    return (t, err);
}

// go: sdk 1.25.5 compress/bzip2/huffman.go:144-147 huffmanSymbolLengthPair
/// `bzip2.huffmanSymbolLengthPair` — a symbol and its code length.
#[derive(Clone, Copy, Default)]
pub(super) struct huffmanSymbolLengthPair {
    // Go: value uint16
    pub(super) value: uint16,
    // Go: length uint8
    pub(super) length: uint8,
}

// go: sdk 1.25.5 compress/bzip2/huffman.go:150-154 huffmanCode
/// `bzip2.huffmanCode` — a symbol, its code and code length.
#[derive(Clone, Copy, Default)]
pub(super) struct huffmanCode {
    // Go: code uint32
    pub(super) code: uint32,
    // Go: codeLen uint8
    pub(super) codeLen: uint8,
    // Go: value uint16
    pub(super) value: uint16,
}

// go: sdk 1.25.5 compress/bzip2/huffman.go:157-233 buildHuffmanNode
/// `bzip2.buildHuffmanNode(t, codes, level)` — build the node of `t` at
/// `level` from a code-sorted slice, returning its index in `t.nodes`.
pub(super) fn buildHuffmanNode(
    t: &mut huffmanTree,
    codes: &slice<huffmanCode>,
    level: uint32,
) -> (uint16, error) {
    // Go: test := uint32(1) << (31 - level)
    //
    // Go neither panics on the `31 - level` underflow nor on a shift
    // count >= 32 — the first wraps, the second yields 0. Rust panics
    // on both, so spell them out. `level` is bounded by 31 for every
    // length vector readBlock admits (lengths <= 20 make all codes a
    // multiple of 2^12, so the low 12 levels always take the
    // superfluous-level arm below and hit its `level == 31` guard);
    // this arm is what keeps a future caller from turning that
    // reasoning into an abort on hostile input.
    let shift = 31u32.wrapping_sub(level);
    let test: uint32 = if shift >= 32 { 0 } else { 1u32 << shift };

    // We have to search the list of codes to find the divide between the left and right sides.
    // Go: firstRightIndex := len(codes)
    let mut firstRightIndex = codes.Len();
    // Go: for i, code := range codes
    for (i, code) in crate::range!(codes) {
        if code.code & test != 0 {
            firstRightIndex = i;
            break;
        }
    }

    // Go: left := codes[:firstRightIndex]; right := codes[firstRightIndex:]
    let left = codes.slice(0, firstRightIndex);
    let right = codes.slice(firstRightIndex, codes.Len());

    // Go: if len(left) == 0 || len(right) == 0
    if left.Len() == 0 || right.Len() == 0 {
        // There is a superfluous level in the Huffman tree indicating
        // a bug in the encoder. However, this bug has been observed in
        // the wild so we handle it.

        // If this function was called recursively then we know that
        // len(codes) >= 2 because, otherwise, we would have hit the
        // "leaf node" case, below, and not recurred.
        //
        // However, for the initial call it's possible that len(codes)
        // is zero or one. Both cases are invalid because a zero length
        // tree cannot encode anything and a length-1 tree can only
        // encode EOF and so is superfluous. We reject both.
        if codes.Len() < 2 {
            return (0, structuralError("empty Huffman tree"));
        }

        // In this case the recursion doesn't always reduce the length
        // of codes so we need to ensure termination via another
        // mechanism.
        if level == 31 {
            // Since len(codes) >= 2 the only way that the values
            // can match at all 32 bits is if they are equal, which
            // is invalid. This ensures that we never enter
            // infinite recursion.
            return (0, structuralError("equal symbols in Huffman tree"));
        }

        if left.Len() == 0 {
            return buildHuffmanNode(t, &right, level + 1);
        }
        return buildHuffmanNode(t, &left, level + 1);
    }

    // Go: nodeIndex = uint16(t.nextNode); node := &t.nodes[t.nextNode]; t.nextNode++
    let nodeIndex: uint16 = touint16(t.nextNode);
    let node = t.nextNode;
    t.nextNode += 1;

    // Go's named return `err` starts nil and is assigned by each half.
    let mut err: error = nil;

    // Go: if len(left) == 1 { node.left = invalidNodeValue; node.leftValue = left[0].value }
    //     else { node.left, err = buildHuffmanNode(t, left, level+1) }
    if left.Len() == 1 {
        // leaf node
        t.nodes[node].left = invalidNodeValue;
        t.nodes[node].leftValue = left[0].value;
    } else {
        let (v, e) = buildHuffmanNode(t, &left, level + 1);
        t.nodes[node].left = v;
        err = e;
    }

    // Go: if err != nil { return }
    if !err.IsNil() {
        return (nodeIndex, err);
    }

    // Go: if len(right) == 1 { node.right = invalidNodeValue; node.rightValue = right[0].value }
    //     else { node.right, err = buildHuffmanNode(t, right, level+1) }
    if right.Len() == 1 {
        // leaf node
        t.nodes[node].right = invalidNodeValue;
        t.nodes[node].rightValue = right[0].value;
    } else {
        let (v, e) = buildHuffmanNode(t, &right, level + 1);
        t.nodes[node].right = v;
        err = e;
    }

    // Go: return
    return (nodeIndex, err);
}
