// go: file compress/flate/token.go decls: literalToken, matchToken, token.literal, token.offset, token.length, lengthCode, offsetCode
//
// The `decls:` manifest above lists token.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// `token`, `lengthCodes`, `offsetCodes` or the four packing constants
// there would report them as dropped ports. They are not dropped —
// each carries its own `// go: sdk` anchor below.
//
// compress/flate/token.go — the compressor's intermediate symbol.
//
// A `token` is one uint32 holding either a literal byte or a
// (length, offset) back-reference, distinguished by two tag bits at
// the top. Packing both into one word is what lets the block writer
// keep a flat `[]token` and decide between a fixed, dynamic or stored
// block by counting frequencies over it, without a second pass over
// the input.
//
// `lengthCodes` and `offsetCodes` are the RFC 1951 §3.2.5 tables,
// transcribed from Go rather than recomputed.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use crate::convert::uint32 as touint32;

// ─── token (token.go:7) ────────────────────────────────────────────────

// 2 bits:   type   0 = literal  1=EOF  2=Match   3=Unused
// 8 bits:   xlength = length - MIN_MATCH_LENGTH
// 22 bits   xoffset = offset - MIN_OFFSET_SIZE, or literal
pub(super) const lengthShift: u32 = 22;
pub(super) const offsetMask: u32 = (1 << lengthShift) - 1;
#[allow(dead_code)]
const typeMask: u32 = 3 << 30;
pub(super) const literalType: u32 = 0 << 30;
pub(super) const matchType: u32 = 1 << 30;

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

// go: sdk 1.25.5 compress/flate/token.go:71-71 literalToken
/// Convert a literal into a literal token.
pub(crate) fn literalToken(literal: u32) -> token {
    return token(literalType + literal);
}

// go: sdk 1.25.5 compress/flate/token.go:74-76 matchToken
/// Convert a < xlength, xoffset > pair into a match token.
pub(crate) fn matchToken(xlength: u32, xoffset: u32) -> token {
    return token(matchType + (xlength << lengthShift) + xoffset);
}

impl token {
    // go: sdk 1.25.5 compress/flate/token.go:79-79 token.literal
    /// Returns the literal of a literal token.
    pub(crate) fn literal(self) -> u32 {
        return self.0.wrapping_sub(literalType);
    }

    // go: sdk 1.25.5 compress/flate/token.go:82-82 token.offset
    /// Returns the extra offset of a match token.
    pub(crate) fn offset(self) -> u32 {
        return self.0 & offsetMask;
    }

    // go: sdk 1.25.5 compress/flate/token.go:84-84 token.length
    /// Returns the length of a match token.
    pub(crate) fn length(self) -> u32 {
        return self.0.wrapping_sub(matchType) >> lengthShift;
    }
}

// go: sdk 1.25.5 compress/flate/token.go:86-86 lengthCode
/// `lengthCode(len)` — length code for `len`.
pub(super) fn lengthCode(len: u32) -> u32 {
    return lengthCodes[len as usize];
}

// go: sdk 1.25.5 compress/flate/token.go:89-97 offsetCode
/// `offsetCode(off)` — offset code corresponding to a specific offset.
pub(super) fn offsetCode(off: u32) -> u32 {
    if off < touint32(offsetCodes.len()) {
        return offsetCodes[off as usize];
    }
    if (off >> 7) < touint32(offsetCodes.len()) {
        return offsetCodes[(off >> 7) as usize] + 14;
    }
    return offsetCodes[(off >> 14) as usize] + 28;
}
