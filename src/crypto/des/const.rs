// go: file crypto/des/const.go decls:
//
// DES tables: initial/final permutations, expansion function,
// permutation function, permuted choices 1 and 2, S-boxes, and the
// key-schedule rotation counts. Verbatim data from const.go @ Go 1.25.5.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use crate::types::byte;

// go: sdk 1.25.5 crypto/des/const.go:14-23 initialPermutation
//
// Used to perform an initial permutation of a 64-bit input block.
// Referenced for provenance: `permuteInitialBlock` in block.rs is the
// hand-unrolled equivalent Go also uses at runtime.
#[allow(dead_code)] // declared in Go's const.go; the runtime path uses the
                    // hand-unrolled permutation in block.rs, exactly as Go does.
pub(crate) const initialPermutation: [byte; 64] = [
    6, 14, 22, 30, 38, 46, 54, 62, 4, 12, 20, 28, 36, 44, 52, 60, 2, 10, 18, 26, 34, 42, 50, 58, 0,
    8, 16, 24, 32, 40, 48, 56, 7, 15, 23, 31, 39, 47, 55, 63, 5, 13, 21, 29, 37, 45, 53, 61, 3, 11,
    19, 27, 35, 43, 51, 59, 1, 9, 17, 25, 33, 41, 49, 57,
];

// go: sdk 1.25.5 crypto/des/const.go:27-36 finalPermutation
//
// Final permutation of a 64-bit preoutput block; the inverse of
// `initialPermutation`. `permuteFinalBlock` is the unrolled equivalent.
#[allow(dead_code)] // declared in Go's const.go; the runtime path uses the
                    // hand-unrolled permutation in block.rs, exactly as Go does.
pub(crate) const finalPermutation: [byte; 64] = [
    24, 56, 16, 48, 8, 40, 0, 32, 25, 57, 17, 49, 9, 41, 1, 33, 26, 58, 18, 50, 10, 42, 2, 34, 27,
    59, 19, 51, 11, 43, 3, 35, 28, 60, 20, 52, 12, 44, 4, 36, 29, 61, 21, 53, 13, 45, 5, 37, 30,
    62, 22, 54, 14, 46, 6, 38, 31, 63, 23, 55, 15, 47, 7, 39,
];

// go: sdk 1.25.5 crypto/des/const.go:40-47 expansionFunction
//
// Expands a 32-bit input block to 48 bits. `feistel` applies this
// expansion inline via shifts, which is what Go's runtime path does too.
#[allow(dead_code)] // declared in Go's const.go; the runtime path uses the
                    // hand-unrolled permutation in block.rs, exactly as Go does.
pub(crate) const expansionFunction: [byte; 48] = [
    0, 31, 30, 29, 28, 27, 28, 27, 26, 25, 24, 23, 24, 23, 22, 21, 20, 19, 20, 19, 18, 17, 16, 15,
    16, 15, 14, 13, 12, 11, 12, 11, 10, 9, 8, 7, 8, 7, 6, 5, 4, 3, 4, 3, 2, 1, 0, 31,
];

// ─── const.go: DES permutation tables ──────────────────────────────

// Go: const.go:14 — initialPermutation [64]byte (referenced by
// permuteInitialBlock's documentation, not used at runtime; the
// hand-unrolled implementation in `permuteInitialBlock` is equivalent).

// Go: const.go:50 — `var permutationFunction = [32]byte{...}`. The
// 32-bit P-permutation applied to the S-box output before XOR with
// the left half.
pub(crate) const permutationFunction: [byte; 32] = [
    16, 25, 12, 11, 3, 20, 4, 15, 31, 17, 9, 6, 27, 14, 1, 22, 30, 24, 8, 18, 0, 5, 29, 23, 13, 19,
    2, 26, 10, 21, 28, 7,
];

// Go: const.go:59 — `var permutedChoice1 = [56]byte{...}`. Selects 56
// bits from the 64-bit key (PC-1 in FIPS-46-3).
pub(crate) const permutedChoice1: [byte; 56] = [
    7, 15, 23, 31, 39, 47, 55, 63, 6, 14, 22, 30, 38, 46, 54, 62, 5, 13, 21, 29, 37, 45, 53, 61, 4,
    12, 20, 28, 1, 9, 17, 25, 33, 41, 49, 57, 2, 10, 18, 26, 34, 42, 50, 58, 3, 11, 19, 27, 35, 43,
    51, 59, 36, 44, 52, 60,
];

// Go: const.go:71 — `var permutedChoice2 = [48]byte{...}`. Selects 48
// bits from the 56-bit half-rotated key (PC-2 in FIPS-46-3).
pub(crate) const permutedChoice2: [byte; 48] = [
    42, 39, 45, 32, 55, 51, 53, 28, 41, 50, 35, 46, 33, 37, 44, 52, 30, 48, 40, 49, 29, 36, 43, 54,
    15, 4, 25, 19, 9, 1, 26, 16, 5, 11, 23, 8, 12, 7, 17, 0, 22, 3, 10, 14, 6, 20, 27, 24,
];

// Go: const.go:82 — `var sBoxes = [8][4][16]uint8{...}`. The eight
// FIPS-46 substitution boxes.
pub(crate) const sBoxes: [[[byte; 16]; 4]; 8] = [
    // S-box 1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    // S-box 2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    // S-box 3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    // S-box 4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    // S-box 5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    // S-box 6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    // S-box 7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    // S-box 8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

// Go: const.go:142 — `var ksRotations = [16]uint8{...}`. Per-round
// circular-shift count for the key schedule.
pub(crate) const ksRotations: [byte; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

//
// goish swap: a `SpinLock<Option<Box<[[u32; 64]; 8]>>>` materialised on
// first call to `generateSubkeys`. Boxed because the table is 2 KiB —
// keeping it on a 2 KiB-default goroutine stack would risk overflow.
