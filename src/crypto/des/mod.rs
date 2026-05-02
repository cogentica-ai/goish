// crypto/des — DES + TripleDES block ciphers (FIPS 46-3).
//
// References:
//   * /share/go/src/crypto/des/cipher.go (165 LOC) — public NewCipher,
//     NewTripleDESCipher, KeySizeError, Encrypt/Decrypt.
//   * /share/go/src/crypto/des/block.go (249 LOC) — cryptBlock,
//     feistel, permuteInitialBlock, permuteFinalBlock, generateSubkeys,
//     ksRotate, unpack, initFeistelBox.
//   * /share/go/src/crypto/des/const.go (142 LOC) — sBoxes,
//     permutationFunction, permutedChoice1/2, ksRotations.
//
// DES is cryptographically broken and should not be used for secure
// applications; goish ships it for protocol compatibility (NTLM,
// legacy Kerberos, PKCS#12) and to round out the symmetric-cipher
// surface alongside crypto/aes.
//
// Slim deviations from upstream (documented):
//
//   * `NewCipher` / `NewTripleDESCipher` return `(Option<Cipher>, error)`
//     and `(Option<TripleDESCipher>, error)`. Go returns
//     `(cipher.Block, error)`. Goish doesn't have nullable trait
//     objects; an `Option<T>` carrying the value (or `None` on error)
//     mirrors the existing `crypto::aes::NewCipher` / `crypto::rc4`
//     surface.
//   * No `fips140only.Enabled` branch — goish has no FIPS 140-only
//     mode. (DES would be unconditionally rejected upstream when that
//     flag is on.)
//   * No `alias.InexactOverlap` panic — goish slices don't expose
//     pointer arithmetic for the overlap check. Callers must respect
//     "dst and src must overlap entirely or not at all" by contract.
//   * `feistelBoxOnce` is replaced by a `SpinLock<Option<...>>`
//     guarding lazy initialization of the 8×64 u32 feistelBox table
//     (no_std has no `sync::Once`). Same end behaviour: the table is
//     materialised on first key-schedule and shared thereafter.
//   * `Cipher` and `TripleDESCipher` are value types. The
//     `cipher::Block` trait takes `&self`, matching Go's `*desCipher`
//     receiver semantics (the round keys are immutable after key
//     setup).

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;

use alloc::boxed::Box;

use crate::crypto::cipher::Block as BlockTrait;
use crate::errors::{ErrorTrait, Wrap, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::runtime::spin::SpinLock;
use crate::strconv;
use crate::types::{byte, int};

// Go: cipher.go:17 — const BlockSize = 8.
/// The DES block size in bytes.
pub const BlockSize: int = 8;

// Go: cipher.go:19 — type KeySizeError int.
/// `des.KeySizeError` — error returned by `NewCipher` /
/// `NewTripleDESCipher` when the supplied key length is wrong (8 for
/// DES, 24 for 3DES).
#[derive(Clone)]
pub struct KeySizeError(pub int);

impl ErrorTrait for KeySizeError {
    // Go: cipher.go:21
    //   func (k KeySizeError) Error() string {
    //       return "crypto/des: invalid key size " + strconv.Itoa(int(k))
    //   }
    fn Error(&self) -> string {
        let mut s = string::from_static("crypto/des: invalid key size ");
        s = s + strconv::Itoa(self.0);
        s
    }
}

// ─── const.go: DES permutation tables ──────────────────────────────

// Go: const.go:14 — initialPermutation [64]byte (referenced by
// permuteInitialBlock's documentation, not used at runtime; the
// hand-unrolled implementation in `permuteInitialBlock` is equivalent).

// Go: const.go:50 — `var permutationFunction = [32]byte{...}`. The
// 32-bit P-permutation applied to the S-box output before XOR with
// the left half.
const permutationFunction: [byte; 32] = [
    16, 25, 12, 11, 3, 20, 4, 15, 31, 17, 9, 6, 27, 14, 1, 22, 30, 24, 8, 18, 0, 5, 29, 23, 13, 19,
    2, 26, 10, 21, 28, 7,
];

// Go: const.go:59 — `var permutedChoice1 = [56]byte{...}`. Selects 56
// bits from the 64-bit key (PC-1 in FIPS-46-3).
const permutedChoice1: [byte; 56] = [
    7, 15, 23, 31, 39, 47, 55, 63, 6, 14, 22, 30, 38, 46, 54, 62, 5, 13, 21, 29, 37, 45, 53, 61, 4,
    12, 20, 28, 1, 9, 17, 25, 33, 41, 49, 57, 2, 10, 18, 26, 34, 42, 50, 58, 3, 11, 19, 27, 35, 43,
    51, 59, 36, 44, 52, 60,
];

// Go: const.go:71 — `var permutedChoice2 = [48]byte{...}`. Selects 48
// bits from the 56-bit half-rotated key (PC-2 in FIPS-46-3).
const permutedChoice2: [byte; 48] = [
    42, 39, 45, 32, 55, 51, 53, 28, 41, 50, 35, 46, 33, 37, 44, 52, 30, 48, 40, 49, 29, 36, 43, 54,
    15, 4, 25, 19, 9, 1, 26, 16, 5, 11, 23, 8, 12, 7, 17, 0, 22, 3, 10, 14, 6, 20, 27, 24,
];

// Go: const.go:82 — `var sBoxes = [8][4][16]uint8{...}`. The eight
// FIPS-46 substitution boxes.
const sBoxes: [[[byte; 16]; 4]; 8] = [
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
const ksRotations: [byte; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

// ─── block.go: feistelBox + lazy initializer ────────────────────────

// Go: block.go:72 — `var feistelBox [8][64]uint32`.
// Go: block.go:74 — `var feistelBoxOnce sync.Once`.
//
// goish swap: a `SpinLock<Option<Box<[[u32; 64]; 8]>>>` materialised on
// first call to `generateSubkeys`. Boxed because the table is 2 KiB —
// keeping it on a 2 KiB-default goroutine stack would risk overflow.
static FEISTEL_BOX: SpinLock<Option<Box<[[u32; 64]; 8]>>> = SpinLock::new(None);

// Go: block.go:77
//   func permuteBlock(src uint64, permutation []uint8) (block uint64) {
//       for position, n := range permutation {
//           bit := (src >> n) & 1
//           block |= bit << uint((len(permutation)-1)-position)
//       }
//       return
//   }
fn permuteBlock(src: u64, permutation: &[byte]) -> u64 {
    let mut block: u64 = 0;
    let n_perm = permutation.len();
    for position in 0..n_perm {
        let n = permutation[position] as u64;
        let bit = (src >> n) & 1;
        block |= bit << ((n_perm - 1) - position) as u64;
    }
    block
}

// Go: block.go:85
//   func initFeistelBox() {
//       for s := range sBoxes {
//           for i := 0; i < 4; i++ {
//               for j := 0; j < 16; j++ {
//                   ... feistelBox[s][t] = uint32(f) ...
//               }
//           }
//       }
//   }
fn initFeistelBox() -> Box<[[u32; 64]; 8]> {
    let mut fb: Box<[[u32; 64]; 8]> = Box::new([[0u32; 64]; 8]);
    for s in 0..8usize {
        for i in 0..4usize {
            for j in 0..16usize {
                // Go: block.go:89
                //   f := uint64(sBoxes[s][i][j]) << (4 * (7 - uint(s)))
                let mut f: u64 = (sBoxes[s][i][j] as u64) << (4 * (7 - s as u64));
                // Go: block.go:90
                //   f = permuteBlock(f, permutationFunction[:])
                f = permuteBlock(f, &permutationFunction);

                // Go: block.go:94
                //   row := uint8(((i & 2) << 4) | i&1)
                //   col := uint8(j << 1)
                //   t := row | col
                let row: u8 = (((i & 2) << 4) | (i & 1)) as u8;
                let col: u8 = (j << 1) as u8;
                let t: u8 = row | col;

                // Go: block.go:99 — pre-rotate by 1 bit (factored out
                //   of the feistel round to avoid per-round shifts).
                f = (f << 1) | (f >> 31);

                // Go: block.go:101 — feistelBox[s][t] = uint32(f)
                fb[s][t as usize] = f as u32;
            }
        }
    }
    fb
}

/// Lazily materialise (or fetch) the global feistelBox. Idempotent.
fn ensureFeistelBox() {
    let mut g = FEISTEL_BOX.lock();
    if g.is_none() {
        *g = Some(initFeistelBox());
    }
}

/// Read-only access to the materialised feistelBox.
#[inline]
fn fb_lookup(s: usize, t: u32) -> u32 {
    let g = FEISTEL_BOX.lock();
    // SAFETY (logical): callers always invoke ensureFeistelBox() first
    // (via generateSubkeys at NewCipher time) before reaching the
    // feistel rounds.
    g.as_ref().unwrap()[s][(t & 0x3f) as usize]
}

// Go: block.go:40
//   func feistel(l, r uint32, k0, k1 uint64) (lout, rout uint32) {
//       var t uint32
//       t = r ^ uint32(k0>>32)
//       l ^= feistelBox[7][t&0x3f] ^ feistelBox[5][(t>>8)&0x3f] ^ ...
//       ...
//       return l, r
//   }
fn feistel(mut l: u32, mut r: u32, k0: u64, k1: u64) -> (u32, u32) {
    let mut t: u32;

    // Go: block.go:43 — t = r ^ uint32(k0>>32)
    t = r ^ ((k0 >> 32) as u32);
    // Go: block.go:44
    //   l ^= feistelBox[7][t&0x3f] ^ feistelBox[5][(t>>8)&0x3f]
    //        ^ feistelBox[3][(t>>16)&0x3f] ^ feistelBox[1][(t>>24)&0x3f]
    l ^= fb_lookup(7, t)
        ^ fb_lookup(5, t >> 8)
        ^ fb_lookup(3, t >> 16)
        ^ fb_lookup(1, t >> 24);

    // Go: block.go:49 — t = ((r << 28) | (r >> 4)) ^ uint32(k0)
    t = ((r << 28) | (r >> 4)) ^ (k0 as u32);
    // Go: block.go:50
    //   l ^= feistelBox[6][t&0x3f] ^ feistelBox[4][(t>>8)&0x3f]
    //        ^ feistelBox[2][(t>>16)&0x3f] ^ feistelBox[0][(t>>24)&0x3f]
    l ^= fb_lookup(6, t)
        ^ fb_lookup(4, t >> 8)
        ^ fb_lookup(2, t >> 16)
        ^ fb_lookup(0, t >> 24);

    // Go: block.go:55 — t = l ^ uint32(k1>>32)
    t = l ^ ((k1 >> 32) as u32);
    // Go: block.go:56
    //   r ^= feistelBox[7][t&0x3f] ^ feistelBox[5][(t>>8)&0x3f]
    //        ^ feistelBox[3][(t>>16)&0x3f] ^ feistelBox[1][(t>>24)&0x3f]
    r ^= fb_lookup(7, t)
        ^ fb_lookup(5, t >> 8)
        ^ fb_lookup(3, t >> 16)
        ^ fb_lookup(1, t >> 24);

    // Go: block.go:61 — t = ((l << 28) | (l >> 4)) ^ uint32(k1)
    t = ((l << 28) | (l >> 4)) ^ (k1 as u32);
    // Go: block.go:62
    //   r ^= feistelBox[6][t&0x3f] ^ feistelBox[4][(t>>8)&0x3f]
    //        ^ feistelBox[2][(t>>16)&0x3f] ^ feistelBox[0][(t>>24)&0x3f]
    r ^= fb_lookup(6, t)
        ^ fb_lookup(4, t >> 8)
        ^ fb_lookup(2, t >> 16)
        ^ fb_lookup(0, t >> 24);

    (l, r)
}

// Go: block.go:109 — bit-tricks unroll of initialPermutation.
fn permuteInitialBlock(mut block: u64) -> u64 {
    // Go: block.go:111
    //   b1 := block >> 48
    //   b2 := block << 48
    //   block ^= b1 ^ b2 ^ b1<<48 ^ b2>>48
    let mut b1 = block >> 48;
    let mut b2 = block << 48;
    block ^= b1 ^ b2 ^ (b1 << 48) ^ (b2 >> 48);

    // Go: block.go:116
    //   b1 = block >> 32 & 0xff00ff
    //   b2 = (block & 0xff00ff00)
    //   block ^= b1<<32 ^ b2 ^ b1<<8 ^ b2<<24
    b1 = (block >> 32) & 0x00ff00ff;
    b2 = block & 0xff00ff00;
    block ^= (b1 << 32) ^ b2 ^ (b1 << 8) ^ (b2 << 24);

    // Go: block.go:131
    //   b1 = block & 0x0f0f00000f0f0000
    //   b2 = block & 0x0000f0f00000f0f0
    //   block ^= b1 ^ b2 ^ b1>>12 ^ b2<<12
    b1 = block & 0x0f0f00000f0f0000;
    b2 = block & 0x0000f0f00000f0f0;
    block ^= b1 ^ b2 ^ (b1 >> 12) ^ (b2 << 12);

    // Go: block.go:145
    //   b1 = block & 0x3300330033003300
    //   b2 = block & 0x00cc00cc00cc00cc
    //   block ^= b1 ^ b2 ^ b1>>6 ^ b2<<6
    b1 = block & 0x3300330033003300;
    b2 = block & 0x00cc00cc00cc00cc;
    block ^= b1 ^ b2 ^ (b1 >> 6) ^ (b2 << 6);

    // Go: block.go:160
    //   b1 = block & 0xaaaaaaaa55555555
    //   block ^= b1 ^ b1>>33 ^ b1<<33
    b1 = block & 0xaaaaaaaa55555555;
    block ^= b1 ^ (b1 >> 33) ^ (b1 << 33);

    block
}

// Go: block.go:177 — bit-tricks reverse of permuteInitialBlock.
fn permuteFinalBlock(mut block: u64) -> u64 {
    // Go: block.go:180 — `b1 := block & 0xaaaaaaaa55555555;
    //     block ^= b1 ^ b1>>33 ^ b1<<33`
    let mut b1 = block & 0xaaaaaaaa55555555;
    block ^= b1 ^ (b1 >> 33) ^ (b1 << 33);

    // Go: block.go:183
    //   b1 = block & 0x3300330033003300
    //   b2 := block & 0x00cc00cc00cc00cc
    //   block ^= b1 ^ b2 ^ b1>>6 ^ b2<<6
    b1 = block & 0x3300330033003300;
    let mut b2 = block & 0x00cc00cc00cc00cc;
    block ^= b1 ^ b2 ^ (b1 >> 6) ^ (b2 << 6);

    // Go: block.go:187
    //   b1 = block & 0x0f0f00000f0f0000
    //   b2 = block & 0x0000f0f00000f0f0
    //   block ^= b1 ^ b2 ^ b1>>12 ^ b2<<12
    b1 = block & 0x0f0f00000f0f0000;
    b2 = block & 0x0000f0f00000f0f0;
    block ^= b1 ^ b2 ^ (b1 >> 12) ^ (b2 << 12);

    // Go: block.go:191
    //   b1 = block >> 32 & 0xff00ff
    //   b2 = (block & 0xff00ff00)
    //   block ^= b1<<32 ^ b2 ^ b1<<8 ^ b2<<24
    b1 = (block >> 32) & 0x00ff00ff;
    b2 = block & 0xff00ff00;
    block ^= (b1 << 32) ^ b2 ^ (b1 << 8) ^ (b2 << 24);

    // Go: block.go:195
    //   b1 = block >> 48
    //   b2 = block << 48
    //   block ^= b1 ^ b2 ^ b1<<48 ^ b2>>48
    b1 = block >> 48;
    b2 = block << 48;
    block ^= b1 ^ b2 ^ (b1 << 48) ^ (b2 >> 48);

    block
}

// Go: block.go:203
//   func ksRotate(in uint32) (out []uint32) {
//       out = make([]uint32, 16)
//       last := in
//       for i := 0; i < 16; i++ {
//           left := (last << (4 + ksRotations[i])) >> 4
//           right := (last << 4) >> (32 - ksRotations[i])
//           out[i] = left | right
//           last = out[i]
//       }
//       return
//   }
fn ksRotate(in_: u32) -> [u32; 16] {
    let mut out = [0u32; 16];
    let mut last: u32 = in_;
    for i in 0..16usize {
        let r = ksRotations[i] as u32;
        let left = (last << (4 + r)) >> 4;
        let right = (last << 4) >> (32 - r);
        out[i] = left | right;
        last = out[i];
    }
    out
}

// Go: block.go:240
//   func unpack(x uint64) uint64 {
//       return ((x>>(6*1))&0xff)<<(8*0) | ...
//   }
fn unpack(x: u64) -> u64 {
    ((x >> (6 * 1)) & 0xff) << (8 * 0)
        | ((x >> (6 * 3)) & 0xff) << (8 * 1)
        | ((x >> (6 * 5)) & 0xff) << (8 * 2)
        | ((x >> (6 * 7)) & 0xff) << (8 * 3)
        | ((x >> (6 * 0)) & 0xff) << (8 * 4)
        | ((x >> (6 * 2)) & 0xff) << (8 * 5)
        | ((x >> (6 * 4)) & 0xff) << (8 * 6)
        | ((x >> (6 * 6)) & 0xff) << (8 * 7)
}

// Helper — read 8 bytes BE → u64. Mirrors `byteorder.BEUint64`.
fn beUint64(b: &slice<byte>) -> u64 {
    ((b[0] as u64) << 56)
        | ((b[1] as u64) << 48)
        | ((b[2] as u64) << 40)
        | ((b[3] as u64) << 32)
        | ((b[4] as u64) << 24)
        | ((b[5] as u64) << 16)
        | ((b[6] as u64) << 8)
        | (b[7] as u64)
}

// Helper — write u64 → 8 bytes BE. Mirrors `byteorder.BEPutUint64`.
fn bePutUint64(b: &mut slice<byte>, v: u64) {
    b[0] = (v >> 56) as byte;
    b[1] = (v >> 48) as byte;
    b[2] = (v >> 40) as byte;
    b[3] = (v >> 32) as byte;
    b[4] = (v >> 24) as byte;
    b[5] = (v >> 16) as byte;
    b[6] = (v >> 8) as byte;
    b[7] = v as byte;
}

// ─── desCipher ──────────────────────────────────────────────────────

// Go: cipher.go:26
//   type desCipher struct {
//       subkeys [16]uint64
//   }
/// `des.Cipher` — a single-DES key schedule. Use `NewCipher` to build
/// one. Implements `cipher::Block`.
#[derive(Clone)]
pub struct Cipher {
    subkeys: [u64; 16],
}

// Go: block.go:217
//   func (c *desCipher) generateSubkeys(keyBytes []byte) {
//       feistelBoxOnce.Do(initFeistelBox)
//       key := byteorder.BEUint64(keyBytes)
//       permutedKey := permuteBlock(key, permutedChoice1[:])
//       leftRotations := ksRotate(uint32(permutedKey >> 28))
//       rightRotations := ksRotate(uint32(permutedKey<<4) >> 4)
//       for i := 0; i < 16; i++ {
//           pc2Input := uint64(leftRotations[i])<<28 | uint64(rightRotations[i])
//           c.subkeys[i] = unpack(permuteBlock(pc2Input, permutedChoice2[:]))
//       }
//   }
fn generateSubkeys(c: &mut Cipher, keyBytes: &slice<byte>) {
    // Go: block.go:218 — feistelBoxOnce.Do(initFeistelBox)
    ensureFeistelBox();

    // Go: block.go:221 — key := byteorder.BEUint64(keyBytes)
    let key = beUint64(keyBytes);
    // Go: block.go:222
    //   permutedKey := permuteBlock(key, permutedChoice1[:])
    let permutedKey = permuteBlock(key, &permutedChoice1);

    // Go: block.go:225
    //   leftRotations := ksRotate(uint32(permutedKey >> 28))
    //   rightRotations := ksRotate(uint32(permutedKey<<4) >> 4)
    let leftRotations = ksRotate((permutedKey >> 28) as u32);
    let rightRotations = ksRotate(((permutedKey << 4) >> 4) as u32);

    // Go: block.go:229
    //   for i := 0; i < 16; i++ {
    //       pc2Input := uint64(leftRotations[i])<<28 | uint64(rightRotations[i])
    //       c.subkeys[i] = unpack(permuteBlock(pc2Input, permutedChoice2[:]))
    //   }
    for i in 0..16usize {
        let pc2Input: u64 = ((leftRotations[i] as u64) << 28) | (rightRotations[i] as u64);
        c.subkeys[i] = unpack(permuteBlock(pc2Input, &permutedChoice2));
    }
}

// Go: block.go:12
//   func cryptBlock(subkeys []uint64, dst, src []byte, decrypt bool) {
//       b := byteorder.BEUint64(src)
//       b = permuteInitialBlock(b)
//       left, right := uint32(b>>32), uint32(b)
//       left = (left << 1) | (left >> 31)
//       right = (right << 1) | (right >> 31)
//       if decrypt {
//           for i := 0; i < 8; i++ {
//               left, right = feistel(left, right, subkeys[15-2*i], subkeys[15-(2*i+1)])
//           }
//       } else {
//           for i := 0; i < 8; i++ {
//               left, right = feistel(left, right, subkeys[2*i], subkeys[2*i+1])
//           }
//       }
//       left = (left << 31) | (left >> 1)
//       right = (right << 31) | (right >> 1)
//       preOutput := (uint64(right) << 32) | uint64(left)
//       byteorder.BEPutUint64(dst, permuteFinalBlock(preOutput))
//   }
fn cryptBlock(subkeys: &[u64; 16], dst: &mut slice<byte>, src: &slice<byte>, decrypt: bool) {
    // Go: block.go:13 — b := byteorder.BEUint64(src)
    let mut b = beUint64(src);
    // Go: block.go:14 — b = permuteInitialBlock(b)
    b = permuteInitialBlock(b);
    // Go: block.go:15 — left, right := uint32(b>>32), uint32(b)
    let mut left = (b >> 32) as u32;
    let mut right = b as u32;

    // Go: block.go:17 — left = (left << 1) | (left >> 31)
    //                   right = (right << 1) | (right >> 31)
    left = (left << 1) | (left >> 31);
    right = (right << 1) | (right >> 31);

    if decrypt {
        // Go: block.go:21
        //   for i := 0; i < 8; i++ {
        //       left, right = feistel(left, right, subkeys[15-2*i], subkeys[15-(2*i+1)])
        //   }
        for i in 0..8usize {
            let (l, r) = feistel(left, right, subkeys[15 - 2 * i], subkeys[15 - (2 * i + 1)]);
            left = l;
            right = r;
        }
    } else {
        // Go: block.go:25
        //   for i := 0; i < 8; i++ {
        //       left, right = feistel(left, right, subkeys[2*i], subkeys[2*i+1])
        //   }
        for i in 0..8usize {
            let (l, r) = feistel(left, right, subkeys[2 * i], subkeys[2 * i + 1]);
            left = l;
            right = r;
        }
    }

    // Go: block.go:30 — left = (left << 31) | (left >> 1)
    //                   right = (right << 31) | (right >> 1)
    left = (left << 31) | (left >> 1);
    right = (right << 31) | (right >> 1);

    // Go: block.go:34 — preOutput := (uint64(right) << 32) | uint64(left)
    let preOutput: u64 = ((right as u64) << 32) | (left as u64);
    // Go: block.go:35 — byteorder.BEPutUint64(dst, permuteFinalBlock(preOutput))
    bePutUint64(dst, permuteFinalBlock(preOutput));
}

// Go: cipher.go:30
//   func NewCipher(key []byte) (cipher.Block, error) {
//       if fips140only.Enabled { ... }
//       if len(key) != 8 { return nil, KeySizeError(len(key)) }
//       c := new(desCipher)
//       c.generateSubkeys(key)
//       return c, nil
//   }
/// `des.NewCipher` — creates and returns a new DES `cipher::Block`. The
/// key must be exactly 8 bytes; otherwise a `KeySizeError` is returned.
pub fn NewCipher(key: slice<byte>) -> (Option<Cipher>, error) {
    // Go: cipher.go:36 — if len(key) != 8 { return nil, KeySizeError(len(key)) }
    if key.Len() != 8 {
        return (None, Wrap(KeySizeError(key.Len())));
    }
    let mut c = Cipher { subkeys: [0u64; 16] };
    generateSubkeys(&mut c, &key);
    (Some(c), nil)
}

impl BlockTrait for Cipher {
    // Go: cipher.go:45 — func (c *desCipher) BlockSize() int { return BlockSize }
    fn BlockSize(&self) -> int {
        BlockSize
    }

    // Go: cipher.go:47
    //   func (c *desCipher) Encrypt(dst, src []byte) {
    //       if len(src) < BlockSize { panic("crypto/des: input not full block") }
    //       if len(dst) < BlockSize { panic("crypto/des: output not full block") }
    //       cryptBlock(c.subkeys[:], dst, src, false)
    //   }
    fn Encrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        if src.Len() < BlockSize {
            panic!("crypto/des: input not full block");
        }
        if dst.Len() < BlockSize {
            panic!("crypto/des: output not full block");
        }
        cryptBlock(&self.subkeys, dst, &src, false);
    }

    // Go: cipher.go:60
    //   func (c *desCipher) Decrypt(dst, src []byte) {
    //       if len(src) < BlockSize { panic("crypto/des: input not full block") }
    //       if len(dst) < BlockSize { panic("crypto/des: output not full block") }
    //       cryptBlock(c.subkeys[:], dst, src, true)
    //   }
    fn Decrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        if src.Len() < BlockSize {
            panic!("crypto/des: input not full block");
        }
        if dst.Len() < BlockSize {
            panic!("crypto/des: output not full block");
        }
        cryptBlock(&self.subkeys, dst, &src, true);
    }
}

// ─── tripleDESCipher ────────────────────────────────────────────────

// Go: cipher.go:74
//   type tripleDESCipher struct {
//       cipher1, cipher2, cipher3 desCipher
//   }
/// `des.TripleDESCipher` — three-key 3DES (EDE) key schedule. Use
/// `NewTripleDESCipher` to build one. Implements `cipher::Block`.
#[derive(Clone)]
pub struct TripleDESCipher {
    cipher1: Cipher,
    cipher2: Cipher,
    cipher3: Cipher,
}

// Go: cipher.go:79
//   func NewTripleDESCipher(key []byte) (cipher.Block, error) {
//       if fips140only.Enabled { ... }
//       if len(key) != 24 { return nil, KeySizeError(len(key)) }
//       c := new(tripleDESCipher)
//       c.cipher1.generateSubkeys(key[:8])
//       c.cipher2.generateSubkeys(key[8:16])
//       c.cipher3.generateSubkeys(key[16:])
//       return c, nil
//   }
/// `des.NewTripleDESCipher` — creates and returns a new 3DES
/// `cipher::Block`. The key must be exactly 24 bytes (three 8-byte
/// DES sub-keys concatenated); otherwise a `KeySizeError` is returned.
pub fn NewTripleDESCipher(key: slice<byte>) -> (Option<TripleDESCipher>, error) {
    // Go: cipher.go:84 — if len(key) != 24 { return nil, KeySizeError(len(key)) }
    if key.Len() != 24 {
        return (None, Wrap(KeySizeError(key.Len())));
    }
    let mut c = TripleDESCipher {
        cipher1: Cipher { subkeys: [0u64; 16] },
        cipher2: Cipher { subkeys: [0u64; 16] },
        cipher3: Cipher { subkeys: [0u64; 16] },
    };
    let k1 = key.slice(0, 8);
    let k2 = key.slice(8, 16);
    let k3 = key.slice(16, 24);
    generateSubkeys(&mut c.cipher1, &k1);
    generateSubkeys(&mut c.cipher2, &k2);
    generateSubkeys(&mut c.cipher3, &k3);
    (Some(c), nil)
}

impl BlockTrait for TripleDESCipher {
    // Go: cipher.go:95 — func (c *tripleDESCipher) BlockSize() int { return BlockSize }
    fn BlockSize(&self) -> int {
        BlockSize
    }

    // Go: cipher.go:97 — Encrypt: 8 rounds c1 forward, 8 rounds c2
    //   reversed, 8 rounds c3 forward.
    fn Encrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        if src.Len() < BlockSize {
            panic!("crypto/des: input not full block");
        }
        if dst.Len() < BlockSize {
            panic!("crypto/des: output not full block");
        }

        // Go: cipher.go:108 — b := byteorder.BEUint64(src)
        let mut b = beUint64(&src);
        // Go: cipher.go:109 — b = permuteInitialBlock(b)
        b = permuteInitialBlock(b);
        // Go: cipher.go:110 — left, right := uint32(b>>32), uint32(b)
        let mut left = (b >> 32) as u32;
        let mut right = b as u32;

        // Go: cipher.go:112 — left = (left << 1) | (left >> 31); right = ...
        left = (left << 1) | (left >> 31);
        right = (right << 1) | (right >> 31);

        // Go: cipher.go:115 — c1 forward
        for i in 0..8usize {
            let (l, r) = feistel(
                left,
                right,
                self.cipher1.subkeys[2 * i],
                self.cipher1.subkeys[2 * i + 1],
            );
            left = l;
            right = r;
        }
        // Go: cipher.go:118 — c2 reversed (swap left/right)
        for i in 0..8usize {
            let (r2, l2) = feistel(
                right,
                left,
                self.cipher2.subkeys[15 - 2 * i],
                self.cipher2.subkeys[15 - (2 * i + 1)],
            );
            right = r2;
            left = l2;
        }
        // Go: cipher.go:121 — c3 forward
        for i in 0..8usize {
            let (l, r) = feistel(
                left,
                right,
                self.cipher3.subkeys[2 * i],
                self.cipher3.subkeys[2 * i + 1],
            );
            left = l;
            right = r;
        }

        // Go: cipher.go:125 — left = (left << 31) | (left >> 1); right = ...
        left = (left << 31) | (left >> 1);
        right = (right << 31) | (right >> 1);

        // Go: cipher.go:128 — preOutput := (uint64(right) << 32) | uint64(left)
        let preOutput: u64 = ((right as u64) << 32) | (left as u64);
        // Go: cipher.go:129 — byteorder.BEPutUint64(dst, permuteFinalBlock(preOutput))
        bePutUint64(dst, permuteFinalBlock(preOutput));
    }

    // Go: cipher.go:132 — Decrypt: c3 reversed, c2 forward, c1 reversed.
    fn Decrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        if src.Len() < BlockSize {
            panic!("crypto/des: input not full block");
        }
        if dst.Len() < BlockSize {
            panic!("crypto/des: output not full block");
        }

        let mut b = beUint64(&src);
        b = permuteInitialBlock(b);
        let mut left = (b >> 32) as u32;
        let mut right = b as u32;

        left = (left << 1) | (left >> 31);
        right = (right << 1) | (right >> 31);

        // Go: cipher.go:150 — c3 reversed
        for i in 0..8usize {
            let (l, r) = feistel(
                left,
                right,
                self.cipher3.subkeys[15 - 2 * i],
                self.cipher3.subkeys[15 - (2 * i + 1)],
            );
            left = l;
            right = r;
        }
        // Go: cipher.go:153 — c2 forward (swap)
        for i in 0..8usize {
            let (r2, l2) = feistel(
                right,
                left,
                self.cipher2.subkeys[2 * i],
                self.cipher2.subkeys[2 * i + 1],
            );
            right = r2;
            left = l2;
        }
        // Go: cipher.go:156 — c1 reversed
        for i in 0..8usize {
            let (l, r) = feistel(
                left,
                right,
                self.cipher1.subkeys[15 - 2 * i],
                self.cipher1.subkeys[15 - (2 * i + 1)],
            );
            left = l;
            right = r;
        }

        left = (left << 31) | (left >> 1);
        right = (right << 31) | (right >> 1);

        let preOutput: u64 = ((right as u64) << 32) | (left as u64);
        bePutUint64(dst, permuteFinalBlock(preOutput));
    }
}
