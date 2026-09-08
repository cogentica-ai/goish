// goishlint:ignore GOISH021 — feistelBoxOnce has no separate Rust binding:
// no_std has no sync::Once, so the Once and the feistelBox array collapse
// into one SpinLock<Option<..>> named feistelBox (see its anchor below).
// go: file crypto/des/block.go decls: cryptBlock, feistel, permuteBlock, initFeistelBox, permuteInitialBlock, permuteFinalBlock, ksRotate, desCipher.generateSubkeys, unpack, ensureFeistelBox, fb_lookup, beUint64, bePutUint64
//
// Deviations from block.go @ Go 1.25.5:
//
//   * `feistelBoxOnce` (a `sync.Once`) becomes a `SpinLock<Option<..>>`
//     guarding lazy init of the 8x64 u32 feistelBox — no_std has no
//     `sync::Once`. Same end behaviour: materialised on first key
//     schedule, shared thereafter. `ensureFeistelBox` / `fb_lookup` are
//     the accessors that discipline implies.
//   * `generateSubkeys` is a free fn taking `&mut Cipher` rather than a
//     `(c *desCipher)` method, so it can live in this file while the
//     struct is declared in cipher.rs (Go has no such constraint).
//   * `beUint64` / `bePutUint64` stand in for `byteorder.BEUint64` /
//     `BEPutUint64`; goish has no crypto/internal/fips140deps/byteorder
//     package yet (Wave C).

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;

use alloc::boxed::Box;

use crate::goslice::slice;
use crate::runtime::spin::SpinLock;
use crate::types::byte;

use super::cipher::Cipher;
use super::konst::{ksRotations, permutationFunction, permutedChoice1, permutedChoice2, sBoxes};

// go: sdk 1.25.5 crypto/des/block.go:72-72 feistelBox
//
//   var feistelBox [8][64]uint32
//   var feistelBoxOnce sync.Once
//
// One SpinLock<Option<..>> carries both Go vars: `None` is the
// pre-`feistelBoxOnce` state, `Some` the materialised table. no_std has
// no sync::Once, so the Once and the array collapse into one cell.
static feistelBox: SpinLock<Option<Box<[[u32; 64]; 8]>>> = SpinLock::new(None);

// go: sdk 1.25.5 crypto/des/block.go:77-83 permuteBlock
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

// go: sdk 1.25.5 crypto/des/block.go:85-105 initFeistelBox
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

// go: none — accessor implied by replacing Go's `feistelBoxOnce sync.Once`
// with a SpinLock<Option<..>> (no_std has no sync::Once).
/// Lazily materialise (or fetch) the global feistelBox. Idempotent.
fn ensureFeistelBox() {
    let mut g = feistelBox.lock();
    if g.is_none() {
        *g = Some(initFeistelBox());
    }
}

// go: none — accessor implied by the SpinLock-guarded feistelBox; Go
// indexes the package-level `feistelBox` array directly.
/// Read-only access to the materialised feistelBox.
#[inline]
fn fb_lookup(s: usize, t: u32) -> u32 {
    let g = feistelBox.lock();
    // SAFETY (logical): callers always invoke ensureFeistelBox() first
    // (via generateSubkeys at NewCipher time) before reaching the
    // feistel rounds.
    g.as_ref().unwrap()[s][(t & 0x3f) as usize]
}

// go: sdk 1.25.5 crypto/des/block.go:40-68 feistel
//   func feistel(l, r uint32, k0, k1 uint64) (lout, rout uint32) {
//       var t uint32
//       t = r ^ uint32(k0>>32)
//       l ^= feistelBox[7][t&0x3f] ^ feistelBox[5][(t>>8)&0x3f] ^ ...
//       ...
//       return l, r
//   }
pub(crate) fn feistel(mut l: u32, mut r: u32, k0: u64, k1: u64) -> (u32, u32) {
    let mut t: u32;

    // Go: block.go:43 — t = r ^ uint32(k0>>32)
    t = r ^ ((k0 >> 32) as u32);
    // Go: block.go:44
    //   l ^= feistelBox[7][t&0x3f] ^ feistelBox[5][(t>>8)&0x3f]
    //        ^ feistelBox[3][(t>>16)&0x3f] ^ feistelBox[1][(t>>24)&0x3f]
    l ^= fb_lookup(7, t) ^ fb_lookup(5, t >> 8) ^ fb_lookup(3, t >> 16) ^ fb_lookup(1, t >> 24);

    // Go: block.go:49 — t = ((r << 28) | (r >> 4)) ^ uint32(k0)
    t = ((r << 28) | (r >> 4)) ^ (k0 as u32);
    // Go: block.go:50
    //   l ^= feistelBox[6][t&0x3f] ^ feistelBox[4][(t>>8)&0x3f]
    //        ^ feistelBox[2][(t>>16)&0x3f] ^ feistelBox[0][(t>>24)&0x3f]
    l ^= fb_lookup(6, t) ^ fb_lookup(4, t >> 8) ^ fb_lookup(2, t >> 16) ^ fb_lookup(0, t >> 24);

    // Go: block.go:55 — t = l ^ uint32(k1>>32)
    t = l ^ ((k1 >> 32) as u32);
    // Go: block.go:56
    //   r ^= feistelBox[7][t&0x3f] ^ feistelBox[5][(t>>8)&0x3f]
    //        ^ feistelBox[3][(t>>16)&0x3f] ^ feistelBox[1][(t>>24)&0x3f]
    r ^= fb_lookup(7, t) ^ fb_lookup(5, t >> 8) ^ fb_lookup(3, t >> 16) ^ fb_lookup(1, t >> 24);

    // Go: block.go:61 — t = ((l << 28) | (l >> 4)) ^ uint32(k1)
    t = ((l << 28) | (l >> 4)) ^ (k1 as u32);
    // Go: block.go:62
    //   r ^= feistelBox[6][t&0x3f] ^ feistelBox[4][(t>>8)&0x3f]
    //        ^ feistelBox[2][(t>>16)&0x3f] ^ feistelBox[0][(t>>24)&0x3f]
    r ^= fb_lookup(6, t) ^ fb_lookup(4, t >> 8) ^ fb_lookup(2, t >> 16) ^ fb_lookup(0, t >> 24);

    (l, r)
}

// go: sdk 1.25.5 crypto/des/block.go:109-173 permuteInitialBlock
// Go: block.go:109 — bit-tricks unroll of initialPermutation.
pub(crate) fn permuteInitialBlock(mut block: u64) -> u64 {
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

// go: sdk 1.25.5 crypto/des/block.go:177-199 permuteFinalBlock
// Go: block.go:177 — bit-tricks reverse of permuteInitialBlock.
pub(crate) fn permuteFinalBlock(mut block: u64) -> u64 {
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

// go: sdk 1.25.5 crypto/des/block.go:203-214 ksRotate
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

// go: sdk 1.25.5 crypto/des/block.go:240-249 unpack
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

// go: none — stands in for `byteorder.BEUint64`; goish has no
// crypto/internal/fips140deps/byteorder package yet (Wave C).
pub(crate) fn beUint64(b: &slice<byte>) -> u64 {
    ((b[0] as u64) << 56)
        | ((b[1] as u64) << 48)
        | ((b[2] as u64) << 40)
        | ((b[3] as u64) << 32)
        | ((b[4] as u64) << 24)
        | ((b[5] as u64) << 16)
        | ((b[6] as u64) << 8)
        | (b[7] as u64)
}

// go: none — stands in for `byteorder.BEPutUint64`; see beUint64.
pub(crate) fn bePutUint64(b: &mut slice<byte>, v: u64) {
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

// go: sdk 1.25.5 crypto/des/block.go:217-239 desCipher.generateSubkeys
//
//   func (c *desCipher) generateSubkeys(keyBytes []byte)
pub(crate) fn generateSubkeys(c: &mut Cipher, keyBytes: &slice<byte>) {
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

// go: sdk 1.25.5 crypto/des/block.go:12-36 cryptBlock
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
pub(crate) fn cryptBlock(
    subkeys: &[u64; 16],
    dst: &mut slice<byte>,
    src: &slice<byte>,
    decrypt: bool,
) {
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
