// go: file crypto/internal/fips140/sha3/keccakf.go decls: keccakF1600Generic, keccakF1600Lanes, bytesToLanes, lanesToBytes
//
// The Keccak-f[1600] permutation (FIPS 202 §3.2).
//
// Go fully unrolls 24 rounds over named lane variables and, on a
// little-endian target, aliases the `[200]byte` state as `*[25]uint64`
// through `unsafe.Pointer`. goish keeps the rolled θ/ρ+π/χ/ι form and
// loads/stores the lanes explicitly little-endian, which is the same
// computation on amd64 without the pointer cast. The unrolled shape is
// where the assembly port would go.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::math::bits;
use crate::types::{byte, int};

use super::sha3::STATE_BYTES;

// ─── Round constants (keccakf[go]:15-40) ───────────────────────────

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

// Lane rotation offsets (FIPS 202 §3.2.2 Table 2).
const RHO: [int; 25] = [
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
];

// go: none — goish idiom: the lane-level core Go expresses as an
// unrolled block inside keccakF1600Generic. Split out so the byte-array
// entry point stays a thin wrapper.
/// θ / ρ+π / χ / ι over 24 rounds, on 25 lanes of 64 bits.
fn keccakF1600Lanes(a: &mut [u64; 25]) {
    // Go: for i := 0; i < 24; i++ (unrolled 4×6)
    let mut i: usize = 0;
    while i < 24 {
        // θ — column parity
        let mut c = [0u64; 5];
        let mut x: usize = 0;
        while x < 5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            x += 1;
        }
        let mut x: usize = 0;
        while x < 5 {
            let d = c[(x + 4) % 5] ^ bits::RotateLeft64(c[(x + 1) % 5], 1);
            let mut y: usize = 0;
            while y < 25 {
                a[y + x] ^= d;
                y += 5;
            }
            x += 1;
        }

        // ρ + π — rotate + permute lanes
        let mut b = [0u64; 25];
        let mut x: usize = 0;
        while x < 5 {
            let mut y: usize = 0;
            while y < 5 {
                b[((2 * x + 3 * y) % 5) * 5 + y] =
                    bits::RotateLeft64(a[5 * y + x], RHO[5 * y + x]);
                y += 1;
            }
            x += 1;
        }

        // χ — non-linear row mixing
        let mut y: usize = 0;
        while y < 25 {
            let mut x: usize = 0;
            while x < 5 {
                a[y + x] = b[y + x] ^ ((!b[y + (x + 1) % 5]) & b[y + (x + 2) % 5]);
                x += 1;
            }
            y += 5;
        }

        // ι — round constant
        a[0] ^= RC[i];

        i += 1;
    }
}

// ─── Byte ↔ lane conversion (little-endian per FIPS 202 §B.1) ────────

// go: none — goish idiom: Go gets the byte↔lane view for free from the
// `unsafe.Pointer` alias on little-endian targets; goish converts
// explicitly.
fn bytesToLanes(b: &[byte; STATE_BYTES]) -> [u64; 25] {
    let mut a = [0u64; 25];
    let mut i: usize = 0;
    while i < 25 {
        let j = i * 8;
        a[i] = (b[j] as u64)
            | ((b[j + 1] as u64) << 8)
            | ((b[j + 2] as u64) << 16)
            | ((b[j + 3] as u64) << 24)
            | ((b[j + 4] as u64) << 32)
            | ((b[j + 5] as u64) << 40)
            | ((b[j + 6] as u64) << 48)
            | ((b[j + 7] as u64) << 56);
        i += 1;
    }
    a
}

// go: none — goish idiom: Go gets the byte↔lane view for free from the
// `unsafe.Pointer` alias on little-endian targets; goish converts
// explicitly.
fn lanesToBytes(a: &[u64; 25], b: &mut [byte; STATE_BYTES]) {
    let mut i: usize = 0;
    while i < 25 {
        let v = a[i];
        let j = i * 8;
        b[j] = (v & 0xff) as byte;
        b[j + 1] = ((v >> 8) & 0xff) as byte;
        b[j + 2] = ((v >> 16) & 0xff) as byte;
        b[j + 3] = ((v >> 24) & 0xff) as byte;
        b[j + 4] = ((v >> 32) & 0xff) as byte;
        b[j + 5] = ((v >> 40) & 0xff) as byte;
        b[j + 6] = ((v >> 48) & 0xff) as byte;
        b[j + 7] = ((v >> 56) & 0xff) as byte;
        i += 1;
    }
}


// go: sdk 1.25.5 crypto/internal/fips140/sha3/keccakf.go:43-431 keccakF1600Generic
/// Go: `func keccakF1600Generic(da *[200]byte)`
///
/// Go aliases `da` as `*[25]uint64` on little-endian targets; goish does
/// the equivalent explicit little-endian load/permute/store.
pub(crate) fn keccakF1600Generic(da: &mut [byte; STATE_BYTES]) {
    let mut lanes = bytesToLanes(da);
    keccakF1600Lanes(&mut lanes);
    lanesToBytes(&lanes, da);
}
