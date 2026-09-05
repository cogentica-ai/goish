// xxh3 — port of github.com/zeebo/xxh3 (v1.1.0, itself a Go port of
// the XXH3 reference), the content-hashing dependency typescript-go
// uses for file/config/AST identity (fileloader, checker, parsecache,
// incremental snapshots, overlayfs).
//
// Anchors (module cache, github.com/zeebo/xxh3@v1.1.0):
//   - Uint128 / primitives:     utils.go
//   - key material / primes:    consts.go (every key64_* constant is
//                               a little-endian read of the 192-byte
//                               key array; this port derives them
//                               from one KEY table via `k64`)
//   - one-shot 128-bit:         hash128.go hashAny128
//   - scalar accumulation:      accum_generic.go accumScalar /
//                               accumBlockScalar (the unrolled Go
//                               bodies collapse to the lane loops
//                               below — same operations, same order)
//   - streaming:                hasher.go (1024+64-byte buffer with
//                               64-byte carry so finalization's
//                               backward stripe read always has
//                               data), hasher128.go
//
// Scope (surface-driven, like the rest of the tsgo campaign): the
// 128-bit API only — Hash128 / HashString128 / Uint128 / Hasher
// {Write, WriteString, Sum64, Sum128, Reset} — which is every xxh3 call
// typescript-go makes. Deferred until a consumer appears: the 64-bit
// one-shots/Sum64, seeded variants, and the SIMD accumulators (this
// is the scalar path; a perf lever if hashing ever profiles hot).
//
// Verified bit-exact against the Go zeebo/xxh3 binary — see
// examples/xxh3_smoke.rs (differential vectors) and the commit
// message (cross-language sweep).

#![allow(non_snake_case)]

extern crate alloc;

use crate::errors::{error, nil};
use crate::types::{byte, int};

const STRIPE: usize = 64;
const BLOCK: usize = 1024;

const PRIME32_1: u64 = 2654435761;
const PRIME32_2: u64 = 2246822519;
const PRIME32_3: u64 = 3266489917;

const PRIME64_1: u64 = 11400714785074694791;
const PRIME64_2: u64 = 14029467366897019727;
const PRIME64_3: u64 = 1609587929392839161;
const PRIME64_4: u64 = 9650029242287828579;
const PRIME64_5: u64 = 2870177450012600261;

/// The XXH3 default secret (consts.go `key`).
const KEY: [u8; 192] = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
];

#[inline(always)]
fn read_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}

#[inline(always)]
fn read_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// consts.go key64_NNN — little-endian u64 at byte offset `o` of KEY.
#[inline(always)]
fn k64(o: usize) -> u64 {
    read_u64(&KEY, o)
}

#[inline(always)]
fn k32(o: usize) -> u32 {
    read_u32(&KEY, o)
}

// utils.go mulFold64.
#[inline(always)]
fn mul_fold64(x: u64, y: u64) -> u64 {
    let p = (x as u128).wrapping_mul(y as u128);
    (p as u64) ^ ((p >> 64) as u64)
}

// utils.go rrmxmx.
#[inline(always)]
fn rrmxmx(mut h64: u64, len: u64) -> u64 {
    h64 ^= h64.rotate_left(49) ^ h64.rotate_left(24);
    h64 = h64.wrapping_mul(0x9fb21c651e98df25);
    h64 ^= (h64 >> 35).wrapping_add(len);
    h64 = h64.wrapping_mul(0x9fb21c651e98df25);
    h64 ^= h64 >> 28;
    h64
}

// utils.go xxh3Avalanche.
#[inline(always)]
fn xxh3_avalanche(mut x: u64) -> u64 {
    x ^= x >> 37;
    x = x.wrapping_mul(0x165667919e3779f9);
    x ^= x >> 32;
    x
}

// utils.go xxh64AvalancheSmall.
#[inline(always)]
fn xxh64_avalanche_small(mut x: u64) -> u64 {
    x = x.wrapping_mul(PRIME64_2);
    x ^= x >> 29;
    x = x.wrapping_mul(PRIME64_3);
    x ^= x >> 32;
    x
}

/// `xxh3.Uint128` (utils.go:11) — a 128-bit hash value, thought of
/// as `Hi<<64 | Lo`. Comparable; the zero value is `Uint128{}`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Uint128 {
    pub Hi: u64,
    pub Lo: u64,
}

impl Uint128 {
    /// `Uint128.Bytes()` (utils.go:16) — canonical big-endian form.
    pub fn Bytes(&self) -> [byte; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.Hi.to_be_bytes());
        out[8..].copy_from_slice(&self.Lo.to_be_bytes());
        out
    }
}

/// `xxh3.Hash(b)` (hash64.go:6) — one-shot 64-bit hash.
pub fn Hash(b: impl AsRef<[byte]>) -> u64 {
    hash_any_64(b.as_ref())
}

/// `xxh3.HashString(s)` (hash64.go:11) — one-shot 64-bit hash of a
/// string (accepts goish `string`, `&str`, `String`).
pub fn HashString<S: AsRef<[byte]>>(s: S) -> u64 {
    hash_any_64(s.as_ref())
}

// hash64.go hashAny — the size-class dispatch. Mirrors hash_any_128
// below; the two share every helper and differ only in finalization.
fn hash_any_64(p: &[u8]) -> u64 {
    let l = p.len();
    let mut acc: u64;

    if l <= 16 {
        if l > 8 {
            // 9-16
            let inputlo = read_u64(p, 0) ^ (k64(24) ^ k64(32));
            let inputhi = read_u64(p, l - 8) ^ (k64(40) ^ k64(48));
            let folded = mul_fold64(inputlo, inputhi);
            return xxh3_avalanche(
                (l as u64)
                    .wrapping_add(inputlo.swap_bytes())
                    .wrapping_add(inputhi)
                    .wrapping_add(folded),
            );
        }
        if l > 3 {
            // 4-8
            let input1 = read_u32(p, 0);
            let input2 = read_u32(p, l - 4);
            let input64 = (input2 as u64).wrapping_add((input1 as u64) << 32);
            let keyed = input64 ^ (k64(8) ^ k64(16));
            return rrmxmx(keyed, l as u64);
        }
        match l {
            3 => {
                let c12 = u16::from_le_bytes([p[0], p[1]]) as u64;
                let c3 = p[2] as u64;
                acc = (c12 << 16).wrapping_add(c3).wrapping_add(3 << 8);
            }
            2 => {
                let c12 = u16::from_le_bytes([p[0], p[1]]) as u64;
                acc = (c12.wrapping_mul((1 << 24) + 1) >> 8).wrapping_add(2 << 8);
            }
            1 => {
                let c1 = p[0] as u64;
                acc = c1
                    .wrapping_mul((1 << 24) + (1 << 16) + 1)
                    .wrapping_add(1 << 8);
            }
            _ => {
                // 0 — xxh_avalanche(key64_056 ^ key64_064)
                return 0x2d06800538d394c2;
            }
        }
        acc ^= (k32(0) ^ k32(4)) as u64;
        return xxh64_avalanche_small(acc);
    }

    if l <= 128 {
        acc = (l as u64).wrapping_mul(PRIME64_1);

        if l > 32 {
            if l > 64 {
                if l > 96 {
                    acc = acc.wrapping_add(mul_fold64(
                        read_u64(p, 6 * 8) ^ k64(96),
                        read_u64(p, 7 * 8) ^ k64(104),
                    ));
                    acc = acc.wrapping_add(mul_fold64(
                        read_u64(p, l - 8 * 8) ^ k64(112),
                        read_u64(p, l - 7 * 8) ^ k64(120),
                    ));
                } // 96
                acc = acc.wrapping_add(mul_fold64(
                    read_u64(p, 4 * 8) ^ k64(64),
                    read_u64(p, 5 * 8) ^ k64(72),
                ));
                acc = acc.wrapping_add(mul_fold64(
                    read_u64(p, l - 6 * 8) ^ k64(80),
                    read_u64(p, l - 5 * 8) ^ k64(88),
                ));
            } // 64
            acc = acc.wrapping_add(mul_fold64(
                read_u64(p, 2 * 8) ^ k64(32),
                read_u64(p, 3 * 8) ^ k64(40),
            ));
            acc = acc.wrapping_add(mul_fold64(
                read_u64(p, l - 4 * 8) ^ k64(48),
                read_u64(p, l - 3 * 8) ^ k64(56),
            ));
        } // 32
        acc = acc.wrapping_add(mul_fold64(read_u64(p, 0) ^ k64(0), read_u64(p, 8) ^ k64(8)));
        acc = acc.wrapping_add(mul_fold64(
            read_u64(p, l - 2 * 8) ^ k64(16),
            read_u64(p, l - 8) ^ k64(24),
        ));

        return xxh3_avalanche(acc);
    }

    if l <= 240 {
        acc = (l as u64).wrapping_mul(PRIME64_1);

        for i in 0..8usize {
            acc = acc.wrapping_add(mul_fold64(
                read_u64(p, i * 16) ^ k64(i * 16),
                read_u64(p, i * 16 + 8) ^ k64(i * 16 + 8),
            ));
        }

        // avalanche
        acc = xxh3_avalanche(acc);

        // trailing groups after 128
        let top = l & !15;
        let mut i = 8 * 16;
        while i < top {
            acc = acc.wrapping_add(mul_fold64(
                read_u64(p, i) ^ read_u64(&KEY, i - 125),
                read_u64(p, i + 8) ^ read_u64(&KEY, i - 117),
            ));
            i += 16;
        }

        // last 16 bytes
        acc = acc.wrapping_add(mul_fold64(
            read_u64(p, l - 16) ^ k64(119),
            read_u64(p, l - 8) ^ k64(127),
        ));

        return xxh3_avalanche(acc);
    }

    acc = (l as u64).wrapping_mul(PRIME64_1);
    let mut accs = INITIAL_ACCS;
    accum_scalar(&mut accs, p);
    merge_accs_64(acc, &accs)
}

// hash64.go's merge-accs tail, shared by hashAny and Hasher.Sum64.
fn merge_accs_64(mut acc: u64, accs: &[u64; 8]) -> u64 {
    acc = acc.wrapping_add(mul_fold64(accs[0] ^ k64(11), accs[1] ^ k64(19)));
    acc = acc.wrapping_add(mul_fold64(accs[2] ^ k64(27), accs[3] ^ k64(35)));
    acc = acc.wrapping_add(mul_fold64(accs[4] ^ k64(43), accs[5] ^ k64(51)));
    acc = acc.wrapping_add(mul_fold64(accs[6] ^ k64(59), accs[7] ^ k64(67)));
    xxh3_avalanche(acc)
}

/// `xxh3.Hash128(b)` (hash128.go:8) — one-shot 128-bit hash.
pub fn Hash128(b: impl AsRef<[byte]>) -> Uint128 {
    hash_any_128(b.as_ref())
}

/// `xxh3.HashString128(s)` (hash128.go:13) — one-shot 128-bit hash
/// of a string (accepts goish `string`, `&str`, `String`).
pub fn HashString128<S: AsRef<[byte]>>(s: S) -> Uint128 {
    hash_any_128(s.as_ref())
}

// hash128.go hashAny128 — the size-class dispatch.
fn hash_any_128(p: &[u8]) -> Uint128 {
    let l = p.len();
    let mut acc = Uint128::default();

    if l <= 16 {
        if l > 8 {
            // 9-16
            let bitflipl = k64(32) ^ k64(40);
            let bitfliph = k64(48) ^ k64(56);

            let input_lo = read_u64(p, 0);
            let mut input_hi = read_u64(p, l - 8);

            let m = ((input_lo ^ input_hi ^ bitflipl) as u128).wrapping_mul(PRIME64_1 as u128);
            let mut m128_l = m as u64;
            let mut m128_h = (m >> 64) as u64;

            m128_l = m128_l.wrapping_add(((l - 1) as u64) << 54);
            input_hi ^= bitfliph;

            m128_h = m128_h
                .wrapping_add(input_hi)
                .wrapping_add(((input_hi as u32) as u64).wrapping_mul(PRIME32_2 - 1));

            m128_l ^= m128_h.swap_bytes();

            let m2 = (m128_l as u128).wrapping_mul(PRIME64_2 as u128);
            acc.Lo = m2 as u64;
            acc.Hi = ((m2 >> 64) as u64).wrapping_add(m128_h.wrapping_mul(PRIME64_2));

            acc.Lo = xxh3_avalanche(acc.Lo);
            acc.Hi = xxh3_avalanche(acc.Hi);
            return acc;
        }
        if l > 3 {
            // 4-8
            let bitflip = k64(16) ^ k64(24);

            let input_lo = read_u32(p, 0);
            let input_hi = read_u32(p, l - 4);
            let input_64 = (input_lo as u64) | ((input_hi as u64) << 32);
            let keyed = input_64 ^ bitflip;

            let m = (keyed as u128).wrapping_mul((PRIME64_1.wrapping_add((l as u64) << 2)) as u128);
            acc.Lo = m as u64;
            acc.Hi = (m >> 64) as u64;

            acc.Hi = acc.Hi.wrapping_add(acc.Lo << 1);
            acc.Lo ^= acc.Hi >> 3;

            acc.Lo ^= acc.Lo >> 35;
            acc.Lo = acc.Lo.wrapping_mul(0x9fb21c651e98df25);
            acc.Lo ^= acc.Lo >> 28;
            acc.Hi = xxh3_avalanche(acc.Hi);
            return acc;
        }
        match l {
            3 => {
                let c12 = u16::from_le_bytes([p[0], p[1]]) as u64;
                let c3 = p[2] as u64;
                acc.Lo = (c12 << 16).wrapping_add(c3).wrapping_add(3 << 8);
            }
            2 => {
                let c12 = u16::from_le_bytes([p[0], p[1]]) as u64;
                acc.Lo = c12.wrapping_mul((1 << 24) + 1) >> 8;
                acc.Lo = acc.Lo.wrapping_add(2 << 8);
            }
            1 => {
                let c1 = p[0] as u64;
                acc.Lo = c1
                    .wrapping_mul((1 << 24) + (1 << 16) + 1)
                    .wrapping_add(1 << 8);
            }
            _ => {
                // 0
                return Uint128 {
                    Hi: 0x99aa06d3014798d8,
                    Lo: 0x6001c324468d497f,
                };
            }
        }
        acc.Hi = ((acc.Lo as u32).swap_bytes().rotate_left(13)) as u64;
        acc.Lo ^= (k32(0) ^ k32(4)) as u64;
        acc.Hi ^= (k32(8) ^ k32(12)) as u64;

        acc.Lo = xxh64_avalanche_small(acc.Lo);
        acc.Hi = xxh64_avalanche_small(acc.Hi);
        return acc;
    }

    if l <= 128 {
        acc.Lo = (l as u64).wrapping_mul(PRIME64_1);

        if l > 32 {
            if l > 64 {
                if l > 96 {
                    let (in8, in7) = (read_u64(p, l - 8 * 8), read_u64(p, l - 7 * 8));
                    let (i6, i7) = (read_u64(p, 6 * 8), read_u64(p, 7 * 8));

                    acc.Hi = acc
                        .Hi
                        .wrapping_add(mul_fold64(in8 ^ k64(112), in7 ^ k64(120)));
                    acc.Hi ^= i6.wrapping_add(i7);
                    acc.Lo = acc.Lo.wrapping_add(mul_fold64(i6 ^ k64(96), i7 ^ k64(104)));
                    acc.Lo ^= in8.wrapping_add(in7);
                }
                let (in6, in5) = (read_u64(p, l - 6 * 8), read_u64(p, l - 5 * 8));
                let (i4, i5) = (read_u64(p, 4 * 8), read_u64(p, 5 * 8));

                acc.Hi = acc
                    .Hi
                    .wrapping_add(mul_fold64(in6 ^ k64(80), in5 ^ k64(88)));
                acc.Hi ^= i4.wrapping_add(i5);
                acc.Lo = acc.Lo.wrapping_add(mul_fold64(i4 ^ k64(64), i5 ^ k64(72)));
                acc.Lo ^= in6.wrapping_add(in5);
            }
            let (in4, in3) = (read_u64(p, l - 4 * 8), read_u64(p, l - 3 * 8));
            let (i2, i3) = (read_u64(p, 2 * 8), read_u64(p, 3 * 8));

            acc.Hi = acc
                .Hi
                .wrapping_add(mul_fold64(in4 ^ k64(48), in3 ^ k64(56)));
            acc.Hi ^= i2.wrapping_add(i3);
            acc.Lo = acc.Lo.wrapping_add(mul_fold64(i2 ^ k64(32), i3 ^ k64(40)));
            acc.Lo ^= in4.wrapping_add(in3);
        }
        let (in2, in1) = (read_u64(p, l - 2 * 8), read_u64(p, l - 1 * 8));
        let (i0, i1) = (read_u64(p, 0), read_u64(p, 8));

        acc.Hi = acc
            .Hi
            .wrapping_add(mul_fold64(in2 ^ k64(16), in1 ^ k64(24)));
        acc.Hi ^= i0.wrapping_add(i1);
        acc.Lo = acc.Lo.wrapping_add(mul_fold64(i0 ^ k64(0), i1 ^ k64(8)));
        acc.Lo ^= in2.wrapping_add(in1);

        let (new_hi, new_lo) = (
            (acc.Lo.wrapping_mul(PRIME64_1))
                .wrapping_add(acc.Hi.wrapping_mul(PRIME64_4))
                .wrapping_add((l as u64).wrapping_mul(PRIME64_2)),
            acc.Hi.wrapping_add(acc.Lo),
        );
        acc.Hi = new_hi;
        acc.Lo = new_lo;

        acc.Hi = xxh3_avalanche(acc.Hi).wrapping_neg();
        acc.Lo = xxh3_avalanche(acc.Lo);
        return acc;
    }

    if l <= 240 {
        acc.Lo = (l as u64).wrapping_mul(PRIME64_1);

        // First 128 bytes: four fixed 32-byte groups.
        for g in 0..4usize {
            let (i0, i1, i2, i3) = (
                read_u64(p, g * 32),
                read_u64(p, g * 32 + 8),
                read_u64(p, g * 32 + 16),
                read_u64(p, g * 32 + 24),
            );
            let ko = g * 32;
            acc.Hi = acc
                .Hi
                .wrapping_add(mul_fold64(i2 ^ k64(ko + 16), i3 ^ k64(ko + 24)));
            acc.Hi ^= i0.wrapping_add(i1);
            acc.Lo = acc
                .Lo
                .wrapping_add(mul_fold64(i0 ^ k64(ko), i1 ^ k64(ko + 8)));
            acc.Lo ^= i2.wrapping_add(i3);
        }

        acc.Hi = xxh3_avalanche(acc.Hi);
        acc.Lo = xxh3_avalanche(acc.Lo);

        // Trailing 32-byte groups after 128 (secret offset i-125…).
        let top = l & !31;
        let mut i = 4 * 32;
        while i < top {
            let (i0, i1, i2, i3) = (
                read_u64(p, i),
                read_u64(p, i + 8),
                read_u64(p, i + 16),
                read_u64(p, i + 24),
            );
            let (kk0, kk1, kk2, kk3) = (k64(i - 125), k64(i - 117), k64(i - 109), k64(i - 101));

            acc.Hi = acc.Hi.wrapping_add(mul_fold64(i2 ^ kk2, i3 ^ kk3));
            acc.Hi ^= i0.wrapping_add(i1);
            acc.Lo = acc.Lo.wrapping_add(mul_fold64(i0 ^ kk0, i1 ^ kk1));
            acc.Lo ^= i2.wrapping_add(i3);
            i += 32;
        }

        // Last 32 bytes.
        {
            let (i0, i1, i2, i3) = (
                read_u64(p, l - 32),
                read_u64(p, l - 24),
                read_u64(p, l - 16),
                read_u64(p, l - 8),
            );
            acc.Hi = acc
                .Hi
                .wrapping_add(mul_fold64(i0 ^ k64(119), i1 ^ k64(127)));
            acc.Hi ^= i2.wrapping_add(i3);
            acc.Lo = acc
                .Lo
                .wrapping_add(mul_fold64(i2 ^ k64(103), i3 ^ k64(111)));
            acc.Lo ^= i0.wrapping_add(i1);
        }

        let (new_hi, new_lo) = (
            (acc.Lo.wrapping_mul(PRIME64_1))
                .wrapping_add(acc.Hi.wrapping_mul(PRIME64_4))
                .wrapping_add((l as u64).wrapping_mul(PRIME64_2)),
            acc.Hi.wrapping_add(acc.Lo),
        );
        acc.Hi = new_hi;
        acc.Lo = new_lo;

        acc.Hi = xxh3_avalanche(acc.Hi).wrapping_neg();
        acc.Lo = xxh3_avalanche(acc.Lo);
        return acc;
    }

    // > 240: 8-lane accumulation.
    acc.Lo = (l as u64).wrapping_mul(PRIME64_1);
    acc.Hi = !((l as u64).wrapping_mul(PRIME64_2));

    let mut accs = INITIAL_ACCS;
    accum_scalar(&mut accs, p);
    merge_accs_128(&accs, acc)
}

const INITIAL_ACCS: [u64; 8] = [
    PRIME32_3, PRIME64_1, PRIME64_2, PRIME64_3, PRIME64_4, PRIME32_2, PRIME64_5, PRIME32_1,
];

// hash128.go "merge accs" tail (also Sum128's blk>0 path).
fn merge_accs_128(accs: &[u64; 8], mut acc: Uint128) -> Uint128 {
    acc.Lo = acc
        .Lo
        .wrapping_add(mul_fold64(accs[0] ^ k64(11), accs[1] ^ k64(19)));
    acc.Hi = acc
        .Hi
        .wrapping_add(mul_fold64(accs[0] ^ k64(117), accs[1] ^ k64(125)));

    acc.Lo = acc
        .Lo
        .wrapping_add(mul_fold64(accs[2] ^ k64(27), accs[3] ^ k64(35)));
    acc.Hi = acc
        .Hi
        .wrapping_add(mul_fold64(accs[2] ^ k64(133), accs[3] ^ k64(141)));

    acc.Lo = acc
        .Lo
        .wrapping_add(mul_fold64(accs[4] ^ k64(43), accs[5] ^ k64(51)));
    acc.Hi = acc
        .Hi
        .wrapping_add(mul_fold64(accs[4] ^ k64(149), accs[5] ^ k64(157)));

    acc.Lo = acc
        .Lo
        .wrapping_add(mul_fold64(accs[6] ^ k64(59), accs[7] ^ k64(67)));
    acc.Hi = acc
        .Hi
        .wrapping_add(mul_fold64(accs[6] ^ k64(165), accs[7] ^ k64(173)));

    acc.Lo = xxh3_avalanche(acc.Lo);
    acc.Hi = xxh3_avalanche(acc.Hi);
    acc
}

// One 64-byte stripe at `data[off..]` with the secret at byte offset
// `koff` (accum_generic.go stripe bodies — the unrolled Go pairs
// collapse to this lane loop: acc[i] gets the 32x32 product of the
// keyed word, acc[i^1] gets the raw word).
#[inline(always)]
fn stripe(accs: &mut [u64; 8], data: &[u8], off: usize, koff: usize) {
    for i in 0..8 {
        let dv = read_u64(data, off + 8 * i);
        let dk = dv ^ k64(koff + 8 * i);
        accs[i ^ 1] = accs[i ^ 1].wrapping_add(dv);
        accs[i] = accs[i].wrapping_add(((dk as u32) as u64).wrapping_mul(dk >> 32));
    }
}

// accum_generic.go scramble step (after each 1024-byte block):
// acc ^= acc>>47; acc ^= key[128+8i]; acc *= prime32_1.
#[inline(always)]
fn scramble(accs: &mut [u64; 8]) {
    for i in 0..8 {
        let mut a = accs[i];
        a ^= a >> 47;
        a ^= k64(128 + 8 * i);
        a = a.wrapping_mul(PRIME32_1);
        accs[i] = a;
    }
}

// accum_generic.go accumBlockScalar — one full 1024-byte block
// (16 stripes, secret advancing 8 bytes per stripe) + scramble.
fn accum_block(accs: &mut [u64; 8], data: &[u8], off: usize) {
    for j in 0..16 {
        stripe(accs, data, off + STRIPE * j, 8 * j);
    }
    scramble(accs);
}

// accum_generic.go accumScalar — full blocks, then the remaining
// whole stripes, then the final (possibly overlapping) stripe read
// backward from the input end at secret offset 121.
fn accum_scalar(accs: &mut [u64; 8], data: &[u8]) {
    let total = data.len();
    let mut off = 0usize;
    let mut l = total;

    while l > BLOCK {
        accum_block(accs, data, off);
        off += BLOCK;
        l -= BLOCK;
    }

    if l > 0 {
        let t = (l - 1) / STRIPE;
        for j in 0..t {
            stripe(accs, data, off + STRIPE * j, 8 * j);
        }
        // Final stripe: the last 64 bytes of the input (may overlap
        // the stripes above), keys at fixed offset 121.
        stripe(accs, data, total - STRIPE, 121);
    }
}

// ─── streaming (hasher.go / hasher128.go) ────────────────────────────

/// `xxh3.Hasher` (hasher.go:9) — streaming XXH3 state. goish scope:
/// the 128-bit surface (`Sum128`); see the module header.
pub struct Hasher {
    acc: [u64; 8],
    blk: u64,
    len: usize,
    buf: [u8; BLOCK + STRIPE],
}

/// `xxh3.New()` (hasher.go:24).
pub fn New() -> Hasher {
    Hasher {
        acc: INITIAL_ACCS,
        blk: 0,
        len: 0,
        buf: [0; BLOCK + STRIPE],
    }
}

impl Default for Hasher {
    fn default() -> Self {
        New()
    }
}

impl Hasher {
    /// `Hasher.Reset()` (hasher.go:44).
    pub fn Reset(&mut self) {
        self.acc = INITIAL_ACCS;
        self.blk = 0;
        self.len = 0;
    }

    /// `Hasher.BlockSize()` (hasher.go:74).
    pub fn BlockSize(&self) -> int {
        STRIPE as int
    }

    /// `Hasher.Write(buf)` (hasher.go:89) — never errors.
    pub fn Write(&mut self, buf: impl AsRef<[byte]>) -> (int, error) {
        let b = buf.as_ref();
        self.update(b);
        (b.len() as int, nil)
    }

    /// `Hasher.WriteString(buf)` (hasher.go:96) — never errors.
    pub fn WriteString<S: AsRef<[byte]>>(&mut self, buf: S) -> (int, error) {
        let b = buf.as_ref();
        self.update(b);
        (b.len() as int, nil)
    }

    // hasher.go updateString.
    fn update(&mut self, mut buf: &[u8]) {
        // First writes: consume whole blocks without copying while
        // the buffer is empty.
        while self.len == 0 && buf.len() > self.buf.len() {
            accum_block(&mut self.acc, buf, 0);
            buf = &buf[BLOCK..];
            self.blk += 1;
        }

        while !buf.is_empty() {
            if self.len < self.buf.len() {
                let n = (self.buf.len() - self.len).min(buf.len());
                self.buf[self.len..self.len + n].copy_from_slice(&buf[..n]);
                self.len += n;
                buf = &buf[n..];
                continue;
            }

            // Buffer full (1024+64): hash the first block, carry the
            // 64-byte tail down so finalization can always read a
            // whole trailing stripe.
            let (head, tail) = self.buf.split_at_mut(BLOCK);
            accum_block(&mut self.acc, head, 0);
            self.blk += 1;
            head[..STRIPE].copy_from_slice(tail);
            self.len = STRIPE;
        }
    }

    /// `Hasher.Sum64()` (hasher.go:131) — the 64-bit hash of the
    /// written data. Does not change the hash state.
    pub fn Sum64(&self) -> u64 {
        if self.blk == 0 {
            return hash_any_64(&self.buf[..self.len]);
        }

        let l = self
            .blk
            .wrapping_mul(BLOCK as u64)
            .wrapping_add(self.len as u64);
        let acc = l.wrapping_mul(PRIME64_1);
        let mut accs = self.acc;

        if self.len > 0 {
            accum_scalar(&mut accs, &self.buf[..self.len]);
        }

        merge_accs_64(acc, &accs)
    }

    /// `Hasher.Sum128()` (hasher.go:205) — the 128-bit hash of the
    /// written data. Does not change the hash state.
    pub fn Sum128(&self) -> Uint128 {
        if self.blk == 0 {
            return hash_any_128(&self.buf[..self.len]);
        }

        let l = self
            .blk
            .wrapping_mul(BLOCK as u64)
            .wrapping_add(self.len as u64);
        let acc = Uint128 {
            Lo: l.wrapping_mul(PRIME64_1),
            Hi: !(l.wrapping_mul(PRIME64_2)),
        };
        let mut accs = self.acc;

        if self.len > 0 {
            accum_scalar(&mut accs, &self.buf[..self.len]);
        }

        merge_accs_128(&accs, acc)
    }
}
