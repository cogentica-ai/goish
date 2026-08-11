// go: file crypto/sha1/sha1block.go decls: blockGeneric
//
// The SHA-1 block step, pure Go. `block` in sha1block_generic[go]'s port
// is the dispatch point the AVX2 and SHA-NI variants replace.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::math::bits;
use crate::types::byte;

use super::sha1::{Digest, CHUNK};

// SHA-1 round constants (RFC 3174 §5). Go declares these in
// sha1block[go], not sha1[go].
//
// Go: `const ( _K0 = 0x5A827999; _K1 = 0x6ED9EBA1; … )`
const _K0: u32 = 0x5A827999;
const _K1: u32 = 0x6ED9EBA1;
const _K2: u32 = 0x8F1BBCDC;
const _K3: u32 = 0xCA62C1D6;

// go: sdk 1.25.5 crypto/sha1/sha1block.go:16-79 blockGeneric
/// Go: `func blockGeneric(dig *digest, p []byte)` — the pure-Go SHA-1
/// compression function.
///
/// `p` is a borrowed `&[byte]`: package-internal, called only from
/// `block`, and the borrow avoids re-wrapping the caller's buffer.
pub(crate) fn blockGeneric(dig: &mut Digest, mut p: &[byte]) {
    let mut w = [0u32; 16];
    let mut h0 = dig.h[0];
    let mut h1 = dig.h[1];
    let mut h2 = dig.h[2];
    let mut h3 = dig.h[3];
    let mut h4 = dig.h[4];
    while p.len() >= CHUNK {
        // Go: for i := 0; i < 16; i++ { w[i] = BE u32 of p[i*4..] }
        let mut i = 0;
        while i < 16 {
            let j = i * 4;
            w[i] = ((p[j] as u32) << 24)
                | ((p[j + 1] as u32) << 16)
                | ((p[j + 2] as u32) << 8)
                | (p[j + 3] as u32);
            i += 1;
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        // Round 1: i = 0..16, no w[] expansion yet.
        let mut i = 0;
        while i < 16 {
            // Go: f := b&c | (^b)&d
            let f = (b & c) | ((!b) & d);
            // Go: t := RotateLeft32(a, 5) + f + e + w[i&0xf] + _K0
            let t = bits::RotateLeft32(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(_K0);
            // Go: a, b, c, d, e = t, a, RotateLeft32(b, 30), c, d
            e = d;
            d = c;
            c = bits::RotateLeft32(b, 30);
            b = a;
            a = t;
            i += 1;
        }
        // Round 1 cont: i = 16..20, with w expansion.
        while i < 20 {
            let tmp = w[(i - 3) & 0xf]
                ^ w[(i - 8) & 0xf]
                ^ w[(i - 14) & 0xf]
                ^ w[i & 0xf];
            w[i & 0xf] = bits::RotateLeft32(tmp, 1);
            let f = (b & c) | ((!b) & d);
            let t = bits::RotateLeft32(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(_K0);
            e = d;
            d = c;
            c = bits::RotateLeft32(b, 30);
            b = a;
            a = t;
            i += 1;
        }
        // Round 2: i = 20..40.
        while i < 40 {
            let tmp = w[(i - 3) & 0xf]
                ^ w[(i - 8) & 0xf]
                ^ w[(i - 14) & 0xf]
                ^ w[i & 0xf];
            w[i & 0xf] = bits::RotateLeft32(tmp, 1);
            let f = b ^ c ^ d;
            let t = bits::RotateLeft32(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(_K1);
            e = d;
            d = c;
            c = bits::RotateLeft32(b, 30);
            b = a;
            a = t;
            i += 1;
        }
        // Round 3: i = 40..60.
        while i < 60 {
            let tmp = w[(i - 3) & 0xf]
                ^ w[(i - 8) & 0xf]
                ^ w[(i - 14) & 0xf]
                ^ w[i & 0xf];
            w[i & 0xf] = bits::RotateLeft32(tmp, 1);
            // Go: f := ((b | c) & d) | (b & c)
            let f = ((b | c) & d) | (b & c);
            let t = bits::RotateLeft32(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(_K2);
            e = d;
            d = c;
            c = bits::RotateLeft32(b, 30);
            b = a;
            a = t;
            i += 1;
        }
        // Round 4: i = 60..80.
        while i < 80 {
            let tmp = w[(i - 3) & 0xf]
                ^ w[(i - 8) & 0xf]
                ^ w[(i - 14) & 0xf]
                ^ w[i & 0xf];
            w[i & 0xf] = bits::RotateLeft32(tmp, 1);
            let f = b ^ c ^ d;
            let t = bits::RotateLeft32(a, 5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(w[i & 0xf])
                .wrapping_add(_K3);
            e = d;
            d = c;
            c = bits::RotateLeft32(b, 30);
            b = a;
            a = t;
            i += 1;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);

        p = &p[CHUNK..];
    }

    dig.h[0] = h0;
    dig.h[1] = h1;
    dig.h[2] = h2;
    dig.h[3] = h3;
    dig.h[4] = h4;
}
