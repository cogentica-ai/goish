// go: file crypto/internal/fips140/aes/aes_generic.go decls: encryptBlockGeneric, decryptBlockGeneric, subw, rotw, expandKeyGeneric, b, putWords
//
// The variable-time table-driven AES. Derived in part from the reference
// ANSI C implementation (rijndael-alg-fst.c, public domain, by Vincent
// Rijmen, Antoon Bosselaers and Paulo Barreto).
//
// See FIPS 197 for the specification, and Daemen and Rijmen's Rijndael
// submission for implementation details:
//   https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
//   https://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf
//
// This implementation is variable-time: it indexes lookup tables with key
// and plaintext bytes. `checkGenericIsExpected` exists so that it cannot
// silently run when hardware AES is available.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140deps::byteorder;
use crate::goslice::slice;
use crate::types::{byte, uint32};

use super::aes::blockExpanded;
use super::aes_noasm::checkGenericIsExpected;
use super::konst::{powx, sbox0, sbox1, td0, td1, td2, td3, te0, te1, te2, te3};

extern crate alloc;

// go: none — goish idiom: Go writes `te0[uint8(s0>>24)]`, relying on
// `uint8()` to truncate. goish bans `as` casts (AGENTS.md §2a) and a
// `uint8()` call-cast would still need a `usize` index, so the byte
// extraction is named once here rather than open-coded 40 times.
#[inline(always)]
fn b(w: uint32, shift: uint32) -> usize {
    return ((w >> shift) & 0xff) as usize;
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes_generic.go:41-86 encryptBlockGeneric
/// Encrypt one block from `src` into `dst`, using the expanded key `c.enc`.
pub(crate) fn encryptBlockGeneric(c: &blockExpanded, dst: &mut slice<byte>, src: &slice<byte>) {
    // Go: checkGenericIsExpected()
    checkGenericIsExpected();
    // Go: xk := c.enc[:]
    let xk = &c.enc;

    // Go: _ = src[15] — early bounds check
    let s: &[byte] = src;
    // Go: s0 := byteorder.BEUint32(src[0:4]) … s3 := byteorder.BEUint32(src[12:16])
    let mut s0 = byteorder::BEUint32(slice::__from_vec(s[0..4].to_vec()));
    let mut s1 = byteorder::BEUint32(slice::__from_vec(s[4..8].to_vec()));
    let mut s2 = byteorder::BEUint32(slice::__from_vec(s[8..12].to_vec()));
    let mut s3 = byteorder::BEUint32(slice::__from_vec(s[12..16].to_vec()));

    // Go: first round just XORs input with key.
    s0 ^= xk[0];
    s1 ^= xk[1];
    s2 ^= xk[2];
    s3 ^= xk[3];

    // Go: middle rounds shuffle using tables.
    let mut k: usize = 4;
    let (mut t0, mut t1, mut t2, mut t3): (uint32, uint32, uint32, uint32) = (0, 0, 0, 0);
    let mut r: i64 = 0;
    while r < c.rounds - 1 {
        // Go: t0 = xk[k+0] ^ te0[uint8(s0>>24)] ^ te1[uint8(s1>>16)] ^
        //           te2[uint8(s2>>8)] ^ te3[uint8(s3)]
        t0 = xk[k] ^ te0[b(s0, 24)] ^ te1[b(s1, 16)] ^ te2[b(s2, 8)] ^ te3[b(s3, 0)];
        t1 = xk[k + 1] ^ te0[b(s1, 24)] ^ te1[b(s2, 16)] ^ te2[b(s3, 8)] ^ te3[b(s0, 0)];
        t2 = xk[k + 2] ^ te0[b(s2, 24)] ^ te1[b(s3, 16)] ^ te2[b(s0, 8)] ^ te3[b(s1, 0)];
        t3 = xk[k + 3] ^ te0[b(s3, 24)] ^ te1[b(s0, 16)] ^ te2[b(s1, 8)] ^ te3[b(s2, 0)];
        k += 4;
        // Go: s0, s1, s2, s3 = t0, t1, t2, t3
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
        r += 1;
    }

    // Go: last round uses s-box directly and XORs to produce output.
    s0 = (uint32::from(sbox0[b(t0, 24)]) << 24)
        | (uint32::from(sbox0[b(t1, 16)]) << 16)
        | (uint32::from(sbox0[b(t2, 8)]) << 8)
        | uint32::from(sbox0[b(t3, 0)]);
    s1 = (uint32::from(sbox0[b(t1, 24)]) << 24)
        | (uint32::from(sbox0[b(t2, 16)]) << 16)
        | (uint32::from(sbox0[b(t3, 8)]) << 8)
        | uint32::from(sbox0[b(t0, 0)]);
    s2 = (uint32::from(sbox0[b(t2, 24)]) << 24)
        | (uint32::from(sbox0[b(t3, 16)]) << 16)
        | (uint32::from(sbox0[b(t0, 8)]) << 8)
        | uint32::from(sbox0[b(t1, 0)]);
    s3 = (uint32::from(sbox0[b(t3, 24)]) << 24)
        | (uint32::from(sbox0[b(t0, 16)]) << 16)
        | (uint32::from(sbox0[b(t1, 8)]) << 8)
        | uint32::from(sbox0[b(t2, 0)]);

    s0 ^= xk[k];
    s1 ^= xk[k + 1];
    s2 ^= xk[k + 2];
    s3 ^= xk[k + 3];

    // Go: _ = dst[15] — early bounds check
    // Go: byteorder.BEPutUint32(dst[0:4], s0) … BEPutUint32(dst[12:16], s3)
    putWords(dst, s0, s1, s2, s3);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes_generic.go:89-134 decryptBlockGeneric
/// Decrypt one block from `src` into `dst`, using the expanded key `c.dec`.
pub(crate) fn decryptBlockGeneric(c: &blockExpanded, dst: &mut slice<byte>, src: &slice<byte>) {
    // Go: checkGenericIsExpected()
    checkGenericIsExpected();
    // Go: xk := c.dec[:]
    let xk = &c.dec;

    // Go: _ = src[15] — early bounds check
    let s: &[byte] = src;
    let mut s0 = byteorder::BEUint32(slice::__from_vec(s[0..4].to_vec()));
    let mut s1 = byteorder::BEUint32(slice::__from_vec(s[4..8].to_vec()));
    let mut s2 = byteorder::BEUint32(slice::__from_vec(s[8..12].to_vec()));
    let mut s3 = byteorder::BEUint32(slice::__from_vec(s[12..16].to_vec()));

    // Go: first round just XORs input with key.
    s0 ^= xk[0];
    s1 ^= xk[1];
    s2 ^= xk[2];
    s3 ^= xk[3];

    // Go: middle rounds shuffle using tables.
    let mut k: usize = 4;
    let (mut t0, mut t1, mut t2, mut t3): (uint32, uint32, uint32, uint32) = (0, 0, 0, 0);
    let mut r: i64 = 0;
    while r < c.rounds - 1 {
        // Go: t0 = xk[k+0] ^ td0[uint8(s0>>24)] ^ td1[uint8(s3>>16)] ^
        //           td2[uint8(s2>>8)] ^ td3[uint8(s1)]
        t0 = xk[k] ^ td0[b(s0, 24)] ^ td1[b(s3, 16)] ^ td2[b(s2, 8)] ^ td3[b(s1, 0)];
        t1 = xk[k + 1] ^ td0[b(s1, 24)] ^ td1[b(s0, 16)] ^ td2[b(s3, 8)] ^ td3[b(s2, 0)];
        t2 = xk[k + 2] ^ td0[b(s2, 24)] ^ td1[b(s1, 16)] ^ td2[b(s0, 8)] ^ td3[b(s3, 0)];
        t3 = xk[k + 3] ^ td0[b(s3, 24)] ^ td1[b(s2, 16)] ^ td2[b(s1, 8)] ^ td3[b(s0, 0)];
        k += 4;
        s0 = t0;
        s1 = t1;
        s2 = t2;
        s3 = t3;
        r += 1;
    }

    // Go: last round uses s-box directly and XORs to produce output.
    s0 = (uint32::from(sbox1[b(t0, 24)]) << 24)
        | (uint32::from(sbox1[b(t3, 16)]) << 16)
        | (uint32::from(sbox1[b(t2, 8)]) << 8)
        | uint32::from(sbox1[b(t1, 0)]);
    s1 = (uint32::from(sbox1[b(t1, 24)]) << 24)
        | (uint32::from(sbox1[b(t0, 16)]) << 16)
        | (uint32::from(sbox1[b(t3, 8)]) << 8)
        | uint32::from(sbox1[b(t2, 0)]);
    s2 = (uint32::from(sbox1[b(t2, 24)]) << 24)
        | (uint32::from(sbox1[b(t1, 16)]) << 16)
        | (uint32::from(sbox1[b(t0, 8)]) << 8)
        | uint32::from(sbox1[b(t3, 0)]);
    s3 = (uint32::from(sbox1[b(t3, 24)]) << 24)
        | (uint32::from(sbox1[b(t2, 16)]) << 16)
        | (uint32::from(sbox1[b(t1, 8)]) << 8)
        | uint32::from(sbox1[b(t0, 0)]);

    s0 ^= xk[k];
    s1 ^= xk[k + 1];
    s2 ^= xk[k + 2];
    s3 ^= xk[k + 3];

    // Go: _ = dst[15] — early bounds check
    putWords(dst, s0, s1, s2, s3);
}

// go: none — goish idiom: Go writes four `byteorder.BEPutUint32(dst[i:j],
// sN)` calls straight into the destination slice. goish's BEPutUint32
// takes `&mut slice<byte>`, so the four stores are staged in one 16-byte
// buffer and copied back — named once rather than repeated in both
// encryptBlockGeneric and decryptBlockGeneric.
fn putWords(dst: &mut slice<byte>, s0: uint32, s1: uint32, s2: uint32, s3: uint32) {
    let mut buf = slice::__from_vec(alloc::vec![0u8; 16]);
    let words = [s0, s1, s2, s3];
    let mut i: usize = 0;
    while i < 4 {
        let mut w = slice::__from_vec(alloc::vec![0u8; 4]);
        byteorder::BEPutUint32(&mut w, words[i]);
        let wr: &[byte] = &w;
        let br: &mut [byte] = &mut buf;
        br[i * 4..i * 4 + 4].copy_from_slice(wr);
        i += 1;
    }
    let src: &[byte] = &buf;
    let out: &mut [byte] = dst;
    out[..16].copy_from_slice(&src[..16]);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes_generic.go:137-142 subw
/// Apply `sbox0` to each byte in `w`.
fn subw(w: uint32) -> uint32 {
    // Go: return uint32(sbox0[w>>24])<<24 | uint32(sbox0[w>>16&0xff])<<16 |
    //            uint32(sbox0[w>>8&0xff])<<8 | uint32(sbox0[w&0xff])
    return (uint32::from(sbox0[b(w, 24)]) << 24)
        | (uint32::from(sbox0[b(w, 16)]) << 16)
        | (uint32::from(sbox0[b(w, 8)]) << 8)
        | uint32::from(sbox0[b(w, 0)]);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes_generic.go:145-145 rotw
/// Rotate.
fn rotw(w: uint32) -> uint32 {
    // Go: func rotw(w uint32) uint32 { return w<<8 | w>>24 }
    return (w << 8) | (w >> 24);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes_generic.go:150-186 expandKeyGeneric
/// Key expansion algorithm. See FIPS 197, Figure 11. Their `rcon[i]` is
/// our `powx[i-1] << 24`.
pub(crate) fn expandKeyGeneric(c: &mut blockExpanded, key: &slice<byte>) {
    // Go: checkGenericIsExpected()
    checkGenericIsExpected();

    // Encryption key setup.
    // Go: var i int; nk := len(key) / 4
    let kr: &[byte] = key;
    let nk: usize = kr.len() / 4;
    let mut i: usize = 0;
    // Go: for i = 0; i < nk; i++ { c.enc[i] = byteorder.BEUint32(key[4*i:]) }
    while i < nk {
        c.enc[i] = byteorder::BEUint32(slice::__from_vec(kr[4 * i..4 * i + 4].to_vec()));
        i += 1;
    }
    // Go: for ; i < c.roundKeysSize(); i++ { … }
    let sz = c.roundKeysSize() as usize;
    while i < sz {
        // Go: t := c.enc[i-1]
        let mut t = c.enc[i - 1];
        // Go: if i%nk == 0 { t = subw(rotw(t)) ^ (uint32(powx[i/nk-1]) << 24) }
        if i % nk == 0 {
            t = subw(rotw(t)) ^ (uint32::from(powx[i / nk - 1]) << 24);
        } else if nk > 6 && i % nk == 4 {
            // Go: } else if nk > 6 && i%nk == 4 { t = subw(t) }
            t = subw(t);
        }
        // Go: c.enc[i] = c.enc[i-nk] ^ t
        c.enc[i] = c.enc[i - nk] ^ t;
        i += 1;
    }

    // Derive decryption key from encryption key.
    // Reverse the 4-word round key sets from enc to produce dec.
    // All sets but the first and last get the MixColumn transform applied.
    // Go: n := c.roundKeysSize()
    let n: usize = c.roundKeysSize() as usize;
    let mut i: usize = 0;
    while i < n {
        // Go: ei := n - i - 4
        let ei = n - i - 4;
        let mut j: usize = 0;
        while j < 4 {
            // Go: x := c.enc[ei+j]
            let mut x = c.enc[ei + j];
            // Go: if i > 0 && i+4 < n { x = td0[sbox0[x>>24]] ^ td1[sbox0[x>>16&0xff]] ^
            //                              td2[sbox0[x>>8&0xff]] ^ td3[sbox0[x&0xff]] }
            if i > 0 && i + 4 < n {
                x = td0[usize::from(sbox0[b(x, 24)])]
                    ^ td1[usize::from(sbox0[b(x, 16)])]
                    ^ td2[usize::from(sbox0[b(x, 8)])]
                    ^ td3[usize::from(sbox0[b(x, 0)])];
            }
            // Go: c.dec[i+j] = x
            c.dec[i + j] = x;
            j += 1;
        }
        i += 4;
    }
}
