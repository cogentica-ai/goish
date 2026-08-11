// go: file crypto/internal/fips140/aes/ctr.go decls: NewCTR, newCTR, CTR.XORKeyStream, RoundToBlock, CTR.XORKeyStreamAt, ctrBlocks, add128
//
// AES-CTR. The counter is carried as a pair of 64-bit limbs rather than a
// 16-byte buffer, so seeking is arithmetic rather than a re-encode.
//
// Deviation: `fips140.RecordApproved()` is dropped — goish's fips140 stub
// has no service indicator, so it is a no-op.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140::alias;
use crate::crypto::internal::fips140::subtle;
use crate::crypto::internal::fips140deps::byteorder;
use crate::goslice::slice;
use crate::math::bits;
use crate::types::{byte, uint64};

use super::aes::{Block, BlockSize};
use super::aes_noasm::encryptBlock;
use super::ctr_noasm::{ctrBlocks1, ctrBlocks2, ctrBlocks4, ctrBlocks8};

extern crate alloc;
use alloc::vec::Vec;

// Go: ctr.go:15
//   type CTR struct {
//       b          Block
//       ivlo, ivhi uint64 // start counter as 64-bit limbs
//       offset     uint64 // for XORKeyStream only
//   }
/// `aes.CTR` — AES in counter mode.
#[derive(Clone)]
pub struct CTR {
    pub(crate) b: Block,
    // start counter as 64-bit limbs
    ivlo: uint64,
    ivhi: uint64,
    // for XORKeyStream only
    offset: uint64,
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/ctr.go:21-27 NewCTR
/// `aes.NewCTR(b, iv)` — a new CTR stream over `b` starting at `iv`.
pub fn NewCTR(b: &Block, iv: &slice<byte>) -> CTR {
    // Go: c := newCTR(b, iv); return &c
    //
    // Go splits this in two so the allocation lands in the caller's frame
    // (issue 70499); goish returns by value, so the split is only shape.
    return newCTR(b, iv);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/ctr.go:28-38 newCTR
/// Go: `func newCTR(b *Block, iv []byte) CTR`
fn newCTR(b: &Block, iv: &slice<byte>) -> CTR {
    // Go: if len(iv) != BlockSize { panic("bad IV length") }
    if iv.Len() != BlockSize {
        panic!("bad IV length");
    }
    let raw: &[byte] = iv;
    // Go: return CTR{b: *b, ivlo: BEUint64(iv[8:16]), ivhi: BEUint64(iv[0:8]), offset: 0}
    return CTR {
        b: b.clone(),
        ivlo: byteorder::BEUint64(slice::__from_vec(raw[8..16].to_vec())),
        ivhi: byteorder::BEUint64(slice::__from_vec(raw[0..8].to_vec())),
        offset: 0,
    };
}

impl CTR {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/ctr.go:40-48 XORKeyStream
    /// `(*CTR).XORKeyStream(dst, src)` — XOR `src` with the keystream and
    /// advance the stream position.
    pub fn XORKeyStream(&mut self, dst: &mut slice<byte>, src: &slice<byte>) {
        // Go: c.XORKeyStreamAt(dst, src, c.offset)
        let off = self.offset;
        self.XORKeyStreamAt(dst, src, off);

        // Go: c.offset, carry = bits.Add64(c.offset, uint64(len(src)), 0)
        let (sum, carry) = bits::Add64(self.offset, src.Len() as uint64, 0);
        self.offset = sum;
        // Go: if carry != 0 { panic("crypto/aes: counter overflow") }
        if carry != 0 {
            panic!("crypto/aes: counter overflow");
        }
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/ctr.go:64-124 XORKeyStreamAt
    /// `(*CTR).XORKeyStreamAt(dst, src, offset)` — like `XORKeyStream` but
    /// keeps no state; instead it seeks into the keystream by `offset`
    /// bytes from the start, ignoring any `XORKeyStream` calls. Allows
    /// random access into the keystream, up to 16 EiB from the start.
    pub fn XORKeyStreamAt(&self, dst: &mut slice<byte>, src: &slice<byte>, offset: uint64) {
        // Go: if len(dst) < len(src) { panic("crypto/aes: len(dst) < len(src)") }
        if dst.Len() < src.Len() {
            panic!("crypto/aes: len(dst) < len(src)");
        }
        // Go: dst = dst[:len(src)]
        // Go: if alias.InexactOverlap(dst, src) { panic("crypto/aes: invalid buffer overlap") }
        if alias::InexactOverlap(dst, src) {
            panic!("crypto/aes: invalid buffer overlap");
        }
        // Go: fips140.RecordApproved() — no-op in goish.

        let bs = BlockSize as usize;
        let srcRaw: &[byte] = src;
        let n = srcRaw.len();
        let mut out: Vec<byte> = Vec::with_capacity(n);

        // Go: ivlo, ivhi := add128(c.ivlo, c.ivhi, offset/BlockSize)
        let (mut ivlo, mut ivhi) = add128(self.ivlo, self.ivhi, offset / (BlockSize as uint64));

        let mut pos: usize = 0;
        // Go: if blockOffset := offset % BlockSize; blockOffset != 0 { … }
        let blockOffset = (offset % (BlockSize as uint64)) as usize;
        if blockOffset != 0 {
            // Go: we have a partial block at the beginning.
            //     var in, out [BlockSize]byte; copy(in[blockOffset:], src)
            let take = core::cmp::min(bs - blockOffset, n);
            let mut inb = alloc::vec![0u8; bs];
            inb[blockOffset..blockOffset + take].copy_from_slice(&srcRaw[..take]);
            let mut ob = slice::__from_vec(alloc::vec![0u8; bs]);
            ctrBlocks1(&self.b, &mut ob, &slice::__from_vec(inb), ivlo, ivhi);
            // Go: n := copy(dst, out[blockOffset:])
            let obr: &[byte] = &ob;
            out.extend_from_slice(&obr[blockOffset..blockOffset + take]);
            pos += take;
            // Go: ivlo, ivhi = add128(ivlo, ivhi, 1)
            let r = add128(ivlo, ivhi, 1);
            ivlo = r.0;
            ivhi = r.1;
        }

        // Go: for len(src) >= 8*BlockSize { ctrBlocks8(…); … }
        while n - pos >= 8 * bs {
            let mut ob = slice::__from_vec(alloc::vec![0u8; 8 * bs]);
            let inb = slice::__from_vec(srcRaw[pos..pos + 8 * bs].to_vec());
            ctrBlocks8(&self.b, &mut ob, &inb, ivlo, ivhi);
            let obr: &[byte] = &ob;
            out.extend_from_slice(obr);
            pos += 8 * bs;
            let r = add128(ivlo, ivhi, 8);
            ivlo = r.0;
            ivhi = r.1;
        }

        // The tail can have at most 7 = 4 + 2 + 1 blocks.
        // Go: if len(src) >= 4*BlockSize { ctrBlocks4(…); … }
        if n - pos >= 4 * bs {
            let mut ob = slice::__from_vec(alloc::vec![0u8; 4 * bs]);
            let inb = slice::__from_vec(srcRaw[pos..pos + 4 * bs].to_vec());
            ctrBlocks4(&self.b, &mut ob, &inb, ivlo, ivhi);
            let obr: &[byte] = &ob;
            out.extend_from_slice(obr);
            pos += 4 * bs;
            let r = add128(ivlo, ivhi, 4);
            ivlo = r.0;
            ivhi = r.1;
        }
        // Go: if len(src) >= 2*BlockSize { ctrBlocks2(…); … }
        if n - pos >= 2 * bs {
            let mut ob = slice::__from_vec(alloc::vec![0u8; 2 * bs]);
            let inb = slice::__from_vec(srcRaw[pos..pos + 2 * bs].to_vec());
            ctrBlocks2(&self.b, &mut ob, &inb, ivlo, ivhi);
            let obr: &[byte] = &ob;
            out.extend_from_slice(obr);
            pos += 2 * bs;
            let r = add128(ivlo, ivhi, 2);
            ivlo = r.0;
            ivhi = r.1;
        }
        // Go: if len(src) >= 1*BlockSize { ctrBlocks1(…); … }
        if n - pos >= bs {
            let mut ob = slice::__from_vec(alloc::vec![0u8; bs]);
            let inb = slice::__from_vec(srcRaw[pos..pos + bs].to_vec());
            ctrBlocks1(&self.b, &mut ob, &inb, ivlo, ivhi);
            let obr: &[byte] = &ob;
            out.extend_from_slice(obr);
            pos += bs;
            let r = add128(ivlo, ivhi, 1);
            ivlo = r.0;
            ivhi = r.1;
        }

        // Go: if len(src) != 0 { … } — a partial block at the end.
        if pos != n {
            let rem = n - pos;
            let mut inb = alloc::vec![0u8; bs];
            inb[..rem].copy_from_slice(&srcRaw[pos..n]);
            let mut ob = slice::__from_vec(alloc::vec![0u8; bs]);
            ctrBlocks1(&self.b, &mut ob, &slice::__from_vec(inb), ivlo, ivhi);
            let obr: &[byte] = &ob;
            out.extend_from_slice(&obr[..rem]);
        }

        let d: &mut [byte] = dst;
        d[..n].copy_from_slice(&out[..n]);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/ctr.go:52-60 RoundToBlock
/// `aes.RoundToBlock(c)` — round the stream offset up to the next block
/// boundary. Used by CTR_DRBG, which discards the rightmost unused bits at
/// each request.
pub fn RoundToBlock(c: &mut CTR) {
    // Go: if remainder := c.offset % BlockSize; remainder != 0 { … }
    let remainder = c.offset % (BlockSize as uint64);
    if remainder != 0 {
        // Go: c.offset, carry = bits.Add64(c.offset, BlockSize-remainder, 0)
        let (sum, carry) = bits::Add64(c.offset, (BlockSize as uint64) - remainder, 0);
        c.offset = sum;
        // Go: if carry != 0 { panic("crypto/aes: counter overflow") }
        if carry != 0 {
            panic!("crypto/aes: counter overflow");
        }
    }
}

// Each ctrBlocksN function XORs src with N blocks of counter keystream,
// and stores it in dst. src is loaded in full before storing dst, so they
// can overlap even inexactly. The starting counter value is passed in as a
// pair of little-endian 64-bit integers.

// go: sdk 1.25.5 crypto/internal/fips140/aes/ctr.go:131-141 ctrBlocks
/// Go: `func ctrBlocks(b *Block, dst, src []byte, ivlo, ivhi uint64)`
pub(crate) fn ctrBlocks(
    b: &Block,
    dst: &mut slice<byte>,
    src: &slice<byte>,
    mut ivlo: uint64,
    mut ivhi: uint64,
) {
    let bs = BlockSize as usize;
    let srcRaw: &[byte] = src;
    let n = srcRaw.len();
    // Go: buf := make([]byte, len(src), 8*BlockSize)
    let mut buf: Vec<byte> = alloc::vec![0u8; n];

    // Go: for i := 0; i < len(buf); i += BlockSize { … }
    let mut i: usize = 0;
    while i < n {
        // Go: byteorder.BEPutUint64(buf[i:], ivhi)
        //     byteorder.BEPutUint64(buf[i+8:], ivlo)
        let mut hi = slice::__from_vec(alloc::vec![0u8; 8]);
        byteorder::BEPutUint64(&mut hi, ivhi);
        let mut lo = slice::__from_vec(alloc::vec![0u8; 8]);
        byteorder::BEPutUint64(&mut lo, ivlo);
        let hir: &[byte] = &hi;
        let lor: &[byte] = &lo;
        // The final block may be partial; only fill what fits.
        let end = core::cmp::min(i + bs, n);
        let mut ctr = alloc::vec![0u8; bs];
        ctr[..8].copy_from_slice(hir);
        ctr[8..16].copy_from_slice(lor);
        // Go: ivlo, ivhi = add128(ivlo, ivhi, 1)
        let r = add128(ivlo, ivhi, 1);
        ivlo = r.0;
        ivhi = r.1;
        // Go: encryptBlock(b, buf[i:], buf[i:])
        let mut enc = slice::__from_vec(alloc::vec![0u8; bs]);
        encryptBlock(b, &mut enc, &slice::__from_vec(ctr));
        let er: &[byte] = &enc;
        buf[i..end].copy_from_slice(&er[..end - i]);
        i += bs;
    }

    // Go: subtle.XORBytes(buf, src, buf) — XOR into buf first, in case src
    // and dst overlap (see above).
    let mut xored = slice::__from_vec(alloc::vec![0u8; n]);
    subtle::XORBytes(
        &mut xored,
        &slice::__from_vec(srcRaw.to_vec()),
        &slice::__from_vec(buf),
    );
    // Go: copy(dst, buf)
    let xr: &[byte] = &xored;
    let d: &mut [byte] = dst;
    d[..n].copy_from_slice(xr);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/ctr.go:143-147 add128
/// Go: `func add128(lo, hi uint64, x uint64) (uint64, uint64)`
pub(crate) fn add128(lo: uint64, hi: uint64, x: uint64) -> (uint64, uint64) {
    // Go: lo, c := bits.Add64(lo, x, 0)
    let (lo, c) = bits::Add64(lo, x, 0);
    // Go: hi, _ = bits.Add64(hi, 0, c)
    let (hi, _) = bits::Add64(hi, 0, c);
    return (lo, hi);
}
