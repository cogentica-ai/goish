// go: file crypto/internal/fips140/aes/cbc.go decls: NewCBCEncrypter, CBCEncrypter.BlockSize, CBCEncrypter.CryptBlocks, CBCEncrypter.SetIV, cryptBlocksEncGeneric, NewCBCDecrypter, CBCDecrypter.BlockSize, CBCDecrypter.CryptBlocks, CBCDecrypter.SetIV, cryptBlocksDecGeneric
//
// AES-CBC. Go's `crypto/cipher.NewCBCEncrypter` routes here when the
// underlying Block is AES, so this is the implementation behind
// cipher.BlockMode for AES.
//
// Deviation: `fips140.RecordApproved()` calls are dropped — goish's
// fips140 stub has no service indicator, so they are no-ops.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140::alias;
use crate::crypto::internal::fips140::subtle;
use crate::goslice::slice;
use crate::types::{byte, int};

use super::aes::{Block, BlockSize};
use super::aes_noasm::{decryptBlock, encryptBlock};
use super::cbc_noasm::{cryptBlocksDec, cryptBlocksEnc};

extern crate alloc;

// Go: cbc.go:13
//   type CBCEncrypter struct {
//       b  Block
//       iv [BlockSize]byte
//   }
/// `aes.CBCEncrypter` — a `cipher.BlockMode` encrypting in cipher block
/// chaining mode.
#[derive(Clone)]
pub struct CBCEncrypter {
    b: Block,
    iv: [byte; 16],
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/cbc.go:20-22 NewCBCEncrypter
/// `aes.NewCBCEncrypter(b, iv)` — a `cipher.BlockMode` which encrypts in
/// cipher block chaining mode, using the given Block.
pub fn NewCBCEncrypter(b: &Block, iv: [byte; 16]) -> CBCEncrypter {
    // Go: return &CBCEncrypter{b: *b, iv: iv}
    return CBCEncrypter { b: b.clone(), iv };
}

impl CBCEncrypter {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/cbc.go:24-24 CBCEncrypter.BlockSize
    /// Go: `func (c *CBCEncrypter) BlockSize() int { return BlockSize }`
    pub fn BlockSize(&self) -> int {
        return BlockSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/cbc.go:26-40 CBCEncrypter.CryptBlocks
    /// `(*CBCEncrypter).CryptBlocks(dst, src)` — encrypt `src` into `dst`.
    pub fn CryptBlocks(&mut self, dst: &mut slice<byte>, src: &slice<byte>) {
        // Go: if len(src)%BlockSize != 0 { panic("crypto/cipher: input not full blocks") }
        if src.Len() % BlockSize != 0 {
            panic!("crypto/cipher: input not full blocks");
        }
        // Go: if len(dst) < len(src) { panic("crypto/cipher: output smaller than input") }
        if dst.Len() < src.Len() {
            panic!("crypto/cipher: output smaller than input");
        }
        // Go: if alias.InexactOverlap(dst[:len(src)], src) { … }
        if alias::InexactOverlap(dst, src) {
            panic!("crypto/cipher: invalid buffer overlap");
        }
        // Go: fips140.RecordApproved() — no-op in goish.
        // Go: if len(src) == 0 { return }
        if src.Len() == 0 {
            return;
        }
        // Go: cryptBlocksEnc(&c.b, &c.iv, dst, src)
        let b = self.b.clone();
        cryptBlocksEnc(&b, &mut self.iv, dst, src);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/cbc.go:42-47 CBCEncrypter.SetIV
    /// `(*CBCEncrypter).SetIV(iv)` — replace the chaining IV.
    pub fn SetIV(&mut self, iv: &slice<byte>) {
        // Go: if len(iv) != len(x.iv) { panic("cipher: incorrect length IV") }
        if iv.Len() != BlockSize {
            panic!("cipher: incorrect length IV");
        }
        // Go: copy(x.iv[:], iv)
        let raw: &[byte] = iv;
        self.iv.copy_from_slice(&raw[..16]);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/cbc.go:50-65 cryptBlocksEncGeneric
/// Go: `func cryptBlocksEncGeneric(b *Block, civ *[BlockSize]byte, dst, src []byte)`
pub(crate) fn cryptBlocksEncGeneric(
    b: &Block,
    civ: &mut [byte; 16],
    dst: &mut slice<byte>,
    src: &slice<byte>,
) {
    // Go: iv := civ[:]
    let mut iv: alloc::vec::Vec<byte> = civ.to_vec();
    let srcRaw: &[byte] = src;
    let n = srcRaw.len();
    let mut out: alloc::vec::Vec<byte> = {
        let d: &[byte] = dst;
        d.to_vec()
    };

    // Go: for len(src) > 0 { … }
    let mut off: usize = 0;
    while off < n {
        // Go: subtle.XORBytes(dst[:BlockSize], src[:BlockSize], iv)
        let mut blk = slice::__from_vec(alloc::vec![0u8; 16]);
        let x = slice::__from_vec(srcRaw[off..off + 16].to_vec());
        let y = slice::__from_vec(iv.clone());
        subtle::XORBytes(&mut blk, &x, &y);
        // Go: encryptBlock(b, dst[:BlockSize], dst[:BlockSize])
        let inp = slice::__from_vec({
            let r: &[byte] = &blk;
            r.to_vec()
        });
        encryptBlock(b, &mut blk, &inp);
        // Go: iv = dst[:BlockSize]
        let r: &[byte] = &blk;
        iv = r.to_vec();
        out[off..off + 16].copy_from_slice(r);
        // Go: src = src[BlockSize:]; dst = dst[BlockSize:]
        off += 16;
    }

    let d: &mut [byte] = dst;
    d[..n].copy_from_slice(&out[..n]);

    // Go: copy(civ[:], iv) — save the iv for the next CryptBlocks call.
    civ.copy_from_slice(&iv[..16]);
}

// Go: cbc.go:65
//   type CBCDecrypter struct {
//       b  Block
//       iv [BlockSize]byte
//   }
/// `aes.CBCDecrypter` — a `cipher.BlockMode` decrypting in cipher block
/// chaining mode.
#[derive(Clone)]
pub struct CBCDecrypter {
    b: Block,
    iv: [byte; 16],
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/cbc.go:74-76 NewCBCDecrypter
/// `aes.NewCBCDecrypter(b, iv)` — a `cipher.BlockMode` which decrypts in
/// cipher block chaining mode, using the given Block.
pub fn NewCBCDecrypter(b: &Block, iv: [byte; 16]) -> CBCDecrypter {
    // Go: return &CBCDecrypter{b: *b, iv: iv}
    return CBCDecrypter { b: b.clone(), iv };
}

impl CBCDecrypter {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/cbc.go:78-78 CBCDecrypter.BlockSize
    /// Go: `func (c *CBCDecrypter) BlockSize() int { return BlockSize }`
    pub fn BlockSize(&self) -> int {
        return BlockSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/cbc.go:80-95 CBCDecrypter.CryptBlocks
    /// `(*CBCDecrypter).CryptBlocks(dst, src)` — decrypt `src` into `dst`.
    pub fn CryptBlocks(&mut self, dst: &mut slice<byte>, src: &slice<byte>) {
        // Go: if len(src)%BlockSize != 0 { panic("crypto/cipher: input not full blocks") }
        if src.Len() % BlockSize != 0 {
            panic!("crypto/cipher: input not full blocks");
        }
        // Go: if len(dst) < len(src) { panic("crypto/cipher: output smaller than input") }
        if dst.Len() < src.Len() {
            panic!("crypto/cipher: output smaller than input");
        }
        // Go: if alias.InexactOverlap(dst[:len(src)], src) { … }
        if alias::InexactOverlap(dst, src) {
            panic!("crypto/cipher: invalid buffer overlap");
        }
        // Go: fips140.RecordApproved() — no-op in goish.
        // Go: if len(src) == 0 { return }
        if src.Len() == 0 {
            return;
        }
        // Go: cryptBlocksDec(&c.b, &c.iv, dst, src)
        let b = self.b.clone();
        cryptBlocksDec(&b, &mut self.iv, dst, src);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/cbc.go:97-102 CBCDecrypter.SetIV
    /// `(*CBCDecrypter).SetIV(iv)` — replace the chaining IV.
    pub fn SetIV(&mut self, iv: &slice<byte>) {
        // Go: if len(iv) != len(x.iv) { panic("cipher: incorrect length IV") }
        if iv.Len() != BlockSize {
            panic!("cipher: incorrect length IV");
        }
        // Go: copy(x.iv[:], iv)
        let raw: &[byte] = iv;
        self.iv.copy_from_slice(&raw[..16]);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/cbc.go:101-130 cryptBlocksDecGeneric
/// Go: `func cryptBlocksDecGeneric(b *Block, civ *[BlockSize]byte, dst, src []byte)`
///
/// For each block we need to XOR the decrypted data with the previous
/// block's ciphertext (the iv). To avoid making a copy each time, Go loops
/// over the blocks backwards; goish does the same.
pub(crate) fn cryptBlocksDecGeneric(
    b: &Block,
    civ: &mut [byte; 16],
    dst: &mut slice<byte>,
    src: &slice<byte>,
) {
    let srcRaw: &[byte] = src;
    let n = srcRaw.len();
    let mut out: alloc::vec::Vec<byte> = {
        let d: &[byte] = dst;
        d.to_vec()
    };

    // Go: iv := *civ; copy(civ[:], src[start:end])
    //     — save the last block of ciphertext as the IV of the next call.
    let iv = *civ;
    civ.copy_from_slice(&srcRaw[n - 16..n]);

    // Go: for start >= 0 { … }
    let mut start: isize = (n as isize) - 16;
    while start >= 0 {
        let s = start as usize;
        // Go: decryptBlock(b, dst[start:end], src[start:end])
        let mut blk = slice::__from_vec(alloc::vec![0u8; 16]);
        let inp = slice::__from_vec(srcRaw[s..s + 16].to_vec());
        decryptBlock(b, &mut blk, &inp);

        let plain: alloc::vec::Vec<byte> = {
            let r: &[byte] = &blk;
            r.to_vec()
        };
        let mut xored = slice::__from_vec(alloc::vec![0u8; 16]);
        if s > 0 {
            // Go: subtle.XORBytes(dst[start:end], dst[start:end], src[prev:start])
            let prev = slice::__from_vec(srcRaw[s - 16..s].to_vec());
            subtle::XORBytes(&mut xored, &slice::__from_vec(plain), &prev);
        } else {
            // Go: the first block is special because it uses the saved iv.
            let ivs = slice::__from_vec(iv.to_vec());
            subtle::XORBytes(&mut xored, &slice::__from_vec(plain), &ivs);
        }
        let r: &[byte] = &xored;
        out[s..s + 16].copy_from_slice(r);

        // Go: end -= BlockSize; start -= BlockSize; prev -= BlockSize
        start -= 16;
    }

    let d: &mut [byte] = dst;
    d[..n].copy_from_slice(&out[..n]);
}
