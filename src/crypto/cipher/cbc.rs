// crypto/cipher/cbc — Cipher Block Chaining (CBC) Mode.
//
// Reference: /share/go/src/crypto/cipher/cbc.go (208 LOC).
//
// CBC provides confidentiality by xoring (chaining) each plaintext block
// with the previous ciphertext block before applying the block cipher.
// See NIST SP 800-38A, pp 10-11.
//
// Slim deviations:
//
//   * `NewCBCEncrypter(b, iv)` returns concrete `CBCEncrypter<B>` (not a
//     boxed `dyn BlockMode`); `NewCBCDecrypter` returns `CBCDecrypter<B>`.
//     Goish has static dispatch — caller spells out the Block type. The
//     two types share the same internal state shape (b, blockSize, iv,
//     tmp), modelled in Go via the unexported `cbc` struct + the
//     `type cbcEncrypter cbc` / `type cbcDecrypter cbc` pattern.
//
//   * AES fast-path branches (`if block, ok := b.(*aes.Block); ok`) are
//     dropped — goish doesn't ship `crypto/internal/fips140/aes`.
//
//   * `cbcEncAble` / `cbcDecAble` interfaces are dropped — goish has no
//     runtime type assertion. Callers wanting a custom CBC mode should
//     implement `BlockMode` directly.
//
//   * `fips140only.Enabled` branches are dropped — goish has no FIPS
//     service-indicator infrastructure.
//
//   * `alias.InexactOverlap(dst[:len(src)], src)` is dropped — goish
//     slices have copy semantics on subslicing.
//
//   * `subtle.XORBytes` calls are open-coded (sub-region semantics don't
//     translate to copy-on-subslice goish slices).
//
//   * `SetIV` is exposed as an inherent method on the concrete types
//     (mirrors Go's `cbcEncrypter.SetIV` / `cbcDecrypter.SetIV`); not
//     part of the `BlockMode` trait surface (matches Go's interface).

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::cipher::{Block, BlockMode};
use crate::goslice::slice;
use crate::types::{byte, int};

// Go: cbc.go:22
//   type cbc struct {
//       b         Block
//       blockSize int
//       iv        []byte
//       tmp       []byte
//   }
struct cbc<B: Block> {
    b: B,
    blockSize: int,
    iv: Vec<byte>,
    tmp: Vec<byte>,
}

// Go: cbc.go:29
//   func newCBC(b Block, iv []byte) *cbc {
//       return &cbc{
//           b:         b,
//           blockSize: b.BlockSize(),
//           iv:        bytes.Clone(iv),
//           tmp:       make([]byte, b.BlockSize()),
//       }
//   }
fn newCBC<B: Block>(b: B, iv: slice<byte>) -> cbc<B> {
    let blockSize = b.BlockSize();
    let bs = blockSize as usize;
    // Go: bytes.Clone(iv)
    let iv_v: Vec<byte> = iv.__into_vec();
    // Go: tmp: make([]byte, b.BlockSize())
    let tmp: Vec<byte> = alloc::vec![0u8; bs];
    cbc { b, blockSize, iv: iv_v, tmp }
}

// Go: cbc.go:38
//   type cbcEncrypter cbc
/// `cipher.CBCEncrypter` — concrete CBC encrypter returned by
/// [`NewCBCEncrypter`]. Generic over the block cipher `B`. Implements
/// [`BlockMode`].
pub struct CBCEncrypter<B: Block>(cbc<B>);

// Go: cbc.go:50
//   func NewCBCEncrypter(b Block, iv []byte) BlockMode {
//       if len(iv) != b.BlockSize() {
//           panic("cipher.NewCBCEncrypter: IV length must equal block size")
//       }
//       if b, ok := b.(*aes.Block); ok { ... }       // dropped
//       if fips140only.Enabled { panic(...) }         // dropped
//       if cbc, ok := b.(cbcEncAble); ok { ... }      // dropped
//       return (*cbcEncrypter)(newCBC(b, iv))
//   }
/// `cipher.NewCBCEncrypter(b, iv)` — returns a [`BlockMode`] which
/// encrypts in cipher block chaining mode using the given block cipher
/// `b`. The length of `iv` must equal `b.BlockSize()`.
pub fn NewCBCEncrypter<B: Block>(b: B, iv: slice<byte>) -> CBCEncrypter<B> {
    // Go: if len(iv) != b.BlockSize() { panic(...) }
    if iv.Len() != b.BlockSize() {
        panic!("cipher.NewCBCEncrypter: IV length must equal block size");
    }
    CBCEncrypter(newCBC(b, iv))
}

// Go: cbc.go:77
//   func (x *cbcEncrypter) BlockSize() int { return x.blockSize }
//
// Go: cbc.go:79
//   func (x *cbcEncrypter) CryptBlocks(dst, src []byte) {
//       if len(src)%x.blockSize != 0 { panic("crypto/cipher: input not full blocks") }
//       if len(dst) < len(src) { panic("crypto/cipher: output smaller than input") }
//       if alias.InexactOverlap(dst[:len(src)], src) { panic(...) }   // dropped
//       if _, ok := x.b.(*aes.Block); ok { panic(...) }                // dropped
//       iv := x.iv
//       for len(src) > 0 {
//           subtle.XORBytes(dst[:x.blockSize], src[:x.blockSize], iv)
//           x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])
//           iv = dst[:x.blockSize]
//           src = src[x.blockSize:]
//           dst = dst[x.blockSize:]
//       }
//       copy(x.iv, iv)
//   }
impl<B: Block> BlockMode for CBCEncrypter<B> {
    fn BlockSize(&self) -> int {
        self.0.blockSize
    }

    fn CryptBlocks(&mut self, dst: &mut slice<byte>, src: slice<byte>) {
        let bs = self.0.blockSize as usize;
        let src_v = src.__into_vec();
        let n = src_v.len();
        // Go: if len(src)%x.blockSize != 0 { panic(...) }
        if n % bs != 0 {
            panic!("crypto/cipher: input not full blocks");
        }
        // Go: if len(dst) < len(src) { panic(...) }
        if (dst.Len() as usize) < n {
            panic!("crypto/cipher: output smaller than input");
        }

        // Go: iv := x.iv
        // We need a working copy because we update iv each block from the
        // freshly-encrypted block; only the final value is written back.
        let mut iv: Vec<byte> = self.0.iv.clone();
        // Staging for "encrypt in place": Go writes the XOR into dst,
        // then encrypts dst-in-place. Goish slices can't expose a sub-
        // region as `&mut slice<byte>`, so we stage the block into a
        // fresh slice<byte>, encrypt, then copy back into dst.
        let mut xor_buf: Vec<byte> = alloc::vec![0u8; bs];

        let mut off: usize = 0;
        // Go: for len(src) > 0
        while off < n {
            // Go: subtle.XORBytes(dst[:x.blockSize], src[:x.blockSize], iv)
            for i in 0..bs {
                xor_buf[i] = src_v[off + i] ^ iv[i];
            }
            // Go: x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])
            //   In goish: encrypt staging buffer into a fresh dst block.
            let src_block: slice<byte> = slice::__from_vec(xor_buf.clone());
            let mut dst_block: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; bs]);
            self.0.b.Encrypt(&mut dst_block, src_block);
            let enc_v = dst_block.__into_vec();
            // Write encrypted block to dst[off..off+bs]
            for i in 0..bs {
                dst[(off + i) as int] = enc_v[i];
            }
            // Go: iv = dst[:x.blockSize]
            iv.copy_from_slice(&enc_v);
            // Go: src = src[x.blockSize:]; dst = dst[x.blockSize:]
            off += bs;
        }
        // Go: copy(x.iv, iv)
        self.0.iv.copy_from_slice(&iv);
    }
}

impl<B: Block> CBCEncrypter<B> {
    // Go: cbc.go:110
    //   func (x *cbcEncrypter) SetIV(iv []byte) {
    //       if len(iv) != len(x.iv) { panic("cipher: incorrect length IV") }
    //       copy(x.iv, iv)
    //   }
    /// `SetIV` resets the IV. The new IV must be the same length as the
    /// existing one.
    pub fn SetIV(&mut self, iv: slice<byte>) {
        if iv.Len() as usize != self.0.iv.len() {
            panic!("cipher: incorrect length IV");
        }
        let iv_v = iv.__into_vec();
        self.0.iv.copy_from_slice(&iv_v);
    }
}

// Go: cbc.go:117
//   type cbcDecrypter cbc
/// `cipher.CBCDecrypter` — concrete CBC decrypter returned by
/// [`NewCBCDecrypter`]. Generic over the block cipher `B`. Implements
/// [`BlockMode`].
pub struct CBCDecrypter<B: Block>(cbc<B>);

// Go: cbc.go:129
//   func NewCBCDecrypter(b Block, iv []byte) BlockMode {
//       if len(iv) != b.BlockSize() {
//           panic("cipher.NewCBCDecrypter: IV length must equal block size")
//       }
//       if b, ok := b.(*aes.Block); ok { ... }      // dropped
//       if fips140only.Enabled { panic(...) }        // dropped
//       if cbc, ok := b.(cbcDecAble); ok { ... }     // dropped
//       return (*cbcDecrypter)(newCBC(b, iv))
//   }
/// `cipher.NewCBCDecrypter(b, iv)` — returns a [`BlockMode`] which
/// decrypts in cipher block chaining mode using the given block cipher
/// `b`. The length of `iv` must equal `b.BlockSize()` and must match the
/// iv used to encrypt the data.
pub fn NewCBCDecrypter<B: Block>(b: B, iv: slice<byte>) -> CBCDecrypter<B> {
    // Go: if len(iv) != b.BlockSize() { panic(...) }
    if iv.Len() != b.BlockSize() {
        panic!("cipher.NewCBCDecrypter: IV length must equal block size");
    }
    CBCDecrypter(newCBC(b, iv))
}

// Go: cbc.go:156
//   func (x *cbcDecrypter) BlockSize() int { return x.blockSize }
//
// Go: cbc.go:158
//   func (x *cbcDecrypter) CryptBlocks(dst, src []byte) {
//       if len(src)%x.blockSize != 0 { panic("crypto/cipher: input not full blocks") }
//       if len(dst) < len(src) { panic("crypto/cipher: output smaller than input") }
//       if alias.InexactOverlap(...) { panic(...) }                 // dropped
//       if _, ok := x.b.(*aes.Block); ok { panic(...) }              // dropped
//       if len(src) == 0 { return }
//
//       end := len(src)
//       start := end - x.blockSize
//       prev := start - x.blockSize
//
//       copy(x.tmp, src[start:end])
//
//       for start > 0 {
//           x.b.Decrypt(dst[start:end], src[start:end])
//           subtle.XORBytes(dst[start:end], dst[start:end], src[prev:start])
//           end = start; start = prev; prev -= x.blockSize
//       }
//
//       x.b.Decrypt(dst[start:end], src[start:end])
//       subtle.XORBytes(dst[start:end], dst[start:end], x.iv)
//
//       x.iv, x.tmp = x.tmp, x.iv
//   }
impl<B: Block> BlockMode for CBCDecrypter<B> {
    fn BlockSize(&self) -> int {
        self.0.blockSize
    }

    fn CryptBlocks(&mut self, dst: &mut slice<byte>, src: slice<byte>) {
        let bs = self.0.blockSize as usize;
        let src_v = src.__into_vec();
        let n = src_v.len();
        // Go: if len(src)%x.blockSize != 0 { panic(...) }
        if n % bs != 0 {
            panic!("crypto/cipher: input not full blocks");
        }
        // Go: if len(dst) < len(src) { panic(...) }
        if (dst.Len() as usize) < n {
            panic!("crypto/cipher: output smaller than input");
        }
        // Go: if len(src) == 0 { return }
        if n == 0 {
            return;
        }

        // Go: end := len(src); start := end - x.blockSize; prev := start - x.blockSize
        let mut end: usize = n;
        let mut start: usize = end - bs;
        // `prev` is signed in spirit (becomes negative on the final
        // iteration when start == 0 and we exit the loop). We carry it
        // as isize to mirror the loop guard cleanly.
        let mut prev: isize = start as isize - bs as isize;

        // Go: copy(x.tmp, src[start:end])
        //   Save the last ciphertext block as the next iv.
        self.0.tmp[..bs].copy_from_slice(&src_v[start..end]);

        // Go: for start > 0
        //   Loop over all but the first block, walking BACKWARDS.
        while start > 0 {
            // Go: x.b.Decrypt(dst[start:end], src[start:end])
            let src_block: slice<byte> =
                slice::__from_vec(src_v[start..end].to_vec());
            let mut dst_block: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; bs]);
            self.0.b.Decrypt(&mut dst_block, src_block);
            let dec_v = dst_block.__into_vec();
            // Go: subtle.XORBytes(dst[start:end], dst[start:end], src[prev:start])
            //   prev > 0 here because we exit when start == 0.
            let prev_u = prev as usize;
            for i in 0..bs {
                dst[(start + i) as int] = dec_v[i] ^ src_v[prev_u + i];
            }
            // Go: end = start; start = prev; prev -= x.blockSize
            end = start;
            start = prev_u;
            prev -= bs as isize;
        }

        // Go: x.b.Decrypt(dst[start:end], src[start:end])
        //   First block uses the saved iv.
        let src_block: slice<byte> =
            slice::__from_vec(src_v[start..end].to_vec());
        let mut dst_block: slice<byte> =
            slice::__from_vec(alloc::vec![0u8; bs]);
        self.0.b.Decrypt(&mut dst_block, src_block);
        let dec_v = dst_block.__into_vec();
        // Go: subtle.XORBytes(dst[start:end], dst[start:end], x.iv)
        for i in 0..bs {
            dst[(start + i) as int] = dec_v[i] ^ self.0.iv[i];
        }

        // Go: x.iv, x.tmp = x.tmp, x.iv
        //   Set the new iv to the first block we copied earlier.
        core::mem::swap(&mut self.0.iv, &mut self.0.tmp);
    }
}

impl<B: Block> CBCDecrypter<B> {
    // Go: cbc.go:202
    //   func (x *cbcDecrypter) SetIV(iv []byte) {
    //       if len(iv) != len(x.iv) { panic("cipher: incorrect length IV") }
    //       copy(x.iv, iv)
    //   }
    /// `SetIV` resets the IV. The new IV must be the same length as the
    /// existing one.
    pub fn SetIV(&mut self, iv: slice<byte>) {
        if iv.Len() as usize != self.0.iv.len() {
            panic!("cipher: incorrect length IV");
        }
        let iv_v = iv.__into_vec();
        self.0.iv.copy_from_slice(&iv_v);
    }
}
