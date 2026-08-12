// go: file crypto/cipher/cfb.go decls: (*cfb).XORKeyStream, NewCFBEncrypter, NewCFBDecrypter, newCFB
//
// crypto/cipher/cfb — CFB (Cipher Feedback) Mode.
//
// Reference: /share/go/src/crypto/cipher/cfb.go (102 LOC).
//
// Slim deviations:
//
//   * `NewCFBEncrypter(b, iv)` and `NewCFBDecrypter(b, iv)` both return
//     a concrete `CFB<B>` value. Goish has static dispatch — caller
//     spells out the Block type. The encrypt/decrypt distinction lives
//     in the struct's `decrypt` flag, just like Go's private `cfb`.
//
//   * FIPS 140-only branch is dropped — goish has no FIPS service
//     indicator.
//
//   * `alias.InexactOverlap` panic is dropped — goish slices have copy
//     semantics on subslicing.
//
//   * `subtle.XORBytes` call is open-coded (sub-region semantics don't
//     translate to copy-on-subslice goish slices).

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::cipher::{Block, Stream};
use crate::goslice::slice;
use crate::types::{byte, int};

// Go cfb.go:15
//   type cfb struct {
//       b       Block
//       next    []byte
//       out     []byte
//       outUsed int
//       decrypt bool
//   }
/// `cipher.CFB` — concrete CFB stream returned by [`NewCFBEncrypter`]
/// or [`NewCFBDecrypter`].
///
/// Generic over the block cipher `B`. The returned value implements
/// [`Stream`].
pub struct CFB<B: Block> {
    b: B,
    next: Vec<byte>,
    out: Vec<byte>,
    out_used: usize,
    decrypt: bool,
}

// Go cfb.go:23
//   func (x *cfb) XORKeyStream(dst, src []byte) {
//       if len(dst) < len(src) { panic("crypto/cipher: output smaller than input") }
//       if alias.InexactOverlap(dst[:len(src)], src) { panic(...) }    // dropped
//       for len(src) > 0 {
//           if x.outUsed == len(x.out) {
//               x.b.Encrypt(x.out, x.next)
//               x.outUsed = 0
//           }
//           if x.decrypt { copy(x.next[x.outUsed:], src) }
//           n := subtle.XORBytes(dst, src, x.out[x.outUsed:])
//           if !x.decrypt { copy(x.next[x.outUsed:], dst) }
//           dst = dst[n:]
//           src = src[n:]
//           x.outUsed += n
//       }
//   }
impl<B: Block> Stream for CFB<B> {
    // go: sdk 1.25.5 crypto/cipher/cfb.go:24-52 cfb.XORKeyStream
    fn XORKeyStream(&mut self, dst: &mut slice<byte>, src: slice<byte>) {
        // Go: if len(dst) < len(src) { panic(...) }
        if dst.Len() < src.Len() {
            panic!("crypto/cipher: output smaller than input");
        }
        let bs = self.b.BlockSize() as usize;
        let src_v = src.__into_vec();
        let mut src_off: usize = 0;
        let mut dst_off: usize = 0;

        // Go: for len(src) > 0
        while src_off < src_v.len() {
            // Go: if x.outUsed == len(x.out) { x.b.Encrypt(x.out, x.next); x.outUsed = 0 }
            if self.out_used == self.out.len() {
                let src_block: slice<byte> = slice::__from_vec(self.next.clone());
                let mut dst_block: slice<byte> =
                    slice::__from_vec(alloc::vec![0u8; bs]);
                self.b.Encrypt(&mut dst_block, src_block);
                self.out = dst_block.__into_vec();
                self.out_used = 0;
            }

            // Go: avail = min(len(src), len(x.out)-x.outUsed)
            let avail_ks = self.out.len() - self.out_used;
            let avail_src = src_v.len() - src_off;
            let n = avail_ks.min(avail_src);

            // Go: if x.decrypt { copy(x.next[x.outUsed:], src) }
            //   On decrypt, ciphertext goes into next[].
            if self.decrypt {
                self.next[self.out_used..self.out_used + n]
                    .copy_from_slice(&src_v[src_off..src_off + n]);
            }

            // Go: n := subtle.XORBytes(dst, src, x.out[x.outUsed:])
            for i in 0..n {
                let v = src_v[src_off + i] ^ self.out[self.out_used + i];
                dst[dst_off + i] = v;
            }

            // Go: if !x.decrypt { copy(x.next[x.outUsed:], dst) }
            //   On encrypt, freshly-written ciphertext (now in dst[..]) feeds back.
            if !self.decrypt {
                for i in 0..n {
                    self.next[self.out_used + i] = dst[dst_off + i];
                }
            }

            // Go: dst = dst[n:]; src = src[n:]; x.outUsed += n
            dst_off += n;
            src_off += n;
            self.out_used += n;
        }
        // Suppress unused warning when bs is only used in the outer compute.
        let _ = bs;
    }
}

// go: sdk 1.25.5 crypto/cipher/cfb.go:63-68 NewCFBEncrypter
// Go cfb.go:62
//   func NewCFBEncrypter(block Block, iv []byte) Stream { ... return newCFB(block, iv, false) }
/// `cipher.NewCFBEncrypter(b, iv)` — returns a [`Stream`] that encrypts
/// with CFB mode using the block cipher `b`. `iv` length must equal
/// `b.BlockSize()`.
///
/// **Deprecated** in Go: CFB is unauthenticated; prefer an AEAD mode.
pub fn NewCFBEncrypter<B: Block>(block: B, iv: slice<byte>) -> CFB<B> {
    // Go: return newCFB(block, iv, false)
    return newCFB(block, iv, false);
}

// go: sdk 1.25.5 crypto/cipher/cfb.go:79-84 NewCFBDecrypter
// Go cfb.go:78
//   func NewCFBDecrypter(block Block, iv []byte) Stream { ... return newCFB(block, iv, true) }
/// `cipher.NewCFBDecrypter(b, iv)` — returns a [`Stream`] that decrypts
/// with CFB mode using the block cipher `b`. `iv` length must equal
/// `b.BlockSize()`.
///
/// **Deprecated** in Go: CFB is unauthenticated; prefer an AEAD mode.
pub fn NewCFBDecrypter<B: Block>(block: B, iv: slice<byte>) -> CFB<B> {
    // Go: return newCFB(block, iv, true)
    return newCFB(block, iv, true);
}

// go: sdk 1.25.5 crypto/cipher/cfb.go:86-102 newCFB
// Go cfb.go:88
//   func newCFB(block Block, iv []byte, decrypt bool) Stream {
//       blockSize := block.BlockSize()
//       if len(iv) != blockSize {
//           panic("cipher.newCFB: IV length must equal block size")
//       }
//       x := &cfb{
//           b:       block,
//           out:     make([]byte, blockSize),
//           next:    make([]byte, blockSize),
//           outUsed: blockSize,
//           decrypt: decrypt,
//       }
//       copy(x.next, iv)
//       return x
//   }
fn newCFB<B: Block>(block: B, iv: slice<byte>, decrypt: bool) -> CFB<B> {
    let blockSize = block.BlockSize();
    // Go: if len(iv) != blockSize { panic(...) }
    if iv.Len() != blockSize {
        panic!("cipher.newCFB: IV length must equal block size");
    }
    let bs = blockSize as usize;
    // Go: out: make([]byte, blockSize), next: make([]byte, blockSize)
    let out: Vec<byte> = alloc::vec![0u8; bs];
    let mut next: Vec<byte> = alloc::vec![0u8; bs];
    // Go: copy(x.next, iv)
    let iv_v = iv.__into_vec();
    next[..bs].copy_from_slice(&iv_v[..bs]);
    // Go: return x
    return CFB {
        b: block,
        next,
        out,
        // Go: outUsed: blockSize  — forces Encrypt on first XORKeyStream.
        out_used: bs,
        decrypt,
    };
}
