// crypto/cipher/ctr — Counter (CTR) Mode.
//
// Reference: /share/go/src/crypto/cipher/ctr.go (115 LOC).
//
// CTR converts a block cipher into a stream cipher by repeatedly
// encrypting an incrementing counter and XOR-ing the resulting stream
// of data with the input. See NIST SP 800-38A, pp 13-15.
//
// Slim deviations:
//
//   * `NewCTR(b, iv)` returns a concrete `CTR<B>` value (not a boxed
//     `dyn Stream`). Goish has static dispatch — caller spells out the
//     Block type. Mirrors the OFB sibling.
//
//   * The AES fast-path branch (`if block, ok := block.(*aes.Block)`)
//     is dropped — goish doesn't ship `crypto/internal/fips140/aes`.
//
//   * The `ctrAble` interface is dropped — goish has no runtime type
//     assertion. Callers wanting a custom CTR implementation should
//     write their own `Stream` directly.
//
//   * `fips140only.Enabled` branch is dropped — goish has no FIPS
//     service-indicator infrastructure.
//
//   * `alias.InexactOverlap(dst[:len(src)], src)` is dropped — goish
//     slices have copy semantics on subslicing, so cross-buffer overlap
//     between distinct goish handles is impossible.
//
//   * Internal scratch buffer is a `Vec<byte>` of fixed capacity. Go
//     uses `make([]byte, 0, bufSize)` then reslices `x.out[:cap(x.out)]`;
//     goish slices don't expose that pattern, so we manage the buffer
//     directly via Vec::resize / Vec::truncate.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::cipher::{Block, Stream};
use crate::goslice::slice;
use crate::types::{byte, int};

// Go: ctr.go:30
//   const streamBufferSize = 512
const streamBufferSize: int = 512;

// Go: ctr.go:23
//   type ctr struct {
//       b       Block
//       ctr     []byte
//       out     []byte
//       outUsed int
//   }
/// `cipher.CTR` — concrete CTR stream returned by [`NewCTR`].
///
/// Generic over the block cipher `B`. The returned value implements
/// [`Stream`].
pub struct CTR<B: Block> {
    b: B,
    ctr: Vec<byte>,
    out: Vec<byte>,
    out_used: usize,
}

// go: sdk 1.25.5 crypto/cipher/ctr.go:41-64 NewCTR
// Go: ctr.go:42
//   func NewCTR(block Block, iv []byte) Stream {
//       if block, ok := block.(*aes.Block); ok {              // dropped
//           return aesCtrWrapper{aes.NewCTR(block, iv)}
//       }
//       if fips140only.Enabled { panic(...) }                  // dropped
//       if ctr, ok := block.(ctrAble); ok { return ctr.NewCTR(iv) } // dropped
//       if len(iv) != block.BlockSize() {
//           panic("cipher.NewCTR: IV length must equal block size")
//       }
//       bufSize := streamBufferSize
//       if bufSize < block.BlockSize() { bufSize = block.BlockSize() }
//       return &ctr{
//           b:       block,
//           ctr:     bytes.Clone(iv),
//           out:     make([]byte, 0, bufSize),
//           outUsed: 0,
//       }
//   }
/// `cipher.NewCTR(b, iv)` — returns a [`Stream`] that encrypts or
/// decrypts using the block cipher `b` in counter mode. The
/// initialization vector `iv` length must equal `b.BlockSize()`.
pub fn NewCTR<B: Block>(b: B, iv: slice<byte>) -> CTR<B> {
    let blockSize = b.BlockSize();
    // Go: if len(iv) != block.BlockSize() { panic(...) }
    if iv.Len() != blockSize {
        panic!("cipher.NewCTR: IV length must equal block size");
    }
    // Go: bufSize := streamBufferSize
    //     if bufSize < block.BlockSize() { bufSize = block.BlockSize() }
    let mut bufSize = streamBufferSize;
    if bufSize < blockSize {
        bufSize = blockSize;
    }
    // Go: ctr: bytes.Clone(iv)
    let ctr_v: Vec<byte> = iv.__into_vec();
    // Go: out: make([]byte, 0, bufSize)
    let out: Vec<byte> = Vec::with_capacity(bufSize as usize);
    CTR { b, ctr: ctr_v, out, out_used: 0 }
}

impl<B: Block> CTR<B> {
    // go: sdk 1.25.5 crypto/cipher/ctr.go:75-94 refill
    // Go: ctr.go:75
    //   func (x *ctr) refill() {
    //       remain := len(x.out) - x.outUsed
    //       copy(x.out, x.out[x.outUsed:])
    //       x.out = x.out[:cap(x.out)]
    //       bs := x.b.BlockSize()
    //       for remain <= len(x.out)-bs {
    //           x.b.Encrypt(x.out[remain:], x.ctr)
    //           remain += bs
    //           // Increment counter
    //           for i := len(x.ctr) - 1; i >= 0; i-- {
    //               x.ctr[i]++
    //               if x.ctr[i] != 0 { break }
    //           }
    //       }
    //       x.out = x.out[:remain]
    //       x.outUsed = 0
    //   }
    fn refill(&mut self) {
        // Go: remain := len(x.out) - x.outUsed
        let mut remain: usize = self.out.len() - self.out_used;
        // Go: copy(x.out, x.out[x.outUsed:])
        if remain > 0 {
            self.out.copy_within(self.out_used..self.out_used + remain, 0);
        }
        // Go: x.out = x.out[:cap(x.out)]
        let cap = self.out.capacity();
        self.out.resize(cap, 0u8);
        // Go: bs := x.b.BlockSize()
        let bs = self.b.BlockSize() as usize;
        // Go: for remain <= len(x.out)-bs {
        //         x.b.Encrypt(x.out[remain:], x.ctr)
        //         ...
        //     }
        let limit = self.out.len();
        while remain + bs <= limit {
            // Encrypt self.ctr into self.out[remain..remain+bs].
            let src: slice<byte> = slice::__from_vec(self.ctr.clone());
            // Stage into a fresh slice<byte> dst then copy back, since
            // we can't hand a sub-region of self.out as &mut slice<byte>.
            let mut dst_block: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; bs]);
            self.b.Encrypt(&mut dst_block, src);
            let dst_v = dst_block.__into_vec();
            self.out[remain..remain + bs].copy_from_slice(&dst_v);
            remain += bs;
            // Go: Increment counter (big-endian add 1)
            //     for i := len(x.ctr) - 1; i >= 0; i--
            //         x.ctr[i]++
            //         if x.ctr[i] != 0 { break }
            let mut i = self.ctr.len();
            while i > 0 {
                i -= 1;
                self.ctr[i] = self.ctr[i].wrapping_add(1);
                if self.ctr[i] != 0 {
                    break;
                }
            }
        }
        // Go: x.out = x.out[:remain]
        self.out.truncate(remain);
        // Go: x.outUsed = 0
        self.out_used = 0;
    }
}

// Go: ctr.go:96
//   func (x *ctr) XORKeyStream(dst, src []byte) {
//       if len(dst) < len(src) { panic("crypto/cipher: output smaller than input") }
//       if alias.InexactOverlap(dst[:len(src)], src) { panic(...) }    // dropped
//       if _, ok := x.b.(*aes.Block); ok { panic(...) }                 // dropped
//       for len(src) > 0 {
//           if x.outUsed >= len(x.out)-x.b.BlockSize() {
//               x.refill()
//           }
//           n := subtle.XORBytes(dst, src, x.out[x.outUsed:])
//           dst = dst[n:]
//           src = src[n:]
//           x.outUsed += n
//       }
//   }
impl<B: Block> Stream for CTR<B> {
    // go: sdk 1.25.5 crypto/cipher/ctr.go:96-118 ctr.XORKeyStream
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
            // Go: if x.outUsed >= len(x.out)-x.b.BlockSize()
            // Cast through isize-equivalent semantics: the Go condition
            // tolerates `len(x.out) - bs` underflowing when out is empty
            // (Go uses signed int). We mirror by checking if out has at
            // least one full block of unused keystream remaining.
            if self.out_used + bs > self.out.len() {
                self.refill();
            }
            // Go: n := subtle.XORBytes(dst, src, x.out[x.outUsed:])
            let avail_ks = self.out.len() - self.out_used;
            let avail_src = src_v.len() - src_off;
            let n = avail_ks.min(avail_src);
            for i in 0..n {
                let v = src_v[src_off + i] ^ self.out[self.out_used + i];
                dst[(dst_off + i) as int] = v;
            }
            // Go: dst = dst[n:]; src = src[n:]; x.outUsed += n
            dst_off += n;
            src_off += n;
            self.out_used += n;
        }
    }
}
