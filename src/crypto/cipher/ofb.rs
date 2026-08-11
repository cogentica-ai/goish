// go: file crypto/cipher/ofb.go decls: NewOFB, (*ofb).refill, (*ofb).XORKeyStream
//
// crypto/cipher/ofb — OFB (Output Feedback) Mode.
//
// Reference: /share/go/src/crypto/cipher/ofb.go (88 LOC).
//
// Slim deviations:
//
//   * `NewOFB(b, iv)` returns a concrete `OFB<B>` value (not a boxed
//     `dyn Stream`). Goish has static dispatch — the caller spells out
//     the Block type (or lets inference fill it in). This mirrors how
//     `rc4::NewCipher` returns `(Option<Cipher>, error)` instead of a
//     `cipher::Stream` trait object.
//
//   * `panic("crypto/cipher: use of OFB is not allowed in FIPS 140-only
//     mode")` is dropped — goish has no FIPS 140-only service indicator.
//
//   * `alias.InexactOverlap(dst[:len(src)], src)` is dropped — goish
//     slices have copy semantics on subslicing, so cross-buffer overlap
//     can't happen between distinct goish handles. Caller-aliased
//     `dst == src` works as in Go (XORBytes reads, then writes).
//
//   * Internal scratch buffer is a `Vec<byte>` of fixed capacity. Go uses
//     `make([]byte, 0, bufSize)` then reslices `x.out[:cap(x.out)]`;
//     goish slices don't expose that pattern, so we track `out_len` and
//     `out_used` as `usize` and re-wrap the Vec as a `slice<byte>` when
//     handing to `subtle::XORBytes` / `b.Encrypt`.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::cipher::{Block, Stream};
use crate::goslice::slice;
use crate::types::{byte, int};

// Note: Go's XORKeyStream calls `subtle.XORBytes(dst, src, keystream)`.
// Goish slices copy on subslicing, so handing sub-regions to `subtle`
// would be wasteful; the loop is open-coded here. The `crypto::subtle`
// module is otherwise the right home for these primitives — see
// `src/crypto/subtle/mod.rs`.

// `streamBufferSize` is declared in ctr.go, not ofb.go; ofb.go simply
// uses it. ctr.rs owns the declaration and this file imports it — one
// `.rs` per `.go`, so redeclaring it here would make ofb.rs look like a
// port of two Go files.
use super::ctr::streamBufferSize;

// Go ofb.go:15
//   type ofb struct {
//       b       Block
//       cipher  []byte
//       out     []byte
//       outUsed int
//   }
/// `cipher.OFB` — concrete OFB stream returned by [`NewOFB`].
///
/// Generic over the block cipher `B`. The returned value implements
/// [`Stream`].
pub struct OFB<B: Block> {
    b: B,
    cipher: Vec<byte>,
    out: Vec<byte>,    // capacity = bufSize, length = valid keystream bytes
    out_used: usize,
}

// go: sdk 1.25.5 crypto/cipher/ofb.go:31-53 NewOFB
// Go ofb.go:31
//   func NewOFB(b Block, iv []byte) Stream {
//       if fips140only.Enabled { panic(...) }     // dropped
//       blockSize := b.BlockSize()
//       if len(iv) != blockSize {
//           panic("cipher.NewOFB: IV length must equal block size")
//       }
//       bufSize := streamBufferSize
//       if bufSize < blockSize { bufSize = blockSize }
//       x := &ofb{...}
//       copy(x.cipher, iv)
//       return x
//   }
/// `cipher.NewOFB(b, iv)` — returns a [`Stream`] that encrypts or
/// decrypts using the block cipher `b` in output-feedback mode. The
/// initialization vector `iv` length must equal `b.BlockSize()`.
///
/// **Deprecated** in Go: OFB is unauthenticated; prefer an AEAD mode.
pub fn NewOFB<B: Block>(b: B, iv: slice<byte>) -> OFB<B> {
    // Go: blockSize := b.BlockSize()
    let blockSize = b.BlockSize();
    // Go: if len(iv) != blockSize { panic(...) }
    if iv.Len() != blockSize {
        panic!("cipher.NewOFB: IV length must equal block size");
    }
    // Go: bufSize := streamBufferSize
    //     if bufSize < blockSize { bufSize = blockSize }
    let mut bufSize = streamBufferSize;
    if bufSize < blockSize {
        bufSize = blockSize;
    }
    // Go: cipher: make([]byte, blockSize)
    let cipher = alloc::vec![0u8; blockSize as usize];
    // Go: out: make([]byte, 0, bufSize)
    let mut out: Vec<byte> = Vec::with_capacity(bufSize as usize);
    // Pre-fill capacity so refill can reslice up to cap() (Go pattern).
    out.resize(0, 0u8);
    // Go: copy(x.cipher, iv)
    let mut x = OFB { b, cipher, out, out_used: 0 };
    let iv_v = iv.__into_vec();
    let n = (iv_v.len()).min(x.cipher.len());
    x.cipher[..n].copy_from_slice(&iv_v[..n]);
    // Go: return x
    return x;
}

impl<B: Block> OFB<B> {
    // go: sdk 1.25.5 crypto/cipher/ofb.go:55-70 refill
    // Go ofb.go:54
    //   func (x *ofb) refill() {
    //       bs := x.b.BlockSize()
    //       remain := len(x.out) - x.outUsed
    //       if remain > x.outUsed { return }
    //       copy(x.out, x.out[x.outUsed:])
    //       x.out = x.out[:cap(x.out)]
    //       for remain < len(x.out)-bs {
    //           x.b.Encrypt(x.cipher, x.cipher)
    //           copy(x.out[remain:], x.cipher)
    //           remain += bs
    //       }
    //       x.out = x.out[:remain]
    //       x.outUsed = 0
    //   }
    fn refill(&mut self) {
        let bs = self.b.BlockSize() as usize;
        // Go: remain := len(x.out) - x.outUsed
        let mut remain: usize = self.out.len() - self.out_used;
        // Go: if remain > x.outUsed { return }
        if remain > self.out_used {
            return;
        }
        // Go: copy(x.out, x.out[x.outUsed:])
        // — shift unused tail to start.
        if remain > 0 {
            self.out.copy_within(self.out_used..self.out_used + remain, 0);
        }
        // Go: x.out = x.out[:cap(x.out)]
        let cap = self.out.capacity();
        self.out.resize(cap, 0u8);
        // Go: for remain < len(x.out)-bs {
        //         x.b.Encrypt(x.cipher, x.cipher)
        //         copy(x.out[remain:], x.cipher)
        //         remain += bs
        //     }
        let limit = self.out.len().saturating_sub(bs);
        while remain < limit {
            // Encrypt cipher into itself: feed src=clone, dst=&mut self.cipher.
            let src: slice<byte> = slice::__from_vec(self.cipher.clone());
            let mut dst: slice<byte> = slice::__from_vec(self.cipher.clone());
            self.b.Encrypt(&mut dst, src);
            self.cipher = dst.__into_vec();
            // Append the newly-encrypted block to out[remain..].
            self.out[remain..remain + bs].copy_from_slice(&self.cipher);
            remain += bs;
        }
        // Go: x.out = x.out[:remain]
        self.out.truncate(remain);
        // Go: x.outUsed = 0
        self.out_used = 0;
    }
}

// Go ofb.go:71
//   func (x *ofb) XORKeyStream(dst, src []byte) {
//       if len(dst) < len(src) { panic("crypto/cipher: output smaller than input") }
//       if alias.InexactOverlap(dst[:len(src)], src) { panic(...) }   // dropped
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
impl<B: Block> Stream for OFB<B> {
    // go: sdk 1.25.5 crypto/cipher/ofb.go:72-88 XORKeyStream
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
            if self.out_used + bs >= self.out.len() {
                self.refill();
            }
            // Go: n := subtle.XORBytes(dst, src, x.out[x.outUsed:])
            //     — XOR up to min(remaining src, remaining keystream).
            let avail_ks = self.out.len() - self.out_used;
            let avail_src = src_v.len() - src_off;
            let n = avail_ks.min(avail_src);
            // XOR n bytes: dst[dst_off..dst_off+n] = src[src_off..src_off+n]
            //                                       ^ self.out[out_used..out_used+n]
            // (Go's `subtle.XORBytes(dst, src, x.out[x.outUsed:])`. Goish
            // sub-slicing copies, so the equivalent is open-coded.)
            for i in 0..n {
                let v = src_v[src_off + i] ^ self.out[self.out_used + i];
                dst[dst_off + i] = v;
            }
            // Go: dst = dst[n:]; src = src[n:]; x.outUsed += n
            dst_off += n;
            src_off += n;
            self.out_used += n;
        }
    }
}

