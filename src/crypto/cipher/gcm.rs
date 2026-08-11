// crypto/cipher/gcm — Galois Counter Mode (GCM) AEAD.
//
// References:
//   * /share/go/src/crypto/cipher/gcm.go (377 LOC) — public NewGCM* +
//     gcmFallback (the generic, non-AES-asm path we're porting).
//   * /share/go/src/crypto/internal/fips140/aes/gcm/gcm.go (143 LOC)
//     — internal fips Block-specific path (kept as a documentary
//     reference; goish has no fips bypass).
//   * /share/go/src/crypto/internal/fips140/aes/gcm/gcm_generic.go
//     (105 LOC) — sealGeneric / openGeneric / deriveCounterGeneric /
//     gcmCounterCryptGeneric / gcmInc32 / gcmAuthGeneric.
//   * /share/go/src/crypto/internal/fips140/aes/gcm/ghash.go (163 LOC)
//     — ghash, ghashMul, ghashAdd, ghashDouble, reverseBits,
//     updateBlocks, ghashUpdate.
//
// Slim deviations from upstream (documented):
//
//   * NewGCM* return `(Option<GCM<B>>, error)`. Go returns
//     `(AEAD, error)` (an interface). Goish has static dispatch — the
//     concrete `GCM<B>` is what callers hold.
//
//   * No `fips140only.Enabled` branches — goish has no FIPS service
//     indicator.
//
//   * No `*aes.Block` fast path. Go's NewGCM checks the cipher's
//     concrete type to enter a hardware-friendly subroutine; goish has
//     no runtime type assertion. The "fallback" generic path is the
//     only path here, applied uniformly to all `B: cipher::Block`
//     implementations.
//
//   * `NewGCMWithRandomNonce` is omitted from v1 — it requires
//     crypto/rand integration plus a Go-style "embed and specialize"
//     pattern that doesn't translate cleanly to static dispatch.
//     Standard 12-byte nonce GCM (the TLS/SSH path) is the priority.
//
//   * `gcmAble` / `gcmAuth` interface escape hatches dropped — goish
//     has no runtime type assertion.
//
//   * `alias.InexactOverlap` / `alias.AnyOverlap` checks dropped —
//     goish slices have copy semantics on subslicing.
//
//   * `subtle.XORBytes` calls are open-coded inline, mirroring
//     existing CBC/CFB/CTR/OFB ports.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::cipher::{Block, AEAD};
use crate::crypto::subtle;
use crate::errors::{error, nil, New as ErrNew};
use crate::goslice::slice;
use crate::types::{byte, int};

// Go: gcm.go:17 — package-level constants.
const gcmBlockSize: int = 16;
const gcmStandardNonceSize: int = 12;
const gcmTagSize: int = 16;
const gcmMinimumTagSize: int = 12; // NIST SP 800-38D recommends ≥12.

// ─── ghash.go: GF(2¹²⁸) field arithmetic ─────────────────────────────

// Go: ghash.go:20
//   type gcmFieldElement struct { low, high uint64 }
/// `gcmFieldElement` — a value in GF(2¹²⁸) stored in big-endian bit
/// order. (See `ghash.go:12` for the bit-position discussion.)
#[derive(Copy, Clone, Default)]
struct gcmFieldElement {
    low: u64,
    high: u64,
}

// Go: ghash.go:69
//   func reverseBits(i int) int {
//       i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
//       i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
//       return i
//   }
/// Reverse the order of the bits of a 4-bit number in `i`.
fn reverseBits(mut i: usize) -> usize {
    i = ((i << 2) & 0xc) | ((i >> 2) & 0x3);
    i = ((i << 1) & 0xa) | ((i >> 1) & 0x5);
    i
}

// Go: ghash.go:76
//   func ghashAdd(x, y *gcmFieldElement) gcmFieldElement {
//       return gcmFieldElement{x.low ^ y.low, x.high ^ y.high}
//   }
/// Adds two GF(2¹²⁸) elements. In a characteristic-2 field, addition
/// is XOR.
fn ghashAdd(x: &gcmFieldElement, y: &gcmFieldElement) -> gcmFieldElement {
    gcmFieldElement {
        low: x.low ^ y.low,
        high: x.high ^ y.high,
    }
}

// Go: ghash.go:82
//   func ghashDouble(x *gcmFieldElement) (double gcmFieldElement) {
//       msbSet := x.high&1 == 1
//       double.high = x.high >> 1
//       double.high |= x.low << 63
//       double.low = x.low >> 1
//       if msbSet { double.low ^= 0xe100000000000000 }
//       return
//   }
/// Doubles an element of GF(2¹²⁸). With the bit-reversed storage
/// convention, doubling is a right shift; the irreducible polynomial
/// 1+x+x²+x⁷+x¹²⁸ rolls over to 0xe100…00.
fn ghashDouble(x: &gcmFieldElement) -> gcmFieldElement {
    let msbSet = (x.high & 1) == 1;
    let mut high = x.high >> 1;
    high |= x.low << 63;
    let mut low = x.low >> 1;
    if msbSet {
        low ^= 0xe100000000000000;
    }
    gcmFieldElement { low, high }
}

// Go: ghash.go:104
//   var ghashReductionTable = []uint16{
//       0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
//       0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
//   }
const ghashReductionTable: [u16; 16] = [
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100, 0xfd20, 0xd940, 0xc560,
    0x9180, 0x8da0, 0xa9c0, 0xb5e0,
];

// Go: ghash.go:110
//   func ghashMul(productTable *[16]gcmFieldElement, y *gcmFieldElement) {
//       ...
//   }
/// Sets `y = y · H` in GF(2¹²⁸), where H is encoded in the precomputed
/// `productTable` (16 entries).
fn ghashMul(productTable: &[gcmFieldElement; 16], y: &mut gcmFieldElement) {
    let mut z = gcmFieldElement { low: 0, high: 0 };

    // Go: for i := 0; i < 2; i++ { word := y.high; if i == 1 { word = y.low } ... }
    for i in 0..2 {
        let mut word: u64 = if i == 0 { y.high } else { y.low };

        // Go: for j := 0; j < 64; j += 4 { ... }
        let mut j: usize = 0;
        while j < 64 {
            // Go: msw := z.high & 0xf
            let msw: u64 = z.high & 0xf;
            // Go: z.high >>= 4; z.high |= z.low << 60; z.low >>= 4
            z.high >>= 4;
            z.high |= z.low << 60;
            z.low >>= 4;
            // Go: z.low ^= uint64(ghashReductionTable[msw]) << 48
            z.low ^= (ghashReductionTable[msw as usize] as u64) << 48;

            // Go: t := productTable[word&0xf]
            let t = productTable[(word & 0xf) as usize];

            // Go: z.low ^= t.low; z.high ^= t.high; word >>= 4
            z.low ^= t.low;
            z.high ^= t.high;
            word >>= 4;

            j += 4;
        }
    }

    *y = z;
}

// Go: ghash.go:143
//   func updateBlocks(productTable *[16]gcmFieldElement, y *gcmFieldElement, blocks []byte) {
//       for len(blocks) > 0 {
//           y.low ^= byteorder.BEUint64(blocks)
//           y.high ^= byteorder.BEUint64(blocks[8:])
//           ghashMul(productTable, y)
//           blocks = blocks[gcmBlockSize:]
//       }
//   }
fn updateBlocks(
    productTable: &[gcmFieldElement; 16],
    y: &mut gcmFieldElement,
    blocks: &[u8],
) {
    let mut off: usize = 0;
    while off + 16 <= blocks.len() {
        let lo = be_u64(&blocks[off..off + 8]);
        let hi = be_u64(&blocks[off + 8..off + 16]);
        y.low ^= lo;
        y.high ^= hi;
        ghashMul(productTable, y);
        off += 16;
    }
}

// Go: ghash.go:154
//   func ghashUpdate(productTable *[16]gcmFieldElement, y *gcmFieldElement, data []byte) {
//       fullBlocks := (len(data) >> 4) << 4
//       updateBlocks(productTable, y, data[:fullBlocks])
//       if len(data) != fullBlocks {
//           var partialBlock [gcmBlockSize]byte
//           copy(partialBlock[:], data[fullBlocks:])
//           updateBlocks(productTable, y, partialBlock[:])
//       }
//   }
fn ghashUpdate(productTable: &[gcmFieldElement; 16], y: &mut gcmFieldElement, data: &[u8]) {
    let fullBlocks = (data.len() >> 4) << 4;
    updateBlocks(productTable, y, &data[..fullBlocks]);
    if data.len() != fullBlocks {
        let mut partial = [0u8; 16];
        let tail = &data[fullBlocks..];
        partial[..tail.len()].copy_from_slice(tail);
        updateBlocks(productTable, y, &partial[..]);
    }
}

// Go: ghash.go:38
//   func ghash(out, H *[gcmBlockSize]byte, inputs ...[]byte) {
//       ...
//   }
/// Compute GHASH(H, inputs...) into the 16-byte `out` array. Each
/// input is zero-padded to a multiple of 128 bits before being absorbed.
fn ghash(out: &mut [u8; 16], h: &[u8; 16], inputs: &[&[u8]]) {
    // Go: var productTable [16]gcmFieldElement
    let mut productTable = [gcmFieldElement::default(); 16];

    // Go: x := gcmFieldElement{ BEUint64(H[:8]), BEUint64(H[8:]) }
    let x = gcmFieldElement {
        low: be_u64(&h[..8]),
        high: be_u64(&h[8..]),
    };
    // Go: productTable[reverseBits(1)] = x
    productTable[reverseBits(1)] = x;

    // Go: for i := 2; i < 16; i += 2 {
    //         productTable[reverseBits(i)]   = ghashDouble(&productTable[reverseBits(i/2)])
    //         productTable[reverseBits(i+1)] = ghashAdd(&productTable[reverseBits(i)], &x)
    //     }
    let mut i: usize = 2;
    while i < 16 {
        let half = productTable[reverseBits(i / 2)];
        let dbl = ghashDouble(&half);
        productTable[reverseBits(i)] = dbl;
        let added = ghashAdd(&dbl, &x);
        productTable[reverseBits(i + 1)] = added;
        i += 2;
    }

    // Go: var y gcmFieldElement
    let mut y = gcmFieldElement { low: 0, high: 0 };
    // Go: for _, input := range inputs { ghashUpdate(&productTable, &y, input) }
    for input in inputs {
        ghashUpdate(&productTable, &mut y, input);
    }

    // Go: BEPutUint64(out[:],  y.low); BEPutUint64(out[8:], y.high)
    put_be_u64(&mut out[..8], y.low);
    put_be_u64(&mut out[8..], y.high);
}

// ─── byte-order helpers (open-coded — encoding/binary takes &[u8] but
// the inner loops favour direct array indexing) ─────────────────────

fn be_u64(b: &[u8]) -> u64 {
    ((b[0] as u64) << 56)
        | ((b[1] as u64) << 48)
        | ((b[2] as u64) << 40)
        | ((b[3] as u64) << 32)
        | ((b[4] as u64) << 24)
        | ((b[5] as u64) << 16)
        | ((b[6] as u64) << 8)
        | (b[7] as u64)
}

fn put_be_u64(b: &mut [u8], v: u64) {
    b[0] = (v >> 56) as u8;
    b[1] = (v >> 48) as u8;
    b[2] = (v >> 40) as u8;
    b[3] = (v >> 32) as u8;
    b[4] = (v >> 24) as u8;
    b[5] = (v >> 16) as u8;
    b[6] = (v >> 8) as u8;
    b[7] = v as u8;
}

fn be_u32(b: &[u8]) -> u32 {
    ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | (b[3] as u32)
}

fn put_be_u32(b: &mut [u8], v: u32) {
    b[0] = (v >> 24) as u8;
    b[1] = (v >> 16) as u8;
    b[2] = (v >> 8) as u8;
    b[3] = v as u8;
}

// ─── gcm_generic.go / gcm.go (gcmFallback): GCM core ─────────────────

// go: sdk 1.25.5 crypto/cipher/gcm.go:351-354 gcmInc32
// Go: gcm.go:351
//   func gcmInc32(counterBlock *[gcmBlockSize]byte) {
//       ctr := counterBlock[len(counterBlock)-4:]
//       byteorder.BEPutUint32(ctr, byteorder.BEUint32(ctr)+1)
//   }
/// Treats the final 4 bytes of `counter` as a big-endian counter and
/// increments it.
fn gcmInc32(counter: &mut [u8; 16]) {
    let v = be_u32(&counter[12..]).wrapping_add(1);
    put_be_u32(&mut counter[12..], v);
}

/// Encrypt one 16-byte block via the underlying `Block` cipher,
/// converting through `slice<byte>` to satisfy the trait signature.
fn block_encrypt<B: Block>(b: &B, dst: &mut [u8; 16], src: &[u8; 16]) {
    let src_s: slice<byte> = slice::__from_vec(src.to_vec());
    let mut dst_s: slice<byte> = slice::__from_vec(alloc::vec![0u8; 16]);
    b.Encrypt(&mut dst_s, src_s);
    let v = dst_s.__into_vec();
    dst.copy_from_slice(&v[..16]);
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:322-332 deriveCounter
// Go: gcm.go:322
//   func deriveCounter(H, counter *[gcmBlockSize]byte, nonce []byte) {
//       if len(nonce) == gcmStandardNonceSize {
//           copy(counter[:], nonce)
//           counter[gcmBlockSize-1] = 1
//       } else {
//           lenBlock := make([]byte, 16)
//           byteorder.BEPutUint64(lenBlock[8:], uint64(len(nonce))*8)
//           J := gcm.GHASH(H, nonce, lenBlock)
//           copy(counter[:], J)
//       }
//   }
/// Compute the initial GCM counter state J0. Standard 96-bit nonces
/// take the fast path (concat with 0x00000001); arbitrary-length
/// nonces fall through to GHASH.
fn deriveCounter(h: &[u8; 16], counter: &mut [u8; 16], nonce: &[u8]) {
    if nonce.len() == gcmStandardNonceSize as usize {
        // Go: copy(counter[:], nonce); counter[gcmBlockSize-1] = 1
        counter[..12].copy_from_slice(nonce);
        // Go: counter[15] = 1 — clear bytes 12..14, set 15.
        counter[12] = 0;
        counter[13] = 0;
        counter[14] = 0;
        counter[15] = 1;
    } else {
        // Go: lenBlock := make([]byte, 16); BEPutUint64(lenBlock[8:], len(nonce)*8)
        let mut lenBlock = [0u8; 16];
        put_be_u64(&mut lenBlock[8..], (nonce.len() as u64) * 8);
        // Go: J := gcm.GHASH(H, nonce, lenBlock); copy(counter[:], J)
        let inputs: [&[u8]; 2] = [nonce, &lenBlock[..]];
        let mut j = [0u8; 16];
        ghash(&mut j, h, &inputs);
        counter.copy_from_slice(&j);
    }
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:334-349 gcmCounterCryptGeneric
// Go: gcm.go:334
//   func gcmCounterCryptGeneric(b Block, out, src []byte, counter *[gcmBlockSize]byte) {
//       var mask [gcmBlockSize]byte
//       for len(src) >= gcmBlockSize {
//           b.Encrypt(mask[:], counter[:])
//           gcmInc32(counter)
//           subtle.XORBytes(out, src, mask[:])
//           out = out[gcmBlockSize:]
//           src = src[gcmBlockSize:]
//       }
//       if len(src) > 0 {
//           b.Encrypt(mask[:], counter[:])
//           gcmInc32(counter)
//           subtle.XORBytes(out, src, mask[:])
//       }
//   }
/// CTR-mode encrypt with 32-bit-wrapping counter (different from
/// AES-CTR's wider-counter mode).
fn gcmCounterCryptGeneric<B: Block>(
    b: &B,
    out: &mut [u8],
    src: &[u8],
    counter: &mut [u8; 16],
) {
    let mut mask = [0u8; 16];
    let mut off: usize = 0;
    let n = src.len();

    // Full blocks.
    while n - off >= 16 {
        block_encrypt(b, &mut mask, counter);
        gcmInc32(counter);
        // Go: subtle.XORBytes(out, src, mask[:])
        for i in 0..16 {
            out[off + i] = src[off + i] ^ mask[i];
        }
        off += 16;
    }
    // Tail (Go path: len(src) > 0).
    if off < n {
        block_encrypt(b, &mut mask, counter);
        gcmInc32(counter);
        let rem = n - off;
        for i in 0..rem {
            out[off + i] = src[off + i] ^ mask[i];
        }
    }
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:356-362 gcmAuth
// Go: gcm.go:356
//   func gcmAuth(out []byte, H, tagMask *[gcmBlockSize]byte, ciphertext, additionalData []byte) {
//       lenBlock := make([]byte, 16)
//       byteorder.BEPutUint64(lenBlock[:8], uint64(len(additionalData))*8)
//       byteorder.BEPutUint64(lenBlock[8:], uint64(len(ciphertext))*8)
//       S := gcm.GHASH(H, additionalData, ciphertext, lenBlock)
//       subtle.XORBytes(out, S, tagMask[:])
//   }
/// Compute GHASH over (AAD || ciphertext || lengthBlock) and XOR with
/// tagMask to produce the authentication tag.
fn gcmAuth(
    out: &mut [u8],
    h: &[u8; 16],
    tagMask: &[u8; 16],
    ciphertext: &[u8],
    additionalData: &[u8],
) {
    let mut lenBlock = [0u8; 16];
    // Go: BEPutUint64(lenBlock[:8],  len(additionalData)*8)
    put_be_u64(&mut lenBlock[..8], (additionalData.len() as u64) * 8);
    // Go: BEPutUint64(lenBlock[8:],  len(ciphertext)*8)
    put_be_u64(&mut lenBlock[8..], (ciphertext.len() as u64) * 8);

    let inputs: [&[u8]; 3] = [additionalData, ciphertext, &lenBlock[..]];
    let mut s = [0u8; 16];
    ghash(&mut s, h, &inputs);
    // Go: subtle.XORBytes(out, S, tagMask[:])
    for i in 0..out.len().min(16) {
        out[i] = s[i] ^ tagMask[i];
    }
}

// ─── public surface ─────────────────────────────────────────────────

// Go: gcm.go (gcmFallback struct, lines 226-230)
//   type gcmFallback struct {
//       cipher    Block
//       nonceSize int
//       tagSize   int
//   }
/// `cipher.GCM` — Galois Counter Mode wrapping a 128-bit block cipher.
/// Returned by `NewGCM` / `NewGCMWithNonceSize` / `NewGCMWithTagSize`.
/// Implements the `cipher::AEAD` trait.
pub struct GCM<B: Block> {
    cipher: B,
    nonceSize: int,
    tagSize: int,
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:30-35 NewGCM
// Go: gcm.go:30
//   func NewGCM(cipher Block) (AEAD, error) {
//       return newGCM(cipher, gcmStandardNonceSize, gcmTagSize)
//   }
/// `cipher.NewGCM(cipher)` — wrap a 128-bit block cipher in GCM with
/// the standard 12-byte nonce and 16-byte tag. The cipher must have a
/// 16-byte block size.
///
/// On success returns `(Some(gcm), nil)`. On invalid block size returns
/// `(None, error)`.
pub fn NewGCM<B: Block>(cipher: B) -> (Option<GCM<B>>, error) {
    newGCM(cipher, gcmStandardNonceSize, gcmTagSize)
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:44-49 NewGCMWithNonceSize
// Go: gcm.go:44
//   func NewGCMWithNonceSize(cipher Block, size int) (AEAD, error) {
//       return newGCM(cipher, size, gcmTagSize)
//   }
/// `cipher.NewGCMWithNonceSize(cipher, size)` — wrap a 128-bit block
/// cipher in GCM with the given nonce length (must be > 0). For
/// compatibility with non-standard nonce lengths.
pub fn NewGCMWithNonceSize<B: Block>(cipher: B, size: int) -> (Option<GCM<B>>, error) {
    newGCM(cipher, size, gcmTagSize)
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:59-64 NewGCMWithTagSize
// Go: gcm.go:59
//   func NewGCMWithTagSize(cipher Block, tagSize int) (AEAD, error) {
//       return newGCM(cipher, gcmStandardNonceSize, tagSize)
//   }
/// `cipher.NewGCMWithTagSize(cipher, tagSize)` — wrap a 128-bit block
/// cipher in GCM with the given tag length (12..=16). For compatibility
/// with non-standard tag lengths.
pub fn NewGCMWithTagSize<B: Block>(cipher: B, tagSize: int) -> (Option<GCM<B>>, error) {
    newGCM(cipher, gcmStandardNonceSize, tagSize)
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:66-81 newGCM
// Go: gcm.go:207
//   func newGCMFallback(cipher Block, nonceSize, tagSize int) (AEAD, error) {
//       if tagSize < gcmMinimumTagSize || tagSize > gcmBlockSize {
//           return nil, errors.New("cipher: incorrect tag size given to GCM")
//       }
//       if nonceSize <= 0 {
//           return nil, errors.New("cipher: the nonce can't have zero length")
//       }
//       if cipher.BlockSize() != gcmBlockSize {
//           return nil, errors.New("cipher: NewGCM requires 128-bit block cipher")
//       }
//       return &gcmFallback{...}, nil
//   }
fn newGCM<B: Block>(cipher: B, nonceSize: int, tagSize: int) -> (Option<GCM<B>>, error) {
    if tagSize < gcmMinimumTagSize || tagSize > gcmBlockSize {
        return (None, ErrNew("cipher: incorrect tag size given to GCM"));
    }
    if nonceSize <= 0 {
        return (None, ErrNew("cipher: the nonce can't have zero length"));
    }
    if cipher.BlockSize() != gcmBlockSize {
        return (
            None,
            ErrNew("cipher: NewGCM requires 128-bit block cipher"),
        );
    }
    (
        Some(GCM {
            cipher,
            nonceSize,
            tagSize,
        }),
        nil,
    )
}

// Go: gcm.go:240 (gcmFallback.Seal) and gcm.go:275 (gcmFallback.Open)
impl<B: Block> AEAD for GCM<B> {
    // go: sdk 1.25.5 crypto/cipher/gcm.go:232-234 gcmFallback.NonceSize
    // Go: gcm.go:232
    //   func (g *gcmFallback) NonceSize() int { return g.nonceSize }
    fn NonceSize(&self) -> int {
        self.nonceSize
    }

    // go: sdk 1.25.5 crypto/cipher/gcm.go:236-238 gcmFallback.Overhead
    // Go: gcm.go:236
    //   func (g *gcmFallback) Overhead() int { return g.tagSize }
    fn Overhead(&self) -> int {
        self.tagSize
    }

    // go: sdk 1.25.5 crypto/cipher/gcm.go:240-273 gcmFallback.Seal
    // Go: gcm.go:240
    //   func (g *gcmFallback) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
    //       ... full sealGeneric inlined ...
    //   }
    fn Seal(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additionalData: slice<byte>,
    ) -> slice<byte> {
        // Go: if len(nonce) != g.nonceSize { panic(...) }
        if nonce.Len() != self.nonceSize {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }
        // Go: if g.nonceSize == 0 { panic(...) }
        if self.nonceSize == 0 {
            panic!("crypto/cipher: incorrect GCM nonce size");
        }
        // Go: if uint64(len(plaintext)) > uint64((1<<32)-2)*gcmBlockSize { panic(...) }
        // Skipped: goish int is i64; bound is (1<<32-2)*16 ≈ 2^36, beyond
        // any realistic test vector. The check exists to match Go.
        let max_pt = ((1u64 << 32) - 2) * (gcmBlockSize as u64);
        if (plaintext.Len() as u64) > max_pt {
            panic!("crypto/cipher: message too large for GCM");
        }

        // Snapshot inputs into Vecs (goish slices are by-value).
        let nonce_v: Vec<byte> = nonce.__into_vec();
        let pt_v: Vec<byte> = plaintext.__into_vec();
        let aad_v: Vec<byte> = additionalData.__into_vec();
        let ts = self.tagSize as usize;
        let n = pt_v.len();

        // Allocate output: appended bytes = len(plaintext)+tagSize.
        // Go: ret, out := sliceForAppend(dst, len(plaintext)+g.tagSize)
        let mut ret_v: Vec<byte> = dst.__into_vec();
        let head_off = ret_v.len();
        ret_v.resize(head_off + n + ts, 0u8);

        // Go: var H, counter, tagMask [gcmBlockSize]byte
        // Go: g.cipher.Encrypt(H[:], H[:])
        let zero = [0u8; 16];
        let mut h_arr = [0u8; 16];
        block_encrypt(&self.cipher, &mut h_arr, &zero);

        let mut counter = [0u8; 16];
        deriveCounter(&h_arr, &mut counter, &nonce_v);

        // Go: gcmCounterCryptGeneric(g.cipher, tagMask[:], tagMask[:], &counter)
        let mut tagMask = [0u8; 16];
        let zero16 = [0u8; 16];
        gcmCounterCryptGeneric(&self.cipher, &mut tagMask, &zero16, &mut counter);

        // Go: gcmCounterCryptGeneric(g.cipher, out, plaintext, &counter)
        // Encrypt PT into the [head_off..head_off+n] region.
        {
            let out_slice = &mut ret_v[head_off..head_off + n];
            gcmCounterCryptGeneric(&self.cipher, out_slice, &pt_v, &mut counter);
        }

        // Go: var tag [gcmTagSize]byte
        // Go: gcmAuth(tag[:], &H, &tagMask, out[:len(plaintext)], additionalData)
        // Go: copy(out[len(plaintext):], tag[:])
        let mut tag = [0u8; 16];
        {
            let ct_slice = &ret_v[head_off..head_off + n];
            gcmAuth(&mut tag, &h_arr, &tagMask, ct_slice, &aad_v);
        }
        // Copy tag (truncated to tagSize) into output.
        for i in 0..ts {
            ret_v[head_off + n + i] = tag[i];
        }

        slice::__from_vec(ret_v)
    }

    // go: sdk 1.25.5 crypto/cipher/gcm.go:275-310 gcmFallback.Open
    // Go: gcm.go:275
    //   func (g *gcmFallback) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
    //       ... full openGeneric inlined ...
    //   }
    fn Open(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additionalData: slice<byte>,
    ) -> (slice<byte>, error) {
        // Go: if len(nonce) != g.nonceSize { panic(...) }
        if nonce.Len() != self.nonceSize {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }
        // Go: if g.tagSize < gcmMinimumTagSize { panic(...) }
        if self.tagSize < gcmMinimumTagSize {
            panic!("crypto/cipher: incorrect GCM tag size");
        }

        let nonce_v: Vec<byte> = nonce.__into_vec();
        let ct_v: Vec<byte> = ciphertext.__into_vec();
        let aad_v: Vec<byte> = additionalData.__into_vec();
        let ts = self.tagSize as usize;

        // Go: if len(ciphertext) < g.tagSize { return nil, errOpen }
        if ct_v.len() < ts {
            return (slice::__from_vec(alloc::vec::Vec::new()), errOpen());
        }
        // Go: if uint64(len(ciphertext)) > ... { return nil, errOpen }
        let max_ct =
            ((1u64 << 32) - 2) * (gcmBlockSize as u64) + (self.tagSize as u64);
        if (ct_v.len() as u64) > max_ct {
            return (slice::__from_vec(alloc::vec::Vec::new()), errOpen());
        }

        // ret, out := sliceForAppend(dst, len(ciphertext)-g.tagSize)
        let plain_len = ct_v.len() - ts;
        let mut ret_v: Vec<byte> = dst.__into_vec();
        let head_off = ret_v.len();
        ret_v.resize(head_off + plain_len, 0u8);

        // Go: g.cipher.Encrypt(H[:], H[:])
        let zero = [0u8; 16];
        let mut h_arr = [0u8; 16];
        block_encrypt(&self.cipher, &mut h_arr, &zero);

        let mut counter = [0u8; 16];
        deriveCounter(&h_arr, &mut counter, &nonce_v);

        // Go: gcmCounterCryptGeneric(g.cipher, tagMask[:], tagMask[:], &counter)
        let mut tagMask = [0u8; 16];
        let zero16 = [0u8; 16];
        gcmCounterCryptGeneric(&self.cipher, &mut tagMask, &zero16, &mut counter);

        // Go: tag := ciphertext[len(ciphertext)-g.tagSize:]
        // Go: ciphertext = ciphertext[:len(ciphertext)-g.tagSize]
        let recv_tag: &[u8] = &ct_v[plain_len..];
        let ct_body: &[u8] = &ct_v[..plain_len];

        // Go: var expectedTag [gcmTagSize]byte
        // Go: gcmAuth(expectedTag[:], &H, &tagMask, ciphertext, additionalData)
        let mut expectedTag = [0u8; 16];
        gcmAuth(&mut expectedTag, &h_arr, &tagMask, ct_body, &aad_v);

        // Go: if subtle.ConstantTimeCompare(expectedTag[:g.tagSize], tag) != 1 {
        //         clear(out); return nil, errOpen
        //     }
        let exp_s: slice<byte> = slice::__from_vec(expectedTag[..ts].to_vec());
        let recv_s: slice<byte> = slice::__from_vec(recv_tag.to_vec());
        if subtle::ConstantTimeCompare(&exp_s, &recv_s) != 1 {
            // Clear the output region (Go: clear(out)).
            for i in 0..plain_len {
                ret_v[head_off + i] = 0;
            }
            return (slice::__from_vec(alloc::vec::Vec::new()), errOpen());
        }

        // Go: gcmCounterCryptGeneric(g.cipher, out, ciphertext, &counter)
        {
            let out_slice = &mut ret_v[head_off..head_off + plain_len];
            gcmCounterCryptGeneric(&self.cipher, out_slice, ct_body, &mut counter);
        }

        (slice::__from_vec(ret_v), nil)
    }
}

// Go: gcm.go:273
//   var errOpen = errors.New("cipher: message authentication failed")
//
// Cached so `errors::Is(err, errOpen())` walks ptr-identity correctly
// (mirrors the bufio / lzw cached-error pattern; see
// memory/feedback_typed_error_unwrap_chain.md).
fn errOpen() -> error {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(ErrNew("cipher: message authentication failed"));
    }
    g.as_ref().unwrap().clone()
}
