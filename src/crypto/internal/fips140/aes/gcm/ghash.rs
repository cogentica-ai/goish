// go: file crypto/internal/fips140/aes/gcm/ghash.go decls: GHASH, ghash, reverseBits, ghashAdd, ghashDouble, ghashMul, updateBlocks, ghashUpdate
//
// GHASH — the GF(2¹²⁸) universal hash underneath GCM's authentication.
//
// This is the variable-time generic implementation, which should not be
// used on any architecture with hardware support for AES-GCM. On amd64
// that is PCLMULQDQ, which goish does not yet use (CRYPTO_PORT.md
// "Assembly").

#![allow(non_snake_case, non_upper_case_globals)]
#![allow(non_camel_case_types)] // Go names (gcmFieldElement)

use crate::crypto::internal::fips140deps::byteorder;
use crate::goslice::slice;
use crate::types::{byte, int, uint64};

extern crate alloc;
use alloc::vec::Vec;

use super::gcm::gcmBlockSize;

// Go: ghash.go:20
//   type gcmFieldElement struct { low, high uint64 }
/// A value in GF(2¹²⁸). To reflect the GCM standard and make big-endian
/// marshaling suitable, the bits are stored in big-endian order:
///
///   * the coefficient of x⁰ is `v.low >> 63`
///   * the coefficient of x⁶³ is `v.low & 1`
///   * the coefficient of x⁶⁴ is `v.high >> 63`
///   * the coefficient of x¹²⁷ is `v.high & 1`
#[derive(Clone, Copy, Default)]
pub(crate) struct gcmFieldElement {
    pub(crate) low: uint64,
    pub(crate) high: uint64,
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/ghash.go:26-31 GHASH
/// `gcm.GHASH(key, inputs...)` — exposed so crypto/cipher can implement
/// non-AES GCM modes. Not allowed as a stand-alone operation in FIPS mode
/// because it is not ACVP tested.
pub fn GHASH(key: &[byte; 16], inputs: &[slice<byte>]) -> slice<byte> {
    // Go: fips140.RecordNonApproved() — no-op in goish.
    // Go: var out [gcmBlockSize]byte; ghash(&out, key, inputs...); return out[:]
    let mut out = [0u8; 16];
    let raw: Vec<&[byte]> = inputs.iter().map(|s| -> &[byte] { s }).collect();
    ghash(&mut out, key, &raw);
    return slice::__from_vec(out.to_vec());
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/ghash.go:37-64 ghash
/// A variable-time generic implementation of GHASH. Each input is
/// zero-padded to 128 bits before being absorbed.
pub(crate) fn ghash(out: &mut [byte; 16], H: &[byte; 16], inputs: &[&[byte]]) {
    // productTable contains the first sixteen powers of the key, H.
    // However, they are in bit-reversed order.
    let mut productTable = [gcmFieldElement::default(); 16];

    // We precompute 16 multiples of H. When we look into this table we
    // use bits from a field element, and those bits are in reverse
    // order — so 4*H is not at index 4 but at index 0010b = 2.
    let x = gcmFieldElement {
        low: byteorder::BEUint64(slice::__from_vec(H[..8].to_vec())),
        high: byteorder::BEUint64(slice::__from_vec(H[8..].to_vec())),
    };
    productTable[reverseBits(1) as usize] = x;

    // Go: for i := 2; i < 16; i += 2 { … }
    let mut i: int = 2;
    while i < 16 {
        productTable[reverseBits(i) as usize] =
            ghashDouble(&productTable[reverseBits(i / 2) as usize]);
        productTable[reverseBits(i + 1) as usize] =
            ghashAdd(&productTable[reverseBits(i) as usize], &x);
        i += 2;
    }

    // Go: var y gcmFieldElement; for _, input := range inputs { … }
    let mut y = gcmFieldElement::default();
    let mut k: usize = 0;
    while k < inputs.len() {
        ghashUpdate(&productTable, &mut y, inputs[k]);
        k += 1;
    }

    // Go: byteorder.BEPutUint64(out[:], y.low); BEPutUint64(out[8:], y.high)
    let mut lo = slice::__from_vec(alloc::vec![0u8; 8]);
    byteorder::BEPutUint64(&mut lo, y.low);
    let mut hi = slice::__from_vec(alloc::vec![0u8; 8]);
    byteorder::BEPutUint64(&mut hi, y.high);
    let lor: &[byte] = &lo;
    let hir: &[byte] = &hi;
    out[..8].copy_from_slice(lor);
    out[8..].copy_from_slice(hir);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/ghash.go:67-71 reverseBits
/// Reverse the order of the bits of the 4-bit number in `i`.
fn reverseBits(i: int) -> int {
    // Go: i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
    let mut i = ((i << 2) & 0xc) | ((i >> 2) & 0x3);
    // Go: i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
    i = ((i << 1) & 0xa) | ((i >> 1) & 0x5);
    return i;
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/ghash.go:74-77 ghashAdd
/// Add two elements of GF(2¹²⁸). In a characteristic-2 field this is XOR.
fn ghashAdd(x: &gcmFieldElement, y: &gcmFieldElement) -> gcmFieldElement {
    // Go: return gcmFieldElement{x.low ^ y.low, x.high ^ y.high}
    return gcmFieldElement {
        low: x.low ^ y.low,
        high: x.high ^ y.high,
    };
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/ghash.go:80-100 ghashDouble
/// Double an element of GF(2¹²⁸).
fn ghashDouble(x: &gcmFieldElement) -> gcmFieldElement {
    // Go: msbSet := x.high&1 == 1
    let msbSet = (x.high & 1) == 1;

    // Because of the bit ordering, doubling is actually a right shift.
    let mut double = gcmFieldElement {
        low: x.low >> 1,
        high: (x.high >> 1) | (x.low << 63),
    };

    // If the most significant bit was set before shifting then it
    // conceptually becomes a term of x^128. That is greater than the
    // irreducible polynomial, so the result has to be reduced. The
    // irreducible polynomial is 1+x+x²+x⁷+x¹²⁸; subtracting it eliminates
    // the x^128 term and also the other four terms. In characteristic-2
    // fields subtraction == addition == XOR.
    if msbSet {
        double.low ^= 0xe100000000000000;
    }

    return double;
}

/// Go: `var ghashReductionTable = []uint16{…}`
const ghashReductionTable: [u16; 16] = [
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0, 0xe100, 0xfd20, 0xd940, 0xc560,
    0x9180, 0x8da0, 0xa9c0, 0xb5e0,
];

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/ghash.go:108-136 ghashMul
/// Set `y` to `y*H`, where H is the GCM key fixed during New.
fn ghashMul(productTable: &[gcmFieldElement; 16], y: &mut gcmFieldElement) {
    // Go: var z gcmFieldElement
    let mut z = gcmFieldElement::default();

    // Go: for i := 0; i < 2; i++ { word := y.high; if i == 1 { word = y.low } … }
    let mut i: usize = 0;
    while i < 2 {
        let mut word = if i == 0 { y.high } else { y.low };

        // Multiplication works by multiplying z by 16 and adding in one
        // of the precomputed multiples of H.
        let mut j: usize = 0;
        while j < 64 {
            let msw = z.high & 0xf;
            z.high >>= 4;
            z.high |= z.low << 60;
            z.low >>= 4;
            z.low ^= (ghashReductionTable[msw as usize] as uint64) << 48;

            // The values in the table are ordered for little-endian bit
            // positions — see the comment in ghash.
            let t = productTable[(word & 0xf) as usize];

            z.low ^= t.low;
            z.high ^= t.high;
            word >>= 4;
            j += 4;
        }
        i += 1;
    }

    // Go: *y = z
    *y = z;
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/ghash.go:140-147 updateBlocks
/// Extend `y` with more polynomial terms from `blocks`, by Horner's rule.
/// `blocks` must be a multiple of `gcmBlockSize` bytes.
fn updateBlocks(productTable: &[gcmFieldElement; 16], y: &mut gcmFieldElement, blocks: &[byte]) {
    let bs = gcmBlockSize as usize;
    let mut off: usize = 0;
    // Go: for len(blocks) > 0 { … }
    while off < blocks.len() {
        // Go: y.low ^= byteorder.BEUint64(blocks); y.high ^= BEUint64(blocks[8:])
        y.low ^= byteorder::BEUint64(slice::__from_vec(blocks[off..off + 8].to_vec()));
        y.high ^= byteorder::BEUint64(slice::__from_vec(blocks[off + 8..off + 16].to_vec()));
        ghashMul(productTable, y);
        // Go: blocks = blocks[gcmBlockSize:]
        off += bs;
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/ghash.go:151-159 ghashUpdate
/// Extend `y` with more polynomial terms from `data`. If `data` is not a
/// multiple of `gcmBlockSize` bytes long, the remainder is zero padded.
fn ghashUpdate(productTable: &[gcmFieldElement; 16], y: &mut gcmFieldElement, data: &[byte]) {
    // Go: fullBlocks := (len(data) >> 4) << 4
    let fullBlocks = (data.len() >> 4) << 4;
    updateBlocks(productTable, y, &data[..fullBlocks]);

    // Go: if len(data) != fullBlocks { … zero-pad the remainder … }
    if data.len() != fullBlocks {
        let mut partialBlock = [0u8; 16];
        let rem = data.len() - fullBlocks;
        partialBlock[..rem].copy_from_slice(&data[fullBlocks..]);
        updateBlocks(productTable, y, &partialBlock);
    }
}
