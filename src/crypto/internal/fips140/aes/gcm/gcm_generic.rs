// go: file crypto/internal/fips140/aes/gcm/gcm_generic.go decls: sealGeneric, openGeneric, deriveCounterGeneric, gcmCounterCryptGeneric, gcmInc32, gcmAuthGeneric
//
// The pure-Go GCM. Counter-mode encryption plus GHASH authentication;
// the assembly builds replace both halves at once with a fused
// AES-NI + PCLMULQDQ implementation.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140::aes;
use crate::crypto::internal::fips140deps::byteorder;
use crate::error;
use crate::goslice::slice;
use crate::types::{byte, uint64};

extern crate alloc;
use alloc::vec::Vec;

use super::gcm::{errOpen, gcmBlockSize, gcmStandardNonceSize, gcmTagSize, GCM};
use super::gcm_noasm::checkGenericIsExpected;
use super::ghash::ghash;

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_generic.go:13-24 sealGeneric
/// Go: `func sealGeneric(out []byte, g *GCM, nonce, plaintext, additionalData []byte)`
pub(crate) fn sealGeneric(
    out: &mut [byte],
    g: &GCM,
    nonce: &slice<byte>,
    plaintext: &slice<byte>,
    additionalData: &slice<byte>,
) {
    // Go: var H, counter, tagMask [gcmBlockSize]byte
    //     aes.EncryptBlockInternal(&g.cipher, H[:], H[:])
    let mut H = [0u8; 16];
    encryptBlockInto(&g.cipher, &mut H, &[0u8; 16]);
    // Go: deriveCounterGeneric(&H, &counter, nonce)
    let mut counter = [0u8; 16];
    deriveCounterGeneric(&H, &mut counter, nonce);
    // Go: gcmCounterCryptGeneric(&g.cipher, tagMask[:], tagMask[:], &counter)
    let mut tagMask = [0u8; 16];
    let zero = [0u8; 16];
    gcmCounterCryptGeneric(&g.cipher, &mut tagMask, &zero, &mut counter);

    // Go: gcmCounterCryptGeneric(&g.cipher, out, plaintext, &counter)
    let ptRaw: &[byte] = plaintext;
    let ptLen = ptRaw.len();
    gcmCounterCryptGeneric(&g.cipher, &mut out[..ptLen], ptRaw, &mut counter);

    // Go: var tag [gcmTagSize]byte
    //     gcmAuthGeneric(tag[:], &H, &tagMask, out[:len(plaintext)], additionalData)
    let mut tag = [0u8; 16];
    let ct: Vec<byte> = out[..ptLen].to_vec();
    let adRaw: &[byte] = additionalData;
    gcmAuthGeneric(&mut tag, &H, &tagMask, &ct, adRaw);
    // Go: copy(out[len(plaintext):], tag[:])
    let n = core::cmp::min(out.len() - ptLen, gcmTagSize as usize);
    out[ptLen..ptLen + n].copy_from_slice(&tag[..n]);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_generic.go:26-44 openGeneric
/// Go: `func openGeneric(out []byte, g *GCM, nonce, ciphertext, additionalData []byte) error`
pub(crate) fn openGeneric(
    out: &mut [byte],
    g: &GCM,
    nonce: &slice<byte>,
    ciphertext: &slice<byte>,
    additionalData: &slice<byte>,
) -> error {
    // Go: var H, counter, tagMask [gcmBlockSize]byte
    //     aes.EncryptBlockInternal(&g.cipher, H[:], H[:])
    let mut H = [0u8; 16];
    encryptBlockInto(&g.cipher, &mut H, &[0u8; 16]);
    // Go: deriveCounterGeneric(&H, &counter, nonce)
    let mut counter = [0u8; 16];
    deriveCounterGeneric(&H, &mut counter, nonce);
    // Go: gcmCounterCryptGeneric(&g.cipher, tagMask[:], tagMask[:], &counter)
    let mut tagMask = [0u8; 16];
    let zero = [0u8; 16];
    gcmCounterCryptGeneric(&g.cipher, &mut tagMask, &zero, &mut counter);

    // Go: tag := ciphertext[len(ciphertext)-g.tagSize:]
    //     ciphertext = ciphertext[:len(ciphertext)-g.tagSize]
    let ctRaw: &[byte] = ciphertext;
    let ctLen = ctRaw.len() - (g.tagSize as usize);
    let tag = &ctRaw[ctLen..];
    let body = &ctRaw[..ctLen];

    // Go: var expectedTag [gcmTagSize]byte
    //     gcmAuthGeneric(expectedTag[:], &H, &tagMask, ciphertext, additionalData)
    let mut expectedTag = [0u8; 16];
    let adRaw: &[byte] = additionalData;
    gcmAuthGeneric(&mut expectedTag, &H, &tagMask, body, adRaw);
    // Go: if subtle.ConstantTimeCompare(expectedTag[:g.tagSize], tag) != 1 { return errOpen }
    let a = slice::__from_vec(expectedTag[..g.tagSize as usize].to_vec());
    let b = slice::__from_vec(tag.to_vec());
    if crate::crypto::subtle::ConstantTimeCompare(&a, &b) != 1 {
        return errOpen.into();
    }

    // Go: gcmCounterCryptGeneric(&g.cipher, out, ciphertext, &counter)
    gcmCounterCryptGeneric(&g.cipher, &mut out[..ctLen], body, &mut counter);

    // Go: return nil
    return crate::errors::nil;
}

// go: none — goish idiom: aes::EncryptBlockInternal takes `slice<byte>`
// per AGENTS.md §3, but GCM's hot loop works on fixed 16-byte arrays.
// This is the one conversion point rather than four.
fn encryptBlockInto(b: &aes::Block, dst: &mut [byte; 16], src: &[byte; 16]) {
    let mut d = slice::__from_vec(alloc::vec![0u8; 16]);
    aes::EncryptBlockInternal(b, &mut d, slice::__from_vec(src.to_vec()));
    let r: &[byte] = &d;
    dst.copy_from_slice(r);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_generic.go:42-64 deriveCounterGeneric
/// Compute the initial GCM counter state from `nonce` (NIST SP 800-38D
/// §7.1). Assumes `counter` is zero on entry.
///
/// GCM has two modes with respect to the initial counter: a fast path for
/// 96-bit nonces, where the nonce plus a four-byte big-endian counter
/// starting at one is used directly, and a slow path for other lengths,
/// where the counter is computed by passing the nonce through GHASH.
pub(crate) fn deriveCounterGeneric(H: &[byte; 16], counter: &mut [byte; 16], nonce: &slice<byte>) {
    let nRaw: &[byte] = nonce;
    // Go: if len(nonce) == gcmStandardNonceSize { copy(counter[:], nonce); counter[15] = 1 }
    if nRaw.len() == gcmStandardNonceSize as usize {
        counter[..nRaw.len()].copy_from_slice(nRaw);
        counter[(gcmBlockSize as usize) - 1] = 1;
    } else {
        // Go: lenBlock := make([]byte, 16)
        //     byteorder.BEPutUint64(lenBlock[8:], uint64(len(nonce))*8)
        //     ghash(counter, H, nonce, lenBlock)
        let mut lenBlock = [0u8; 16];
        putBEUint64(&mut lenBlock[8..], (nRaw.len() as uint64) * 8);
        ghash(counter, H, &[nRaw, &lenBlock]);
    }
}

// go: none — goish idiom: byteorder::BEPutUint64 takes `&mut slice<byte>`
// per AGENTS.md §3; GCM works on fixed arrays, so this is the single
// adaptation point.
fn putBEUint64(dst: &mut [byte], v: uint64) {
    let mut w = slice::__from_vec(alloc::vec![0u8; 8]);
    byteorder::BEPutUint64(&mut w, v);
    let r: &[byte] = &w;
    dst[..8].copy_from_slice(r);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_generic.go:69-86 gcmCounterCryptGeneric
/// Encrypt `src` with AES in counter mode with 32-bit wrapping (which is
/// different from AES-CTR) and place the result in `out`. `counter` is
/// the initial value and is updated with the next.
pub(crate) fn gcmCounterCryptGeneric(
    b: &aes::Block,
    out: &mut [byte],
    src: &[byte],
    counter: &mut [byte; 16],
) {
    // Go: var mask [gcmBlockSize]byte
    let mut mask = [0u8; 16];
    let bs = gcmBlockSize as usize;

    let mut off: usize = 0;
    // Go: for len(src) >= gcmBlockSize { … }
    while src.len() - off >= bs {
        // Go: aes.EncryptBlockInternal(b, mask[:], counter[:]); gcmInc32(counter)
        encryptBlockInto(b, &mut mask, counter);
        gcmInc32(counter);

        // Go: subtle.XORBytes(out, src, mask[:])
        let mut k: usize = 0;
        while k < bs {
            out[off + k] = src[off + k] ^ mask[k];
            k += 1;
        }
        off += bs;
    }

    // Go: if len(src) > 0 { … } — the trailing partial block.
    if off < src.len() {
        encryptBlockInto(b, &mut mask, counter);
        gcmInc32(counter);
        let rem = src.len() - off;
        let mut k: usize = 0;
        while k < rem {
            out[off + k] = src[off + k] ^ mask[k];
            k += 1;
        }
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_generic.go:90-93 gcmInc32
/// Treat the final four bytes of `counterBlock` as a big-endian value and
/// increment it.
pub(crate) fn gcmInc32(counterBlock: &mut [byte; 16]) {
    // Go: ctr := counterBlock[len(counterBlock)-4:]
    //     byteorder.BEPutUint32(ctr, byteorder.BEUint32(ctr)+1)
    let base = (gcmBlockSize as usize) - 4;
    let cur = byteorder::BEUint32(slice::__from_vec(counterBlock[base..].to_vec()));
    let mut w = slice::__from_vec(alloc::vec![0u8; 4]);
    byteorder::BEPutUint32(&mut w, cur.wrapping_add(1));
    let r: &[byte] = &w;
    counterBlock[base..].copy_from_slice(r);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_generic.go:95-104 gcmAuthGeneric
/// Calculate GHASH(additionalData, ciphertext), mask the result with
/// `tagMask`, and write it to `out`.
pub(crate) fn gcmAuthGeneric(
    out: &mut [byte; 16],
    H: &[byte; 16],
    tagMask: &[byte; 16],
    ciphertext: &[byte],
    additionalData: &[byte],
) {
    // Go: checkGenericIsExpected()
    checkGenericIsExpected();
    // Go: lenBlock := make([]byte, 16)
    //     byteorder.BEPutUint64(lenBlock[:8], uint64(len(additionalData))*8)
    //     byteorder.BEPutUint64(lenBlock[8:], uint64(len(ciphertext))*8)
    let mut lenBlock = [0u8; 16];
    putBEUint64(&mut lenBlock[..8], (additionalData.len() as uint64) * 8);
    putBEUint64(&mut lenBlock[8..], (ciphertext.len() as uint64) * 8);
    // Go: var S [gcmBlockSize]byte
    //     ghash(&S, H, additionalData, ciphertext, lenBlock)
    let mut S = [0u8; 16];
    ghash(&mut S, H, &[additionalData, ciphertext, &lenBlock]);
    // Go: subtle.XORBytes(out, S[:], tagMask[:])
    let mut k: usize = 0;
    while k < 16 {
        out[k] = S[k] ^ tagMask[k];
        k += 1;
    }
}
