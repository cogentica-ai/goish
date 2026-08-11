// go: file crypto/cipher/gcm.go decls: NewGCM, NewGCMWithNonceSize, NewGCMWithTagSize, newGCM
// go: file crypto/cipher/gcm.go decls: NewGCMWithRandomNonce, (gcmWithRandomNonce).NonceSize, (gcmWithRandomNonce).Overhead, (gcmWithRandomNonce).Seal, (gcmWithRandomNonce).Open
// go: file crypto/cipher/gcm.go decls: newGCMFallback, (*gcmFallback).NonceSize, (*gcmFallback).Overhead, (*gcmFallback).Seal, (*gcmFallback).Open
// go: file crypto/cipher/gcm.go decls: deriveCounter, gcmCounterCryptGeneric, gcmInc32, gcmAuth, sliceForAppend
//
// crypto/cipher/gcm — Galois Counter Mode (GCM) AEAD.
//
// GHASH itself is NOT re-implemented here. Go's gcm.go calls
// `gcm.GHASH` from crypto/internal/fips140/aes/gcm; goish does the same
// (`fipsgcm::GHASH`), so there is exactly one GF(2¹²⁸) implementation in
// the tree and this file ports exactly one Go file.
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
//   * No `*aes.Block` fast path in `newGCM`. Go's newGCM checks the
//     cipher's concrete type to enter the hardware-friendly fips140
//     subroutine; goish has no runtime type assertion on a generic
//     `B: Block`, so the generic path is the only path here, applied
//     uniformly. (`NewGCMWithRandomNonce` takes a `dyn Block` and CAN
//     do the assertion, so it keeps Go's shape.)
//
//   * `gcmAble` — the interface a Block implements to supply its own
//     GCM — is dropped: goish has no runtime type assertion, and no
//     goish Block supplies one.
//     goishlint:ignore GOISH021 gcmAble — no runtime type assertion
//
//   * Go's `gcmFallback` — the generic non-AES implementation — is
//     goish's `GCM<B>` (see the note at the struct itself). Static
//     dispatch makes it the only implementation rather than a fallback,
//     so the name would be misleading.
//     goishlint:ignore GOISH021 gcmFallback — renamed to GCM<B>, see above
//
//   * `alias.InexactOverlap` / `alias.AnyOverlap` checks dropped —
//     goish slices have copy semantics on subslicing.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::cipher::{Block, AEAD};
use crate::crypto::internal::fips140::aes::gcm as fipsgcm;
use crate::crypto::subtle;
use crate::errors::{error, nil, New as ErrNew};
use crate::goslice::slice;
use crate::internal::byteorder;
use crate::types::byte;
use crate::{int, uint64};

// Go gcm.go:17-22 — package-level constants.
const gcmBlockSize: int = 16;
const gcmStandardNonceSize: int = 12;
const gcmTagSize: int = 16;
const gcmMinimumTagSize: int = 12; // NIST SP 800-38D recommends ≥12.

// ─── public surface ─────────────────────────────────────────────────

// go: sdk 1.25.5 crypto/cipher/gcm.go:226-230 gcmFallback
//
//   type gcmFallback struct {
//       cipher    Block
//       nonceSize int
//       tagSize   int
//   }
//
/// `cipher.GCM` — Galois Counter Mode wrapping a 128-bit block cipher.
/// Returned by `NewGCM` / `NewGCMWithNonceSize` / `NewGCMWithTagSize`.
/// Implements the `cipher::AEAD` trait.
///
/// This is Go's `gcmFallback`: the generic, non-AES implementation. With
/// static dispatch it is the only implementation, so "fallback" would be
/// a misleading name.
pub struct GCM<B: Block> {
    cipher: B,
    nonceSize: int,
    tagSize: int,
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:30-35 NewGCM
//
//   func NewGCM(cipher Block) (AEAD, error) {
//       return newGCM(cipher, gcmStandardNonceSize, gcmTagSize)
//   }
//
/// `cipher.NewGCM(cipher)` — wrap a 128-bit block cipher in GCM with
/// the standard 12-byte nonce and 16-byte tag. The cipher must have a
/// 16-byte block size.
///
/// On success returns `(Some(gcm), nil)`. On invalid block size returns
/// `(None, error)`.
pub fn NewGCM<B: Block>(cipher: B) -> (Option<GCM<B>>, error) {
    return newGCM(cipher, gcmStandardNonceSize, gcmTagSize);
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:44-49 NewGCMWithNonceSize
//
//   func NewGCMWithNonceSize(cipher Block, size int) (AEAD, error) {
//       return newGCM(cipher, size, gcmTagSize)
//   }
//
/// `cipher.NewGCMWithNonceSize(cipher, size)` — wrap a 128-bit block
/// cipher in GCM with the given nonce length (must be > 0). For
/// compatibility with non-standard nonce lengths.
pub fn NewGCMWithNonceSize<B: Block>(cipher: B, size: int) -> (Option<GCM<B>>, error) {
    return newGCM(cipher, size, gcmTagSize);
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:59-64 NewGCMWithTagSize
//
//   func NewGCMWithTagSize(cipher Block, tagSize int) (AEAD, error) {
//       return newGCM(cipher, gcmStandardNonceSize, tagSize)
//   }
//
/// `cipher.NewGCMWithTagSize(cipher, tagSize)` — wrap a 128-bit block
/// cipher in GCM with the given tag length (12..=16). For compatibility
/// with non-standard tag lengths.
pub fn NewGCMWithTagSize<B: Block>(cipher: B, tagSize: int) -> (Option<GCM<B>>, error) {
    return newGCM(cipher, gcmStandardNonceSize, tagSize);
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:66-81 newGCM
//
// Go's body first type-asserts `cipher.(*aes.Block)` to reach the fips140
// gcm.New; a generic `B: Block` cannot be asserted on, so what is left is
// Go's own non-AES arm.
fn newGCM<B: Block>(cipher: B, nonceSize: int, tagSize: int) -> (Option<GCM<B>>, error) {
    // Go: return newGCMFallback(cipher, nonceSize, tagSize)
    return newGCMFallback(cipher, nonceSize, tagSize);
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:93-103 NewGCMWithRandomNonce
/// Return the given cipher wrapped in Galois Counter Mode, with randomly
/// generated nonces. The cipher must have been created by
/// [`crate::crypto::aes::NewCipher`].
///
/// It generates a random 96-bit nonce, which is prepended to the
/// ciphertext by Seal, and is extracted from the ciphertext by Open. The
/// NonceSize of the AEAD is zero, while the Overhead is 28 bytes.
pub fn NewGCMWithRandomNonce(
    cipher: &(dyn Block + Send + Sync + 'static),
) -> (Option<gcmWithRandomNonce>, error) {
    use crate::goany::AsExt;

    // Go: c, ok := cipher.(*aes.Block); if !ok { … }
    let c = match cipher.As::<crate::crypto::internal::fips140::aes::Block>() {
        None => {
            return (
                None,
                ErrNew("cipher: NewGCMWithRandomNonce requires aes.Block"),
            )
        }
        Some(c) => c,
    };
    // Go: g, err := gcm.New(c, gcmStandardNonceSize, gcmTagSize)
    let (g, err) = fipsgcm::New(c, gcmStandardNonceSize, gcmTagSize);
    if err != nil {
        return (None, err);
    }
    // Go: return gcmWithRandomNonce{g}, nil
    return (Some(gcmWithRandomNonce { GCM: g.unwrap() }), nil);
}

// Go gcm.go:105-107
//   type gcmWithRandomNonce struct { *gcm.GCM }
//
/// Go embeds `*gcm.GCM`; goish names the field, per AGENTS.md §5.
pub struct gcmWithRandomNonce {
    GCM: fipsgcm::GCM,
}

impl AEAD for gcmWithRandomNonce {
    // go: sdk 1.25.5 crypto/cipher/gcm.go:109-111 gcmWithRandomNonce.NonceSize
    fn NonceSize(&self) -> int {
        return 0;
    }

    // go: sdk 1.25.5 crypto/cipher/gcm.go:113-115 gcmWithRandomNonce.Overhead
    fn Overhead(&self) -> int {
        return gcmStandardNonceSize + gcmTagSize;
    }

    // go: sdk 1.25.5 crypto/cipher/gcm.go:117-162 gcmWithRandomNonce.Seal
    //
    // Go slices `out` into an aliasing `nonce` and `ciphertext` and hands
    // both to SealWithRandomNonce, then spends ~30 lines on the overlap
    // cases that creates (`alias.InexactOverlap` / `AnyOverlap`, and the
    // memmove when dst aliases plaintext). goish slices do not share a
    // backing store — `sliceForAppend` already returns an offset rather
    // than a second handle for exactly this reason — so the nonce and
    // ciphertext are filled separately and concatenated. The overlap
    // branches are unreachable here and are not ported.
    fn Seal(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additionalData: slice<byte>,
    ) -> slice<byte> {
        // Go: if len(nonce) != 0 { panic(…) }
        if nonce.Len() != 0 {
            panic!("crypto/cipher: non-empty nonce passed to GCMWithRandomNonce");
        }

        let ptLen = plaintext.Len();
        let mut n = slice::__from_vec(alloc::vec![0u8; gcmStandardNonceSize as usize]);
        let mut ct = slice::__from_vec(alloc::vec![0u8; (ptLen + gcmTagSize) as usize]);
        // Go: gcm.SealWithRandomNonce(g.GCM, nonce, ciphertext, plaintext, additionalData)
        fipsgcm::SealWithRandomNonce(&self.GCM, &mut n, &mut ct, plaintext, additionalData);

        // Go: ret, out := sliceForAppend(dst, …); nonce = out[:12];
        //     ciphertext = out[12:]. goish fills the two pieces above and
        //     appends them to dst's contents here.
        let (ret, off) = sliceForAppend(&dst, gcmStandardNonceSize + ptLen + gcmTagSize);
        let head: &[byte] = &ret;
        let mut v: Vec<byte> = Vec::with_capacity(head.len());
        v.extend_from_slice(&head[..off as usize]);
        let nr: &[byte] = &n;
        let cr: &[byte] = &ct;
        v.extend_from_slice(nr);
        v.extend_from_slice(cr);
        // Go: return ret
        return slice::__from_vec(v);
    }

    // go: sdk 1.25.5 crypto/cipher/gcm.go:164-198 gcmWithRandomNonce.Open
    //
    // Same deviation as Seal: Go's aliasing branches (which exist so that
    // `dst` may be `ciphertext[:0]`) cannot arise for goish slices, so the
    // nonce and body are simply split off the front.
    fn Open(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additionalData: slice<byte>,
    ) -> (slice<byte>, error) {
        // Go: if len(nonce) != 0 { panic(…) }
        if nonce.Len() != 0 {
            panic!("crypto/cipher: non-empty nonce passed to GCMWithRandomNonce");
        }
        // Go: if len(ciphertext) < gcmStandardNonceSize+gcmTagSize { return nil, errOpen }
        if ciphertext.Len() < gcmStandardNonceSize + gcmTagSize {
            return (slice::__from_vec(Vec::new()), errOpen());
        }

        // Go: nonce = ciphertext[:gcmStandardNonceSize]
        //     ciphertext = ciphertext[gcmStandardNonceSize:]
        let raw: &[byte] = &ciphertext;
        let n = gcmStandardNonceSize as usize;
        let nonce = slice::__from_vec(raw[..n].to_vec());
        let body = slice::__from_vec(raw[n..].to_vec());

        // Go: _, err := g.GCM.Open(out[:0], nonce, ciphertext, additionalData)
        return self.GCM.Open(dst, nonce, body, additionalData);
    }
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:207-221 newGCMFallback
//
// Go's `gcmFallback` is goish's `GCM<B>`. The `gcmAble` arm of Go's body
// is dropped: no goish Block supplies its own GCM.
fn newGCMFallback<B: Block>(cipher: B, nonceSize: int, tagSize: int) -> (Option<GCM<B>>, error) {
    // Go: if tagSize < gcmMinimumTagSize || tagSize > gcmBlockSize { … }
    if tagSize < gcmMinimumTagSize || tagSize > gcmBlockSize {
        return (None, ErrNew("cipher: incorrect tag size given to GCM"));
    }
    // Go: if nonceSize <= 0 { … }
    if nonceSize <= 0 {
        return (None, ErrNew("cipher: the nonce can't have zero length"));
    }
    // Go: if cipher.BlockSize() != gcmBlockSize { … }
    if cipher.BlockSize() != gcmBlockSize {
        return (
            None,
            ErrNew("cipher: NewGCM requires 128-bit block cipher"),
        );
    }
    // Go: return &gcmFallback{cipher: cipher, nonceSize: nonceSize, tagSize: tagSize}, nil
    return (
        Some(GCM {
            cipher,
            nonceSize,
            tagSize,
        }),
        nil,
    );
}

impl<B: Block> AEAD for GCM<B> {
    // go: sdk 1.25.5 crypto/cipher/gcm.go:232-234 gcmFallback.NonceSize
    //
    //   func (g *gcmFallback) NonceSize() int { return g.nonceSize }
    fn NonceSize(&self) -> int {
        return self.nonceSize;
    }

    // go: sdk 1.25.5 crypto/cipher/gcm.go:236-238 gcmFallback.Overhead
    //
    //   func (g *gcmFallback) Overhead() int { return g.tagSize }
    fn Overhead(&self) -> int {
        return self.tagSize;
    }

    // go: sdk 1.25.5 crypto/cipher/gcm.go:240-271 gcmFallback.Seal
    fn Seal(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additionalData: slice<byte>,
    ) -> slice<byte> {
        // Go: if len(nonce) != g.nonceSize { panic(…) }
        if nonce.Len() != self.nonceSize {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }
        // Go: if g.nonceSize == 0 { panic(…) }
        if self.nonceSize == 0 {
            panic!("crypto/cipher: incorrect GCM nonce size");
        }
        // Go: if uint64(len(plaintext)) > uint64((1<<32)-2)*gcmBlockSize { panic(…) }
        let max_pt = uint64((1u64 << 32) - 2) * uint64(gcmBlockSize);
        if uint64(plaintext.Len()) > max_pt {
            panic!("crypto/cipher: message too large for GCM");
        }

        // Snapshot inputs into Vecs (goish slices are by-value).
        let pt_v: Vec<byte> = plaintext.__into_vec();
        let aad_v: Vec<byte> = additionalData.__into_vec();
        let ts = self.tagSize as usize;
        let n = pt_v.len();

        // Go: ret, out := sliceForAppend(dst, len(plaintext)+g.tagSize)
        let mut ret_v: Vec<byte> = dst.__into_vec();
        let head_off = ret_v.len();
        ret_v.resize(head_off + n + ts, 0u8);

        // Go: var H, counter, tagMask [gcmBlockSize]byte
        // Go: g.cipher.Encrypt(H[:], H[:])
        let zero = [0u8; 16];
        let mut H = [0u8; 16];
        block_encrypt(&self.cipher, &mut H, &zero);

        // Go: deriveCounter(&H, &counter, nonce)
        let mut counter = [0u8; 16];
        deriveCounter(&H, &mut counter, nonce);

        // Go: gcmCounterCryptGeneric(g.cipher, tagMask[:], tagMask[:], &counter)
        let mut tagMask = [0u8; 16];
        let zero16 = [0u8; 16];
        gcmCounterCryptGeneric(&self.cipher, &mut tagMask, &zero16, &mut counter);

        // Go: gcmCounterCryptGeneric(g.cipher, out, plaintext, &counter)
        {
            let out_slice = &mut ret_v[head_off..head_off + n];
            gcmCounterCryptGeneric(&self.cipher, out_slice, &pt_v, &mut counter);
        }

        // Go: var tag [gcmTagSize]byte
        // Go: gcmAuth(tag[:], &H, &tagMask, out[:len(plaintext)], additionalData)
        let mut tag = [0u8; 16];
        {
            let ct_slice = &ret_v[head_off..head_off + n];
            gcmAuth(&mut tag, &H, &tagMask, ct_slice, &aad_v);
        }
        // Go: copy(out[len(plaintext):], tag[:])
        let mut i: usize = 0;
        while i < ts {
            ret_v[head_off + n + i] = tag[i];
            i += 1;
        }

        // Go: return ret
        return slice::__from_vec(ret_v);
    }

    // go: sdk 1.25.5 crypto/cipher/gcm.go:275-320 gcmFallback.Open
    fn Open(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additionalData: slice<byte>,
    ) -> (slice<byte>, error) {
        // Go: if len(nonce) != g.nonceSize { panic(…) }
        if nonce.Len() != self.nonceSize {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }
        // Go: if g.tagSize < gcmMinimumTagSize { panic(…) }
        if self.tagSize < gcmMinimumTagSize {
            panic!("crypto/cipher: incorrect GCM tag size");
        }

        let ct_v: Vec<byte> = ciphertext.__into_vec();
        let aad_v: Vec<byte> = additionalData.__into_vec();
        let ts = self.tagSize as usize;

        // Go: if len(ciphertext) < g.tagSize { return nil, errOpen }
        if ct_v.len() < ts {
            return (slice::__from_vec(Vec::new()), errOpen());
        }
        // Go: if uint64(len(ciphertext)) > uint64((1<<32)-2)*gcmBlockSize+uint64(g.tagSize) {
        //         return nil, errOpen
        //     }
        let max_ct = uint64((1u64 << 32) - 2) * uint64(gcmBlockSize) + uint64(self.tagSize);
        if uint64(ct_v.len()) > max_ct {
            return (slice::__from_vec(Vec::new()), errOpen());
        }

        // Go: ret, out := sliceForAppend(dst, len(ciphertext)-g.tagSize)
        let plain_len = ct_v.len() - ts;
        let mut ret_v: Vec<byte> = dst.__into_vec();
        let head_off = ret_v.len();
        ret_v.resize(head_off + plain_len, 0u8);

        // Go: var H, counter, tagMask [gcmBlockSize]byte
        // Go: g.cipher.Encrypt(H[:], H[:])
        let zero = [0u8; 16];
        let mut H = [0u8; 16];
        block_encrypt(&self.cipher, &mut H, &zero);

        // Go: deriveCounter(&H, &counter, nonce)
        let mut counter = [0u8; 16];
        deriveCounter(&H, &mut counter, nonce);

        // Go: gcmCounterCryptGeneric(g.cipher, tagMask[:], tagMask[:], &counter)
        let mut tagMask = [0u8; 16];
        let zero16 = [0u8; 16];
        gcmCounterCryptGeneric(&self.cipher, &mut tagMask, &zero16, &mut counter);

        // Go: tag := ciphertext[len(ciphertext)-g.tagSize:]
        // Go: ciphertext = ciphertext[:len(ciphertext)-g.tagSize]
        let recv_tag: &[byte] = &ct_v[plain_len..];
        let ct_body: &[byte] = &ct_v[..plain_len];

        // Go: var expectedTag [gcmTagSize]byte
        // Go: gcmAuth(expectedTag[:], &H, &tagMask, ciphertext, additionalData)
        let mut expectedTag = [0u8; 16];
        gcmAuth(&mut expectedTag, &H, &tagMask, ct_body, &aad_v);

        // Go: if subtle.ConstantTimeCompare(expectedTag[:g.tagSize], tag) != 1 {
        //         clear(out); return nil, errOpen
        //     }
        let exp_s: slice<byte> = slice::__from_vec(expectedTag[..ts].to_vec());
        let recv_s: slice<byte> = slice::__from_vec(recv_tag.to_vec());
        if subtle::ConstantTimeCompare(&exp_s, &recv_s) != 1 {
            // Go: clear(out)
            let mut i: usize = 0;
            while i < plain_len {
                ret_v[head_off + i] = 0;
                i += 1;
            }
            return (slice::__from_vec(Vec::new()), errOpen());
        }

        // Go: gcmCounterCryptGeneric(g.cipher, out, ciphertext, &counter)
        {
            let out_slice = &mut ret_v[head_off..head_off + plain_len];
            gcmCounterCryptGeneric(&self.cipher, out_slice, ct_body, &mut counter);
        }

        // Go: return ret, nil
        return (slice::__from_vec(ret_v), nil);
    }
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:322-332 deriveCounter
//
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
//
/// Compute the initial GCM counter state J0. Standard 96-bit nonces
/// take the fast path (concat with 0x00000001); arbitrary-length
/// nonces fall through to GHASH.
fn deriveCounter(H: &[byte; 16], counter: &mut [byte; 16], nonce: slice<byte>) {
    if nonce.Len() == gcmStandardNonceSize {
        // Go: copy(counter[:], nonce)
        let raw: &[byte] = &nonce;
        let n = raw.len();
        counter[..n].copy_from_slice(raw);
        // Go: counter[gcmBlockSize-1] = 1 — the untouched middle bytes are
        // already zero because `counter` is a fresh zero array.
        counter[gcmBlockSize as usize - 1] = 1;
    } else {
        // Go: lenBlock := make([]byte, 16)
        //     byteorder.BEPutUint64(lenBlock[8:], uint64(len(nonce))*8)
        let mut hi = slice::__from_vec(alloc::vec![0u8; 8]);
        byteorder::BEPutUint64(&mut hi, uint64(nonce.Len()) * 8);
        let hir: &[byte] = &hi;
        let mut lenBlock_v: Vec<byte> = alloc::vec![0u8; 16];
        lenBlock_v[8..].copy_from_slice(hir);
        let lenBlock = slice::__from_vec(lenBlock_v);
        // Go: J := gcm.GHASH(H, nonce, lenBlock); copy(counter[:], J)
        let J = fipsgcm::GHASH(H, &[nonce, lenBlock]);
        let jr: &[byte] = &J;
        counter.copy_from_slice(&jr[..16]);
    }
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:334-349 gcmCounterCryptGeneric
//
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
//
/// CTR-mode encrypt with a 32-bit-wrapping counter (different from
/// AES-CTR's wider-counter mode).
///
/// `out` and `src` are `&[byte]` rather than `slice<byte>` because every
/// call site hands in a sub-region of a larger buffer, which a goish
/// `slice` cannot expose without copying. Go's `subtle.XORBytes(out, src,
/// mask[:])` is open-coded for the same reason.
fn gcmCounterCryptGeneric<B: Block>(
    b: &B,
    out: &mut [byte],
    src: &[byte],
    counter: &mut [byte; 16],
) {
    let bs = gcmBlockSize as usize;
    let mut mask = [0u8; 16];
    let mut off: usize = 0;
    let n = src.len();

    // Go: for len(src) >= gcmBlockSize { … }
    while n - off >= bs {
        // Go: b.Encrypt(mask[:], counter[:]); gcmInc32(counter)
        block_encrypt(b, &mut mask, counter);
        gcmInc32(counter);
        // Go: subtle.XORBytes(out, src, mask[:])
        let mut i: usize = 0;
        while i < bs {
            out[off + i] = src[off + i] ^ mask[i];
            i += 1;
        }
        // Go: out = out[gcmBlockSize:]; src = src[gcmBlockSize:]
        off += bs;
    }
    // Go: if len(src) > 0 { … }
    if off < n {
        block_encrypt(b, &mut mask, counter);
        gcmInc32(counter);
        let rem = n - off;
        let mut i: usize = 0;
        while i < rem {
            out[off + i] = src[off + i] ^ mask[i];
            i += 1;
        }
    }
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:351-354 gcmInc32
//
//   func gcmInc32(counterBlock *[gcmBlockSize]byte) {
//       ctr := counterBlock[len(counterBlock)-4:]
//       byteorder.BEPutUint32(ctr, byteorder.BEUint32(ctr)+1)
//   }
//
/// Treats the final 4 bytes of `counterBlock` as a big-endian counter and
/// increments it.
fn gcmInc32(counterBlock: &mut [byte; 16]) {
    // Go: ctr := counterBlock[len(counterBlock)-4:]
    let n = counterBlock.len();
    let ctr = slice::__from_vec(counterBlock[n - 4..].to_vec());
    // Go: byteorder.BEPutUint32(ctr, byteorder.BEUint32(ctr)+1)
    let v = byteorder::BEUint32(ctr).wrapping_add(1);
    let mut put = slice::__from_vec(alloc::vec![0u8; 4]);
    byteorder::BEPutUint32(&mut put, v);
    let raw: &[byte] = &put;
    counterBlock[n - 4..].copy_from_slice(raw);
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:356-362 gcmAuth
//
//   func gcmAuth(out []byte, H, tagMask *[gcmBlockSize]byte, ciphertext, additionalData []byte) {
//       lenBlock := make([]byte, 16)
//       byteorder.BEPutUint64(lenBlock[:8], uint64(len(additionalData))*8)
//       byteorder.BEPutUint64(lenBlock[8:], uint64(len(ciphertext))*8)
//       S := gcm.GHASH(H, additionalData, ciphertext, lenBlock)
//       subtle.XORBytes(out, S, tagMask[:])
//   }
//
/// Compute GHASH over (AAD || ciphertext || lengthBlock) and XOR with
/// `tagMask` to produce the authentication tag.
fn gcmAuth(
    out: &mut [byte],
    H: &[byte; 16],
    tagMask: &[byte; 16],
    ciphertext: &[byte],
    additionalData: &[byte],
) {
    // Go: lenBlock := make([]byte, 16)
    //     byteorder.BEPutUint64(lenBlock[:8], uint64(len(additionalData))*8)
    //     byteorder.BEPutUint64(lenBlock[8:], uint64(len(ciphertext))*8)
    let mut lo = slice::__from_vec(alloc::vec![0u8; 8]);
    byteorder::BEPutUint64(&mut lo, uint64(additionalData.len()) * 8);
    let mut hi = slice::__from_vec(alloc::vec![0u8; 8]);
    byteorder::BEPutUint64(&mut hi, uint64(ciphertext.len()) * 8);
    let lor: &[byte] = &lo;
    let hir: &[byte] = &hi;
    let mut lenBlock_v: Vec<byte> = alloc::vec![0u8; 16];
    lenBlock_v[..8].copy_from_slice(lor);
    lenBlock_v[8..].copy_from_slice(hir);

    // Go: S := gcm.GHASH(H, additionalData, ciphertext, lenBlock)
    let inputs = [
        slice::__from_vec(additionalData.to_vec()),
        slice::__from_vec(ciphertext.to_vec()),
        slice::__from_vec(lenBlock_v),
    ];
    let S = fipsgcm::GHASH(H, &inputs);

    // Go: subtle.XORBytes(out, S, tagMask[:])
    let s_raw: &[byte] = &S;
    let n = out.len().min(s_raw.len()).min(tagMask.len());
    let mut i: usize = 0;
    while i < n {
        out[i] = s_raw[i] ^ tagMask[i];
        i += 1;
    }
}

// go: sdk 1.25.5 crypto/cipher/gcm.go:368-377 sliceForAppend
//
// Take a slice and a requested number of bytes. It returns a slice with the
// contents of the given slice followed by that many bytes and a second
// slice that aliases into it and contains only the extra bytes.
//
// Go's two results alias one backing array, which is the whole point of the
// function there — `out` is written and `ret` is returned. goish's `slice`
// has no way to hand out two aliasing handles safely, so this returns the
// combined slice and the offset at which the extra bytes begin; every Go
// call site uses `out` only as `head[offset..]`.
fn sliceForAppend(inb: &slice<byte>, n: int) -> (slice<byte>, int) {
    let src: &[byte] = inb;
    // Go: if total := len(in) + n; cap(in) >= total { head = in[:total] } else { … }
    let total = src.len() + n as usize;
    let mut head: Vec<byte> = Vec::with_capacity(total);
    head.extend_from_slice(src);
    head.resize(total, 0);
    // Go: tail = head[len(in):]; return
    return (slice::__from_vec(head), int(src.len()));
}

// go: none — goish glue: goish's `Block::Encrypt` takes `slice<byte>`,
// while GCM's internals work on fixed `[byte; 16]` arrays. Go passes
// `mask[:]` / `H[:]` directly because a Go array slices for free. No Go
// counterpart; pure marshalling.
fn block_encrypt<B: Block>(b: &B, dst: &mut [byte; 16], src: &[byte; 16]) {
    let src_s: slice<byte> = slice::__from_vec(src.to_vec());
    let mut dst_s: slice<byte> = slice::__from_vec(alloc::vec![0u8; 16]);
    b.Encrypt(&mut dst_s, src_s);
    let v = dst_s.__into_vec();
    dst.copy_from_slice(&v[..16]);
}

// go: none — goish idiom: Go declares `var errOpen = errors.New(…)` as a
// package-level sentinel (gcm.go:273). goish caches it behind a lazy slot
// so `errors::Is(err, errOpen())` compares by Arc identity, matching the
// sibling port in crypto/internal/fips140/aes/gcm/gcm.rs.
//
/// Go: `var errOpen = errors.New("cipher: message authentication failed")`
fn errOpen() -> error {
    use crate::runtime::spin::SpinLock;
    static SLOT: SpinLock<Option<error>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(ErrNew("cipher: message authentication failed"));
    }
    return g.as_ref().unwrap().clone();
}
