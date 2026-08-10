// goishlint:ignore GOISH018 — `sealAfterIndicator` is folded into `Seal`.
// In Go it exists so that GCMForTLS13 and friends in gcm_nonces[go] can
// seal *after* recording a FIPS service indicator that differs from
// plain GCM's; goish's fips140 stub has no service indicator, so the two
// bodies would be byte-identical. Port it with gcm_nonces[go].
// go: file crypto/internal/fips140/aes/gcm/gcm.go decls: New, newGCM, GCM.NonceSize, GCM.Overhead, GCM.Seal, GCM.Open, sliceForAppend
//
// crypto/internal/fips140/aes/gcm — AES-GCM (NIST SP 800-38D).
//
// Deviations from gcm[go] @ Go 1.25.5:
//
//   * `New` returns `(Option<GCM>, error)` rather than `(*GCM, error)`;
//     goish has no nil pointer for a by-value struct. `newGCM` keeps its
//     shape (Go outlines it so `New` stays inlineable) because the
//     argument validation lives there.
//   * `fips140.Record{Non,}Approved()` calls are dropped: goish's fips140
//     stub has no service indicator.
//   * cast[go]'s `init` is not ported: no CAST registry in goish.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140::aes;
use crate::crypto::internal::fips140::alias;
use crate::error;
use crate::goslice::slice;
use crate::types::{byte, int, uint64};

extern crate alloc;
use alloc::vec::Vec;

use super::gcm_noasm::{gcmPlatformData, initGCM, open, seal};

/// Go: `gcmBlockSize = 16`
pub(crate) const gcmBlockSize: int = 16;
/// Go: `gcmTagSize = 16`
pub(crate) const gcmTagSize: int = 16;
/// Go: `gcmMinimumTagSize = 12` — NIST SP 800-38D recommends tags with
/// 12 or more bytes.
pub(crate) const gcmMinimumTagSize: int = 12;
/// Go: `gcmStandardNonceSize = 12`
pub(crate) const gcmStandardNonceSize: int = 12;

// Go: gcm.go:14
//   type GCM struct { cipher aes.Block; nonceSize, tagSize int; gcmPlatformData }
/// `gcm.GCM` — Galois/Counter Mode with a specific key.
#[derive(Clone)]
pub struct GCM {
    pub(crate) cipher: aes::Block,
    pub(crate) nonceSize: int,
    pub(crate) tagSize: int,
    #[allow(dead_code)]
    pub(crate) platform: gcmPlatformData,
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm.go:20-23 New
/// `gcm.New(cipher, nonceSize, tagSize)` — a new GCM over `cipher`.
pub fn New(cipher: &aes::Block, nonceSize: int, tagSize: int) -> (Option<GCM>, error) {
    // Go: return newGCM(&GCM{}, cipher, nonceSize, tagSize)
    //
    // Go passes a zero GCM in so the allocation lands on the parent
    // stack; goish returns by value, so the parameter is dropped.
    return newGCM(cipher, nonceSize, tagSize);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm.go:29-42 newGCM
/// Go: `func newGCM(g *GCM, cipher *aes.Block, nonceSize, tagSize int) (*GCM, error)`
fn newGCM(cipher: &aes::Block, nonceSize: int, tagSize: int) -> (Option<GCM>, error) {
    // Go: if tagSize < gcmMinimumTagSize || tagSize > gcmBlockSize { … }
    if tagSize < gcmMinimumTagSize || tagSize > gcmBlockSize {
        return (
            None,
            crate::errors::New("cipher: incorrect tag size given to GCM"),
        );
    }
    // Go: if nonceSize <= 0 { … }
    if nonceSize <= 0 {
        return (
            None,
            crate::errors::New("cipher: the nonce can't have zero length"),
        );
    }
    // Go: if cipher.BlockSize() != gcmBlockSize { … }
    if cipher.BlockSize() != gcmBlockSize {
        return (
            None,
            crate::errors::New("cipher: NewGCM requires 128-bit block cipher"),
        );
    }
    // Go: g.cipher = *cipher; g.nonceSize = nonceSize; g.tagSize = tagSize
    let mut g = GCM {
        cipher: cipher.clone(),
        nonceSize,
        tagSize,
        platform: gcmPlatformData {},
    };
    // Go: initGCM(g)
    initGCM(&mut g);
    // Go: return g, nil
    return (Some(g), crate::errors::nil);
}

impl GCM {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm.go:51-53 NonceSize
    /// Go: `func (g *GCM) NonceSize() int { return g.nonceSize }`
    pub fn NonceSize(&self) -> int {
        return self.nonceSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm.go:55-57 Overhead
    /// Go: `func (g *GCM) Overhead() int { return g.tagSize }`
    pub fn Overhead(&self) -> int {
        return self.tagSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm.go:59-62 Seal
    /// `(*GCM).Seal(dst, nonce, plaintext, data)` — encrypt and
    /// authenticate `plaintext`, authenticate `data`, and append the
    /// result to `dst`.
    pub fn Seal(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        data: slice<byte>,
    ) -> slice<byte> {
        // Go: fips140.RecordNonApproved(); return g.sealAfterIndicator(…)
        //
        // Go's sealAfterIndicator body is inlined here — see the
        // GOISH018 note at the top of this file.
        // Go: if len(nonce) != g.nonceSize { panic(…) }
        if nonce.Len() != self.nonceSize {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }
        // Go: if g.nonceSize == 0 { panic("crypto/cipher: incorrect GCM nonce size") }
        if self.nonceSize == 0 {
            panic!("crypto/cipher: incorrect GCM nonce size");
        }
        // Go: if uint64(len(plaintext)) > uint64((1<<32)-2)*gcmBlockSize { panic(…) }
        if (plaintext.Len() as uint64) > ((1u64 << 32) - 2) * (gcmBlockSize as uint64) {
            panic!("crypto/cipher: message too large for GCM");
        }

        // Go: ret, out := sliceForAppend(dst, len(plaintext)+g.tagSize)
        let (mut ret, headLen) = sliceForAppend(dst, plaintext.Len() + self.tagSize);
        {
            let outv = slice::__from_vec({
                let r: &[byte] = &ret;
                r[headLen..].to_vec()
            });
            // Go: if alias.InexactOverlap(out, plaintext) { panic(…) }
            if alias::InexactOverlap(&outv, &plaintext) {
                panic!("crypto/cipher: invalid buffer overlap of output and input");
            }
            // Go: if alias.AnyOverlap(out, data) { panic(…) }
            if alias::AnyOverlap(&outv, &data) {
                panic!("crypto/cipher: invalid buffer overlap of output and additional data");
            }
        }

        // Go: seal(out, g, nonce, plaintext, data); return ret
        let mut outbuf: Vec<byte> = alloc::vec![0u8; (plaintext.Len() + self.tagSize) as usize];
        seal(&mut outbuf, self, &nonce, &plaintext, &data);
        {
            let r: &mut [byte] = &mut ret;
            r[headLen..].copy_from_slice(&outbuf);
        }
        return ret;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm.go:88-121 Open
    /// `(*GCM).Open(dst, nonce, ciphertext, data)` — authenticate and
    /// decrypt `ciphertext`, appending the plaintext to `dst`.
    pub fn Open(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        data: slice<byte>,
    ) -> (slice<byte>, error) {
        // Go: if len(nonce) != g.nonceSize { panic(…) }
        if nonce.Len() != self.nonceSize {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }
        // Go: sanity check so authentication cannot always succeed if an
        // implementation leaves tagSize uninitialized.
        if self.tagSize < gcmMinimumTagSize {
            panic!("crypto/cipher: incorrect GCM tag size");
        }

        // Go: if len(ciphertext) < g.tagSize { return nil, errOpen }
        if ciphertext.Len() < self.tagSize {
            return (slice::__from_vec(Vec::new()), errOpen());
        }
        // Go: if uint64(len(ciphertext)) > uint64((1<<32)-2)*gcmBlockSize+uint64(g.tagSize) { … }
        if (ciphertext.Len() as uint64)
            > ((1u64 << 32) - 2) * (gcmBlockSize as uint64) + (self.tagSize as uint64)
        {
            return (slice::__from_vec(Vec::new()), errOpen());
        }

        // Go: ret, out := sliceForAppend(dst, len(ciphertext)-g.tagSize)
        let (mut ret, headLen) = sliceForAppend(dst, ciphertext.Len() - self.tagSize);
        {
            let outv = slice::__from_vec({
                let r: &[byte] = &ret;
                r[headLen..].to_vec()
            });
            // Go: if alias.InexactOverlap(out, ciphertext) { panic(…) }
            if alias::InexactOverlap(&outv, &ciphertext) {
                panic!("crypto/cipher: invalid buffer overlap of output and input");
            }
            // Go: if alias.AnyOverlap(out, data) { panic(…) }
            if alias::AnyOverlap(&outv, &data) {
                panic!("crypto/cipher: invalid buffer overlap of output and additional data");
            }
        }

        // Go: if err := open(out, g, nonce, ciphertext, data); err != nil { clear(out); return nil, err }
        let mut outbuf: Vec<byte> =
            alloc::vec![0u8; (ciphertext.Len() - self.tagSize) as usize];
        let err = open(&mut outbuf, self, &nonce, &ciphertext, &data);
        if err != crate::errors::nil {
            // We sometimes decrypt and authenticate concurrently, so the
            // buffer is cleared on a tag mismatch — consistent across
            // platforms, and it never releases unauthenticated plaintext.
            let mut z: usize = 0;
            while z < outbuf.len() {
                outbuf[z] = 0;
                z += 1;
            }
            return (slice::__from_vec(Vec::new()), err);
        }
        {
            let r: &mut [byte] = &mut ret;
            r[headLen..].copy_from_slice(&outbuf);
        }
        // Go: return ret, nil
        return (ret, crate::errors::nil);
    }
}

// go: none — goish idiom: Go declares `var errOpen = errors.New(…)` as a
// package-level sentinel. goish builds it on demand; `errors::Is` on the
// result is not meaningful either way because Go's GCM never wraps it.
/// Go: `var errOpen = errors.New("cipher: message authentication failed")`
pub(crate) fn errOpen() -> error {
    return crate::errors::New("cipher: message authentication failed");
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm.go:126-135 sliceForAppend
/// Take a slice and a requested number of bytes. Returns a slice with the
/// contents of `in` followed by that many bytes, and the offset at which
/// the extra bytes begin.
///
/// Go returns two slices, the second aliasing into the first. goish
/// cannot hand out two live views of one buffer, so it returns the head
/// plus the offset and the caller writes through `ret[headLen..]`.
fn sliceForAppend(inp: slice<byte>, n: int) -> (slice<byte>, usize) {
    // Go: if total := len(in) + n; cap(in) >= total { head = in[:total] }
    //     else { head = make([]byte, total); copy(head, in) }
    let src: &[byte] = &inp;
    let headLen = src.len();
    let mut head: Vec<byte> = Vec::with_capacity(headLen + (n as usize));
    head.extend_from_slice(src);
    head.resize(headLen + (n as usize), 0);
    // Go: tail = head[len(in):]
    return (slice::__from_vec(head), headLen);
}
