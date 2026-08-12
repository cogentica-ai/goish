// go: file crypto/internal/fips140/aes/gcm/gcm_nonces.go decls: SealWithRandomNonce, NewGCMWithCounterNonce, GCMWithCounterNonce.NonceSize, GCMWithCounterNonce.Overhead, GCMWithCounterNonce.Seal, GCMWithCounterNonce.Open, NewGCMForTLS12, GCMForTLS12.NonceSize, GCMForTLS12.Overhead, GCMForTLS12.Seal, GCMForTLS12.Open, NewGCMForTLS13, GCMForTLS13.NonceSize, GCMForTLS13.Overhead, GCMForTLS13.Seal, GCMForTLS13.Open, NewGCMForSSH, GCMForSSH.NonceSize, GCMForSSH.Overhead, GCMForSSH.Seal, GCMForSSH.Open
//
// The nonce-discipline wrappers. Each enforces a different construction
// rule so that a nonce can never repeat under one key — the failure that
// destroys GCM's security outright.
//
//   GCMWithCounterNonce  FIPS 140-3 IG C.H Scenario 3: 32-bit module
//                        name || 64-bit counter
//   GCMForTLS12          RFC 5288 §3 / RFC 9325 §7.2.1 (Scenario 1.a)
//   GCMForTLS13          RFC 8446 §5.3 — the counter is XOR-masked, and
//                        the mask is learned from the first call
//   GCMForSSH            RFC 5647 (Scenario 1.d)
//
// No deviations from gcm_nonces[go] @ Go 1.25.5.
//
// This file carried two, and both had quietly expired — the code was
// still working around gaps that had since been filled:
//
//   * `fips140.RecordApproved()` was dropped as a no-op "because goish's
//     fips140 stub has no service indicator", and each Seal therefore
//     called `GCM::Seal` instead of Go's `sealAfterIndicator`, the two
//     being identical without an indicator. The record functions are now
//     ported, though still inert — `setIndicator` is a runtime linkname
//     stub, see fips140/indicator.rs — so this restores Go's shape
//     rather than fixing a live bug. It matters because the fold was an
//     inversion waiting to happen: `GCM::Seal` records NON-approved, so
//     the moment the indicator works, every approved path here would
//     report the opposite of the truth. RecordApproved, then
//     sealAfterIndicator, is what Go does and what stays correct.
//   * `SealWithRandomNonce` drew its nonce from `crypto::rand::Read`
//     rather than `drbg.Read`, on the grounds that drbg's pooled `Read`
//     needed `sync.Pool`, `internal/sysrand` and `crypto/internal/entropy`.
//     All three are ported and drbg is 8/8, so it now calls `drbg::Read`
//     as Go does. That also makes this the FIPS-approved construction,
//     which the old note explicitly said it was not.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140;
use crate::crypto::internal::fips140::aes;
use crate::crypto::internal::fips140::alias;
use crate::crypto::internal::fips140::drbg;
use crate::crypto::internal::fips140deps::byteorder;
use crate::error;
use crate::goslice::slice;
use crate::types::{byte, int, uint32, uint64};

extern crate alloc;
use alloc::vec::Vec;

use super::gcm::{gcmStandardNonceSize, gcmTagSize, New, GCM};
use super::gcm_noasm::seal;

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:24-43 SealWithRandomNonce
/// `gcm.SealWithRandomNonce(g, nonce, out, plaintext, additionalData)` —
/// encrypt `plaintext` into `out` and write a random nonce to `nonce`.
///
/// `nonce` must be 12 bytes and `out` 16 bytes longer than `plaintext`.
/// Note this is NOT a `cipher.AEAD` Seal method.
pub fn SealWithRandomNonce(
    g: &GCM,
    nonce: &mut slice<byte>,
    out: &mut slice<byte>,
    plaintext: slice<byte>,
    additionalData: slice<byte>,
) {
    // Go: if uint64(len(plaintext)) > uint64((1<<32)-2)*gcmBlockSize { panic(…) }
    if (plaintext.Len() as uint64) > ((1u64 << 32) - 2) * 16 {
        panic!("crypto/cipher: message too large for GCM");
    }
    // Go: if len(nonce) != gcmStandardNonceSize { panic(…) }
    if nonce.Len() != gcmStandardNonceSize {
        panic!("crypto/cipher: incorrect nonce length given to GCMWithRandomNonce");
    }
    // Go: if len(out) != len(plaintext)+gcmTagSize { panic(…) }
    if out.Len() != plaintext.Len() + gcmTagSize {
        panic!("crypto/cipher: incorrect output length given to GCMWithRandomNonce");
    }
    // Go: if alias.InexactOverlap(out, plaintext) { panic(…) }
    if alias::InexactOverlap(out, &plaintext) {
        panic!("crypto/cipher: invalid buffer overlap of output and input");
    }
    // Go: if alias.AnyOverlap(out, additionalData) { panic(…) }
    if alias::AnyOverlap(out, &additionalData) {
        panic!("crypto/cipher: invalid buffer overlap of output and additional data");
    }
    // Go: fips140.RecordApproved()
    fips140::RecordApproved();
    // Go: drbg.Read(nonce)
    drbg::Read(nonce);
    // Go: seal(out, g, nonce, plaintext, additionalData)
    let mut buf: Vec<byte> = alloc::vec![0u8; out.Len() as usize];
    seal(&mut buf, g, nonce, &plaintext, &additionalData);
    let d: &mut [byte] = out;
    d.copy_from_slice(&buf);
}

// go: none — goish idiom: the four wrappers below share this
// monotonic-counter check verbatim in Go, once per Seal. Naming it keeps
// the four bodies readable and the rule in one place.
/// Panic unless `counter` is strictly ahead of everything already sealed,
/// then record the next expected value.
fn advanceCounter(next: &mut uint64, counter: uint64) {
    // Go: if counter == math.MaxUint64 { panic("crypto/cipher: counter wrapped") }
    if counter == u64::MAX {
        panic!("crypto/cipher: counter wrapped");
    }
    // Go: if counter < g.next { panic("crypto/cipher: counter decreased") }
    if counter < *next {
        panic!("crypto/cipher: counter decreased");
    }
    // Go: g.next = counter + 1
    *next = counter + 1;
}

// go: none — goish idiom: Go reads the trailing counter as
// `byteorder.BEUint64(nonce[len(nonce)-8:])` inline in each Seal.
fn nonceCounter(nonce: &slice<byte>) -> uint64 {
    let raw: &[byte] = nonce;
    return byteorder::BEUint64(slice::__from_vec(raw[raw.len() - 8..].to_vec()));
}

// ─── GCMWithCounterNonce (IG C.H Scenario 3) ──────────────────────────

/// `gcm.GCMWithCounterNonce` — GCM restricted to deterministic nonces of
/// the form 32-bit module name || 64-bit counter.
#[derive(Clone)]
pub struct GCMWithCounterNonce {
    g: GCM,
    ready: bool,
    fixedName: uint32,
    start: uint64,
    next: uint64,
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:51-57 NewGCMWithCounterNonce
/// `gcm.NewGCMWithCounterNonce(cipher)` — a GCM that enforces the
/// counter-nonce construction.
pub fn NewGCMWithCounterNonce(cipher: &aes::Block) -> (Option<GCMWithCounterNonce>, error) {
    // Go: g, err := newGCM(&GCM{}, cipher, gcmStandardNonceSize, gcmTagSize)
    let (g, err) = New(cipher, gcmStandardNonceSize, gcmTagSize);
    if err != crate::errors::nil {
        return (None, err);
    }
    // Go: return &GCMWithCounterNonce{g: *g}, nil
    return (
        Some(GCMWithCounterNonce {
            g: g.unwrap(),
            ready: false,
            fixedName: 0,
            start: 0,
            next: 0,
        }),
        crate::errors::nil,
    );
}

impl GCMWithCounterNonce {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:67-67 GCMWithCounterNonce.NonceSize
    pub fn NonceSize(&self) -> int {
        return gcmStandardNonceSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:69-69 GCMWithCounterNonce.Overhead
    pub fn Overhead(&self) -> int {
        return gcmTagSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:71-99 GCMWithCounterNonce.Seal
    pub fn Seal(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        data: slice<byte>,
    ) -> slice<byte> {
        // Go: if len(nonce) != gcmStandardNonceSize { panic(…) }
        if nonce.Len() != gcmStandardNonceSize {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }

        // Go: counter := byteorder.BEUint64(nonce[len(nonce)-8:])
        let mut counter = nonceCounter(&nonce);
        let raw: &[byte] = &nonce;
        let name = byteorder::BEUint32(slice::__from_vec(raw[..4].to_vec()));
        // Go: if !g.ready { … first invocation sets the name and start … }
        if !self.ready {
            self.ready = true;
            self.start = counter;
            self.fixedName = name;
        }
        // Go: if g.fixedName != byteorder.BEUint32(nonce[:4]) { panic(…) }
        if self.fixedName != name {
            panic!("crypto/cipher: incorrect module name given to GCMWithCounterNonce");
        }
        // Go: counter -= g.start
        counter = counter.wrapping_sub(self.start);

        // Ensure the counter is monotonically increasing.
        advanceCounter(&mut self.next, counter);

        // Go: fips140.RecordApproved()
        fips140::RecordApproved();
        // Go: return g.g.sealAfterIndicator(dst, nonce, plaintext, data)
        return self.g.sealAfterIndicator(dst, nonce, plaintext, data);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:101-104 GCMWithCounterNonce.Open
    pub fn Open(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        data: slice<byte>,
    ) -> (slice<byte>, error) {
        // Go: fips140.RecordApproved()
        fips140::RecordApproved();
        // Go: return g.g.Open(dst, nonce, ciphertext, data)
        return self.g.Open(dst, nonce, ciphertext, data);
    }
}

// ─── GCMForTLS12 (RFC 5288 §3, RFC 9325 §7.2.1) ───────────────────────

/// `gcm.GCMForTLS12` — GCM with TLS 1.2's explicit-nonce discipline.
#[derive(Clone)]
pub struct GCMForTLS12 {
    g: GCM,
    next: uint64,
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:111-117 NewGCMForTLS12
/// `gcm.NewGCMForTLS12(cipher)` — a GCM that enforces RFC 5288 nonces.
pub fn NewGCMForTLS12(cipher: &aes::Block) -> (Option<GCMForTLS12>, error) {
    let (g, err) = New(cipher, gcmStandardNonceSize, gcmTagSize);
    if err != crate::errors::nil {
        return (None, err);
    }
    return (
        Some(GCMForTLS12 {
            g: g.unwrap(),
            next: 0,
        }),
        crate::errors::nil,
    );
}

impl GCMForTLS12 {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:124-124 GCMForTLS12.NonceSize
    pub fn NonceSize(&self) -> int {
        return gcmStandardNonceSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:126-126 GCMForTLS12.Overhead
    pub fn Overhead(&self) -> int {
        return gcmTagSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:128-146 GCMForTLS12.Seal
    pub fn Seal(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        data: slice<byte>,
    ) -> slice<byte> {
        if nonce.Len() != gcmStandardNonceSize {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }
        // Go: counter := byteorder.BEUint64(nonce[len(nonce)-8:])
        let counter = nonceCounter(&nonce);
        advanceCounter(&mut self.next, counter);
        // Go: fips140.RecordApproved()
        fips140::RecordApproved();
        // Go: return g.g.sealAfterIndicator(dst, nonce, plaintext, data)
        return self.g.sealAfterIndicator(dst, nonce, plaintext, data);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:148-151 GCMForTLS12.Open
    pub fn Open(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        data: slice<byte>,
    ) -> (slice<byte>, error) {
        // Go: fips140.RecordApproved()
        fips140::RecordApproved();
        // Go: return g.g.Open(dst, nonce, ciphertext, data)
        return self.g.Open(dst, nonce, ciphertext, data);
    }
}

// ─── GCMForTLS13 (RFC 8446 §5.3) ──────────────────────────────────────

/// `gcm.GCMForTLS13` — GCM with TLS 1.3's masked-counter nonce
/// discipline. The mask is learned from the first Seal, where the record
/// counter is zero.
#[derive(Clone)]
pub struct GCMForTLS13 {
    g: GCM,
    ready: bool,
    mask: uint64,
    next: uint64,
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:155-161 NewGCMForTLS13
/// `gcm.NewGCMForTLS13(cipher)` — a GCM that enforces RFC 8446 nonces.
pub fn NewGCMForTLS13(cipher: &aes::Block) -> (Option<GCMForTLS13>, error) {
    let (g, err) = New(cipher, gcmStandardNonceSize, gcmTagSize);
    if err != crate::errors::nil {
        return (None, err);
    }
    return (
        Some(GCMForTLS13 {
            g: g.unwrap(),
            ready: false,
            mask: 0,
            next: 0,
        }),
        crate::errors::nil,
    );
}

impl GCMForTLS13 {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:170-170 GCMForTLS13.NonceSize
    pub fn NonceSize(&self) -> int {
        return gcmStandardNonceSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:172-172 GCMForTLS13.Overhead
    pub fn Overhead(&self) -> int {
        return gcmTagSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:174-198 GCMForTLS13.Seal
    pub fn Seal(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        data: slice<byte>,
    ) -> slice<byte> {
        if nonce.Len() != gcmStandardNonceSize {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }
        // Go: counter := byteorder.BEUint64(nonce[len(nonce)-8:])
        let mut counter = nonceCounter(&nonce);
        // Go: if !g.ready { … in the first call the counter is zero, so we
        //     learn the XOR mask … }
        if !self.ready {
            self.ready = true;
            self.mask = counter;
        }
        // Go: counter ^= g.mask
        counter ^= self.mask;
        advanceCounter(&mut self.next, counter);
        // Go: fips140.RecordApproved()
        fips140::RecordApproved();
        // Go: return g.g.sealAfterIndicator(dst, nonce, plaintext, data)
        return self.g.sealAfterIndicator(dst, nonce, plaintext, data);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:200-203 GCMForTLS13.Open
    pub fn Open(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        data: slice<byte>,
    ) -> (slice<byte>, error) {
        // Go: fips140.RecordApproved()
        fips140::RecordApproved();
        // Go: return g.g.Open(dst, nonce, ciphertext, data)
        return self.g.Open(dst, nonce, ciphertext, data);
    }
}

// ─── GCMForSSH (RFC 5647) ─────────────────────────────────────────────

/// `gcm.GCMForSSH` — GCM with SSH's nonce discipline.
#[derive(Clone)]
pub struct GCMForSSH {
    g: GCM,
    ready: bool,
    start: uint64,
    next: uint64,
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:209-215 NewGCMForSSH
/// `gcm.NewGCMForSSH(cipher)` — a GCM that enforces RFC 5647 nonces.
pub fn NewGCMForSSH(cipher: &aes::Block) -> (Option<GCMForSSH>, error) {
    let (g, err) = New(cipher, gcmStandardNonceSize, gcmTagSize);
    if err != crate::errors::nil {
        return (None, err);
    }
    return (
        Some(GCMForSSH {
            g: g.unwrap(),
            ready: false,
            start: 0,
            next: 0,
        }),
        crate::errors::nil,
    );
}

impl GCMForSSH {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:224-224 GCMForSSH.NonceSize
    pub fn NonceSize(&self) -> int {
        return gcmStandardNonceSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:226-226 GCMForSSH.Overhead
    pub fn Overhead(&self) -> int {
        return gcmTagSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:228-252 GCMForSSH.Seal
    pub fn Seal(
        &mut self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        data: slice<byte>,
    ) -> slice<byte> {
        if nonce.Len() != gcmStandardNonceSize {
            panic!("crypto/cipher: incorrect nonce length given to GCM");
        }
        // Go: counter := byteorder.BEUint64(nonce[len(nonce)-8:])
        let mut counter = nonceCounter(&nonce);
        // Go: if !g.ready { … in the first call we learn the start value … }
        if !self.ready {
            self.ready = true;
            self.start = counter;
        }
        // Go: counter -= g.start
        counter = counter.wrapping_sub(self.start);
        advanceCounter(&mut self.next, counter);
        // Go: fips140.RecordApproved()
        fips140::RecordApproved();
        // Go: return g.g.sealAfterIndicator(dst, nonce, plaintext, data)
        return self.g.sealAfterIndicator(dst, nonce, plaintext, data);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_nonces.go:254-257 GCMForSSH.Open
    pub fn Open(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        data: slice<byte>,
    ) -> (slice<byte>, error) {
        // Go: fips140.RecordApproved()
        fips140::RecordApproved();
        // Go: return g.g.Open(dst, nonce, ciphertext, data)
        return self.g.Open(dst, nonce, ciphertext, data);
    }
}
