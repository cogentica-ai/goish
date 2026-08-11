// go: file crypto/internal/fips140/tls12/tls12.go decls: PRF, pHash, MasterSecret
//
// crypto/internal/fips140/tls12 — the TLS 1.2 pseudo-random function
// (RFC 5246 §5) and extended master secret derivation (RFC 7627), both
// allowed by SP 800-135 Rev. 1 §4.2.2.
//
// Deviations from tls12[go] @ Go 1.25.5:
//
//   * The hash factory is `fn() -> Box<dyn Hash + Send + Sync>` rather
//     than Go's `func() H` generic, matching `hmac::New`.
//   * `MasterSecret`'s type switch exists only to drive
//     `fips140.RecordNonApproved()` for hashes outside {SHA-256, SHA-384,
//     SHA-512}. goish's fips140 stub records nothing, so the switch is
//     documented rather than executed — every branch would be a no-op.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::internal::fips140::hmac;
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::Hash;
use crate::io;
use crate::types::{byte, int};

/// Go: `const masterSecretLength = 48`
const masterSecretLength: int = 48;
/// Go: `const extendedMasterSecretLabel = "extended master secret"`
const extendedMasterSecretLabel: &str = "extended master secret";

// go: sdk 1.25.5 crypto/internal/fips140/tls12/tls12.go:15-25 PRF
/// `tls12.PRF(hash, secret, label, seed, keyLen)` — the TLS 1.2
/// pseudo-random function.
pub fn PRF(
    hash: fn() -> Box<dyn Hash + Send + Sync>,
    secret: slice<byte>,
    label: string,
    seed: slice<byte>,
    keyLen: int,
) -> slice<byte> {
    // Go: labelAndSeed := make([]byte, len(label)+len(seed))
    //     copy(labelAndSeed, label); copy(labelAndSeed[len(label):], seed)
    let lraw: &[byte] = label.as_bytes();
    let sraw: &[byte] = &seed;
    let mut labelAndSeed: Vec<byte> = Vec::with_capacity(lraw.len() + sraw.len());
    labelAndSeed.extend_from_slice(lraw);
    labelAndSeed.extend_from_slice(sraw);

    // Go: result := make([]byte, keyLen); pHash(hash, result, secret, labelAndSeed)
    let mut result: Vec<byte> = alloc::vec![0u8; keyLen as usize];
    pHash(hash, &mut result, secret, &labelAndSeed);
    // Go: return result
    return slice::__from_vec(result);
}

// go: sdk 1.25.5 crypto/internal/fips140/tls12/tls12.go:27-45 pHash
/// The P_hash function, as defined in RFC 5246 §5.
fn pHash(
    hash: fn() -> Box<dyn Hash + Send + Sync>,
    result: &mut [byte],
    secret: slice<byte>,
    seed: &[byte],
) {
    // Go: h := hmac.New(hash, secret); h.Write(seed); a := h.Sum(nil)
    let mut h = hmac::New(hash, secret);
    let _ = io::Writer::Write(&mut h, slice::__from_vec(seed.to_vec()));
    let mut a: Vec<byte> = h.Sum(slice::__from_vec(Vec::new())).__into_vec();

    // Go: for len(result) > 0 { … }
    let mut off: usize = 0;
    while off < result.len() {
        // Go: h.Reset(); h.Write(a); h.Write(seed); b := h.Sum(nil)
        <hmac::HMAC as Hash>::Reset(&mut h);
        let _ = io::Writer::Write(&mut h, slice::__from_vec(a.clone()));
        let _ = io::Writer::Write(&mut h, slice::__from_vec(seed.to_vec()));
        let b: Vec<byte> = h.Sum(slice::__from_vec(Vec::new())).__into_vec();
        // Go: n := copy(result, b); result = result[n:]
        let n = core::cmp::min(result.len() - off, b.len());
        result[off..off + n].copy_from_slice(&b[..n]);
        off += n;

        // Go: h.Reset(); h.Write(a); a = h.Sum(nil)
        <hmac::HMAC as Hash>::Reset(&mut h);
        let _ = io::Writer::Write(&mut h, slice::__from_vec(a.clone()));
        a = h.Sum(slice::__from_vec(Vec::new())).__into_vec();
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/tls12/tls12.go:50-70 MasterSecret
/// `tls12.MasterSecret(hash, preMasterSecret, transcript)` — the TLS 1.2
/// extended master secret derivation (RFC 7627).
pub fn MasterSecret(
    hash: fn() -> Box<dyn Hash + Send + Sync>,
    preMasterSecret: slice<byte>,
    transcript: slice<byte>,
) -> slice<byte> {
    // Go: switch any(h).(type) { case *sha256.Digest: …; case *sha512.Digest: …;
    //     default: fips140.RecordNonApproved() }
    //
    // "The TLS 1.2 KDF is an approved KDF when the following conditions
    // are satisfied: [...] (3) P_HASH uses either SHA-256, SHA-384 or
    // SHA-512." Every arm of that switch only records a service
    // indicator, which goish's fips140 stub does not implement, so the
    // check is documented here rather than executed.

    // Go: return PRF(hash, preMasterSecret, extendedMasterSecretLabel,
    //                transcript, masterSecretLength)
    return PRF(
        hash,
        preMasterSecret,
        string::from_static(extendedMasterSecretLabel),
        transcript,
        masterSecretLength,
    );
}
