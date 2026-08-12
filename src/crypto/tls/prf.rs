// go: file crypto/tls/prf.go decls: splitPreMasterSecret, pHash, prf10, prf12, noEKMBecauseRenegotiation, noEKMBecauseNoEMS
//
// crypto/tls — the TLS 1.0-1.2 pseudo-random function.
//
// **Partial port.** Everything in prf.go that does not need the
// `cipherSuite` record is here: the PRF itself (RFC 2246 §5, RFC 5246
// §5), the pre-master-secret split, and the two EKM refusal stubs. The
// remainder — `prfAndHashForVersion`, `masterFromPreMasterSecret`,
// `keysFromMasterSecret`, the `finishedHash` methods and
// `ekmFromMasterSecret` — all take a `*cipherSuite`, which lives in the
// unported half of cipher_suites.go. See ROADMAP.md.
//
// goishlint:ignore GOISH018 prfAndHashForVersion, prfForVersion, masterFromPreMasterSecret, extMasterFromPreMasterSecret, keysFromMasterSecret, newFinishedHash, Write, Sum, clientSum, serverSum, hashForClientCertificate, discardHandshakeBuffer, ekmFromMasterSecret — every one takes a *cipherSuite; see the banner.
// goishlint:ignore GOISH019 finishedHash — same.
// goishlint:ignore GOISH021 prfFunc, finishedHash, masterSecretLength, finishedVerifyLength, masterSecretLabel, extendedMasterSecretLabel, keyExpansionLabel, clientFinishedLabel, serverFinishedLabel — same.

#![allow(non_snake_case, dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::hmac;
use crate::crypto::internal::fips140::tls12;
use crate::crypto::md5;
use crate::crypto::sha1;
use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::{Hash, IntoHashFunc};
use crate::io::Writer as _;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/tls/prf.go:23-27 splitPreMasterSecret
/// Split a premaster secret in two as specified in RFC 4346, Section 5.
pub(crate) fn splitPreMasterSecret(secret: slice<byte>) -> (slice<byte>, slice<byte>) {
    // Go: s1 = secret[0 : (len(secret)+1)/2]
    //     s2 = secret[len(secret)/2:]
    let n = secret.Len();
    let s1 = secret.slice(0, (n + 1) / 2);
    let s2 = secret.slice(n / 2, n);
    return (s1, s2);
}

// go: sdk 1.25.5 crypto/tls/prf.go:30-49 pHash
/// The P_hash function, as defined in RFC 4346, Section 5.
pub(crate) fn pHash<H: IntoHashFunc + Clone>(
    result: &mut slice<byte>,
    secret: slice<byte>,
    seed: slice<byte>,
    hash: H,
) {
    // Go: h := hmac.New(hash, secret); h.Write(seed); a := h.Sum(nil)
    let mut h = hmac::New(hash.clone(), secret);
    let _ = h.Write(seed.clone());
    let mut a = h.Sum(slice::__from_vec(Vec::new()));

    // Go: j := 0; for j < len(result) { … }
    let mut j: int = 0;
    while j < result.Len() {
        // Go: h.Reset(); h.Write(a); h.Write(seed); b := h.Sum(nil)
        h.Reset();
        let _ = h.Write(a.clone());
        let _ = h.Write(seed.clone());
        let b = h.Sum(slice::__from_vec(Vec::new()));
        // Go: copy(result[j:], b)
        let mut i: int = 0;
        while i < b.Len() && j + i < result.Len() {
            result[(j + i) as usize] = b[i as usize];
            i += 1;
        }
        // Go: j += len(b)
        j += b.Len();

        // Go: h.Reset(); h.Write(a); a = h.Sum(nil)
        h.Reset();
        let _ = h.Write(a.clone());
        a = h.Sum(slice::__from_vec(Vec::new()));
    }
}

// go: sdk 1.25.5 crypto/tls/prf.go:51-71 prf10
/// The TLS 1.0 pseudo-random function, as defined in RFC 2246, Section 5.
pub(crate) fn prf10(
    secret: slice<byte>,
    label: string,
    seed: slice<byte>,
    keyLen: int,
) -> slice<byte> {
    // Go: result := make([]byte, keyLen)
    let mut result: slice<byte> = slice::__from_vec(alloc::vec![0u8; keyLen as usize]);
    // Go: hashSHA1 := sha1.New; hashMD5 := md5.New

    // Go: labelAndSeed := make([]byte, len(label)+len(seed))
    //     copy(labelAndSeed, label)
    //     copy(labelAndSeed[len(label):], seed)
    let lab: &[byte] = label.as_bytes();
    let mut labelAndSeed: Vec<byte> = Vec::with_capacity(lab.len() + seed.Len() as usize);
    labelAndSeed.extend_from_slice(lab);
    let seedRaw: &[byte] = &seed;
    labelAndSeed.extend_from_slice(seedRaw);
    let labelAndSeed = slice::__from_vec(labelAndSeed);

    // Go: s1, s2 := splitPreMasterSecret(secret)
    let (s1, s2) = splitPreMasterSecret(secret);
    // Go: pHash(result, s1, labelAndSeed, hashMD5)
    pHash(&mut result, s1, labelAndSeed.clone(), md5::NewHash as fn() -> alloc::boxed::Box<dyn Hash + Send + Sync>);
    // Go: result2 := make([]byte, len(result)); pHash(result2, s2, labelAndSeed, hashSHA1)
    let mut result2: slice<byte> = slice::__from_vec(alloc::vec![0u8; result.Len() as usize]);
    pHash(&mut result2, s2, labelAndSeed, sha1::NewHash as fn() -> alloc::boxed::Box<dyn Hash + Send + Sync>);

    // Go: for i, b := range result2 { result[i] ^= b }
    for (i, b) in crate::range!(result2) {
        result[i as usize] ^= *b;
    }

    // Go: return result
    return result;
}

// go: sdk 1.25.5 crypto/tls/prf.go:73-77 prf12
/// The TLS 1.2 pseudo-random function, as defined in RFC 5246, Section 5.
///
/// Deviation: Go returns a `prfFunc` closure that captures `hashFunc`.
/// goish has no `dyn Fn` in a public signature (see CONTRIBUTING.md §5),
/// so the closure is inlined at the one place Go calls the result — the
/// arguments are identical and `tls12::PRF` does the work either way.
/// goishlint:ignore GOISH020 prf12 — Go takes 1 arg and returns a closure over the other 4; see above
pub(crate) fn prf12<H: IntoHashFunc>(
    hashFunc: H,
    secret: slice<byte>,
    label: string,
    seed: slice<byte>,
    keyLen: int,
) -> slice<byte> {
    // Go: return tls12.PRF(hashFunc, secret, label, seed, keyLen)
    return tls12::PRF(hashFunc, secret, label, seed, keyLen);
}

// go: sdk 1.25.5 crypto/tls/prf.go:257-259 noEKMBecauseRenegotiation
/// Used as the value of `ConnectionState.ekm` when renegotiation is
/// enabled, so that all key-material export requests fail.
pub(crate) fn noEKMBecauseRenegotiation(
    _label: string,
    _context: slice<byte>,
    _length: int,
) -> (slice<byte>, error) {
    // Go: return nil, errors.New("crypto/tls: ExportKeyingMaterial is
    //     unavailable when renegotiation is enabled")
    return (
        slice::__from_vec(Vec::new()),
        crate::errors::New(
            "crypto/tls: ExportKeyingMaterial is unavailable when renegotiation is enabled",
        ),
    );
}

// go: sdk 1.25.5 crypto/tls/prf.go:264-266 noEKMBecauseNoEMS
/// Used as the value of `ConnectionState.ekm` when Extended Master
/// Secret is not negotiated, so that all key-material export requests
/// fail.
pub(crate) fn noEKMBecauseNoEMS(
    _label: string,
    _context: slice<byte>,
    _length: int,
) -> (slice<byte>, error) {
    // Go: return nil, errors.New("crypto/tls: ExportKeyingMaterial is
    //     unavailable when neither TLS 1.3 nor Extended Master Secret
    //     are negotiated; override with GODEBUG=tlsunsafeekm=1")
    return (
        slice::__from_vec(Vec::new()),
        crate::errors::New(
            "crypto/tls: ExportKeyingMaterial is unavailable when neither TLS 1.3 nor Extended Master Secret are negotiated; override with GODEBUG=tlsunsafeekm=1",
        ),
    );
}
