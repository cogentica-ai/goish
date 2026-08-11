// go: file crypto/hkdf/hkdf.go decls: Extract, Expand, Key, checkFIPS140Only
//
// crypto/hkdf — HKDF Extract / Expand / Key (RFC 5869).
//
// Go 1.25 makes this a thin wrapper over crypto/internal/fips140/hkdf;
// goish follows. The length validation lives here, the algorithm there.
//
// Slim deviations:
//   * Hash factory is `fn() -> Box<dyn Hash + Send + Sync>` instead of Go's
//     `func() H` generic, matching the convention already established
//     by `crypto::hmac::New`.
//   * No `crypto/internal/fips140hash.UnwrapNew` — that package is not
//     ported (it needs Go's `//go:linkname` to reach sha3's inner
//     Digest). `checkFIPS140Only` IS ported, and its `fips140only.Enabled`
//     guard is statically false in goish, so it always returns nil.
//   * `MarkAsUsedInKDF` is applied in the fips140 implementation, as in
//     Go — it is inert in goish, but the call site is the Go one.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::internal::fips140::hkdf as fips;
use crate::crypto::internal::fips140only;
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::Hash;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/hkdf/hkdf.go:27-33 Extract
/// `hkdf.Extract(h, secret, salt)` — a pseudorandom key from `secret`
/// and an optional `salt`.
pub fn Extract(
    h: fn() -> Box<dyn Hash + Send + Sync>,
    secret: slice<byte>,
    salt: slice<byte>,
) -> (slice<byte>, error) {
    // Go: if err := checkFIPS140Only(h, secret); err != nil { return nil, err }
    let err = checkFIPS140Only(h, &secret);
    if err != crate::nil {
        return (slice::__from_vec(Vec::new()), err);
    }
    let err = checkFIPS140Only(h, &secret);
    if err != crate::nil {
        return (slice::__from_vec(Vec::new()), err);
    }
    // Go: return hkdf.Extract(h, secret, salt), nil
    return (fips::Extract(h, secret, salt), nil);
}

// go: sdk 1.25.5 crypto/hkdf/hkdf.go:42-54 Expand
/// `hkdf.Expand(h, pseudorandomKey, info, keyLength)` — expand a
/// pseudorandom key into `keyLength` bytes of output keying material.
pub fn Expand(
    h: fn() -> Box<dyn Hash + Send + Sync>,
    pseudorandomKey: slice<byte>,
    info: string,
    keyLength: int,
) -> (slice<byte>, error) {
    // Go: limit := h().Size() * 255
    //     if keyLength > limit { return nil, errors.New("hkdf: requested key length too large") }
    let limit = h().Size() * 255;
    if keyLength > limit {
        return (
            slice::__from_vec(Vec::new()),
            errors::New(string::from_static("hkdf: requested key length too large")),
        );
    }
    // Go: if err := checkFIPS140Only(h, pseudorandomKey); err != nil { return nil, err }
    let err = checkFIPS140Only(h, &pseudorandomKey);
    if err != crate::nil {
        return (slice::__from_vec(Vec::new()), err);
    }
    // Go: return hkdf.Expand(h, pseudorandomKey, info, keyLength), nil
    return (fips::Expand(h, pseudorandomKey, info, keyLength), nil);
}

// go: sdk 1.25.5 crypto/hkdf/hkdf.go:59-71 Key
/// `hkdf.Key(h, secret, salt, info, keyLength)` — Extract then Expand.
pub fn Key(
    h: fn() -> Box<dyn Hash + Send + Sync>,
    secret: slice<byte>,
    salt: slice<byte>,
    info: string,
    keyLength: int,
) -> (slice<byte>, error) {
    // Go: limit := h().Size() * 255
    //     if keyLength > limit { return nil, errors.New("hkdf: requested key length too large") }
    let limit = h().Size() * 255;
    if keyLength > limit {
        return (
            slice::__from_vec(Vec::new()),
            errors::New(string::from_static("hkdf: requested key length too large")),
        );
    }
    // Go: if err := checkFIPS140Only(h, secret); err != nil { return nil, err }
    // Go: return hkdf.Key(h, secret, salt, info, keyLength), nil
    return (fips::Key(h, secret, salt, info, keyLength), nil);
}

// go: sdk 1.25.5 crypto/hkdf/hkdf.go:79-90 checkFIPS140Only
/// Reject short keys and non-approved hashes in FIPS 140-only mode.
///
/// `fips140only::Enabled` is a `const false` in goish, so this always
/// returns nil today; it is ported in full because the guard is real Go
/// code and a future FIPS 140-only mode would need it correct.
fn checkFIPS140Only(
    h: fn() -> Box<dyn Hash + Send + Sync>,
    key: &slice<byte>,
) -> error {
    // Go: if !fips140only.Enabled { return nil }
    if !fips140only::Enabled {
        return nil;
    }
    // Go: if len(key) < 112/8 { return errors.New(…) }
    if key.Len() < 112 / 8 {
        return errors::New(
            "crypto/hkdf: use of keys shorter than 112 bits is not allowed in FIPS 140-only mode",
        );
    }
    // Go: if !fips140only.ApprovedHash(h()) { return errors.New(…) }
    if !fips140only::ApprovedHash(&h()) {
        return errors::New(
            "crypto/hkdf: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode",
        );
    }
    // Go: return nil
    return nil;
}
