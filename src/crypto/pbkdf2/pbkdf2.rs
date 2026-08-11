// goishlint:ignore GOISH018 — `checkFIPS140Only` (pbkdf2.go) rejects
// short keys/salts and non-approved hashes when `fips140only.Enabled` is
// set. goish has no FIPS-140-only mode (the flag is statically false), so
// every call site takes the nil path. Port it with
// crypto/internal/fips140only.
// go: file crypto/pbkdf2/pbkdf2.go decls: Key
//
// crypto/pbkdf2 — PBKDF2 key derivation (RFC 8018 / PKCS #5 v2.1).
// Go 1.25 makes this a thin wrapper over crypto/internal/fips140/pbkdf2;
// goish follows.
//
// Deviation: the hash factory is `impl IntoHashFunc` (`hash::HashFunc`)
// rather than Go's `func() Hash` generic, matching `hmac::New`.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::boxed::Box;

use crate::crypto::internal::fips140::pbkdf2 as fips;
use crate::errors::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::{Hash, IntoHashFunc};
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/pbkdf2/pbkdf2.go:40-54 Key
/// `pbkdf2.Key(h, password, salt, iter, keyLength)` — derive a key of
/// `keyLength` bytes from `password` and `salt` over `iter` iterations.
pub fn Key(
    h: impl IntoHashFunc,
    password: string,
    salt: slice<byte>,
    iter: int,
    keyLength: int,
) -> (slice<byte>, error) {
    let h = h.into_hash_func();
    // Go: if err := checkFIPS140Only(h, password, salt, keyLength); err != nil { … }
    // Go: return pbkdf2.Key(h, password, salt, iter, keyLength)
    return fips::Key(h, password, salt, iter, keyLength);
}
