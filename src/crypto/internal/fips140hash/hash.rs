// go: file crypto/internal/fips140hash/hash.go decls: sha3Unwrap, Unwrap, UnwrapNew
//
// Deviations from hash[go] @ Go 1.25.5:
//
//   * `sha3Unwrap` is a `//go:linkname` declaration with no body, bound at
//     link time to an unexported function in crypto/sha3. goish has no
//     linkname; `crypto::sha3::SHA3`'s inner `s` field is `pub(crate)`,
//     which is the same reach Go's linkname buys, so the function has a
//     body instead of a declaration.
//   * Go returns the *same* inner `*fsha3.Digest` the wrapper holds, so
//     writes through the result would be visible through the original.
//     goish returns an owned clone. Every Go call site either passes a
//     freshly constructed hash (`Unwrap(hash.New())`) or overwrites the
//     variable it read from (`hash = Unwrap(hash)`), so no caller can
//     observe the difference.
//   * `UnwrapNew` returns Go's `func() hash.Hash` closure as a
//     `hash::HashFunc` — the carrier added for exactly this function.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::boxed::Box;

use crate::crypto::internal::fips140::sha3 as fsha3;
use crate::crypto::sha3;
use crate::hash::{Hash, HashFunc, IntoHashFunc};

// go: sdk 1.25.5 crypto/internal/fips140hash/hash.go:14-15 sha3Unwrap
//
//   //go:linkname sha3Unwrap
//   func sha3Unwrap(*sha3.SHA3) *fsha3.Digest
fn sha3Unwrap(s: &sha3::SHA3) -> fsha3::Digest {
    return s.s.clone();
}

// go: sdk 1.25.5 crypto/internal/fips140hash/hash.go:17-28 Unwrap
/// Return h, or a crypto/internal/fips140 inner implementation of h.
///
/// The return value can be type asserted to one of
/// [crypto/internal/fips140/sha256.Digest],
/// [crypto/internal/fips140/sha512.Digest], or
/// [crypto/internal/fips140/sha3.Digest] if it is a FIPS 140-3 approved
/// hash.
pub fn Unwrap(h: Box<dyn Hash + Send + Sync>) -> Box<dyn Hash + Send + Sync> {
    // Go: if sha3, ok := h.(*sha3.SHA3); ok { return sha3Unwrap(sha3) }
    if let Some(any) = h.__goish_as_dyn_any() {
        if let Some(s) = any.downcast_ref::<sha3::SHA3>() {
            return Box::new(sha3Unwrap(s));
        }
    }
    // Go: return h
    return h;
}

// go: sdk 1.25.5 crypto/internal/fips140hash/hash.go:30-34 UnwrapNew
/// Return a function that calls newHash and applies [Unwrap] to the return
/// value.
pub fn UnwrapNew(newHash: impl IntoHashFunc) -> HashFunc {
    let newHash = newHash.into_hash_func();
    // Go: return func() hash.Hash { return Unwrap(newHash()) }
    return HashFunc::New(move || Unwrap(newHash.Call()));
}
