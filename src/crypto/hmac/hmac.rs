// go: file crypto/hmac/hmac.go decls: New, Equal
//
// Package hmac implements the Keyed-Hash Message Authentication Code
// (HMAC) as defined in FIPS 198. Go 1.25 makes this a thin wrapper over
// crypto/internal/fips140/hmac; goish follows.
//
// Deviations: no BoringCrypto branch (cgo is out of scope), no
// fips140hash.UnwrapNew, and no fips140only.Enabled key-length/hash
// checks — goish has no FIPS 140-only mode.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::boxed::Box;

use crate::crypto::internal::fips140::hmac as fipshmac;
use crate::goslice::slice;
use crate::hash::{Hash, IntoHashFunc};
use crate::types::byte;

pub use fipshmac::HMAC;

// go: sdk 1.25.5 crypto/hmac/hmac.go:52-71 New
/// `hmac.New(h, key)` — a new HMAC hash using the given hash constructor
/// and key. `h` must return a fresh hash on every call.
pub fn New<H: IntoHashFunc>(h: H, key: slice<byte>) -> HMAC {
    // Go: return hmac.New(h, key)
    return fipshmac::New(h, key);
}


// ─── Equal — constant-time MAC compare (Go: hmac.go:60) ───────────────

// go: sdk 1.25.5 crypto/hmac/hmac.go:60-65 Equal
/// `hmac.Equal(a, b)` (hmac.go:60) — constant-time MAC comparison.
/// Returns false on length mismatch, otherwise compares byte-by-byte
/// without short-circuiting (no timing leak).
pub fn Equal(a: slice<byte>, b: slice<byte>) -> bool {
    // Go (subtle.ConstantTimeCompare, subtle.go:18):
    //   if len(x) != len(y) { return 0 }
    //   var v byte; for i := 0; i < len(x); i++ { v |= x[i] ^ y[i] }
    //   return ConstantTimeByteEq(v, 0)
    let ar: &[byte] = &a;
    let br: &[byte] = &b;
    if ar.len() != br.len() {
        return false;
    }
    let mut v: u8 = 0;
    let mut i = 0;
    while i < ar.len() {
        v |= ar[i] ^ br[i];
        i += 1;
    }
    v == 0
}
