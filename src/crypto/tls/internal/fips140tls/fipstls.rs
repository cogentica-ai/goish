// go: file crypto/tls/internal/fips140tls/fipstls.go decls: Force, Required, TestingOnlyAbandon
//
// Package fips140tls controls whether crypto/tls requires FIPS-approved
// settings.
//
// goishlint:ignore GOISH018 — fipstls.go's `init()` is
// `if fips140.Enabled() { Force() }`. goish has no per-package init
// driver, so the same call happens lazily on first access; see
// `required()` below. Nothing else is in its body.

#![allow(non_snake_case)]

use crate::crypto::fips140;
use crate::lazy::Lazy;
use crate::sync::atomic;

// Go: fipstls.go:13
//   var required atomic.Bool
//
// Go's `init()` seeds this from `fips140.Enabled()`. goish has no init
// driver, so the seeding is folded into the Lazy initialiser — the value
// is the same and it is still established before any observer can read
// it, which is what the init guaranteed.
static required: Lazy<atomic::Bool> = Lazy::new(|| atomic::Bool::new(fips140::Enabled()));

// go: sdk 1.25.5 crypto/tls/internal/fips140tls/fipstls.go:21-25 Force
/// Force crypto/tls to restrict TLS configurations to FIPS-approved
/// settings. By design, this call is impossible to undo (except in
/// tests).
pub fn Force() {
    // Go: required.Store(true)
    required.Store(true);
}

// go: sdk 1.25.5 crypto/tls/internal/fips140tls/fipstls.go:27-33 Required
/// Report whether FIPS-approved settings are required.
///
/// Required is true if FIPS 140-3 mode is enabled with
/// GODEBUG=fips140=on, or if the crypto/tls/fipsonly package is imported
/// by a Go+BoringCrypto build.
pub fn Required() -> bool {
    // Go: return required.Load()
    return required.Load();
}

// go: sdk 1.25.5 crypto/tls/internal/fips140tls/fipstls.go:35-37 TestingOnlyAbandon
pub fn TestingOnlyAbandon() {
    // Go: required.Store(false)
    required.Store(false);
}
