// crypto/internal/fips140 — Go's FIPS 140-3 module parent package.
//
// In Go this package owns the FIPS-mode flag, the per-goroutine service
// indicator, and the CAST/PCT self-test drivers. goish does not ship a
// validated FIPS module: the runtime never enters FIPS mode, so this is
// a MINIMAL STUB.
//
// What is stubbed (note for the RSA porting tasks):
//   * `Enabled()`           — always returns false (FIPS mode off).
//   * `Name()` / `Version()`— the formal module identity strings.
//   * `Supported()`         — always returns `errors::nil` (no error).
//   * service indicator     — `ResetServiceIndicator`, `ServiceIndicator`,
//                             `RecordApproved`, `RecordNonApproved` are
//                             no-ops; `ServiceIndicator` returns false.
//   * `CAST(name, f)`       — runs `f` immediately and panics if it
//                             errors (the `Enabled` early-return is
//                             dropped: with FIPS off Go skips the test,
//                             but running it unconditionally is harmless
//                             and gives the RSA self-tests real coverage).
//   * `PCT(name, f)`        — same as `CAST`.
//
// The Go original keeps a per-goroutine indicator via runtime linkname;
// goish has no such hook, so the indicator collapses to a stateless
// no-op. RSA code may call `RecordApproved`/`RecordNonApproved` freely.

#![allow(non_snake_case)]

extern crate alloc;

use crate::error;
use crate::gostring::string;

pub mod bigmod;
pub mod check;
pub mod drbg;
pub mod ed25519;
pub mod aes;
pub mod alias;
pub mod edwards25519;
pub mod pbkdf2;
pub mod rsa;
pub mod subtle;
pub mod hkdf;
pub mod hmac;
pub mod sha256;
pub mod sha3;
pub mod sha512;

/// `fips140.Enabled` — whether FIPS 140-3 mode is active. Always false
/// in goish (no validated module).
pub fn Enabled() -> bool {
    false
}

/// `fips140.Supported()` — error if FIPS mode can't be enabled. goish
/// returns success unconditionally (mode is simply never entered).
pub fn Supported() -> error {
    crate::errors::nil
}

/// `fips140.Name()` — the formal module name.
pub fn Name() -> string {
    string::from_static("Go Cryptographic Module")
}

/// `fips140.Version()` — the formal module version.
pub fn Version() -> string {
    string::from_static("latest")
}

// ─── Service indicator (Go: indicator.go) ─────────────────────────────
// goish has no per-goroutine indicator slot; these collapse to no-ops.

/// `fips140.ResetServiceIndicator()` — no-op stub.
pub fn ResetServiceIndicator() {}

/// `fips140.ServiceIndicator()` — always false (indicator unsupported).
pub fn ServiceIndicator() -> bool {
    false
}

/// `fips140.RecordApproved()` — records use of an approved service.
/// No-op stub.
pub fn RecordApproved() {}

/// `fips140.RecordNonApproved()` — records use of a non-approved
/// service. No-op stub.
pub fn RecordNonApproved() {}

// ─── Self-test drivers (Go: cast.go) ──────────────────────────────────

/// `fips140.CAST(name, f)` — Cryptographic Algorithm Self-Test driver.
/// Runs `f` and panics ("entering the error state") if it errors.
pub fn CAST<F>(name: &str, f: F)
where
    F: FnOnce() -> error,
{
    let err = f();
    if !err.IsNil() {
        panic_self_test(name, &err);
    }
}

/// `fips140.PCT(name, f)` — Pairwise Consistency Test driver. Runs `f`
/// and panics if it errors.
pub fn PCT<F>(name: &str, f: F)
where
    F: FnOnce() -> error,
{
    let err = f();
    if !err.IsNil() {
        panic_self_test(name, &err);
    }
}

fn panic_self_test(name: &str, _err: &error) -> ! {
    let mut msg = alloc::string::String::from("FIPS 140-3 self-test failed: ");
    msg.push_str(name);
    panic!("{}", msg)
}
