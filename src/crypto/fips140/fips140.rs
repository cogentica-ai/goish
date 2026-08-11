// go: file crypto/fips140/fips140.go decls: Enabled

#![allow(non_snake_case)]

use crate::crypto::internal::fips140;
use crate::crypto::internal::fips140::check;

// go: sdk 1.25.5 crypto/fips140/fips140.go:12-25 Enabled
/// Report whether the cryptography libraries are operating in FIPS 140-3
/// mode.
///
/// It can be controlled at runtime using the GODEBUG setting "fips140".
/// If set to "on", FIPS 140-3 mode is enabled. If set to "only",
/// non-approved cryptography functions will additionally return errors or
/// panic.
///
/// This can't be changed after the program has started.
pub fn Enabled() -> bool {
    // Go: if fips140.Enabled && !check.Verified { panic(…) }
    if fips140::Enabled() && !check::Verified {
        panic!("crypto/fips140: FIPS 140-3 mode enabled, but integrity check didn't pass");
    }
    // Go: return fips140.Enabled
    return fips140::Enabled();
}
