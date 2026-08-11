// crypto/internal/fips140/check — Go's FIPS 140 self-integrity check.
//
// In Go this package runs a HMAC integrity check over the module at
// init time and is imported by `bigmod` purely as a side-effecting
// blank import (`_ "crypto/internal/fips140/check"`). goish has no
// per-package init driver and performs no integrity self-check, so
// this module is intentionally empty / side-effect-free.

#![allow(non_snake_case)]

/// Go: `var Verified bool` — set true by check.go's `init()` once the
/// module's HMAC integrity check has passed.
///
/// goish runs no integrity self-check, so this is a `const false`, and
/// `crypto/fips140.Enabled()`'s
/// `if fips140.Enabled && !check.Verified { panic(...) }` guard is
/// unreachable — `fips140::Enabled()` is false too. Both are ported in
/// full rather than collapsed; see `crypto/internal/fips140only`.
pub const Verified: bool = false;
