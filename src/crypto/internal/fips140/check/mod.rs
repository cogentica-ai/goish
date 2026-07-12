// crypto/internal/fips140/check — Go's FIPS 140 self-integrity check.
//
// In Go this package runs a HMAC integrity check over the module at
// init time and is imported by `bigmod` purely as a side-effecting
// blank import (`_ "crypto/internal/fips140/check"`). goish has no
// per-package init driver and performs no integrity self-check, so
// this module is intentionally empty / side-effect-free.

#![allow(non_snake_case)]
