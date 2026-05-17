// crypto/internal/fips140/edwards25519 — the edwards25519 curve, used
// by crypto/ed25519.
//
// Faithful port of Go 1.25.5's
// crypto/internal/fips140/edwards25519. Currently only the `field`
// sub-package (GF(2^255-19) arithmetic) is ported; the Scalar, Point,
// and edwards25519 ed25519 logic land in follow-up tasks.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

pub mod field;
