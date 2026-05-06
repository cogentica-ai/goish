// crypto/rsa — minimal port of Go's `crypto/rsa` package.
//
// v1 ships only the public-key data type — the algorithm itself
// (encrypt / decrypt / sign / verify) is deferred. This is enough to
// support consumers like `titanous/rocacheck` that read the modulus
// `N` directly without performing any RSA operation.
//
// Mirrors crypto/rsa/rsa.go's `PublicKey` shape:
//
//   type PublicKey struct {
//       N *big.Int  // modulus
//       E int       // public exponent
//   }

#![allow(non_snake_case)]

extern crate alloc;

use crate::math::big;
use crate::types::int;

#[derive(Clone, Default)]
pub struct PublicKey {
    /// Modulus.
    pub N: big::Int,
    /// Public exponent.
    pub E: int,
}

// Polymorphic-nil for `*rsa.PublicKey`. Go callers pass nil pointers
// occasionally; in goish the natural model is a default-valued struct,
// matched by the per-type Nil impls.
impl PartialEq<crate::nilval::Nil> for PublicKey {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.N == crate::nilval::nil && self.E == 0
    }
}
impl PartialEq<PublicKey> for crate::nilval::Nil {
    fn eq(&self, other: &PublicKey) -> bool {
        other.N == crate::nilval::nil && other.E == 0
    }
}
impl From<crate::nilval::Nil> for PublicKey {
    fn from(_: crate::nilval::Nil) -> Self {
        PublicKey::default()
    }
}
