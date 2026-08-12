// go: file crypto/ecdh/ecdh.go decls: PublicKey.Bytes, PublicKey.Equal, PublicKey.Curve, PrivateKey.ECDH, PrivateKey.Bytes, PrivateKey.Equal, PrivateKey.Curve, PrivateKey.PublicKey, PrivateKey.Public
//
// Package ecdh implements Elliptic Curve Diffie-Hellman over NIST curves
// and Curve25519.
//
// Deviations from ecdh[go] @ Go 1.25.5:
//
//   * `Curve` is a `#[goish::interface]` trait. Go's `curve Curve` field
//     is an interface value compared with `==` for identity; goish holds
//     `&'static (dyn Curve + Send + Sync)` and compares by `String()`,
//     which is the curve's canonical name and unique across the five
//     implementations.
//   * `crypto/internal/boring` is out of scope (no cgo), so the boring
//     fields and every `if boring.Enabled` arm are dropped.
//   * Constructors returning `(*T, error)` return `(T, error)` with the
//     zero value on the error path.
//   * `Equal(x crypto.PublicKey)` takes `crypto.PublicKey = any`; goish
//     takes `&PublicKey` directly, because goish's `Any` downcast would
//     add a registration requirement for a comparison Go gets from the
//     type switch. The `ok` arm of Go's assertion is the type system here.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::subtle;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::string;
use crate::types::byte;
use crate::error;

// Go: ecdh.go:18-53
//   type Curve interface { GenerateKey; NewPrivateKey; NewPublicKey; ecdh }
/// A curve usable for ECDH key agreement.
#[goish::interface]
pub trait Curve {
    /// The canonical name of the curve. Go gets this from each
    /// implementation's `String()`; the trait declares it because goish
    /// uses it for the identity comparison Go does on the interface value.
    fn String(&self) -> string;

    /// Generate a random PrivateKey.
    ///
    /// Most applications should use [crypto/rand.Reader] as rand. Note
    /// that the returned key does not depend deterministically on the
    /// bytes read from rand, and may change between calls and/or between
    /// versions.
    fn GenerateKey(
        &self,
        rand: &mut (dyn io::Reader + Send + Sync + 'static),
    ) -> (PrivateKey, error);

    /// Check that key is valid and return a PrivateKey.
    ///
    /// For NIST curves, this follows SEC 1, Version 2.0, Section 2.3.6.
    /// For X25519, this only checks the scalar length.
    fn NewPrivateKey(&self, key: &slice<byte>) -> (PrivateKey, error);

    /// Check that key is valid and return a PublicKey.
    ///
    /// For NIST curves, this decodes an uncompressed point according to
    /// SEC 1, Version 2.0, Section 2.3.4. For X25519, this only checks the
    /// u-coordinate length.
    fn NewPublicKey(&self, key: &slice<byte>) -> (PublicKey, error);

    /// Perform an ECDH exchange and return the shared secret. It's exposed
    /// as the PrivateKey.ECDH method.
    fn ecdh(&self, local: &PrivateKey, remote: &PublicKey) -> (slice<byte>, error);
}

// Go: ecdh.go:55-65
//   type PublicKey struct { curve Curve; publicKey []byte; boring …; fips … }
/// An ECDH public key, usually a peer's ECDH share sent over the wire.
#[derive(Clone)]
pub struct PublicKey {
    pub(super) curve: &'static (dyn Curve + Send + Sync),
    pub(super) publicKey: slice<byte>,
}

impl PublicKey {
    // go: sdk 1.25.5 crypto/ecdh/ecdh.go:67-73 PublicKey.Bytes
    /// Return a copy of the encoding of the public key.
    pub fn Bytes(&self) -> slice<byte> {
        let r: &[byte] = &self.publicKey;
        return slice::__from_vec(r.to_vec());
    }

    // go: sdk 1.25.5 crypto/ecdh/ecdh.go:75-89 PublicKey.Equal
    /// Report whether x represents the same public key as k.
    ///
    /// Note that there can be equivalent public keys with different
    /// encodings which would return false from this check but behave the
    /// same way as inputs to ECDH.
    ///
    /// This check is performed in constant time as long as the key types
    /// and their curve match.
    pub fn Equal(&self, x: &PublicKey) -> bool {
        return self.curve.String() == x.curve.String()
            && subtle::ConstantTimeCompare(&self.publicKey, &x.publicKey) == 1;
    }

    // go: sdk 1.25.5 crypto/ecdh/ecdh.go:91-93 PublicKey.Curve
    pub fn Curve(&self) -> &'static (dyn Curve + Send + Sync) {
        return self.curve;
    }
}

// Go: ecdh.go:95-106
//   type PrivateKey struct { curve Curve; privateKey []byte; publicKey *PublicKey; … }
/// An ECDH private key, usually kept secret.
#[derive(Clone)]
pub struct PrivateKey {
    pub(super) curve: &'static (dyn Curve + Send + Sync),
    pub(super) privateKey: slice<byte>,
    pub(super) publicKey: PublicKey,
}

// go: none — Go's error paths return a nil `*PublicKey` / `*PrivateKey`.
// goish pairs a zero value with the error, so every such site needs one;
// P-256 stands in for the curve, which is never read because callers check
// the error first. `crypto/ecdsa`'s ECDH bridge is the first consumer.
impl Default for PublicKey {
    fn default() -> Self {
        return PublicKey {
            curve: super::nist::P256(),
            publicKey: slice::__from_vec(alloc::vec::Vec::new()),
        };
    }
}

// go: none — see the PublicKey impl above.
impl Default for PrivateKey {
    fn default() -> Self {
        return PrivateKey {
            curve: super::nist::P256(),
            privateKey: slice::__from_vec(alloc::vec::Vec::new()),
            publicKey: PublicKey::default(),
        };
    }
}

impl PrivateKey {
    // go: sdk 1.25.5 crypto/ecdh/ecdh.go:108-124 PrivateKey.ECDH
    /// Perform an ECDH exchange and return the shared secret. The
    /// [PrivateKey] and [PublicKey] must use the same curve.
    ///
    /// For NIST curves, this performs ECDH as specified in SEC 1, Version
    /// 2.0, Section 3.3.1, and returns the x-coordinate encoded according
    /// to SEC 1, Version 2.0, Section 2.3.5. The result is never the point
    /// at infinity.
    ///
    /// For [X25519], this performs ECDH as specified in RFC 7748, Section
    /// 6.1. If the result is the all-zero value, ECDH returns an error.
    pub fn ECDH(&self, remote: &PublicKey) -> (slice<byte>, error) {
        if self.curve.String() != remote.curve.String() {
            return (
                slice::__from_vec(Vec::<byte>::new()),
                errors::New("crypto/ecdh: private key and public key curves do not match"),
            );
        }
        return self.curve.ecdh(self, remote);
    }

    // go: sdk 1.25.5 crypto/ecdh/ecdh.go:126-132 PrivateKey.Bytes
    /// Return a copy of the encoding of the private key.
    pub fn Bytes(&self) -> slice<byte> {
        let r: &[byte] = &self.privateKey;
        return slice::__from_vec(r.to_vec());
    }

    // go: sdk 1.25.5 crypto/ecdh/ecdh.go:134-148 PrivateKey.Equal
    /// Report whether x represents the same private key as k.
    ///
    /// This check is performed in constant time as long as the key types
    /// and their curve match.
    pub fn Equal(&self, x: &PrivateKey) -> bool {
        return self.curve.String() == x.curve.String()
            && subtle::ConstantTimeCompare(&self.privateKey, &x.privateKey) == 1;
    }

    // go: sdk 1.25.5 crypto/ecdh/ecdh.go:150-152 PrivateKey.Curve
    pub fn Curve(&self) -> &'static (dyn Curve + Send + Sync) {
        return self.curve;
    }

    // go: sdk 1.25.5 crypto/ecdh/ecdh.go:154-156 PrivateKey.PublicKey
    pub fn PublicKey(&self) -> PublicKey {
        return self.publicKey.clone();
    }

    // go: sdk 1.25.5 crypto/ecdh/ecdh.go:158-162 PrivateKey.Public
    /// Implement the implicit interface of all standard library private
    /// keys. See the docs of [crypto.PrivateKey].
    pub fn Public(&self) -> PublicKey {
        return self.PublicKey();
    }
}
