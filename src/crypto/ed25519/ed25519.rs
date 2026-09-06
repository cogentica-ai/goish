// goishlint:ignore GOISH021 — `privateKeyCache` (ed25519.go:84) is a
// `fips140cache.Cache[byte, ed25519.PrivateKey]` keyed by the address of
// the key's first byte. goish has no crypto/internal/fips140cache port
// yet (Wave C, 2 fns), so PrivateKey.Sign expands the key on every call
// instead of reusing a cached expansion. Correctness-equivalent; slower
// for repeated signing with one key. Remove this ignore when
// fips140cache lands.
// go: file crypto/ed25519/ed25519.go decls: PublicKey.Equal, PrivateKey.Public, PrivateKey.Equal, PrivateKey.Seed, PrivateKey.Sign, Options.HashFunc, GenerateKey, NewKeyFromSeed, Sign, Verify, VerifyWithOptions, from, eq, PublicKey, __goish_as_dyn_any, empty_slice, str_to_slice, optionsContext
//
// goishlint:ignore GOISH018 newKeyFromSeed, sign — in Go these are the
//     middle of a three-layer call: `NewKeyFromSeed` -> `newKeyFromSeed`
//     -> `fips140/ed25519`, and likewise for `Sign`. The middle layer
//     exists to write into a caller-provided buffer, which goish does not
//     need because the fips call returns the key. Both exported functions
//     call `fips::` directly.
//
// crypto/ed25519 — port of Go 1.25's public `crypto/ed25519` package.
//
// This is the PUBLIC `crypto/ed25519` surface: a thin wrapper over the
// constant-time FIPS-internal Ed25519 implementation at
// `crate::crypto::internal::fips140::ed25519`.
//
// Strategy
// --------
// Go's public `crypto/ed25519` keeps `PublicKey`/`PrivateKey` as the
// byte-slice types `type PublicKey []byte` / `type PrivateKey []byte`
// for backwards compatibility, but every actual EdDSA operation is
// performed by parsing the byte material into the FIPS-internal
// `crypto/internal/fips140/ed25519` key types and dispatching there.
// This module mirrors that bridge exactly — see Go's `crypto/ed25519/
// ed25519.go`.
//
// Slim deviations from the Go original:
//   * Go caches the parsed `*ed25519.PrivateKey` keyed by the address
//     of the slice's first byte (`fips140cache.Cache`). goish has no
//     such cache; `Sign` / `(PrivateKey).Sign` re-parse the key each
//     call. The result is byte-identical, only slightly slower.
//   * `fips140only` mode is not modelled, so the Ed25519ctx FIPS-mode
//     rejection branch is absent — Ed25519ctx is always permitted.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto;
use crate::crypto::internal::fips140::ed25519 as fips;
use crate::crypto::subtle;
use crate::error;
use crate::errors;
use crate::io;
use crate::slice;
use crate::strconv;
use crate::string;
use crate::types::{byte, int};

// ─── Size constants (Go: ed25519.go:30-39) ────────────────────────────

/// PublicKeySize is the size, in bytes, of public keys as used in this
/// package.
pub const PublicKeySize: int = 32;
/// PrivateKeySize is the size, in bytes, of private keys as used in
/// this package.
pub const PrivateKeySize: int = 64;
/// SignatureSize is the size, in bytes, of signatures generated and
/// verified by this package.
pub const SignatureSize: int = 64;
/// SeedSize is the size, in bytes, of private key seeds. These are the
/// private key representations used by RFC 8032.
pub const SeedSize: int = 32;

// ─── PublicKey (Go: ed25519.go:42) ────────────────────────────────────

/// `PublicKey` is the type of Ed25519 public keys. Go models it as
/// `type PublicKey []byte`; goish wraps the byte slice in a newtype so
/// it carries a concrete identity for the `crypto.PublicKey` downcast
/// used by `Equal`.
#[derive(Clone, Default)]
pub struct PublicKey(pub slice<byte>);

impl PublicKey {
    // go: sdk 1.25.5 crypto/ed25519/ed25519.go:48-54 PublicKey.Equal
    /// `(PublicKey).Equal(x)` (Go: ed25519.go:48) — reports whether
    /// `self` and `x` have the same value. `x` is a `crypto.PublicKey`;
    /// a non-`PublicKey` value compares unequal (Go's `x.(PublicKey)`
    /// comma-ok miss returns false).
    pub fn Equal(&self, x: &crypto::PublicKey) -> bool {
        match x.downcast_ref::<PublicKey>() {
            Some(xx) => subtle::ConstantTimeCompare(&self.0, &xx.0) == 1,
            None => false,
        }
    }
}

// Polymorphic-nil for `PublicKey` (Go's `PublicKey` is a nilable slice
// type — a nil public key is the empty/absent slice).
impl From<crate::nilval::Nil> for PublicKey {
    // go: none — goish idiom (polymorphic nil / trait shim / local helper)
    fn from(_: crate::nilval::Nil) -> Self {
        PublicKey(slice::__from_vec(Vec::new()))
    }
}
impl PartialEq<crate::nilval::Nil> for PublicKey {
    // go: none — goish idiom (polymorphic nil / trait shim / local helper)
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.0.Len() == 0
    }
}
impl PartialEq<PublicKey> for crate::nilval::Nil {
    // go: none — goish idiom (polymorphic nil / trait shim / local helper)
    fn eq(&self, other: &PublicKey) -> bool {
        other.0.Len() == 0
    }
}

// ─── PrivateKey (Go: ed25519.go:57) ───────────────────────────────────

/// `PrivateKey` is the type of Ed25519 private keys. It implements
/// [`crypto::Signer`]. Go models it as `type PrivateKey []byte`; the
/// 64-byte encoding is `seed || publicKey`.
#[derive(Clone, Default)]
pub struct PrivateKey(pub slice<byte>);

impl PrivateKey {
    // go: sdk 1.25.5 crypto/ed25519/ed25519.go:60-64 PrivateKey.Public
    /// `(PrivateKey).Public()` (Go: ed25519.go:60) — returns the
    /// [`PublicKey`] corresponding to `priv` (the trailing 32 bytes of
    /// the encoding), boxed as a `crypto.PublicKey`.
    pub fn Public(&self) -> crypto::PublicKey {
        alloc::sync::Arc::new(self.PublicKey())
    }

    // go: none — goish idiom (polymorphic nil / trait shim / local helper)
    /// `(PrivateKey).Public()` returning the concrete [`PublicKey`].
    /// Convenience over the boxed `crypto.PublicKey` form for goish
    /// callers that want the typed value directly.
    pub fn PublicKey(&self) -> PublicKey {
        let mut publicKey: Vec<byte> = alloc::vec![0u8; PublicKeySize as usize];
        // Go: copy(publicKey, priv[32:])
        let mut i: int = 0;
        while i < PublicKeySize && (32 + i) < self.0.Len() {
            publicKey[i as usize] = self.0[32 + i];
            i += 1;
        }
        PublicKey(slice::__from_vec(publicKey))
    }

    // go: sdk 1.25.5 crypto/ed25519/ed25519.go:67-73 PrivateKey.Equal
    /// `(PrivateKey).Equal(x)` (Go: ed25519.go:67) — reports whether
    /// `self` and `x` have the same value. A non-`PrivateKey` value
    /// compares unequal.
    pub fn Equal(&self, x: &crypto::PrivateKey) -> bool {
        match x.downcast_ref::<PrivateKey>() {
            Some(xx) => subtle::ConstantTimeCompare(&self.0, &xx.0) == 1,
            None => false,
        }
    }

    // go: sdk 1.25.5 crypto/ed25519/ed25519.go:78-80 PrivateKey.Seed
    /// `(PrivateKey).Seed()` (Go: ed25519.go:78) — the private key seed
    /// (the leading [`SeedSize`] bytes). Provided for interoperability
    /// with RFC 8032.
    pub fn Seed(&self) -> slice<byte> {
        let mut seed: Vec<byte> = Vec::with_capacity(SeedSize as usize);
        let mut i: int = 0;
        while i < SeedSize && i < self.0.Len() {
            seed.push(self.0[i]);
            i += 1;
        }
        slice::__from_vec(seed)
    }

    // go: sdk 1.25.5 crypto/ed25519/ed25519.go:95-122 PrivateKey.Sign
    /// `(PrivateKey).Sign(rand, message, opts)` (Go: ed25519.go:95) —
    /// signs `message`, implementing [`crypto::Signer`]. `rand` is
    /// ignored and may be a nil reader.
    ///
    /// If `opts.HashFunc()` is [`crypto::SHA512`] the pre-hashed
    /// Ed25519ph variant is used and `message` is expected to be a
    /// SHA-512 hash; otherwise `opts.HashFunc()` must be
    /// `crypto::Hash(0)` and `message` must not be hashed.
    pub fn Sign(
        &self,
        _rand: &mut dyn io::Reader,
        message: slice<byte>,
        opts: &dyn crypto::SignerOpts,
    ) -> (slice<byte>, error) {
        let (k, err) = fips::NewPrivateKey(self.0.clone());
        if !err.IsNil() {
            return (empty_slice(), err);
        }
        let hash = opts.HashFunc();
        // Go: context defaults to "" unless opts is *Options.
        let context = optionsContext(opts);
        if hash == crypto::SHA512 {
            // Ed25519ph
            return fips::SignPH(&k, message, str_to_slice(&context));
        }
        if hash == crypto::Hash(0) && context.Len() != 0 {
            // Ed25519ctx
            return fips::SignCtx(&k, message, str_to_slice(&context));
        }
        if hash == crypto::Hash(0) {
            // Ed25519
            return (fips::Sign(&k, message), errors::nil);
        }
        (
            empty_slice(),
            errors::New(string::from_static(
                "ed25519: expected opts.HashFunc() zero (unhashed message, \
                 for standard Ed25519) or SHA-512 (for Ed25519ph)",
            )),
        )
    }
}

// `crypto.Signer` impl — Go's `PrivateKey` implements `crypto.Signer`.
impl crypto::Signer for PrivateKey {
    // go: sdk 1.25.5 crypto/ed25519/ed25519.go:60-64 PrivateKey.Public
    fn Public(&self) -> crypto::PublicKey {
        PrivateKey::Public(self)
    }
    // go: sdk 1.25.5 crypto/ed25519/ed25519.go:95-122 PrivateKey.Sign
    fn Sign(
        &self,
        rand: &mut dyn io::Reader,
        digest: slice<byte>,
        opts: &dyn crypto::SignerOpts,
    ) -> (slice<byte>, error) {
        PrivateKey::Sign(self, rand, digest, opts)
    }
}

// Polymorphic-nil for `PrivateKey`.
impl From<crate::nilval::Nil> for PrivateKey {
    // go: none — goish idiom (polymorphic nil / trait shim / local helper)
    fn from(_: crate::nilval::Nil) -> Self {
        PrivateKey(slice::__from_vec(Vec::new()))
    }
}
impl PartialEq<crate::nilval::Nil> for PrivateKey {
    // go: none — goish idiom (polymorphic nil / trait shim / local helper)
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.0.Len() == 0
    }
}
impl PartialEq<PrivateKey> for crate::nilval::Nil {
    // go: none — goish idiom (polymorphic nil / trait shim / local helper)
    fn eq(&self, other: &PrivateKey) -> bool {
        other.0.Len() == 0
    }
}

// ─── Options (Go: ed25519.go:126) ─────────────────────────────────────

/// `Options` can be used with [`PrivateKey::Sign`] or
/// [`VerifyWithOptions`] to select Ed25519 variants.
#[derive(Clone, Default)]
pub struct Options {
    /// `Hash` can be zero for regular Ed25519, or [`crypto::SHA512`]
    /// for Ed25519ph.
    pub Hash: crypto::Hash,
    /// `Context`, if not empty, selects Ed25519ctx or provides the
    /// context string for Ed25519ph. It can be at most 255 bytes long.
    pub Context: string,
}

impl Options {
    // go: sdk 1.25.5 crypto/ed25519/ed25519.go:136-136 Options.HashFunc
    /// `(*Options).HashFunc()` (Go: ed25519.go:136) — returns `o.Hash`,
    /// satisfying `crypto.SignerOpts`.
    pub fn HashFunc(&self) -> crypto::Hash {
        self.Hash
    }
}

impl crypto::SignerOpts for Options {
    // go: sdk 1.25.5 crypto/ed25519/ed25519.go:136-136 Options.HashFunc
    fn HashFunc(&self) -> crypto::Hash {
        self.Hash
    }
    // go: none — goish idiom (polymorphic nil / trait shim / local helper)
    // Override the interface's hidden downcast hook so `(PrivateKey).
    // Sign` can recover the concrete `Options` from a `&dyn SignerOpts`
    // (Go's `opts.(*Options)` comma-ok). The transpiler normally emits
    // this override; this module hand-writes the impl, so it is added
    // explicitly here.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        Some(self)
    }
}

// ─── GenerateKey (Go: ed25519.go:143) ─────────────────────────────────

// go: sdk 1.25.5 crypto/ed25519/ed25519.go:143-156 GenerateKey
/// `GenerateKey(rand)` — generates a public/private key pair using
/// entropy from `rand`. If `rand` is a nil reader, [`crypto::rand`]'s
/// `Reader` is used.
///
/// The output is deterministic and equivalent to reading [`SeedSize`]
/// bytes from `rand` and passing them to [`NewKeyFromSeed`].
pub fn GenerateKey(rand: Option<&mut dyn io::Reader>) -> (PublicKey, PrivateKey, error) {
    // Go: seed := make([]byte, SeedSize); io.ReadFull(rand, seed)
    let mut seed: slice<byte> = slice::__from_vec(alloc::vec![0u8; SeedSize as usize]);
    let err = match rand {
        Some(r) => {
            let (_, e) = io::ReadFull(r, &mut seed);
            e
        }
        None => {
            // rand == nil ⇒ crypto/rand.Reader.
            let mut r = crate::crypto::rand::RandReader;
            let (_, e) = io::ReadFull(&mut r, &mut seed);
            e
        }
    };
    if !err.IsNil() {
        return (PublicKey::default(), PrivateKey::default(), err);
    }

    let privateKey = NewKeyFromSeed(seed);
    let publicKey = privateKey.PublicKey();
    (publicKey, privateKey, errors::nil)
}

// ─── NewKeyFromSeed (Go: ed25519.go:162) ──────────────────────────────

// go: sdk 1.25.5 crypto/ed25519/ed25519.go:162-167 NewKeyFromSeed
/// `NewKeyFromSeed(seed)` — calculates a private key from a seed. It
/// panics if `len(seed)` is not [`SeedSize`]. Provided for
/// interoperability with RFC 8032.
pub fn NewKeyFromSeed(seed: slice<byte>) -> PrivateKey {
    let (k, err) = fips::NewPrivateKeyFromSeed(seed.clone());
    if !err.IsNil() {
        // NewPrivateKeyFromSeed only errors on a bad seed length.
        let mut msg = string::from_static("ed25519: bad seed length: ");
        msg = msg + strconv::Itoa(seed.Len());
        panic!("{}", msg);
    }
    PrivateKey(k.Bytes())
}

// ─── Sign (Go: ed25519.go:180) ────────────────────────────────────────

// go: sdk 1.25.5 crypto/ed25519/ed25519.go:180-186 Sign
/// `Sign(privateKey, message)` — signs the message with `privateKey`
/// and returns a 64-byte signature. It panics if `len(privateKey)` is
/// not [`PrivateKeySize`].
pub fn Sign(privateKey: &PrivateKey, message: slice<byte>) -> slice<byte> {
    let (k, err) = fips::NewPrivateKey(privateKey.0.clone());
    if !err.IsNil() {
        let mut msg = string::from_static("ed25519: bad private key: ");
        msg = msg + err.Error();
        panic!("{}", msg);
    }
    fips::Sign(&k, message)
}

// ─── Verify (Go: ed25519.go:206) ──────────────────────────────────────

// go: sdk 1.25.5 crypto/ed25519/ed25519.go:206-208 Verify
/// `Verify(publicKey, message, sig)` — reports whether `sig` is a valid
/// signature of `message` by `publicKey`. It panics if
/// `len(publicKey)` is not [`PublicKeySize`].
pub fn Verify(publicKey: &PublicKey, message: slice<byte>, sig: slice<byte>) -> bool {
    let opts = Options {
        Hash: crypto::Hash(0),
        Context: string::default(),
    };
    VerifyWithOptions(publicKey, message, sig, &opts).IsNil()
}

// ─── VerifyWithOptions (Go: ed25519.go:221) ───────────────────────────

// go: sdk 1.25.5 crypto/ed25519/ed25519.go:221-242 VerifyWithOptions
/// `VerifyWithOptions(publicKey, message, sig, opts)` — reports whether
/// `sig` is a valid signature of `message` by `publicKey`. A valid
/// signature is indicated by a nil error. It panics if
/// `len(publicKey)` is not [`PublicKeySize`].
///
/// If `opts.Hash` is [`crypto::SHA512`] the pre-hashed Ed25519ph
/// variant is used; otherwise `opts.Hash` must be `crypto::Hash(0)`.
pub fn VerifyWithOptions(
    publicKey: &PublicKey,
    message: slice<byte>,
    sig: slice<byte>,
    opts: &Options,
) -> error {
    let l = publicKey.0.Len();
    if l != PublicKeySize {
        let mut msg = string::from_static("ed25519: bad public key length: ");
        msg = msg + strconv::Itoa(l);
        panic!("{}", msg);
    }
    let (k, err) = fips::NewPublicKey(publicKey.0.clone());
    if !err.IsNil() {
        return err;
    }
    if opts.Hash == crypto::SHA512 {
        // Ed25519ph
        return fips::VerifyPH(&k, message, sig, str_to_slice(&opts.Context));
    }
    if opts.Hash == crypto::Hash(0) && opts.Context.Len() != 0 {
        // Ed25519ctx
        return fips::VerifyCtx(&k, message, sig, str_to_slice(&opts.Context));
    }
    if opts.Hash == crypto::Hash(0) {
        // Ed25519
        return fips::Verify(&k, message, sig);
    }
    errors::New(string::from_static(
        "ed25519: expected opts.Hash zero (unhashed message, for standard \
         Ed25519) or SHA-512 (for Ed25519ph)",
    ))
}

// ─── small helpers ────────────────────────────────────────────────────

// go: none — goish idiom (polymorphic nil / trait shim / local helper)
// Empty `slice<byte>` for the `nil` return slot of failing fns.
fn empty_slice() -> slice<byte> {
    slice::__from_vec(Vec::new())
}

// go: none — goish idiom (polymorphic nil / trait shim / local helper)
// `string` → `slice<byte>` at the fips boundary (Go's `Options.Context`
// is a string; the fips package takes the context as bytes).
fn str_to_slice(s: &string) -> slice<byte> {
    slice::__from_vec(s.as_bytes().to_vec())
}

// go: none — goish idiom (polymorphic nil / trait shim / local helper)
// Go: `if opts, ok := opts.(*Options); ok { context = opts.Context }`.
// goish: downcast the `&dyn SignerOpts` to an `Options` via the
// interface's hidden `__goish_as_dyn_any` hook; default to the empty
// context on a miss.
fn optionsContext(opts: &dyn crypto::SignerOpts) -> string {
    match opts.__goish_as_dyn_any() {
        Some(any_ref) => match any_ref.downcast_ref::<Options>() {
            Some(o) => o.Context.clone(),
            None => string::default(),
        },
        None => string::default(),
    }
}
