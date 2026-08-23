// go: file hash/hash.go decls:
//
// hash — Go's `hash` package, ported.
//
// Trait surface mirrors Go's interface hierarchy:
//
//   Go                                     goish
//   ────────────────────────────────────   ─────────────────────────────
//   type Hash interface { io.Writer; ... }  pub trait Hash: io::Writer
//   type Hash32 interface { Hash; ... }     pub trait Hash32: Hash
//   type Hash64 interface { Hash; ... }     pub trait Hash64: Hash
//   type Cloner interface { Hash; ... }     pub trait Cloner: Hash
//   type XOF interface { io.Writer; ... }   pub trait XOF: io::Writer
//
// Implementations live in submodules: hash::fnv (FNV-1, FNV-1a),
// future hash::crc32, etc. Each Write returns `(int, error)` — `error`
// is always nil per Go's spec ("It never returns an error.").
//
// `Hash` and `Cloner` carry `#[goish::interface(embeds)]` so that a
// `Box<dyn Hash + Send + Sync>` carrier supports Go's comma-ok
// interface assertion. That is what `crypto/internal/fips140/hmac`
// needs for `h.inner.(marshalable)` and `h.inner.(hash.Cloner)`. The
// `embeds` flag says the supertrait clause models Go's interface
// embedding rather than a bound over a foreign trait, so the macro's
// hidden downcast helpers are inherited instead of re-declared.
//
// Both are *composite* in macro terms, so neither gets an auto-emitted
// nil sentinel and the assertion is spelled `carrier.As::<d!(Cloner)>()`
// rather than `cast!` — see goany.rs::AsExt. Concrete impls override
// `__goish_as_dyn_any` (and the `_mut` mirror) to `Some(self)` once, in
// their `impl io::Writer`, and each implementing package registers its
// own types (e.g. fips140/sha256's `register_sha256_impls`) — `hash`
// itself imports only `io`, as in Go.
//
// Slim deviations from Go:
//   * Sum takes `slice<byte>` and returns `slice<byte>` (matches the
//     goish primitive convention; Go uses `[]byte`).
//   * `Sum` takes `&self`. Go's is on a pointer receiver and its
//     contract only *says* it does not change state; goish enforces
//     that in the type system. An implementation that needs scratch
//     state (HMAC's outer hash) builds it locally.

#![allow(non_snake_case)]

extern crate alloc;

use crate::error;
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int};
use alloc::boxed::Box;

// go: sdk 1.25.5 hash/hash.go:26-46 Hash
/// `hash.Hash` (hash/hash.go:26) — common interface for all hash
/// functions. Implementors must also implement `io::Writer` (Write is
/// inherited; it never returns an error per Go's contract).
#[goish::interface(embeds)]
pub trait Hash: io::Writer {
    /// `Sum(b)` — append the current hash to `b` and return the
    /// resulting slice. Does not change the underlying hash state.
    fn Sum(&self, b: slice<byte>) -> slice<byte>;
    /// `Reset()` — reset the Hash to its initial state.
    fn Reset(&mut self);
    /// `Size()` — number of bytes Sum will append.
    fn Size(&self) -> int;
    /// `BlockSize()` — the hash's underlying block size.
    fn BlockSize(&self) -> int;
}

// go: sdk 1.25.5 hash/hash.go:49-52 Hash32
/// `hash.Hash32` (hash/hash.go:49) — 32-bit hash with `Sum32`.
pub trait Hash32: Hash {
    fn Sum32(&self) -> u32;
}

// go: sdk 1.25.5 hash/hash.go:55-58 Hash64
/// `hash.Hash64` (hash/hash.go:55) — 64-bit hash with `Sum64`.
pub trait Hash64: Hash {
    fn Sum64(&self) -> u64;
}

// go: sdk 1.25.5 hash/hash.go:69-72 Cloner
/// `hash.Cloner` (hash/hash.go:69) — a hash whose state can be cloned,
/// returning a value with equivalent and independent state.
///
/// A hash that can only decide at runtime whether it is cloneable (one
/// that wraps another hash, like `hmac.HMAC`) returns an error wrapping
/// [`crate::errors::ErrUnsupported`]. Otherwise `Clone` must return a
/// nil error.
///
/// Go returns the `Cloner` interface; goish returns the boxed trait
/// object. `Box<dyn Cloner + Send + Sync>` upcasts to
/// `Box<dyn Hash + Send + Sync>` where a plain hash is wanted.
#[goish::interface(embeds)]
pub trait Cloner: Hash {
    /// `Clone()` — an independent copy of this hash's state.
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error);
}

// go: none — goish idiom: the nil sentinel `#[goish::interface]` emits
// automatically for a trivial trait, hand-written because `Cloner` is
// composite (the macro cannot synthesize `impl io::Writer`/`impl Hash`
// for a sentinel it does not know the supertraits of). Lets a failing
// `Clone` return bare `nil.into()`, as Go returns a nil interface.
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub struct __NilCloner;

impl io::Writer for __NilCloner {
    // go: none — goish idiom: nil-interface sentinel method (see __NilCloner).
    fn Write(&mut self, _p: slice<byte>) -> (int, error) {
        panic!("goish: method call on nil Cloner interface")
    }
}

impl Hash for __NilCloner {
    // go: none — goish idiom: nil-interface sentinel method (see __NilCloner).
    fn Sum(&self, _b: slice<byte>) -> slice<byte> {
        panic!("goish: method call on nil Cloner interface")
    }
    // go: none — goish idiom: nil-interface sentinel method (see __NilCloner).
    fn Reset(&mut self) {
        panic!("goish: method call on nil Cloner interface")
    }
    // go: none — goish idiom: nil-interface sentinel method (see __NilCloner).
    fn Size(&self) -> int {
        panic!("goish: method call on nil Cloner interface")
    }
    // go: none — goish idiom: nil-interface sentinel method (see __NilCloner).
    fn BlockSize(&self) -> int {
        panic!("goish: method call on nil Cloner interface")
    }
}

impl Cloner for __NilCloner {
    // go: none — goish idiom: nil-interface sentinel method (see __NilCloner).
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        panic!("goish: method call on nil Cloner interface")
    }
}

impl From<crate::Nil> for Box<dyn Cloner + Send + Sync> {
    #[inline]
    // go: none — goish idiom: nil-interface sentinel method (see __NilCloner).
    fn from(_: crate::Nil) -> Self {
        return Box::new(__NilCloner);
    }
}

// go: sdk 1.25.5 hash/hash.go:75-92 XOF
/// `hash.XOF` (hash/hash.go:75) — an extendable output function: a hash
/// with arbitrary or unlimited output length.
///
/// A plain trait, not a `#[goish::interface]`: XOF embeds *two* goish
/// interfaces (`io.Writer` and `io.Reader`), so the macro's hidden
/// helpers would be ambiguous rather than merely inherited. Nothing in
/// goish type-asserts to XOF, so it needs no downcast registry.
pub trait XOF: io::Writer + io::Reader {
    /// `Reset()` — reset the XOF to its initial state.
    fn Reset(&mut self);
    /// `BlockSize()` — the XOF's underlying block size.
    fn BlockSize(&self) -> int;
}

// ─── HashFunc — the carrier for Go's `func() hash.Hash` ───────────────

// go: none — Go's `func() hash.Hash` is a first-class value, and the
// standard library passes closures for it: `fips140hash.UnwrapNew(h)`
// returns one that captures `h`, and `crypto/hkdf` and `crypto/ecdsa`
// hand that straight to `hmac.New` and `SignDeterministic`.
//
// goish had typed every such parameter as a bare `fn` pointer, which
// cannot hold a capture, so those Go call sites had nothing to translate
// to. `HashFunc` is the runtime gap being filled rather than papered over
// (AGENTS.md §5 rule 4): the `Arc<dyn Fn>` lives *inside* a concrete goish
// type, so no signature or struct field ever spells `dyn Fn`.
//
// It is `Clone` because the values that hold one — `hmac::HMAC`,
// `ecdsa::hmacDRBG` — are copied around the way Go copies a func value.
#[derive(Clone)]
pub struct HashFunc(alloc::sync::Arc<dyn Fn() -> Box<dyn Hash + Send + Sync> + Send + Sync>);

impl HashFunc {
    // go: none — goish idiom: build a HashFunc from any callable. Go
    // writes the closure literal directly.
    pub fn New<F>(f: F) -> Self
    where
        F: Fn() -> Box<dyn Hash + Send + Sync> + Send + Sync + 'static,
    {
        return HashFunc(alloc::sync::Arc::new(f));
    }

    // go: none — goish idiom: Go writes `h()`; a newtype needs a method.
    pub fn Call(&self) -> Box<dyn Hash + Send + Sync> {
        return (self.0)();
    }
}

// go: none — lets every existing call site keep passing a plain function
// (`hmac::New(sha512::NewHash, key)`) while the parameter type widens to
// accept closures. Same shape as AGENTS.md §4's `impl Into<string>` rule.
pub trait IntoHashFunc {
    fn into_hash_func(self) -> HashFunc;
}

impl IntoHashFunc for HashFunc {
    // go: none — goish idiom: the reflexive arm, so a HashFunc can be
    // passed anywhere the trait is accepted.
    fn into_hash_func(self) -> HashFunc {
        return self;
    }
}

impl<F> IntoHashFunc for F
where
    F: Fn() -> Box<dyn Hash + Send + Sync> + Send + Sync + 'static,
{
    // go: none — goish idiom: wraps a plain function or a closure, which
    // is what makes `hmac::New(sha512::NewHash, key)` and
    // `hmac::New(move || inner(), key)` both compile.
    fn into_hash_func(self) -> HashFunc {
        return HashFunc::New(self);
    }
}
