// go: file crypto/internal/fips140/hmac/hmac.go decls: HMAC.Sum, HMAC.Write, HMAC.Size, HMAC.BlockSize, HMAC.Reset, New, MarkAsUsedInKDF, errCloneUnsupported.Error, errCloneUnsupported.Unwrap, HMAC.Clone, register_hmac_impls, MarshalBinary, UnmarshalBinary, __goish_as_dyn_any, __goish_as_dyn_any_mut
//
// crypto/internal/fips140/hmac — HMAC per FIPS 198-1. The public
// crypto/hmac package is a thin wrapper over this.
//
//   HMAC = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ message))
//
// Deviations from hmac.go @ Go 1.25.5:
//
//   * `New` takes `impl IntoHashFunc` (stored as `hash::HashFunc`) rather than a
//     generic `func() H`; goish has no generic-over-hash constructor, and
//     the uniqueness check Go performs (`hm.outer == hm.inner`, guarded by
//     recover) is unnecessary because two calls to a fn pointer always
//     produce distinct boxes.
//
//         hmac::New(crypto::sha256::NewHash, key)
//
//   * No stored `outer` field. goish's `Hash::Sum` takes `&self`, so Sum
//     cannot reset-and-write a shared outer the way Go does; it builds
//     one from the stashed constructor instead. The FIPS 198-1 §6 state
//     cache below makes that as cheap as Go's path — restoring the
//     marshaled opad state costs one UnmarshalBinary either way.
//   * `fips140.RecordNonApproved()` calls in Sum are dropped: goish's
//     fips140 stub has no service indicator, so they are no-ops.
//   * `marshalable` is a nominal `#[goish::interface]` rather than Go's
//     structural interface, so the hashes that satisfy it are `impl`ed
//     and registered explicitly (see `register_hmac_impls`). A hash
//     without those impls takes the slow path, exactly as in Go.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)] // Go names (errCloneUnsupported, marshalable)

use crate::error;
use crate::goslice::slice;
use crate::hash::{Cloner, Hash, HashFunc, IntoHashFunc};
use crate::io;
use crate::types::{byte, int};

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

// go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:27-30 marshalable
//
//   type marshalable interface {
//       MarshalBinary() ([]byte, error)
//       UnmarshalBinary([]byte) error
//   }
/// The combination of `encoding.BinaryMarshaler` and
/// `encoding.BinaryUnmarshaler`. Their method definitions are repeated
/// here to avoid a dependency on the encoding package, as in Go.
#[goish::interface]
pub trait marshalable {
    fn MarshalBinary(&self) -> (slice<byte>, error);
    fn UnmarshalBinary(&mut self, b: slice<byte>) -> error;
}

// go: none — goish idiom: `marshalable` is nominal, so the hashes that
// satisfy it structurally in Go are `impl`ed here. Go's own Sum
// type-switches on `*sha256.Digest` / `*sha512.Digest` / `*sha3.Digest`,
// so this file already depends on those packages upstream.
impl marshalable for crate::crypto::internal::fips140::sha256::Digest {
    // go: none — goish idiom: `marshalable` is nominal, so satisfying it
    // is an explicit forwarder rather than Go's structural match.
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return crate::crypto::internal::fips140::sha256::Digest::MarshalBinary(self);
    }
    // go: none — goish idiom: `marshalable` is nominal, so satisfying it
    // is an explicit forwarder rather than Go's structural match.
    fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        return crate::crypto::internal::fips140::sha256::Digest::UnmarshalBinary(self, b);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: see the sha256 impl above. Go's Sum
// type-switches on `*sha512.Digest` too, so the dependency matches.
impl marshalable for crate::crypto::internal::fips140::sha512::Digest {
    // go: none — goish idiom: `marshalable` is nominal, so satisfying it
    // is an explicit forwarder rather than Go's structural match.
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return crate::crypto::internal::fips140::sha512::Digest::MarshalBinary(self);
    }
    // go: none — goish idiom: `marshalable` is nominal, so satisfying it
    // is an explicit forwarder rather than Go's structural match.
    fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        return crate::crypto::internal::fips140::sha512::Digest::UnmarshalBinary(self, b);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: see the sha256 impl above. Go's hmac has no MD5 branch (MD5 is not a FIPS hash), but
// goish's crypto/hmac accepts it, so the fast path applies.
impl marshalable for crate::crypto::md5::Digest {
    // go: none — goish idiom: `marshalable` is nominal, so satisfying it
    // is an explicit forwarder rather than Go's structural match.
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return crate::crypto::md5::Digest::MarshalBinary(self);
    }
    // go: none — goish idiom: `marshalable` is nominal, so satisfying it
    // is an explicit forwarder rather than Go's structural match.
    fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        return crate::crypto::md5::Digest::UnmarshalBinary(self, b);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: see the sha256 impl above. Same for SHA-1: outside the FIPS module, still used by TLS 1.2.
impl marshalable for crate::crypto::sha1::Digest {
    // go: none — goish idiom: `marshalable` is nominal, so satisfying it
    // is an explicit forwarder rather than Go's structural match.
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return crate::crypto::sha1::Digest::MarshalBinary(self);
    }
    // go: none — goish idiom: `marshalable` is nominal, so satisfying it
    // is an explicit forwarder rather than Go's structural match.
    fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        return crate::crypto::sha1::Digest::UnmarshalBinary(self, b);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: see the sha256 impl above. Go's Sum
// type-switches on `*sha3.Digest` as well.
impl marshalable for crate::crypto::internal::fips140::sha3::Digest {
    // go: none — goish idiom: `marshalable` is nominal, so satisfying it
    // is an explicit forwarder rather than Go's structural match.
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        return crate::crypto::internal::fips140::sha3::Digest::MarshalBinary(self);
    }
    // go: none — goish idiom: `marshalable` is nominal, so satisfying it
    // is an explicit forwarder rather than Go's structural match.
    fn UnmarshalBinary(&mut self, b: slice<byte>) -> error {
        return crate::crypto::internal::fips140::sha3::Digest::UnmarshalBinary(self, b);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: `#[goish::interface]` downcast registries are
// filled at runtime, one entry per `impl Trait for Concrete`; Go's itabs
// are built by the linker. Idempotent and cheap; called from `New`.
/// Register the hashes that implement [`marshalable`] and
/// `hash::Cloner`, so `New`'s HMAC can assert on its inner hash.
fn register_hmac_impls() {
    __goish_register_marshalable_impl::<crate::crypto::internal::fips140::sha256::Digest>();
    __goish_register_marshalable_impl::<crate::crypto::internal::fips140::sha512::Digest>();
    crate::crypto::internal::fips140::sha256::register_sha256_impls();
    crate::crypto::internal::fips140::sha512::register_sha512_impls();
    __goish_register_marshalable_impl::<crate::crypto::md5::Digest>();
    __goish_register_marshalable_impl::<crate::crypto::sha1::Digest>();
    crate::crypto::md5::register_md5_impls();
    crate::crypto::sha1::register_sha1_impls();
    __goish_register_marshalable_impl::<crate::crypto::internal::fips140::sha3::Digest>();
    crate::crypto::internal::fips140::sha3::register_sha3_impls();
    // HMAC is itself a Cloner, so a `Box<dyn Hash>` holding one must be
    // able to assert to `hash.Cloner` — Go gets this from the itab.
    crate::hash::__goish_register_Cloner_impl::<HMAC>();
    crate::hash::__goish_register_Hash_impl::<HMAC>();
    crate::io::__goish_register_Writer_impl::<HMAC>();
}

/// `hmac.HMAC` (fips140/hmac/hmac.go:32) — keyed-hash MAC.
pub struct HMAC {
    // Go: opad, ipad []byte
    // "opad and ipad may share underlying storage with HMAC clones."
    opad: Vec<byte>,
    ipad: Vec<byte>,
    // Go: inner hash.Hash (fed key⊕ipad on Reset)
    inner: Box<dyn Hash + Send + Sync>,
    // Goish-only: stashed constructor — we need it inside `Sum(&self)`
    // to build a fresh outer hasher (since Box<dyn Hash> isn't Clone
    // and Sum's contract is non-mutating). Stands in for Go's `outer`.
    h_ctor: HashFunc,
    // Go: marshaled bool — "If marshaled is true, then opad and ipad do
    // not contain a padded copy of the key, but rather the marshaled
    // state of outer/inner after opad/ipad has been fed into it."
    marshaled: bool,
    // Go: forHKDF, keyLen — stored to inform the service-indicator
    // decision in Sum. goish's fips140 stub records nothing, so they are
    // carried for shape and read by MarkAsUsedInKDF.
    forHKDF: bool,
    keyLen: int,
}

// go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:133-133 errCloneUnsupported
//
//   type errCloneUnsupported struct{}
/// Returned by `Clone` when the underlying hash cannot be cloned.
#[derive(Clone)]
pub struct errCloneUnsupported;

impl crate::errors::ErrorTrait for errCloneUnsupported {
    // go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:135-137 errCloneUnsupported.Error
    fn Error(&self) -> crate::gostring::string {
        return crate::gostring::string::from_static(
            "crypto/hmac: hash does not support hash.Cloner",
        );
    }

    // go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:139-141 errCloneUnsupported.Unwrap
    //
    //   func (e errCloneUnsupported) Unwrap() error { return errors.ErrUnsupported }
    //
    // Lives inside `impl ErrorTrait` rather than an inherent impl: that
    // is the method `errors::Is` walks, so an inherent `Unwrap` would
    // leave `errors::Is(err, ErrUnsupported)` false — the one thing this
    // error exists to make true.
    fn Unwrap(&self) -> error {
        return crate::errors::ErrUnsupported.into();
    }
}

impl HMAC {
    // go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:145-165 HMAC.Clone
    //
    //   func (h *HMAC) Clone() (hash.Cloner, error)
    /// Implements `hash::Cloner` if the underlying hash does. Otherwise
    /// it returns an error wrapping `errors::ErrUnsupported`.
    pub fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        // Go: r := *h; ic, ok := h.inner.(hash.Cloner); if !ok { … }
        //
        // Composite interfaces have no nil sentinel, so the assertion is
        // spelled `.As::<…>()` rather than `cast!` (goany.rs::AsExt).
        let ic = match crate::goany::AsExt::As::<dyn Cloner + Send + Sync>(&*self.inner) {
            Some(c) => c,
            // Go: return nil, errCloneUnsupported{}
            None => return (crate::nil.into(), errCloneUnsupported.into()),
        };
        // Go: r.inner, err = ic.Clone(); if err != nil { … }
        //
        // goish keeps no `outer` field, so Go's second assertion on
        // h.outer is subsumed: the same constructor produced both, so an
        // inner that clones implies an outer that clones.
        let (inner, err) = ic.Clone();
        if err != crate::errors::nil {
            return (crate::nil.into(), errCloneUnsupported.into());
        }
        // Go: return &r, nil
        return (
            Box::new(HMAC {
                opad: self.opad.clone(),
                ipad: self.ipad.clone(),
                inner,
                h_ctor: self.h_ctor.clone(),
                marshaled: self.marshaled,
                forHKDF: self.forHKDF,
                keyLen: self.keyLen,
            }),
            crate::errors::nil,
        );
    }
}

impl Cloner for HMAC {
    // go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:145-165 HMAC.Clone
    fn Clone(&self) -> (Box<dyn Cloner + Send + Sync>, error) {
        return HMAC::Clone(self);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:207-209 MarkAsUsedInKDF
//
//   func MarkAsUsedInKDF(h *HMAC) { h.forHKDF = true }
/// Record that this HMAC instance is used as part of a KDF. Go consults
/// the flag in `Sum` to skip the short-key service-indicator penalty;
/// goish's fips140 stub records nothing, so the flag is inert but kept
/// so the Go call sites port verbatim.
pub fn MarkAsUsedInKDF(h: &mut HMAC) {
    h.forHKDF = true;
}

// go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:168-206 New
/// `hmac.New(h, key)` (hmac.go:39) — new HMAC using `h()` as the
/// underlying hash. `h` must produce a fresh `Hash` on each call.
///
/// Goish-specific: `h` is anything `IntoHashFunc` accepts — a plain
/// function like the per-hash `NewHash` helper, or a closure. It is stored
/// as a `hash::HashFunc`, which is what lets Go's
/// `fips140hash.UnwrapNew(h)` closures translate:
///
/// ```ignore
/// hmac::New(crypto::sha256::NewHash, key)
/// hmac::New(crypto::sha1::NewHash, key)
/// hmac::New(crypto::md5::NewHash, key)
/// ```
pub fn New<H: IntoHashFunc>(h: H, key: slice<byte>) -> HMAC {
    let h = h.into_hash_func();
    register_hmac_impls();
    // Go: hm := &HMAC{keyLen: len(key)}
    let keyLen = key.Len();
    // Go: hm := &HMAC{keyLen: len(key)}
    // Go: hm.outer = h(); hm.inner = h()
    let mut inner = h.Call();
    // Go: blocksize := hm.inner.BlockSize()
    let blocksize = inner.BlockSize() as usize;
    // Go: hm.ipad = make([]byte, blocksize); hm.opad = make([]byte, blocksize)
    let mut ipad: Vec<byte> = alloc::vec![0; blocksize];
    let mut opad: Vec<byte> = alloc::vec![0; blocksize];

    let key_raw: &[byte] = &key;
    let key_bytes: Vec<byte> = if key_raw.len() > blocksize {
        // Go: if len(key) > blocksize { hm.outer.Write(key); key = hm.outer.Sum(nil) }
        let mut tmp = h.Call();
        let _ = io::Writer::Write(&mut *tmp, key.clone());
        let empty: slice<byte> = slice::__from_vec(Vec::new());
        let s = tmp.Sum(empty);
        s.__into_vec()
    } else {
        key_raw.to_vec()
    };

    // Go: copy(hm.ipad, key); copy(hm.opad, key)
    let n = core::cmp::min(key_bytes.len(), blocksize);
    ipad[..n].copy_from_slice(&key_bytes[..n]);
    opad[..n].copy_from_slice(&key_bytes[..n]);

    // Go: for i := range hm.ipad { hm.ipad[i] ^= 0x36 }
    // Go: for i := range hm.opad { hm.opad[i] ^= 0x5c }
    let mut i = 0;
    while i < blocksize {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
        i += 1;
    }

    // Go: hm.inner.Write(hm.ipad)
    let _ = io::Writer::Write(&mut *inner, slice::__from_vec(ipad.clone()));

    // Go: return hm
    return HMAC {
        opad,
        ipad,
        inner,
        h_ctor: h,
        marshaled: false,
        forHKDF: false,
        keyLen,
    };
}

// ─── Hash trait impls for HMAC ────────────────────────────────────────

impl io::Writer for HMAC {
    // go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:75-77 HMAC.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: return h.inner.Write(p)
        io::Writer::Write(&mut *self.inner, p)
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` concrete impl overrides so `carrier.As::<…>()`
    // can reach this type. Go's itabs make it unnecessary.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

impl Hash for HMAC {
    // go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:47-73 HMAC.Sum
    // Go: HMAC.Sum (fips140/hmac/hmac.go:47)
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: origLen := len(in)
        let origLen = {
            let raw: &[byte] = &b;
            raw.len()
        };
        // Go: in = h.inner.Sum(in)
        let in1 = self.inner.Sum(b);

        // Inner digest sits at in1[origLen..].
        let inner_digest: Vec<byte> = {
            let raw: &[byte] = &in1;
            raw[origLen..].to_vec()
        };

        // Go: if h.marshaled { h.outer.(marshalable).UnmarshalBinary(h.opad) }
        //     else { h.outer.Reset(); h.outer.Write(h.opad) }
        //
        // goish keeps no `outer` field (Sum takes `&self`), so the outer
        // hasher is built here. A fresh hasher is already in its reset
        // state, which makes Go's two branches the same shape: restore
        // the cached post-opad state, or feed opad.
        let mut outer = self.h_ctor.Call();
        if self.marshaled {
            match goish::cast!(&mut *outer, marshalable) {
                Some(mo) => {
                    let err = mo.UnmarshalBinary(slice::__from_vec(self.opad.clone()));
                    // Go: panic(err) — Reset only sets marshaled after a
                    // successful round-trip, so this cannot fire.
                    if err != crate::errors::nil {
                        panic!("crypto/hmac: outer UnmarshalBinary failed");
                    }
                }
                None => panic!("crypto/hmac: marshaled state on a non-marshalable hash"),
            }
        } else {
            let _ = io::Writer::Write(&mut *outer, slice::__from_vec(self.opad.clone()));
        }
        // Go: h.outer.Write(in[origLen:])
        let _ = io::Writer::Write(&mut *outer, slice::__from_vec(inner_digest));
        // Go: return h.outer.Sum(in[:origLen])
        let mut prefix: Vec<byte> = in1.__into_vec();
        prefix.truncate(origLen);
        outer.Sum(slice::__from_vec(prefix))
    }

    // go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:82-131 HMAC.Reset
    // Go: HMAC.Reset (fips140/hmac/hmac.go:82)
    fn Reset(&mut self) {
        // Go: if h.marshaled { h.inner.(marshalable).UnmarshalBinary(h.ipad); return }
        if self.marshaled {
            let ipad = self.ipad.clone();
            match goish::cast!(&mut *self.inner, marshalable) {
                Some(mi) => {
                    let err = mi.UnmarshalBinary(slice::__from_vec(ipad));
                    // Go: panic(err)
                    if err != crate::errors::nil {
                        panic!("crypto/hmac: inner UnmarshalBinary failed");
                    }
                }
                None => panic!("crypto/hmac: marshaled state on a non-marshalable hash"),
            }
            return;
        }

        // Go: h.inner.Reset(); h.inner.Write(h.ipad)
        self.inner.Reset();
        let _ = io::Writer::Write(&mut *self.inner, slice::__from_vec(self.ipad.clone()));

        // If the underlying hash is marshalable, we can save some time by
        // saving a copy of the hash state now, and restoring it on future
        // calls to Reset and Sum instead of writing ipad/opad every time.
        //
        // We do this on Reset to avoid slowing down the common
        // single-use case.
        //
        // This is allowed by FIPS 198-1, Section 6: "Conceptually, the
        // intermediate results of the compression function on the B-byte
        // blocks (K0 ⊕ ipad) and (K0 ⊕ opad) can be precomputed once, at
        // the time of generation of the key K, or before its first use.
        // These intermediate results can be stored and then used to
        // initialize H each time that a message needs to be authenticated
        // using the same key. [...] These stored intermediate values shall
        // be treated and protected in the same manner as secret keys."

        // Go: marshalableInner, innerOK := h.inner.(marshalable)
        //     if !innerOK { return }
        //     imarshal, err := marshalableInner.MarshalBinary()
        //     if err != nil { return }
        let (mi, innerOK) = goish::cast!(&*self.inner, marshalable);
        if !innerOK {
            return;
        }
        let (imarshal, err) = mi.MarshalBinary();
        if err != crate::errors::nil {
            return;
        }

        // Go: marshalableOuter, outerOK := h.outer.(marshalable)
        //     if !outerOK { return }
        //     h.outer.Reset(); h.outer.Write(h.opad)
        //     omarshal, err := marshalableOuter.MarshalBinary()
        //     if err != nil { return }
        //
        // goish builds the outer hasher on demand; a fresh one is already
        // reset, so this is Go's `h.outer.Reset(); h.outer.Write(h.opad)`.
        let mut outer = self.h_ctor.Call();
        let _ = io::Writer::Write(&mut *outer, slice::__from_vec(self.opad.clone()));
        let (mo, outerOK) = goish::cast!(&*outer, marshalable);
        if !outerOK {
            return;
        }
        let (omarshal, err) = mo.MarshalBinary();
        if err != crate::errors::nil {
            return;
        }

        // Go: h.ipad = imarshal; h.opad = omarshal; h.marshaled = true
        self.ipad = imarshal.__into_vec();
        self.opad = omarshal.__into_vec();
        self.marshaled = true;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:79 HMAC.Size
    fn Size(&self) -> int {
        self.inner.Size()
    }

    // go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:80 HMAC.BlockSize
    fn BlockSize(&self) -> int {
        self.inner.BlockSize()
    }
}
