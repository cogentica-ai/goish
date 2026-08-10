// goishlint:ignore GOISH021 — `marshalable` (hmac.go:27) is the
// BinaryMarshaler+BinaryUnmarshaler pair Go type-asserts the inner/outer
// hashes against to cache their post-ipad/opad state (FIPS 198-1 §6).
// goish's hash::Hash exposes no MarshalBinary/UnmarshalBinary, so there is
// nothing to assert against and Reset re-feeds ipad instead. Port this
// when hash gains binary marshaling.
// go: file crypto/internal/fips140/hmac/hmac.go decls: HMAC.Sum, HMAC.Write, HMAC.Size, HMAC.BlockSize, HMAC.Reset, New, MarkAsUsedInKDF, errCloneUnsupported.Error, errCloneUnsupported.Unwrap, HMAC.Clone
//
// crypto/internal/fips140/hmac — HMAC per FIPS 198-1. The public
// crypto/hmac package is a thin wrapper over this.
//
// Deviations from hmac.go @ Go 1.25.5:
//
//   * `New` takes `fn() -> Box<dyn Hash + Send + Sync>` rather than a
//     generic `func() H`; goish has no generic-over-hash constructor, and
//     the uniqueness check Go performs (`hm.outer == hm.inner`, guarded by
//     recover) is unnecessary because two calls to a fn pointer always
//     produce distinct boxes.
//   * No `marshalable` fast path: Go caches the marshaled inner/outer state
//     after the first Reset (FIPS 198-1 §6). goish's hash::Hash has no
//     MarshalBinary/UnmarshalBinary, so Reset re-feeds ipad each time —
//     correctness-equivalent, slower for repeated Reset+Sum cycles.
//   * `fips140.RecordNonApproved()` calls in Sum are dropped: goish's
//     fips140 stub has no service indicator, so they are no-ops.
// crypto/hmac — Go's `crypto/hmac`, ported (FIPS 198-1).
//
// HMAC = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ message))
//
// Inlines Go's `crypto/internal/fips140/hmac/hmac.go::HMAC` since
// goish has no fips140 internal layer.
//
// Slim deviations:
//   * Constructor takes `fn() -> Box<dyn Hash + Send + Sync>` (a function pointer
//     yielding boxed `hash.Hash`) instead of Go's `func() hash.Hash`
//     interface return. Each hash module exposes a `NewHash` boxed
//     wrapper for this purpose:
//
//         hmac::New(crypto::sha256::NewHash, key)
//
//   * No Cloner / MarshalBinary / UnmarshalBinary fast path — Reset
//     re-feeds ipad each time (the FIPS-198 §6 cached-state optimization
//     is omitted since goish hashes don't implement BinaryMarshaler).
//   * Sum is `&self` per goish's Hash trait, so we synthesize a fresh
//     outer hasher each call instead of reset-and-write on a stored
//     outer (Go does the latter). Same digest, slightly more work.
//   * No `MarkAsUsedInKDF` — goish has no FIPS service-indicator.
//   * `Equal(a, b)` is constant-time via xor-accumulate (matches
//     `crypto/subtle.ConstantTimeCompare`).

#![allow(non_snake_case)]
#![allow(non_camel_case_types)] // Go names (errCloneUnsupported)

use crate::error;
use crate::goslice::slice;
use crate::hash::Hash;
use crate::io;
use crate::types::{byte, int};

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// `hmac.HMAC` (fips140/hmac/hmac.go:32) — keyed-hash MAC.
pub struct HMAC {
    // Go: opad, ipad []byte
    opad: Vec<byte>,
    ipad: Vec<byte>,
    // Go: inner hash.Hash (fed key⊕ipad on Reset)
    inner: Box<dyn Hash>,
    // Goish-only: stashed constructor — we need it inside `Sum(&self)`
    // to build a fresh outer hasher (since Box<dyn Hash> isn't Clone
    // and Sum's contract is non-mutating).
    h_ctor: fn() -> Box<dyn Hash + Send + Sync>,
    // Go: forHKDF, keyLen — stored to inform the service-indicator
    // decision in Sum. goish's fips140 stub records nothing, so they are
    // carried for shape and read by MarkAsUsedInKDF.
    forHKDF: bool,
    keyLen: int,
}

// go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:133-141 errCloneUnsupported
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
}

impl errCloneUnsupported {
    // go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:139-141 errCloneUnsupported.Unwrap
    //
    //   func (e errCloneUnsupported) Unwrap() error { return errors.ErrUnsupported }
    pub fn Unwrap(&self) -> error {
        return crate::errors::ErrUnsupported.into();
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:145-165 HMAC.Clone
//
//   func (h *HMAC) Clone() (hash.Cloner, error)
/// Clone the HMAC state. goish's `hash::Hash` has no `Cloner`
/// counterpart, so this rebuilds from the stashed constructor and the
/// stored pads — equivalent state, and it cannot fail the way Go's can
/// (Go returns errCloneUnsupported when the inner hash is not a Cloner).
pub fn Clone(h: &HMAC) -> (HMAC, error) {
    let mut inner = (h.h_ctor)();
    let _ = io::Writer::Write(&mut inner, slice::__from_vec(h.ipad.clone()));
    return (
        HMAC {
            opad: h.opad.clone(),
            ipad: h.ipad.clone(),
            inner,
            h_ctor: h.h_ctor,
            forHKDF: h.forHKDF,
            keyLen: h.keyLen,
        },
        crate::errors::nil,
    );
}

// go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:208-210 MarkAsUsedInKDF
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
/// Goish-specific: `h` is `fn() -> Box<dyn Hash + Send + Sync>` (a function pointer
/// returning a boxed Hash). Use the per-hash `NewHash` helper:
///
/// ```ignore
/// hmac::New(crypto::sha256::NewHash, key)
/// hmac::New(crypto::sha1::NewHash, key)
/// hmac::New(crypto::md5::NewHash, key)
/// ```
pub fn New(h: fn() -> Box<dyn Hash + Send + Sync>, key: slice<byte>) -> HMAC {
    // Go: hm := &HMAC{keyLen: len(key)}
    let keyLen = key.Len();
    // Go: hm := &HMAC{keyLen: len(key)}
    // Go: hm.outer = h(); hm.inner = h()
    let mut inner = h();
    // Go: blocksize := hm.inner.BlockSize()
    let blocksize = inner.BlockSize() as usize;
    // Go: hm.ipad = make([]byte, blocksize); hm.opad = make([]byte, blocksize)
    let mut ipad: Vec<byte> = alloc::vec![0; blocksize];
    let mut opad: Vec<byte> = alloc::vec![0; blocksize];

    let key_raw: &[byte] = &key;
    let key_bytes: Vec<byte> = if key_raw.len() > blocksize {
        // Go: if len(key) > blocksize { hm.outer.Write(key); key = hm.outer.Sum(nil) }
        let mut tmp = h();
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

        // Go: h.outer.Reset(); h.outer.Write(h.opad); h.outer.Write(in[origLen:])
        // Build outer = H(opad ∥ inner_digest) using a fresh hasher.
        let mut outer = (self.h_ctor)();
        let _ = io::Writer::Write(&mut *outer, slice::__from_vec(self.opad.clone()));
        let _ = io::Writer::Write(&mut *outer, slice::__from_vec(inner_digest));
        // Go: return h.outer.Sum(in[:origLen])
        let mut prefix: Vec<byte> = in1.__into_vec();
        prefix.truncate(origLen);
        outer.Sum(slice::__from_vec(prefix))
    }

    // go: sdk 1.25.5 crypto/internal/fips140/hmac/hmac.go:82-131 HMAC.Reset
    // Go: HMAC.Reset (fips140/hmac/hmac.go:82)
    fn Reset(&mut self) {
        // Go: h.inner.Reset(); h.inner.Write(h.ipad)
        self.inner.Reset();
        let _ = io::Writer::Write(&mut *self.inner, slice::__from_vec(self.ipad.clone()));
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
