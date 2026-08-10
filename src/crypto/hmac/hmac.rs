// go: file crypto/hmac/hmac.go decls: New, Equal, Write, Sum, Reset, Size, BlockSize
//
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
}

// go: sdk 1.25.5 crypto/hmac/hmac.go:39-57 New
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

    HMAC {
        opad,
        ipad,
        inner,
        h_ctor: h,
    }
}

// ─── Hash trait impls for HMAC ────────────────────────────────────────

impl io::Writer for HMAC {
    // go: none — goish idiom (local helper / no Go counterpart)
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: return h.inner.Write(p)
        io::Writer::Write(&mut *self.inner, p)
    }
}

impl Hash for HMAC {
    // go: none — goish idiom (local helper / no Go counterpart)
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

    // go: none — goish idiom (local helper / no Go counterpart)
    // Go: HMAC.Reset (fips140/hmac/hmac.go:82)
    fn Reset(&mut self) {
        // Go: h.inner.Reset(); h.inner.Write(h.ipad)
        self.inner.Reset();
        let _ = io::Writer::Write(&mut *self.inner, slice::__from_vec(self.ipad.clone()));
    }

    // go: none — goish idiom (local helper / no Go counterpart)
    // Go: HMAC.Size (fips140/hmac/hmac.go:79) — equal to inner.Size().
    fn Size(&self) -> int {
        self.inner.Size()
    }

    // go: none — goish idiom (local helper / no Go counterpart)
    // Go: HMAC.BlockSize (fips140/hmac/hmac.go:80)
    fn BlockSize(&self) -> int {
        self.inner.BlockSize()
    }
}

// ─── Equal — constant-time MAC compare (Go: hmac.go:60) ───────────────

// go: sdk 1.25.5 crypto/hmac/hmac.go:60-65 Equal
/// `hmac.Equal(a, b)` (hmac.go:60) — constant-time MAC comparison.
/// Returns false on length mismatch, otherwise compares byte-by-byte
/// without short-circuiting (no timing leak).
pub fn Equal(a: slice<byte>, b: slice<byte>) -> bool {
    // Go (subtle.ConstantTimeCompare, subtle.go:18):
    //   if len(x) != len(y) { return 0 }
    //   var v byte; for i := 0; i < len(x); i++ { v |= x[i] ^ y[i] }
    //   return ConstantTimeByteEq(v, 0)
    let ar: &[byte] = &a;
    let br: &[byte] = &b;
    if ar.len() != br.len() {
        return false;
    }
    let mut v: u8 = 0;
    let mut i = 0;
    while i < ar.len() {
        v |= ar[i] ^ br[i];
        i += 1;
    }
    v == 0
}
