// gostring — Go's `string`, ported.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   var s string                         let s: string = ...
//   s := "hello"                         let s = string("hello");
//   len(s)                               len(s)
//   s[i]                                 s[i]            ← byte (Index<int>)
//   s + t                                s + t           ← Add
//   s == t                               s == t          ← PartialEq
//   for i, r := range s                  for (i, r) in range!(s)
//
// The struct is named lowercase `string` to match Go's type. Lives in
// the type namespace; the conversion function `string(x)` (in convert.rs)
// lives in the value namespace, so they coexist — same as Go.
//
// Backing: `Arc<[u8]>`. Immutable like Go. Cheap clone (atomic refcount).
// Like Go's string, it holds raw bytes — UTF-8 only by convention, not
// invariant. A `string` may be empty, but never "nil".

#![allow(non_camel_case_types)]

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::ops::{Add, Index};

use crate::builtin::Len as LenTrait;
use crate::types::{byte, int};

#[derive(Clone)]
pub struct string {
    bytes: Arc<[u8]>,
}

impl string {
    /// Empty string. Matches Go's zero value `""`.
    pub fn new() -> Self {
        Self {
            bytes: Arc::from([] as [u8; 0]),
        }
    }

    /// From a Rust string literal — the construction path for goish
    /// source code. Allocates and copies once at first use.
    #[inline]
    pub fn from_static(s: &'static str) -> Self {
        Self {
            bytes: Arc::from(s.as_bytes()),
        }
    }

    /// From a borrowed byte sequence. Copies. Used by `string(b)` for
    /// `slice<byte>` and by internal callers (utf8 encoders).
    ///
    /// Backed by `Arc<[u8]>` (one allocation: ArcInner header +
    /// inline payload). Construction cost is competitive with
    /// `String::from_utf8_lossy(b).into_owned()` (both do
    /// alloc + memcpy of len bytes); the small structural overhead
    /// vs `Vec::<u8>::from(&[u8])` is the Arc refcount fields. We
    /// pay that overhead deliberately because it makes `clone()`
    /// O(1) — a refcount bump rather than a full copy — which
    /// matches Go's value-type-with-shared-backing semantics.
    #[inline]
    pub fn from_bytes(b: &[u8]) -> Self {
        Self { bytes: Arc::from(b) }
    }

    /// Internal hand-off when an owned `Vec<u8>` is already prepared
    /// (concat, rune encoding). Avoids one copy that `from_bytes` would
    /// do. Dunder + `#[doc(hidden)]` mark it "do not call directly" —
    /// public so macros can reach it via path resolution.
    #[doc(hidden)]
    pub fn __from_vec(v: Vec<u8>) -> Self {
        Self { bytes: Arc::from(v) }
    }

    /// `len(s)` byte count. Method form — `len(s)` free function also
    /// works via the `Len` trait impl below.
    #[allow(non_snake_case)]
    pub fn Len(&self) -> int {
        self.bytes.len() as int
    }

    /// Internal byte access for utf8/range/comparison machinery. Public
    /// users get bytes via the `bytes(s)` builtin, which copies into a
    /// `slice<byte>` (Go-faithful semantics).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Crate-internal accessor for byte content. Called from sibling
/// modules (e.g., `testing`, `fmt`) that need byte-level access
/// without copying.
#[inline]
pub(crate) fn __crate_as_bytes(s: &string) -> &[u8] {
    s.as_bytes()
}

impl Default for string {
    fn default() -> Self {
        Self::new()
    }
}

// ─── From<&str> — enables slice!([]string{"a", "b"}) via .into() ─────
//
// Generalized from `&'static str` to any `&str` so non-static borrowed
// strings (e.g., from `bufio::Scanner.Text()` chains, or `&str` keys in
// `map<string, V>` index impls) can flow into a `string` without the
// caller needing to think about lifetimes.

impl From<&str> for string {
    fn from(s: &str) -> Self {
        string::from_bytes(s.as_bytes())
    }
}

// ─── Borrow<[u8]> — lets BTreeMap<string, V> look up by &[u8] / &str ──
//
// Required so the `map<string, V>` Index<&str> specialization can
// delegate to `BTreeMap::get(key.as_bytes())` without allocating a fresh
// `string` for each read. Borrow's invariant (Hash/Ord must agree) is
// satisfied: our `string` Ord/PartialEq/Hash all operate byte-wise.

impl core::borrow::Borrow<[u8]> for string {
    #[inline]
    fn borrow(&self) -> &[u8] {
        &self.bytes
    }
}

// ─── builtin len(s) ────────────────────────────────────────────────────

impl LenTrait for string {
    #[inline]
    fn __len(&self) -> int {
        self.bytes.len() as int
    }
}

// ─── s[i] — byte indexing, Go-faithful ────────────────────────────────

impl Index<int> for string {
    type Output = byte;
    fn index(&self, i: int) -> &byte {
        // Bounds check matches Go: panics on out-of-range, byte access
        // (NOT rune access — `s[i]` in Go returns a byte too).
        &self.bytes[i as usize]
    }
}

// ─── s + t — concat ───────────────────────────────────────────────────

impl Add<string> for string {
    type Output = string;
    fn add(self, rhs: string) -> string {
        let mut v = Vec::with_capacity(self.bytes.len() + rhs.bytes.len());
        v.extend_from_slice(&self.bytes);
        v.extend_from_slice(&rhs.bytes);
        string::__from_vec(v)
    }
}

impl Add<&str> for string {
    type Output = string;
    fn add(self, rhs: &str) -> string {
        let mut v = Vec::with_capacity(self.bytes.len() + rhs.len());
        v.extend_from_slice(&self.bytes);
        v.extend_from_slice(rhs.as_bytes());
        string::__from_vec(v)
    }
}

// ─── equality / hash / ordering — byte-wise (Go-faithful) ─────────────

impl PartialEq for string {
    fn eq(&self, other: &Self) -> bool {
        // Fast path: same Arc → same bytes (covers literals shared via
        // clone). Falls through to byte compare otherwise.
        Arc::ptr_eq(&self.bytes, &other.bytes) || *self.bytes == *other.bytes
    }
}
impl Eq for string {}

impl PartialEq<&str> for string {
    fn eq(&self, other: &&str) -> bool {
        &*self.bytes == other.as_bytes()
    }
}

impl Hash for string {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash the bytes, not the Arc identity — matches Go map semantics.
        self.bytes.hash(state);
    }
}

impl PartialOrd for string {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for string {
    fn cmp(&self, other: &Self) -> Ordering {
        (*self.bytes).cmp(&*other.bytes)
    }
}
