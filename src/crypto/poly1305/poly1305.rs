// go: file vendor/golang.org/x/crypto/internal/poly1305/poly1305.go decls: Sum, Verify, New, MAC.Size, MAC.Write, MAC.Sum, MAC.Verify
//
// crypto/poly1305 — the public one-time MAC surface: TagSize, the MAC
// type and its four methods, plus the two package-level helpers.
//
// The generic arithmetic those delegate to is in `sum_generic.rs`, one
// `.rs` per `.go` as Go splits them. goish has no assembly path, so
// the generic implementation is always the implementation — Go picks
// between them in sum_asm.go / mac_noasm.go, neither of which is
// ported.
//
// Slim deviations:
//   * `New` returns `MAC` by value where Go returns `*MAC`.
//   * `Write` takes `&[byte]` and does not return `(n, error)`: Go's
//     signature exists to satisfy io.Writer, and its error is always
//     nil. The panic-after-Sum behaviour is Go's, from `MAC.Write`.
//   * `Sum` appends into a caller-supplied Vec rather than returning a
//     new slice.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::types::byte;

use super::sum_generic::MacGeneric;

// go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/poly1305.go:23-23 TagSize
/// TagSize is the size, in bytes, of a Poly1305 authenticator.
pub const TagSize: usize = 16;

// ─── public API ────────────────────────────────────────────────────────

/// `MAC` — a running Poly1305 authenticator.
pub struct MAC {
    inner: MacGeneric,
    finalized: bool,
}

impl MAC {
    // go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/poly1305.go:50-61 New
    /// `poly1305.New` — creates a new MAC using a 32-byte one-time key.
    pub fn New(key: &[byte; 32]) -> Self {
        return MAC {
            inner: MacGeneric::new_from_key(key),
            finalized: false,
        };
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/poly1305.go:70-70 MAC.Size
    /// Go: `func (h *MAC) Size() int { return TagSize }` — the tag
    /// width, so a MAC satisfies hash.Hash's Size. It was missing here
    /// until the manifest asked for it.
    pub fn Size(&self) -> crate::types::int {
        return crate::int(TagSize);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/poly1305.go:76-83 MAC.Write
    /// Write adds data to the running MAC. Panics after Sum.
    ///
    /// Go returns `(n int, err error)` to satisfy io.Writer and its
    /// error is always nil; goish returns nothing.
    pub fn Write(&mut self, p: &[byte]) {
        if self.finalized {
            panic!("poly1305: write to MAC after Sum");
        }
        self.inner.write(p);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/poly1305.go:85-92 MAC.Sum
    /// Sum appends the 16-byte tag to `b` and marks the MAC finalized.
    pub fn Sum(&mut self, b: &mut alloc::vec::Vec<byte>) {
        let mut tag = [0u8; TagSize];
        self.inner.sum_into(&mut tag);
        self.finalized = true;
        b.extend_from_slice(&tag);
        return;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/poly1305.go:94-98 MAC.Verify
    /// Verify returns true if `expected` matches the MAC of all data written so far.
    pub fn Verify(&mut self, expected: &[byte]) -> bool {
        let mut tag = [0u8; TagSize];
        self.inner.sum_into(&mut tag);
        self.finalized = true;
        if expected.len() != TagSize {
            return false;
        }
        // constant-time compare
        let mut diff = 0u8;
        for i in 0..TagSize {
            diff |= tag[i] ^ expected[i];
        }
        return diff == 0;
    }
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/poly1305.go:28-33 Sum
/// `poly1305.Sum` — generate a 16-byte tag for `msg` into `out`.
pub fn Sum(out: &mut [byte; TagSize], msg: &[byte], key: &[byte; 32]) {
    let mut mac = MAC::New(key);
    mac.Write(msg);
    let mut v = alloc::vec::Vec::new();
    mac.Sum(&mut v);
    out.copy_from_slice(&v[..TagSize]);
    return;
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/internal/poly1305/poly1305.go:35-48 Verify
/// `poly1305.Verify` — verify a 16-byte tag for `msg`.
pub fn Verify(mac: &[byte; TagSize], msg: &[byte], key: &[byte; 32]) -> bool {
    let mut tmp = [0u8; TagSize];
    Sum(&mut tmp, msg, key);
    let mut diff = 0u8;
    for i in 0..TagSize {
        diff |= tmp[i] ^ mac[i];
    }
    return diff == 0;
}
