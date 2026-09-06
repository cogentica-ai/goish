// go: file vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305_generic.go decls: writeWithPadding, writeUint64, chacha20poly1305.sealGeneric, chacha20poly1305.openGeneric
//
// crypto/chacha20poly1305 — the generic (non-assembly) seal and open
// bodies, plus the two Poly1305 framing helpers they use. Go keeps
// these in their own file so the amd64 build can replace them; goish
// has no assembly path, so these are always the implementation.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::chacha20;
use crate::crypto::poly1305;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::types::byte;

use super::chacha20poly1305::{errOpen, ChaCha20Poly1305};

// go: sdk 1.25.5 vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305_generic.go:24-28 writeUint64
/// Write `n` as a little-endian u64 into the Poly1305 MAC.
fn write_uint64(p: &mut poly1305::MAC, n: usize) {
    let buf = crate::uint64(n).to_le_bytes();
    p.Write(&buf);
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305_generic.go:15-22 writeWithPadding
/// Write `b` with 16-byte alignment padding into the MAC.
fn write_with_padding(p: &mut poly1305::MAC, b: &[byte]) {
    p.Write(b);
    let rem = b.len() % 16;
    if rem != 0 {
        let pad = [0u8; 16];
        p.Write(&pad[..16 - rem]);
    }
}

impl ChaCha20Poly1305 {
    // go: sdk 1.25.5 vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305_generic.go:30-51 chacha20poly1305.sealGeneric
    /// `sealGeneric` — encrypt plaintext + compute Poly1305 tag.
    pub(super) fn seal_generic(
        &self,
        dst: &[byte],
        nonce: &[byte],
        plaintext: &[byte],
        aad: &[byte],
    ) -> slice<byte> {
        // Generate Poly1305 key (first 32 bytes of ChaCha20 block 0)
        // XOR zeros with keystream = keystream itself
        let zeros32 = [0u8; 32];
        let mut poly_key = [0u8; 32];
        let (mut cipher, _) = chacha20::new_from_bytes(&self.key, nonce);
        let c = cipher
            .as_mut()
            .expect("chacha20poly1305: cipher init failed");
        c.XORKeyStream(&mut poly_key, &zeros32);
        c.SetCounter(1); // skip first block (used for poly key)

        // Encrypt plaintext into a separate buffer first
        let mut ciphertext: Vec<byte> = alloc::vec![0u8; plaintext.len()];
        c.XORKeyStream(&mut ciphertext, plaintext);

        // Compute Poly1305 tag
        let mut p = poly1305::MAC::New(&poly_key);
        write_with_padding(&mut p, aad);
        write_with_padding(&mut p, &ciphertext);
        write_uint64(&mut p, aad.len());
        write_uint64(&mut p, plaintext.len());
        let mut tag_vec = Vec::new();
        p.Sum(&mut tag_vec);

        // Build output: dst || ciphertext || tag
        let mut out: Vec<byte> =
            Vec::with_capacity(dst.len() + ciphertext.len() + poly1305::TagSize);
        out.extend_from_slice(dst);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag_vec[..poly1305::TagSize]);
        return slice::<byte>::__from_vec(out);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305_generic.go:53-81 chacha20poly1305.openGeneric
    /// `openGeneric` — verify Poly1305 tag and decrypt.
    pub(super) fn open_generic(
        &self,
        dst: &[byte],
        nonce: &[byte],
        ciphertext: &[byte],
        aad: &[byte],
    ) -> (slice<byte>, error) {
        let tag = &ciphertext[ciphertext.len() - 16..];
        let ciphertext = &ciphertext[..ciphertext.len() - 16];

        // Generate Poly1305 key
        let zeros32 = [0u8; 32];
        let mut poly_key = [0u8; 32];
        let (mut cipher, _) = chacha20::new_from_bytes(&self.key, nonce);
        let c = cipher
            .as_mut()
            .expect("chacha20poly1305: cipher init failed");
        c.XORKeyStream(&mut poly_key, &zeros32);
        c.SetCounter(1);

        // Verify tag
        let mut p = poly1305::MAC::New(&poly_key);
        write_with_padding(&mut p, aad);
        write_with_padding(&mut p, ciphertext);
        write_uint64(&mut p, aad.len());
        write_uint64(&mut p, ciphertext.len());
        if !p.Verify(tag) {
            // Go: return nil, errOpen
            return (slice::<byte>::__from_vec(Vec::new()), errOpen.into());
        }

        // Decrypt
        let mut out: Vec<byte> = Vec::with_capacity(dst.len() + ciphertext.len());
        out.extend_from_slice(dst);
        let start = out.len();
        out.resize(start + ciphertext.len(), 0u8);
        let pt = &mut out[start..];
        let ct_copy: Vec<byte> = ciphertext.to_vec();
        c.XORKeyStream(pt, &ct_copy);

        return (slice::<byte>::__from_vec(out), errors::nil);
    }
}
