// crypto/chacha20poly1305 — ChaCha20-Poly1305 AEAD.
//
// Port of:
//   vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305.go         (98 LOC)
//   vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305_generic.go (81 LOC)
//
// Implements cipher::AEAD (NonceSize=12, Overhead=16) using ChaCha20 for encryption
// and Poly1305 for authentication. RFC 8439.
//
// Slim deviations:
//   * `New` returns `(Option<ChaCha20Poly1305>, error)` instead of `(cipher.AEAD, error)`.
//   * Seal/Open work directly on &[byte] and Vec<byte> to avoid slice<byte> overhead.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::chacha20;
use crate::crypto::cipher::AEAD as AEADTrait;
use crate::crypto::poly1305;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::types::{byte, int};

/// KeySize is the size of the key, in bytes.
pub const KeySize: usize = 32;
/// NonceSize is the size of the nonce, in bytes.
pub const NonceSize: usize = 12;
/// Overhead is the Poly1305 tag size — the difference between ciphertext and plaintext lengths.
pub const Overhead: usize = 16;

/// `chacha20poly1305.ChaCha20Poly1305` — AEAD cipher.
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: [byte; KeySize],
}

/// `chacha20poly1305.New` — creates a new ChaCha20-Poly1305 AEAD from a 32-byte key.
pub fn New(key: slice<byte>) -> (Option<ChaCha20Poly1305>, error) {
    let v = key.__into_vec();
    if v.len() != KeySize {
        return (None, errors::New("chacha20poly1305: bad key length"));
    }
    let mut k = [0u8; KeySize];
    k.copy_from_slice(&v);
    (Some(ChaCha20Poly1305 { key: k }), errors::nil)
}

/// Write `n` as a little-endian u64 into the Poly1305 MAC.
fn write_uint64(p: &mut poly1305::MAC, n: usize) {
    let buf = (n as u64).to_le_bytes();
    p.Write(&buf);
}

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
    /// `sealGeneric` — encrypt plaintext + compute Poly1305 tag.
    fn seal_generic(
        &self,
        dst: &[byte],
        nonce: &[byte],
        plaintext: &[byte],
        aad: &[byte],
    ) -> Vec<byte> {
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
        out
    }

    /// `openGeneric` — verify Poly1305 tag and decrypt.
    fn open_generic(
        &self,
        dst: &[byte],
        nonce: &[byte],
        ciphertext: &[byte],
        aad: &[byte],
    ) -> (Vec<byte>, error) {
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
            return (
                Vec::new(),
                errors::New("chacha20poly1305: message authentication failed"),
            );
        }

        // Decrypt
        let mut out: Vec<byte> = Vec::with_capacity(dst.len() + ciphertext.len());
        out.extend_from_slice(dst);
        let start = out.len();
        out.resize(start + ciphertext.len(), 0u8);
        let pt = &mut out[start..];
        let ct_copy: Vec<byte> = ciphertext.to_vec();
        c.XORKeyStream(pt, &ct_copy);

        (out, errors::nil)
    }
}

// Implement cipher::AEAD for ChaCha20Poly1305
impl AEADTrait for ChaCha20Poly1305 {
    fn NonceSize(&self) -> int {
        NonceSize as int
    }

    fn Overhead(&self) -> int {
        Overhead as int
    }

    fn Seal(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additional_data: slice<byte>,
    ) -> slice<byte> {
        let nonce_v = nonce.__into_vec();
        let plaintext_v = plaintext.__into_vec();
        let aad_v = additional_data.__into_vec();
        let dst_v = dst.__into_vec();

        if nonce_v.len() != NonceSize {
            panic!("chacha20poly1305: bad nonce length passed to Seal");
        }

        let out = self.seal_generic(&dst_v, &nonce_v, &plaintext_v, &aad_v);
        slice::<byte>::__from_vec(out)
    }

    fn Open(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additional_data: slice<byte>,
    ) -> (slice<byte>, error) {
        let nonce_v = nonce.__into_vec();
        let ciphertext_v = ciphertext.__into_vec();
        let aad_v = additional_data.__into_vec();
        let dst_v = dst.__into_vec();

        if nonce_v.len() != NonceSize {
            panic!("chacha20poly1305: bad nonce length passed to Open");
        }
        if ciphertext_v.len() < 16 {
            return (
                slice::<byte>::__from_vec(Vec::new()),
                errors::New("chacha20poly1305: message authentication failed"),
            );
        }

        let (out, err) = self.open_generic(&dst_v, &nonce_v, &ciphertext_v, &aad_v);
        (slice::<byte>::__from_vec(out), err)
    }
}
