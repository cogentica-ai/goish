// crypto/chacha20poly1305 — module root.
//
// The port is split the way Go splits it: `chacha20poly1305.rs` for the
// exported AEAD surface, `chacha20poly1305_generic.rs` for the seal and
// open bodies. This file only re-exports, so callers keep writing
// `chacha20poly1305::New(key)`.

pub mod chacha20poly1305;
mod chacha20poly1305_generic;

pub use chacha20poly1305::{ChaCha20Poly1305, KeySize, New, NonceSize, Overhead};
