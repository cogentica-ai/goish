// go: file crypto/aes/aes.go decls: KeySizeError.Error, NewCipher, BlockSize, Encrypt, Decrypt
//
// Package aes implements AES encryption (formerly Rijndael), as defined
// in U.S. Federal Information Processing Standards Publication 197.
// Go 1.25 makes this a thin wrapper over crypto/internal/fips140/aes;
// goish follows.
//
// The AES operations in this package are not implemented using
// constant-time algorithms. An exception is when running on systems with
// enabled hardware support for AES that makes these operations
// constant-time — on amd64 that is AES-NI, which goish does not yet use
// (see CRYPTO_PORT.md "Assembly"). Until it does, treat every operation
// here as variable-time.
//
// Deviation: no boring branch (cgo is out of scope).

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::cipher::Block as BlockTrait;
use crate::crypto::internal::fips140::aes as fips;
use crate::errors::{error, ErrorTrait, Wrap};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strconv;
use crate::types::{byte, int};

pub use fips::Block;

/// `aes.BlockSize` — the AES block size in bytes.
pub const BlockSize: int = 16;

// Go: aes.go:26
//   type KeySizeError int
/// `aes.KeySizeError` — returned by `NewCipher` for a key that is not 16,
/// 24 or 32 bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeySizeError(pub int);

impl ErrorTrait for KeySizeError {
    // go: sdk 1.25.5 crypto/aes/aes.go:28-30 KeySizeError.Error
    fn Error(&self) -> string {
        // Go: return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
        return string::from_static("crypto/aes: invalid key size ") + strconv::Itoa(self.0);
    }
}

// go: sdk 1.25.5 crypto/aes/aes.go:36-47 NewCipher
/// `aes.NewCipher(key)` — a new `cipher.Block`. `key` must be the AES
/// key: 16, 24 or 32 bytes, selecting AES-128, AES-192 or AES-256.
///
/// Goish returns `(Option<Block>, error)` rather than Go's
/// `(cipher.Block, error)` interface value; `Block` implements the
/// `crypto::cipher::Block` trait, so it can be used wherever the
/// interface is wanted.
pub fn NewCipher(key: slice<byte>) -> (Option<Block>, error) {
    // Go: k := len(key)
    let k = key.Len();
    // Go: switch k { default: return nil, KeySizeError(k); case 16, 24, 32: break }
    match k {
        16 | 24 | 32 => {}
        _ => return (None, Wrap(KeySizeError(k))),
    }
    // Go: return aes.New(key)
    return fips::New(key);
}

// ─── crypto/cipher.Block trait impl ───────────────────────────────────
//
// Go's `*aes.Block` satisfies `cipher.Block` structurally. goish's
// interfaces are nominal, so the impl is spelled out here — in the public
// package, because `crypto::cipher` is the package that declares the
// trait and the fips140 tree does not import it.

impl BlockTrait for Block {
    // go: none — goish idiom: Go's *aes.Block satisfies cipher.Block
    // structurally; goish's interfaces are nominal, so each method is an
    // explicit forwarder to the inherent one on fips140/aes.Block.
    fn BlockSize(&self) -> int {
        return Block::BlockSize(self);
    }

    // go: none — goish idiom: Go's *aes.Block satisfies cipher.Block
    // structurally; goish's interfaces are nominal, so each method is an
    // explicit forwarder to the inherent one on fips140/aes.Block.
    fn Encrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        Block::Encrypt(self, dst, src);
    }

    // go: none — goish idiom: Go's *aes.Block satisfies cipher.Block
    // structurally; goish's interfaces are nominal, so each method is an
    // explicit forwarder to the inherent one on fips140/aes.Block.
    fn Decrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        Block::Decrypt(self, dst, src);
    }

    // go: none — goish idiom: the hidden Any-view hook every
    // `#[goish::interface]` impl must override for `cast!` to see the
    // concrete type. Go spells the same thing as the type assertion
    // `cipher.(*aes.Block)`, which crypto/cipher.NewGCMWithRandomNonce
    // performs on its argument.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }

    // go: none — goish idiom: see __goish_as_dyn_any above.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}
