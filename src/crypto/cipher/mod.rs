// crypto/cipher — block cipher mode interfaces.
//
// Reference: /share/go/src/crypto/cipher/cipher.go (99 LOC, 4 ifaces)
//
// v1 ships only the trait declarations, mirroring `encoding/encoding.go`
// in shape: pure interface surface that future cipher modes (CBC, CTR,
// CFB, OFB, GCM) will implement once the underlying block ciphers
// (AES, etc.) land. Goish types that already embed a cipher
// (`hmac` / `subtle` etc.) ship inherent methods today; the traits exist
// so user code can write trait-bound generics
// (`fn enc<B: cipher::Block>(b: B)`) and so future mode-of-operation
// code can demand a `Block` without coupling to a concrete impl.
//
// Slim deviations from Go (documented):
//
//   - `Encrypt` / `Decrypt` / `XORKeyStream` / `CryptBlocks` take
//     `&mut slice<byte>` for `dst` to satisfy Rust's mutability rule;
//     this matches the goish `io::Reader::Read(&mut p)` precedent.
//
//   - `Seal` / `Open` return `slice<byte>` by value (and an `error` for
//     `Open`). Go's signature returns the appended slice; goish
//     mirrors this — the `dst` argument is passed by value (consumed)
//     and the new slice is returned, exactly like
//     `encoding::BinaryAppender::AppendBinary`.

#![allow(non_snake_case)]

use crate::error;
use crate::goslice::slice;
use crate::types::{byte, int};

// Go: cipher.go:15
//   type Block interface {
//       BlockSize() int
//       Encrypt(dst, src []byte)
//       Decrypt(dst, src []byte)
//   }
/// `cipher.Block` — an implementation of a block cipher using a given
/// key. Provides the capability to encrypt or decrypt individual
/// blocks. Mode implementations (CBC, CTR, CFB, OFB, GCM) extend that
/// capability to streams of blocks.
#[goish::interface]
pub trait Block {
    /// Returns the cipher's block size.
    fn BlockSize(&self) -> int;

    /// Encrypts the first block in `src` into `dst`.
    /// `dst` and `src` must overlap entirely or not at all.
    fn Encrypt(&self, dst: &mut slice<byte>, src: slice<byte>);

    /// Decrypts the first block in `src` into `dst`.
    /// `dst` and `src` must overlap entirely or not at all.
    fn Decrypt(&self, dst: &mut slice<byte>, src: slice<byte>);
}

// Go: cipher.go:29
//   type Stream interface {
//       XORKeyStream(dst, src []byte)
//   }
/// `cipher.Stream` — a stream cipher.
///
/// `XORKeyStream` XORs each byte in the given slice with a byte from
/// the cipher's key stream. `dst` and `src` must overlap entirely or
/// not at all.
///
/// If `len(dst) < len(src)`, `XORKeyStream` should panic. It is
/// acceptable to pass a `dst` bigger than `src`; in that case, only
/// `dst[..src.Len()]` is updated.
///
/// Multiple calls to `XORKeyStream` behave as if the concatenation of
/// the `src` buffers was passed in a single run. The stream maintains
/// state and does not reset at each call.
#[goish::interface]
pub trait Stream {
    fn XORKeyStream(&mut self, dst: &mut slice<byte>, src: slice<byte>);
}

// Go: cipher.go:45
//   type BlockMode interface {
//       BlockSize() int
//       CryptBlocks(dst, src []byte)
//   }
/// `cipher.BlockMode` — a block cipher running in a block-based mode
/// (CBC, ECB etc).
///
/// `CryptBlocks` encrypts or decrypts a number of blocks. The length
/// of `src` must be a multiple of the block size. `dst` and `src` must
/// overlap entirely or not at all.
///
/// If `len(dst) < len(src)`, `CryptBlocks` should panic. It is
/// acceptable to pass a `dst` bigger than `src`; in that case, only
/// `dst[..src.Len()]` is updated.
///
/// Multiple calls to `CryptBlocks` behave as if the concatenation of
/// the `src` buffers was passed in a single run. The mode maintains
/// state and does not reset at each call.
#[goish::interface]
pub trait BlockMode {
    fn BlockSize(&self) -> int;
    fn CryptBlocks(&mut self, dst: &mut slice<byte>, src: slice<byte>);
}

// Go: cipher.go:66
//   type AEAD interface {
//       NonceSize() int
//       Overhead() int
//       Seal(dst, nonce, plaintext, additionalData []byte) []byte
//       Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
//   }
/// `cipher.AEAD` — a cipher mode providing authenticated encryption
/// with associated data. See
/// <https://en.wikipedia.org/wiki/Authenticated_encryption>.
#[goish::interface]
pub trait AEAD {
    /// Returns the size of the nonce that must be passed to `Seal`
    /// and `Open`.
    fn NonceSize(&self) -> int;

    /// Returns the maximum difference between the lengths of a
    /// plaintext and its ciphertext.
    fn Overhead(&self) -> int;

    /// `Seal` encrypts and authenticates `plaintext`, authenticates
    /// the additional data and appends the result to `dst`, returning
    /// the updated slice. The nonce must be `NonceSize()` bytes long
    /// and unique for all time, for a given key.
    ///
    /// To reuse `plaintext`'s storage for the encrypted output, use
    /// `plaintext[..0]` as `dst`. Otherwise, the remaining capacity of
    /// `dst` must not overlap `plaintext`. `dst` and `additionalData`
    /// may not overlap.
    fn Seal(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additionalData: slice<byte>,
    ) -> slice<byte>;

    /// `Open` decrypts and authenticates `ciphertext`, authenticates
    /// the additional data and, if successful, appends the resulting
    /// plaintext to `dst`, returning the updated slice. The nonce
    /// must be `NonceSize()` bytes long and both it and the
    /// additional data must match the value passed to `Seal`.
    ///
    /// To reuse `ciphertext`'s storage for the decrypted output, use
    /// `ciphertext[..0]` as `dst`. Otherwise, the remaining capacity
    /// of `dst` must not overlap `ciphertext`. `dst` and
    /// `additionalData` may not overlap.
    ///
    /// Even if the function fails, the contents of `dst`, up to its
    /// capacity, may be overwritten.
    fn Open(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additionalData: slice<byte>,
    ) -> (slice<byte>, error);
}

// ─── Stream wrappers (io.go) ──────────────────────────────────────────
//
// Submodule that pairs `Stream` with `io::Reader` / `io::Writer`. Public
// surface is re-exported here so users write `cipher::StreamReader` and
// `cipher::StreamWriter` exactly as in Go.

mod cbc;
mod cfb;
mod ctr;
mod gcm;
mod io;
mod ofb;

pub use self::cbc::{
    CBCDecrypter, CBCEncrypter, NewCBCDecrypter, NewCBCEncrypter,
};
pub use self::cfb::{NewCFBDecrypter, NewCFBEncrypter, CFB};
pub use self::ctr::{NewCTR, CTR};
pub use self::gcm::{
    gcmWithRandomNonce, NewGCM, NewGCMWithNonceSize, NewGCMWithRandomNonce, NewGCMWithTagSize,
    GCM,
};
pub use self::io::{StreamReader, StreamWriter};
pub use self::ofb::{NewOFB, OFB};
