// go: file crypto/internal/fips140/aes/aes.go decls: blockExpanded.roundKeysSize, KeySizeError.Error, New, newOutlined, newBlockExpanded, Block.BlockSize, Block.Encrypt, Block.Decrypt, EncryptBlockInternal, zeroBlock
//
// crypto/internal/fips140/aes — AES (FIPS 197). The public crypto/aes
// package is a thin wrapper over this.
//
// Deviations from aes[go] @ Go 1.25.5:
//
//   * `New` returns `(Option<Block>, error)` rather than `(*Block,
//     error)`; goish has no nil pointer for a by-value struct.
//   * `newOutlined` exists to keep `New` inlineable in Go by moving the
//     allocation to the caller's frame. goish returns by value, so there
//     is nothing to outline — it is kept for shape and because the key
//     size check lives there.
//   * `fips140.RecordNonApproved()` calls in Encrypt/Decrypt are dropped:
//     goish's fips140 stub has no service indicator, so they are no-ops.
//   * cast[go]'s `init` — `fips140.CAST("AES-CBC", …)` — is not ported:
//     goish's fips140 stub has no CAST registry. Port it with that
//     registry; examples/aes_smoke.rs covers the same vectors.

#![allow(non_snake_case, non_upper_case_globals)]
#![allow(non_camel_case_types)] // Go names (blockExpanded, block)

use crate::crypto::internal::fips140::alias;
use crate::errors::{ErrorTrait, Wrap};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strconv;
use crate::types::{byte, int};

use super::aes_noasm::{decryptBlock, encryptBlock, newBlock};

/// `aes.BlockSize` — the AES block size in bytes.
pub const BlockSize: int = 16;

// Go: aes.go:18
//   type Block struct {
//       block
//   }
/// `aes.Block` — an instance of AES using a particular key. Safe for
/// concurrent use.
///
/// Go embeds the per-architecture `block` type, which on every target but
/// s390x is itself just `blockExpanded`. goish is single-target, so the
/// two layers collapse into one struct; `block` stays as a type alias in
/// aes_noasm[go]'s port so the file boundary still matches.
#[derive(Clone)]
pub struct Block {
    pub(crate) rounds: int,
    // Round keys, where only the first (rounds + 1) × (128 ÷ 32) words
    // are used.
    pub(crate) enc: [u32; 60],
    pub(crate) dec: [u32; 60],
}

/// `aes.blockExpanded` — the block type used for all architectures except
/// s390x, which feeds the raw key directly to its instructions. Aliased to
/// [`Block`]: see the note there.
pub(crate) type blockExpanded = Block;

// AES-128 has 128-bit keys, 10 rounds, and uses 11 128-bit round keys
// (11×128÷32 = 44 32-bit words).
//
// AES-192 has 192-bit keys, 12 rounds, and uses 13 128-bit round keys
// (13×128÷32 = 52 32-bit words).
//
// AES-256 has 256-bit keys, 14 rounds, and uses 15 128-bit round keys
// (15×128÷32 = 60 32-bit words).

pub(crate) const aes128KeySize: int = 16;
pub(crate) const aes192KeySize: int = 24;
pub(crate) const aes256KeySize: int = 32;

pub(crate) const aes128Rounds: int = 10;
pub(crate) const aes192Rounds: int = 12;
pub(crate) const aes256Rounds: int = 14;

impl Block {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/aes.go:50-52 roundKeysSize
    /// Go: `func (b *blockExpanded) roundKeysSize() int` — the number of
    /// `uint32` of `b.enc` or `b.dec` that are used.
    pub(crate) fn roundKeysSize(&self) -> int {
        // Go: return (b.rounds + 1) * (128 / 32)
        return (self.rounds + 1) * (128 / 32);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/aes.go:88-88 BlockSize
    /// Go: `func (c *Block) BlockSize() int { return BlockSize }`
    pub fn BlockSize(&self) -> int {
        return BlockSize;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/aes.go:90-104 Encrypt
    /// `(*Block).Encrypt(dst, src)` — encrypt one block from `src` into
    /// `dst`.
    pub fn Encrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        // Go: fips140.RecordNonApproved() — AES-ECB is not approved in
        // FIPS 140-3 mode. goish's fips140 stub records nothing.
        // Go: if len(src) < BlockSize { panic("crypto/aes: input not full block") }
        if src.Len() < BlockSize {
            panic!("crypto/aes: input not full block");
        }
        // Go: if len(dst) < BlockSize { panic("crypto/aes: output not full block") }
        if dst.Len() < BlockSize {
            panic!("crypto/aes: output not full block");
        }
        // Go: if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) { … }
        if alias::InexactOverlap(dst, &src) {
            panic!("crypto/aes: invalid buffer overlap");
        }
        // Go: encryptBlock(c, dst, src)
        encryptBlock(self, dst, &src);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/aes.go:106-120 Decrypt
    /// `(*Block).Decrypt(dst, src)` — decrypt one block from `src` into
    /// `dst`.
    pub fn Decrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        // Go: fips140.RecordNonApproved() — see Encrypt.
        // Go: if len(src) < BlockSize { panic("crypto/aes: input not full block") }
        if src.Len() < BlockSize {
            panic!("crypto/aes: input not full block");
        }
        // Go: if len(dst) < BlockSize { panic("crypto/aes: output not full block") }
        if dst.Len() < BlockSize {
            panic!("crypto/aes: output not full block");
        }
        // Go: if alias.InexactOverlap(dst[:BlockSize], src[:BlockSize]) { … }
        if alias::InexactOverlap(dst, &src) {
            panic!("crypto/aes: invalid buffer overlap");
        }
        // Go: decryptBlock(c, dst, src)
        decryptBlock(self, dst, &src);
    }
}

// Go: aes.go:54
//   type KeySizeError int
/// `aes.KeySizeError` — returned by `New` for a key that is not 16, 24 or
/// 32 bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeySizeError(pub int);

impl ErrorTrait for KeySizeError {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/aes.go:56-58 KeySizeError.Error
    fn Error(&self) -> string {
        // Go: return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
        return string::from_static("crypto/aes: invalid key size ") + strconv::Itoa(self.0);
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes.go:63-66 New
/// `aes.New(key)` — a new AES `Block`. `key` must be 16, 24 or 32 bytes,
/// selecting AES-128, AES-192 or AES-256.
pub fn New(key: slice<byte>) -> (Option<Block>, crate::error) {
    // Go: return newOutlined(&Block{}, key)
    //
    // Go passes a zero Block in so the allocation happens on the parent
    // stack; goish returns by value, so the parameter is dropped.
    return newOutlined(key);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes.go:71-78 newOutlined
/// Go: `func newOutlined(b *Block, key []byte) (*Block, error)` — marked
/// `go:noinline` there so `New` stays inlineable. goish keeps it for the
/// key-size check; there is no allocation to outline.
fn newOutlined(key: slice<byte>) -> (Option<Block>, crate::error) {
    // Go: switch len(key) { case aes128KeySize, aes192KeySize, aes256KeySize:
    //     default: return nil, KeySizeError(len(key)) }
    let k = key.Len();
    if k != aes128KeySize && k != aes192KeySize && k != aes256KeySize {
        return (None, Wrap(KeySizeError(k)));
    }
    // Go: return newBlock(b, key), nil
    return (Some(newBlock(key)), crate::errors::nil);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes.go:80-86 newBlockExpanded
/// Go: `func newBlockExpanded(c *blockExpanded, key []byte)` — set the
/// round count from the key length and run the generic key schedule.
pub(crate) fn newBlockExpanded(c: &mut blockExpanded, key: &slice<byte>) {
    // Go: switch len(key) { case aes128KeySize: c.rounds = aes128Rounds; … }
    match key.Len() {
        v if v == aes128KeySize => c.rounds = aes128Rounds,
        v if v == aes192KeySize => c.rounds = aes192Rounds,
        v if v == aes256KeySize => c.rounds = aes256Rounds,
        _ => {}
    }
    // Go: expandKeyGeneric(c, key)
    super::aes_generic::expandKeyGeneric(c, key);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/aes.go:125-127 EncryptBlockInternal
/// `aes.EncryptBlockInternal(c, dst, src)` — apply the AES encryption
/// function to one block. Internal, meant only for the gcm package.
pub fn EncryptBlockInternal(c: &Block, dst: &mut slice<byte>, src: slice<byte>) {
    // Go: encryptBlock(c, dst, src)
    encryptBlock(c, dst, &src);
}

// go: none — goish idiom: Go builds a zero `Block` at the call site with
// the composite literal `&Block{}`; Rust needs every field named.
pub(crate) fn zeroBlock() -> Block {
    return Block {
        rounds: 0,
        enc: [0; 60],
        dec: [0; 60],
    };
}
