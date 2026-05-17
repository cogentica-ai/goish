// crypto — Go's `crypto` parent package.
//
// Hash registry + Signer / Decrypter trait declarations + the standard
// hash function identifiers. Line-by-line port of crypto/crypto.go
// from Go 1.25.5; submodule declarations follow.
//
// Slim deviations:
//   * `PublicKey` / `PrivateKey` are `dyn Any`-shaped trait aliases since
//     goish lacks Go's bare `any` interface; the runtime cost is the same
//     (vtable dispatch on Equal / Public).
//   * `RegisterHash` panics on out-of-range `Hash` like Go; the registry
//     is a `SpinLock<[Option<Box<dyn Fn>>; maxHash]>` instead of Go's
//     mutable global slice. Each goish hash module can register itself
//     in its own init path.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::Hash as HashTrait;
use crate::io;
use crate::runtime::spin::SpinLock;
use crate::strconv;
use crate::types::{byte, int, uint};
use alloc::boxed::Box;
use core::any::Any;

pub mod aes;
pub mod cipher;
pub mod des;
pub mod hkdf;
pub mod hmac;
pub mod internal;
pub mod md5;
pub mod pbkdf2;
pub mod rand;
pub mod rc4;
pub mod rsa;
pub mod sha1;
pub mod sha256;
pub mod sha3;
pub mod sha512;
pub mod subtle;
pub mod tls;

// ─── Hash identifier (Go: crypto.go:14) ───────────────────────────────

/// `crypto.Hash` — identifies a cryptographic hash function.
pub type Hash = uint;

// Hash constants (Go: crypto.go:69-90). Numbered starting at 1; matches
// Go's `iota`-driven enumeration.
pub const MD4: Hash = 1;
pub const MD5: Hash = 2;
pub const SHA1: Hash = 3;
pub const SHA224: Hash = 4;
pub const SHA256: Hash = 5;
pub const SHA384: Hash = 6;
pub const SHA512: Hash = 7;
pub const MD5SHA1: Hash = 8;
pub const RIPEMD160: Hash = 9;
pub const SHA3_224: Hash = 10;
pub const SHA3_256: Hash = 11;
pub const SHA3_384: Hash = 12;
pub const SHA3_512: Hash = 13;
pub const SHA512_224: Hash = 14;
pub const SHA512_256: Hash = 15;
pub const BLAKE2s_256: Hash = 16;
pub const BLAKE2b_256: Hash = 17;
pub const BLAKE2b_384: Hash = 18;
pub const BLAKE2b_512: Hash = 19;
const maxHash: Hash = 20;

// Digest sizes in bytes (Go: crypto.go:91-111).
const DIGEST_SIZES: [u8; maxHash as usize] = {
    let mut t = [0u8; maxHash as usize];
    t[MD4 as usize] = 16;
    t[MD5 as usize] = 16;
    t[SHA1 as usize] = 20;
    t[SHA224 as usize] = 28;
    t[SHA256 as usize] = 32;
    t[SHA384 as usize] = 48;
    t[SHA512 as usize] = 64;
    t[SHA512_224 as usize] = 28;
    t[SHA512_256 as usize] = 32;
    t[SHA3_224 as usize] = 28;
    t[SHA3_256 as usize] = 32;
    t[SHA3_384 as usize] = 48;
    t[SHA3_512 as usize] = 64;
    t[MD5SHA1 as usize] = 36;
    t[RIPEMD160 as usize] = 20;
    t[BLAKE2s_256 as usize] = 32;
    t[BLAKE2b_256 as usize] = 32;
    t[BLAKE2b_384 as usize] = 48;
    t[BLAKE2b_512 as usize] = 64;
    t
};

/// `crypto.HashName(h)` (helper for `Hash.String`) — RFC 8017 / NIST name.
///
/// Mirrors Go's `Hash.String` (crypto.go:23). Goish exposes it as a free
/// function since `Hash` is a type alias for `uint`.
pub fn HashName(h: Hash) -> string {
    match h {
        x if x == MD4 => string::from_static("MD4"),
        x if x == MD5 => string::from_static("MD5"),
        x if x == SHA1 => string::from_static("SHA-1"),
        x if x == SHA224 => string::from_static("SHA-224"),
        x if x == SHA256 => string::from_static("SHA-256"),
        x if x == SHA384 => string::from_static("SHA-384"),
        x if x == SHA512 => string::from_static("SHA-512"),
        x if x == MD5SHA1 => string::from_static("MD5+SHA1"),
        x if x == RIPEMD160 => string::from_static("RIPEMD-160"),
        x if x == SHA3_224 => string::from_static("SHA3-224"),
        x if x == SHA3_256 => string::from_static("SHA3-256"),
        x if x == SHA3_384 => string::from_static("SHA3-384"),
        x if x == SHA3_512 => string::from_static("SHA3-512"),
        x if x == SHA512_224 => string::from_static("SHA-512/224"),
        x if x == SHA512_256 => string::from_static("SHA-512/256"),
        x if x == BLAKE2s_256 => string::from_static("BLAKE2s-256"),
        x if x == BLAKE2b_256 => string::from_static("BLAKE2b-256"),
        x if x == BLAKE2b_384 => string::from_static("BLAKE2b-384"),
        x if x == BLAKE2b_512 => string::from_static("BLAKE2b-512"),
        _ => {
            // Go: "unknown hash value " + strconv.Itoa(int(h))
            let mut buf: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
            buf.extend_from_slice(b"unknown hash value ");
            let n = strconv::Itoa(h as int);
            let raw_n = n.Len();
            let mut i: int = 0;
            while i < raw_n {
                buf.push(n[i]);
                i += 1;
            }
            string::from_bytes(&buf)
        }
    }
}

/// `Hash.Size()` (crypto.go:116) — digest length in bytes.
pub fn HashSize(h: Hash) -> int {
    if h > 0 && h < maxHash {
        return DIGEST_SIZES[h as usize] as int;
    }
    panic!("crypto: Size of unknown hash function");
}

/// `Hash.HashFunc()` (crypto.go:18) — identity, satisfies `SignerOpts`.
pub fn HashFunc(h: Hash) -> Hash {
    h
}

// ─── Hash registry (Go: crypto.go:123) ────────────────────────────────

type HashCtor = Box<dyn Fn() -> Box<dyn HashTrait + Send + Sync> + Send + Sync>;

/// Registry of `Hash → constructor`. Entries are populated by per-algorithm
/// modules at call time; goish has no `init()` so consumers register
/// explicitly via `RegisterHash`.
static HASH_REGISTRY: SpinLock<[Option<HashCtor>; maxHash as usize]> =
    SpinLock::new([
        // 0 .. maxHash slots, all None.
        None, None, None, None, None,
        None, None, None, None, None,
        None, None, None, None, None,
        None, None, None, None, None,
    ]);

/// `crypto.RegisterHash(h, f)` (crypto.go:145).
pub fn RegisterHash<F>(h: Hash, f: F)
where
    F: Fn() -> Box<dyn HashTrait + Send + Sync> + Send + Sync + 'static,
{
    if h >= maxHash {
        panic!("crypto: RegisterHash of unknown hash function");
    }
    let mut g = HASH_REGISTRY.lock();
    g[h as usize] = Some(Box::new(f));
}

/// `Hash.New()` (crypto.go:127). Panics if the hash is not registered.
pub fn HashNew(h: Hash) -> Box<dyn HashTrait + Send + Sync> {
    if h > 0 && h < maxHash {
        let g = HASH_REGISTRY.lock();
        if let Some(ref f) = g[h as usize] {
            return f();
        }
    }
    panic!("crypto: requested hash function is unavailable");
}

/// `Hash.Available()` (crypto.go:138).
pub fn HashAvailable(h: Hash) -> bool {
    if h >= maxHash {
        return false;
    }
    let g = HASH_REGISTRY.lock();
    g[h as usize].is_some()
}

/// Register every hash algorithm shipped with goish's `crypto` tree so
/// `crypto::HashNew(h)` resolves for the standard SHAs and MD5. Call
/// once from a port's bootstrap path (or `#[goish::main]`) before the
/// first lookup. Idempotent — re-registering replaces the existing
/// constructor, which is harmless because every entry resolves to the
/// same NewHash function.
///
/// Go side: each hash subpackage's `init()` calls
/// `crypto.RegisterHash(crypto.SHA256, sha256.New)` etc. Goish has no
/// per-package init driver, so the registration has to be explicit.
pub fn RegisterStandardHashes() {
    RegisterHash(MD5, crate::crypto::md5::NewHash);
    RegisterHash(SHA1, crate::crypto::sha1::NewHash);
    RegisterHash(SHA224, crate::crypto::sha256::NewHash224);
    RegisterHash(SHA256, crate::crypto::sha256::NewHash);
    RegisterHash(SHA384, crate::crypto::sha512::NewHash384);
    RegisterHash(SHA512, crate::crypto::sha512::NewHash);
    RegisterHash(SHA512_224, crate::crypto::sha512::NewHash512_224);
    RegisterHash(SHA512_256, crate::crypto::sha512::NewHash512_256);
    RegisterHash(SHA3_224, crate::crypto::sha3::NewHash224);
    RegisterHash(SHA3_256, crate::crypto::sha3::NewHash256);
    RegisterHash(SHA3_384, crate::crypto::sha3::NewHash384);
    RegisterHash(SHA3_512, crate::crypto::sha3::NewHash512);
}

// ─── Signer / Decrypter trait surface (Go: crypto.go:152-240) ─────────

/// `crypto.PublicKey` (crypto.go:152) — opaque public key. Concrete types
/// live in `crypto/rsa`, `crypto/ecdsa`, etc.
pub type PublicKey = Box<dyn Any + Send + Sync>;

/// `crypto.PrivateKey` (crypto.go:164) — opaque private key.
pub type PrivateKey = Box<dyn Any + Send + Sync>;

/// `crypto.SignerOpts` (crypto.go:218) — options for `Signer.Sign`.
#[goish::interface]
pub trait SignerOpts: Send + Sync {
    /// Returns the hash function used; zero indicates no hashing.
    fn HashFunc(&self) -> Hash;
}

// `Hash` is a type alias for `uint`, so we can't `impl SignerOpts for Hash`
// without a newtype. Goish callers pass `&HashOpts(h)` instead.
/// Newtype wrapper so a bare `Hash` can satisfy `SignerOpts`. Mirrors Go's
/// `func (h Hash) HashFunc() Hash` (crypto.go:18) where `Hash` itself is
/// the receiver.
pub struct HashOpts(pub Hash);

impl SignerOpts for HashOpts {
    fn HashFunc(&self) -> Hash {
        self.0
    }
}

/// `crypto.Signer` (crypto.go:180) — opaque signing key.
#[goish::interface]
pub trait Signer: Send + Sync {
    fn Public(&self) -> PublicKey;
    fn Sign(
        &self,
        rand: &mut dyn io::Reader,
        digest: slice<byte>,
        opts: &dyn SignerOpts,
    ) -> (slice<byte>, error);
}

/// `crypto.MessageSigner` (crypto.go:213) — signer that can hash internally.
pub trait MessageSigner: Signer {
    fn SignMessage(
        &self,
        rand: &mut dyn io::Reader,
        msg: slice<byte>,
        opts: &dyn SignerOpts,
    ) -> (slice<byte>, error);
}

/// `crypto.DecrypterOpts` (crypto.go:240) — opaque option bag.
pub type DecrypterOpts = Box<dyn Any + Send + Sync>;

/// `crypto.Decrypter` (crypto.go:229) — opaque private key for asymmetric
/// decryption.
#[goish::interface]
pub trait Decrypter: Send + Sync {
    fn Public(&self) -> PublicKey;
    fn Decrypt(
        &self,
        rand: &mut dyn io::Reader,
        msg: slice<byte>,
        opts: Option<&DecrypterOpts>,
    ) -> (slice<byte>, error);
}
