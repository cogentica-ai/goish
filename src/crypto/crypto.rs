// crypto — Go's `crypto` parent package.
//
// Hash registry + Signer / Decrypter trait declarations + the standard
// hash function identifiers, ported from crypto/crypto.go of Go 1.25.5.
//
// Slim deviations:
//   * `PublicKey` / `PrivateKey` are `dyn Any`-shaped trait aliases since
//     goish lacks Go's bare `any` interface; the runtime cost is the same
//     (vtable dispatch on Equal / Public).
//   * `RegisterHash` panics on out-of-range `Hash` like Go; the registry
//     is a `SpinLock<[Option<Box<dyn Fn>>; maxHash]>` instead of Go's
//     mutable global slice. Each goish hash module can register itself
//     in its own init path. Go's `var hashes` is that slice, so it is
//     spelled `HASH_REGISTRY` here — a lock is not optional without a
//     package init phase to write it from.
//     goishlint:ignore GOISH021 hashes — renamed to HASH_REGISTRY, see above

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::Hash as HashTrait;
use crate::io;
use crate::runtime::spin::SpinLock;
use crate::strconv;
use crate::int;
use crate::types::{byte, uint};
use alloc::boxed::Box;
use core::any::Any;

// ─── Hash identifier — crypto.go:16 ──────────────────────────────────

/// `crypto.Hash` — identifies a cryptographic hash function.
///
/// Go declares `type Hash uint` at crypto.go:16 — a *defined type*, not
/// an alias, so
/// it carries `HashFunc`, `String`, `Size`, `New` and `Available` as
/// methods and satisfies [`SignerOpts`] directly. goish mirrors that with a
/// newtype; the wrapped `uint` is public because Go's conversion
/// `crypto.Hash(n)` / `uint(h)` is unrestricted.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Hash(pub uint);

// Hash constants (Go: crypto.go:69-90). Numbered starting at 1; matches
// Go's `iota`-driven enumeration.
pub const MD4: Hash = Hash(1);
pub const MD5: Hash = Hash(2);
pub const SHA1: Hash = Hash(3);
pub const SHA224: Hash = Hash(4);
pub const SHA256: Hash = Hash(5);
pub const SHA384: Hash = Hash(6);
pub const SHA512: Hash = Hash(7);
pub const MD5SHA1: Hash = Hash(8);
pub const RIPEMD160: Hash = Hash(9);
pub const SHA3_224: Hash = Hash(10);
pub const SHA3_256: Hash = Hash(11);
pub const SHA3_384: Hash = Hash(12);
pub const SHA3_512: Hash = Hash(13);
pub const SHA512_224: Hash = Hash(14);
pub const SHA512_256: Hash = Hash(15);
pub const BLAKE2s_256: Hash = Hash(16);
pub const BLAKE2b_256: Hash = Hash(17);
pub const BLAKE2b_384: Hash = Hash(18);
pub const BLAKE2b_512: Hash = Hash(19);
const maxHash: Hash = Hash(20);

// Digest sizes in bytes (Go: crypto.go:91-111).
const DIGEST_SIZES: [u8; maxHash.0 as usize] = {
    let mut t = [0u8; maxHash.0 as usize];
    t[MD4.0 as usize] = 16;
    t[MD5.0 as usize] = 16;
    t[SHA1.0 as usize] = 20;
    t[SHA224.0 as usize] = 28;
    t[SHA256.0 as usize] = 32;
    t[SHA384.0 as usize] = 48;
    t[SHA512.0 as usize] = 64;
    t[SHA512_224.0 as usize] = 28;
    t[SHA512_256.0 as usize] = 32;
    t[SHA3_224.0 as usize] = 28;
    t[SHA3_256.0 as usize] = 32;
    t[SHA3_384.0 as usize] = 48;
    t[SHA3_512.0 as usize] = 64;
    t[MD5SHA1.0 as usize] = 36;
    t[RIPEMD160.0 as usize] = 20;
    t[BLAKE2s_256.0 as usize] = 32;
    t[BLAKE2b_256.0 as usize] = 32;
    t[BLAKE2b_384.0 as usize] = 48;
    t[BLAKE2b_512.0 as usize] = 64;
    t
};

impl Hash {
    // go: sdk 1.25.5 crypto/crypto.go:19-21 Hash.HashFunc
    /// Simply returns the value of `h` so that [`Hash`] implements
    /// [`SignerOpts`].
    pub fn HashFunc(&self) -> Hash {
        return *self;
    }

    // go: sdk 1.25.5 crypto/crypto.go:23-66 Hash.String
    /// The RFC 8017 / NIST name of the hash function.
    pub fn String(&self) -> string {
        let h = *self;
        return match h {
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
                let n = strconv::Itoa(int(h.0));
                let raw_n = n.Len();
                let mut i: int = 0;
                while i < raw_n {
                    buf.push(n[i]);
                    i += 1;
                }
                string::from_bytes(&buf)
            }
        };
    }

    // go: sdk 1.25.5 crypto/crypto.go:116-121 Hash.Size
    /// Returns the length, in bytes, of a digest resulting from the given
    /// hash function. It doesn't require that the hash function in question
    /// be linked into the program.
    pub fn Size(&self) -> int {
        if self.0 > 0 && *self < maxHash {
            return int(DIGEST_SIZES[self.0 as usize]);
        }
        panic!("crypto: Size of unknown hash function");
    }
}

// ─── Hash registry — crypto.go:123 ───────────────────────────────────

type HashCtor = Box<dyn Fn() -> Box<dyn HashTrait + Send + Sync> + Send + Sync>;

/// Registry of `Hash → constructor`. Entries are populated by per-algorithm
/// modules at call time; goish has no `init()` so consumers register
/// explicitly via `RegisterHash`.
static HASH_REGISTRY: SpinLock<[Option<HashCtor>; maxHash.0 as usize]> =
    SpinLock::new([
        // 0 .. maxHash slots, all None.
        None, None, None, None, None,
        None, None, None, None, None,
        None, None, None, None, None,
        None, None, None, None, None,
    ]);

// go: sdk 1.25.5 crypto/crypto.go:145-150 RegisterHash
/// Registers a function that returns a new instance of the given hash
/// function. Go calls this from each hash package's `init`; goish has no
/// per-package init driver, so [`RegisterStandardHashes`] does it.
pub fn RegisterHash<F>(h: Hash, f: F)
where
    F: Fn() -> Box<dyn HashTrait + Send + Sync> + Send + Sync + 'static,
{
    if h >= maxHash {
        panic!("crypto: RegisterHash of unknown hash function");
    }
    let mut g = HASH_REGISTRY.lock();
    g[h.0 as usize] = Some(Box::new(f));
}

impl Hash {
    // go: sdk 1.25.5 crypto/crypto.go:127-135 Hash.New
    /// Returns a new `hash.Hash` calculating the given hash function. Panics
    /// if the hash function is not linked into the binary.
    pub fn New(&self) -> Box<dyn HashTrait + Send + Sync> {
        if self.0 > 0 && *self < maxHash {
            let g = HASH_REGISTRY.lock();
            if let Some(ref f) = g[self.0 as usize] {
                return f();
            }
        }
        panic!("crypto: requested hash function is unavailable");
    }

    // go: sdk 1.25.5 crypto/crypto.go:138-140 Hash.Available
    /// Reports whether the given hash function is linked into the binary.
    pub fn Available(&self) -> bool {
        if *self >= maxHash {
            return false;
        }
        let g = HASH_REGISTRY.lock();
        return g[self.0 as usize].is_some();
    }
}

// go: none — Go registers each hash from its own package's `init()`;
// goish has no per-package init driver, so registration is explicit.
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

// go: none — goish idiom: Go's `priv.(crypto.Signer)` is a *structural*
// assertion — the compiler already knows `*rsa.PrivateKey` has the two
// methods, so nothing has to be registered anywhere. Rust's traits are
// nominal, so `#[goish::interface]` closes the gap with a runtime
// registry (goany.rs:557), and that registry is only populated by an
// explicit `__goish_register_Signer_impl::<C>()` per `impl Signer for
// C`. Nothing was calling it, so **every** `cast!(priv, crypto::Signer)`
// missed and `x509::CreateCertificate` reported "certificate private key
// does not implement crypto.Signer" for a key that plainly does.
//
// This is `RegisterStandardHashes`'s sibling and for the same reason:
// goish has no per-package `init()` driver, so what Go does at link time
// is done here, once, from `goish::init()`.
/// Register every private-key type in goish's `crypto` tree that
/// implements [`Signer`], so that `goish::cast!(key, crypto::Signer)` on
/// an `Any`-wrapped key resolves. Idempotent.
///
/// `crypto/ecdsa`'s `PrivateKey` is absent because it does not yet
/// implement [`Signer`] in goish — Go's does. Adding it belongs to
/// `crypto/ecdsa`, not here; until then an ECDSA key cannot sign an
/// x509 certificate.
pub fn RegisterStandardSigners() {
    __goish_register_Signer_impl::<crate::crypto::rsa::PrivateKey>();
    __goish_register_Signer_impl::<crate::crypto::ed25519::PrivateKey>();
}

// ─── Signer / Decrypter trait surface — crypto.go:162-243 ────────────

/// Go: `type PublicKey any` at crypto.go:162 — opaque public key. Concrete types
/// live in `crypto/rsa`, `crypto/ecdsa`, etc. Arc-backed (not Box) so
/// the carrier is cheaply clonable — Go interface values copy by
/// reference, and `tls.Certificate` embeds a `crypto.PrivateKey` in a
/// `Clone`-able struct.
pub type PublicKey = alloc::sync::Arc<dyn Any + Send + Sync>;

/// Go: `type PrivateKey any` at crypto.go:176 — opaque private key.
pub type PrivateKey = alloc::sync::Arc<dyn Any + Send + Sync>;

/// Go: `type SignerOpts interface` at crypto.go:219 — options for
/// `Signer.Sign`.
#[goish::interface]
pub trait SignerOpts: Send + Sync {
    /// Returns the hash function used; zero indicates no hashing.
    fn HashFunc(&self) -> Hash;
}

/// Go's `func (h Hash) HashFunc() Hash` is what makes `Hash`
/// itself a `SignerOpts`, so callers write `key.Sign(rand, digest,
/// crypto.SHA256)`. goish spells the same thing now that `Hash` is a
/// defined type rather than an alias — the former `HashOpts` wrapper is
/// gone.
impl SignerOpts for Hash {
    // go: sdk 1.25.5 crypto/crypto.go:19-21 Hash.HashFunc
    fn HashFunc(&self) -> Hash {
        return *self;
    }
}

/// Go: `type Signer interface` at crypto.go:180 — an opaque private key
/// that can be used for signing operations.
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

/// Go: `type MessageSigner interface` at crypto.go:213 — a signer that
/// hashes the message itself. It embeds `Signer`, which is why the
/// attribute carries `embeds` (AGENTS.md §9a): without it both traits
/// re-declare the macro's hidden helpers and every call on
/// `dyn MessageSigner` is E0034.
#[goish::interface(embeds)]
pub trait MessageSigner: Signer {
    fn SignMessage(
        &self,
        rand: &mut dyn io::Reader,
        msg: slice<byte>,
        opts: &dyn SignerOpts,
    ) -> (slice<byte>, error);
}

// go: sdk 1.25.5 crypto/crypto.go:245-255 SignMessage
/// Signs `msg` with `signer`. If `signer` implements [`MessageSigner`],
/// `SignMessage` is called directly. Otherwise `msg` is hashed with
/// `opts.HashFunc()` and signed with [`Signer::Sign`].
///
/// Go writes the upgrade as `signer.(MessageSigner)`. `MessageSigner` is a
/// composite interface, so it has no nil sentinel and `cast!` rejects it —
/// the upgrade goes through `.As::<dyn MessageSigner + …>()` instead
/// (AGENTS.md §9a).
pub fn SignMessage(
    signer: &(dyn Signer + Send + Sync + 'static),
    rand: &mut dyn io::Reader,
    msg: slice<byte>,
    opts: &dyn SignerOpts,
) -> (slice<byte>, error) {
    use crate::goany::AsExt;

    if let Some(ms) = signer.As::<dyn MessageSigner + Send + Sync>() {
        return ms.SignMessage(rand, msg, opts);
    }
    let mut msg = msg;
    if opts.HashFunc() != Hash(0) {
        let mut h = opts.HashFunc().New();
        let _ = io::Writer::Write(&mut h, msg.clone());
        msg = HashTrait::Sum(&*h, slice::__from_vec(alloc::vec::Vec::new()));
    }
    return signer.Sign(rand, msg, opts);
}

/// Go: `type DecrypterOpts any` at crypto.go:240 — opaque option bag.
pub type DecrypterOpts = Box<dyn Any + Send + Sync>;

/// Go: `type Decrypter interface` at crypto.go:229 — an opaque private key
/// for asymmetric decryption.
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
