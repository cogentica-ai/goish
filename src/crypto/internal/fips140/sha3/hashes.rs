// go: file crypto/internal/fips140/sha3/hashes.go decls: New224, New256, New384, New512, NewLegacyKeccak256, NewLegacyKeccak512
//
// The fixed-output-length SHA-3 constructors, plus the two legacy
// non-standard Keccak variants.
//
// Deviation: Go's TODO to `crypto.RegisterHash(crypto.SHA3_224, …)` is
// not ported — goish has no crypto.Hash registry to register into.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::types::byte;

use super::sha3::{newDigest, Digest};

// ─── Domain separators and rates (hashes[go]:34-46) ───────────────────

/// Go: `dsbyteSHA3 = 0b00000110`
pub(crate) const dsbyteSHA3: byte = 0b00000110;
/// Go: `dsbyteKeccak = 0b00000001`
pub(crate) const dsbyteKeccak: byte = 0b00000001;
/// Go: `dsbyteShake = 0b00011111`
pub(crate) const dsbyteShake: byte = 0b00011111;
/// Go: `dsbyteCShake = 0b00000100`
pub(crate) const dsbyteCShake: byte = 0b00000100;

// rateK[c] is the rate in bytes for Keccak[c] where c is the capacity in
// bits. The sponge is 1600 bits, so the rate is 1600 - c bits.
pub(crate) const rateK256: usize = (1600 - 256) / 8;
pub(crate) const rateK448: usize = (1600 - 448) / 8;
pub(crate) const rateK512: usize = (1600 - 512) / 8;
pub(crate) const rateK768: usize = (1600 - 768) / 8;
pub(crate) const rateK1024: usize = (1600 - 1024) / 8;

// go: sdk 1.25.5 crypto/internal/fips140/sha3/hashes.go:8-10 New224
/// `sha3.New224()` — a new Digest computing the SHA3-224 hash.
pub fn New224() -> Digest {
    // Go: return &Digest{rate: rateK448, outputLen: 28, dsbyte: dsbyteSHA3}
    return newDigest(rateK448, 28, dsbyteSHA3);
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/hashes.go:13-15 New256
/// `sha3.New256()` — a new Digest computing the SHA3-256 hash.
pub fn New256() -> Digest {
    return newDigest(rateK512, 32, dsbyteSHA3);
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/hashes.go:18-20 New384
/// `sha3.New384()` — a new Digest computing the SHA3-384 hash.
pub fn New384() -> Digest {
    return newDigest(rateK768, 48, dsbyteSHA3);
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/hashes.go:23-25 New512
/// `sha3.New512()` — a new Digest computing the SHA3-512 hash.
pub fn New512() -> Digest {
    return newDigest(rateK1024, 64, dsbyteSHA3);
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/hashes.go:50-52 NewLegacyKeccak256
/// `sha3.NewLegacyKeccak256()` — a new Digest computing the legacy,
/// non-standard Keccak-256 hash.
pub fn NewLegacyKeccak256() -> Digest {
    return newDigest(rateK512, 32, dsbyteKeccak);
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/hashes.go:56-58 NewLegacyKeccak512
/// `sha3.NewLegacyKeccak512()` — a new Digest computing the legacy,
/// non-standard Keccak-512 hash.
pub fn NewLegacyKeccak512() -> Digest {
    return newDigest(rateK1024, 64, dsbyteKeccak);
}
