// go: file crypto/internal/fips140/sha3/sha3_noasm.go decls: keccakF1600, Digest.write, Digest.read, Digest.sum
//
// The SHA-3 dispatch points. Go builds this file under
// `(!amd64 && !arm64 && !s390x) || purego`; sha3_amd64[go] substitutes a
// `keccakF1600` that uses the AVX-512 assembly when available, and s390x
// replaces write/read/sum wholesale with its KIMD/KLMD instructions.
//
// goish has only the generic path so far; the assembly port replaces
// `keccakF1600`'s body here and leaves every caller untouched.

#![allow(non_snake_case)]

use crate::errors::error;
use crate::goslice::slice;
use crate::types::{byte, int};

use super::keccakf::keccakF1600Generic;
use super::sha3::{Digest, STATE_BYTES};

// go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3_noasm.go:9-11 keccakF1600
/// Go: `func keccakF1600(a *[200]byte) { keccakF1600Generic(a) }`
pub(crate) fn keccakF1600(a: &mut [byte; STATE_BYTES]) {
    // Go: keccakF1600Generic(a)
    keccakF1600Generic(a);
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3_noasm.go:13-15 Digest.write
/// Go: `func (d *Digest) write(p []byte) (n int, err error)`
pub(crate) fn write(d: &mut Digest, p: slice<byte>) -> (int, error) {
    // Go: return d.writeGeneric(p)
    return d.writeGeneric(p);
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3_noasm.go:16-18 Digest.read
/// Go: `func (d *Digest) read(out []byte) (n int, err error)`
pub(crate) fn read(d: &mut Digest, out: &mut [byte]) -> usize {
    // Go: return d.readGeneric(out)
    return d.readGeneric(out);
}

// go: sdk 1.25.5 crypto/internal/fips140/sha3/sha3_noasm.go:19-21 Digest.sum
/// Go: `func (d *Digest) sum(b []byte) []byte`
pub(crate) fn sum(d: &Digest, b: slice<byte>) -> slice<byte> {
    // Go: return d.sumGeneric(b)
    return d.sumGeneric(b);
}
