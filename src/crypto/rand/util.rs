// go: file crypto/rand/util.go decls: Prime, Int
//
// Deviations from util[go] @ Go 1.25.5:
//
//   * `*big.Int` returns become owned `big::Int`, the spelling
//     `crypto/rsa` already uses for Go's `*big.Int` fields. Go's `nil`
//     error return therefore becomes the zero `big::Int`; callers must
//     check the error, which is what Go's contract already requires.
//   * `n.Sub(max, n.SetUint64(1))` chains a `*big.Int` through its own
//     mutation — `SetUint64` returns the receiver, which `Sub` then
//     reads as its second operand. Rust cannot alias `&mut n` and `&n`
//     in one call, so the intermediate is materialised into `one`.
//   * `for i := range bytes` shapes and `bytes[0] &= …` stay literal;
//     only the `1<<b` arithmetic is spelled with goish's fixed-width
//     types instead of Go's untyped constants.

#![allow(non_snake_case)]

use crate::crypto::internal::fips140only;
use crate::crypto::internal::randutil;
use crate::error;
use crate::errors;
use crate::io;
use crate::math::big;
use crate::{byte, int, uint, uint8};

// go: sdk 1.25.5 crypto/rand/util.go:15-63 Prime
// goishlint:ignore GOISH023 - the candidate `loop` is diverging; every
// exit is an explicit `return`, exactly as in Go's `for { … }`.
/// Return a number of the given bit length that is prime with high
/// probability. Prime will return error for any error returned by
/// rand.Read or if `bits < 2`.
pub fn Prime(rand: &mut (dyn io::Reader + Send + Sync + 'static), bits: int) -> (big::Int, error) {
    // Go: if fips140only.Enabled { return nil, errors.New(…) }
    if fips140only::Enabled {
        return (
            big::Int::new(),
            errors::New("crypto/rand: use of Prime is not allowed in FIPS 140-only mode"),
        );
    }
    // Go: if bits < 2 { return nil, errors.New(…) }
    if bits < 2 {
        return (
            big::Int::new(),
            errors::New("crypto/rand: prime size must be at least 2-bit"),
        );
    }

    randutil::MaybeReadByte(rand);

    // Go: b := uint(bits % 8); if b == 0 { b = 8 }
    let mut b: uint = uint(bits % 8);
    if b == 0 {
        b = 8;
    }

    // Go: bytes := make([]byte, (bits+7)/8); p := new(big.Int)
    let mut bytes = crate::make!([]byte, (bits + 7) / 8);
    let n = bytes.Len();
    let mut p = big::Int::new();

    loop {
        // Go: if _, err := io.ReadFull(rand, bytes); err != nil { return nil, err }
        let (_, err) = io::ReadFull(rand, &mut bytes);
        if !err.IsNil() {
            return (big::Int::new(), err);
        }

        // Clear bits in the first byte to make sure the candidate has a size <= bits.
        bytes[0] &= uint8(((1i64 << b) - 1) & 0xff);
        // Don't let the value be too small, i.e, set the most significant two bits.
        // Setting the top two bits, rather than just the top bit,
        // means that when two of these values are multiplied together,
        // the result isn't ever one bit short.
        if b >= 2 {
            bytes[0] |= 3u8 << (b - 2);
        } else {
            // Here b==1, because b cannot be zero.
            bytes[0] |= 1;
            if n > 1 {
                bytes[1] |= 0x80;
            }
        }
        // Make the value odd since an even number this large certainly isn't prime.
        bytes[n - 1] |= 1;

        // Go: p.SetBytes(bytes); if p.ProbablyPrime(20) { return p, nil }
        p.SetBytes(bytes.clone());
        if p.ProbablyPrime(20) {
            return (p, crate::nil.into());
        }
    }
}

// go: sdk 1.25.5 crypto/rand/util.go:65-104 Int
// goishlint:ignore GOISH023 - the retry `loop` is diverging; every exit
// is an explicit `return`, exactly as in Go's `for { … }`.
/// Return a uniform random value in `[0, max)`. It panics if `max <= 0`,
/// and returns an error if rand.Read returns one.
pub fn Int(
    rand: &mut (dyn io::Reader + Send + Sync + 'static),
    max: &big::Int,
) -> (big::Int, error) {
    // Go: if max.Sign() <= 0 { panic("crypto/rand: argument to Int is <= 0") }
    if max.Sign() <= 0 {
        panic!("crypto/rand: argument to Int is <= 0");
    }
    // Go: n = new(big.Int); n.Sub(max, n.SetUint64(1))
    let mut n = big::Int::new();
    n.SetUint64(1);
    let one = n.clone();
    n.Sub(max, &one);
    // bitLen is the maximum bit length needed to encode a value < max.
    let bitLen = n.BitLen();
    if bitLen == 0 {
        // the only valid result is 0
        return (n, crate::nil.into());
    }
    // k is the maximum byte length needed to encode a value < max.
    let k = (bitLen + 7) / 8;
    // b is the number of bits in the most significant byte of max-1.
    let mut b: uint = uint(bitLen % 8);
    if b == 0 {
        b = 8;
    }

    // Go: bytes := make([]byte, k)
    let mut bytes = crate::make!([]byte, k);

    loop {
        // Go: _, err = io.ReadFull(rand, bytes); if err != nil { return nil, err }
        let (_, err) = io::ReadFull(rand, &mut bytes);
        if !err.IsNil() {
            return (big::Int::new(), err);
        }

        // Clear bits in the first byte to increase the probability
        // that the candidate is < max.
        bytes[0] &= uint8(((1i64 << b) - 1) & 0xff);

        // Go: n.SetBytes(bytes); if n.Cmp(max) < 0 { return }
        n.SetBytes(bytes.clone());
        if n.Cmp(max) < 0 {
            return (n, crate::nil.into());
        }
    }
}
