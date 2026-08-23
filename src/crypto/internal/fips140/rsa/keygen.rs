// go: file crypto/internal/fips140/rsa/keygen.go decls: GenerateKey, totient, randomPrime, isPrime, millerRabinSetup, millerRabinIteration
//
// RSA key generation — FIPS 186-5, Appendix A.1.3.
//
// Deviations from keygen[go] @ Go 1.25.5:
//
//   * `drbg.ReadWithReader` / `drbg.Read` are the `read_with_reader` /
//     `drbg_read` shims in rsa.rs (no goish `fips140/drbg` package yet).
//   * Go's `primes` is a `var []uint`; goish spells it `static PRIMES:
//     [uint; 255]`, same values, same order.
//   * `millerRabin.m` is a `Vec<byte>` scratch buffer, not a
//     `slice<byte>`: it is module-private state, never a Go-API type.

extern crate alloc;

use super::pkcs1v15::{signPKCS1v15, verifyPKCS1v15};
use super::rsa::{
    drbg_read, newPrivateKey, nil_bytes, read_with_reader, zero_modulus, zero_private_key,
    PrivateKey,
};
use crate::crypto::internal::fips140;
use crate::crypto::internal::fips140::bigmod::{Modulus, Nat};
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int, uint};
use alloc::vec::Vec;

// go: sdk 1.25.5 crypto/internal/fips140/rsa/keygen.go:17-131 GenerateKey
// goishlint:ignore GOISH023 - the retry `loop` is diverging; every exit
// is an explicit `return`, exactly as in Go's `for { … }`.
/// `GenerateKey` generates a new RSA key pair of the given bit size.
/// `bits` must be at least 32.
pub fn GenerateKey(rand: &mut dyn io::Reader, bits: int) -> (PrivateKey, error) {
    if bits < 32 {
        return (zero_private_key(), errors::New("rsa: key too small"));
    }
    fips140::RecordApproved();
    if bits < 2048 || bits % 2 == 1 {
        fips140::RecordNonApproved();
    }

    loop {
        let (p, err) = randomPrime(rand, (bits + 1) / 2);
        if !err.IsNil() {
            return (zero_private_key(), err);
        }
        let (q, err) = randomPrime(rand, bits / 2);
        if !err.IsNil() {
            return (zero_private_key(), err);
        }

        let (P, err) = Modulus::NewModulus(p.clone());
        if !err.IsNil() {
            return (zero_private_key(), err);
        }
        let (Q, err) = Modulus::NewModulus(q.clone());
        if !err.IsNil() {
            return (zero_private_key(), err);
        }

        {
            let mut qExp = Q.Nat();
            qExp.ExpandFor(&P);
            if qExp.Equal(&P.Nat()) == 1 {
                return (
                    zero_private_key(),
                    errors::New("rsa: generated p == q, random source is broken"),
                );
            }
        }

        let (N, err) = Modulus::NewModulusProduct(p.clone(), q.clone());
        if !err.IsNil() {
            return (zero_private_key(), err);
        }
        if N.BitLen() != bits {
            return (
                zero_private_key(),
                errors::New("rsa: internal error: modulus size incorrect"),
            );
        }

        // FIPS 186-5, A.1.1(3) requires computing d as e⁻¹ mod λ(N)
        // where λ(N) = lcm(p-1, q-1).
        let (lambda, err) = totient(&P, &Q);
        if errors::Is(err.clone(), errDivisorTooLarge) {
            // The divisor is too large; try again with different primes.
            continue;
        }
        if !err.IsNil() {
            return (zero_private_key(), err);
        }

        let mut e = Nat::NewNat();
        e.SetUint(65537);
        let mut dScratch = Nat::NewNat();
        let (d, ok) = dScratch.InverseVarTime(&e, &lambda);
        if !ok {
            // GCD(e, lcm(p-1, q-1)) != 1; waste a prime, retry.
            continue;
        }

        {
            let mut eExp = e.clone();
            eExp.ExpandFor(&lambda);
            eExp.Mul(&d, &lambda);
            if eExp.IsOne() == 0 {
                return (
                    zero_private_key(),
                    errors::New("rsa: internal error: e*d != 1 mod λ(N)"),
                );
            }
        }

        let (k, err) = newPrivateKey(N, 65537, d, P, Q);
        if !err.IsNil() {
            return (zero_private_key(), err);
        }

        if k.fipsApproved {
            fips140::PCT("RSA sign and verify PCT", || {
                let hash: [byte; 32] = [
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
                ];
                let h = slice::<byte>::__from_vec(hash.to_vec());
                let (sig, err) = signPKCS1v15(&k, crate::crypto::SHA256, h.clone());
                if !err.IsNil() {
                    return err;
                }
                return verifyPKCS1v15(&k.PublicKey(), crate::crypto::SHA256, h, sig);
            });
        }

        return (k, errors::nil);
    }
}

crate::var! {
    /// `errDivisorTooLarge` is returned by `totient` when gcd(p-1, q-1)
    /// is too large.
    errDivisorTooLarge: error = "divisor too large";
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/keygen.go:137-177 totient
/// `totient` computes the Carmichael totient function λ(N) = lcm(p-1, q-1).
fn totient(p: &Modulus, q: &Modulus) -> (Modulus, error) {
    let mut a = p.Nat();
    a.SubOne(p);
    let mut b = q.Nat();
    b.SubOne(q);

    // lcm(a, b) = a×b / gcd(a, b) = a × (b / gcd(a, b)).
    //
    // Our GCD requires at least one number to be odd. For LCM we only
    // need to preserve the larger prime power of each prime factor, so
    // we right-shift the number with the fewest trailing zeros until
    // it's odd. For odd a, b and m >= n, lcm(a×2ᵐ, b×2ⁿ) = lcm(a×2ᵐ, b).
    let az = a.TrailingZeroBitsVarTime();
    let bz = b.TrailingZeroBitsVarTime();
    if az < bz {
        a.ShiftRightVarTime(az);
    } else {
        b.ShiftRightVarTime(bz);
    }

    let mut gcdScratch = Nat::NewNat();
    let (gcd, err) = gcdScratch.GCDVarTime(&a, &b);
    if !err.IsNil() {
        return (zero_modulus(), err);
    }
    if gcd.IsOdd() == 0 {
        return (
            zero_modulus(),
            errors::New("rsa: internal error: gcd(a, b) is even"),
        );
    }

    // To avoid multiple-precision division, reject divisors above 2³²-1
    // and try again. (Probability 2⁻⁶⁴ on 64-bit platforms.)
    if gcd.BitLenVarTime() > 32 {
        return (zero_modulus(), errDivisorTooLarge.into());
    }
    let gcdBits = gcd.Bits();
    if gcd.IsZero() == 1 || gcdBits[0] == 0 {
        return (
            zero_modulus(),
            errors::New("rsa: internal error: gcd(a, b) is zero"),
        );
    }
    let rem = b.DivShortVarTime(gcdBits[0]);
    if rem != 0 {
        return (
            zero_modulus(),
            errors::New("rsa: internal error: b is not divisible by gcd(a, b)"),
        );
    }

    return Modulus::NewModulusProduct(a.Bytes(p), b.Bytes(q));
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/keygen.go:181-231 randomPrime
// goishlint:ignore GOISH023 - the candidate `loop` is diverging; every
// exit is an explicit `return`, exactly as in Go's `for { … }`.
/// `randomPrime` returns a random prime number of the given bit size
/// following the process in FIPS 186-5, Appendix A.1.3.
fn randomPrime(rand: &mut dyn io::Reader, bits: int) -> (slice<byte>, error) {
    if bits < 16 {
        return (
            nil_bytes(),
            errors::New("rsa: prime size must be at least 16 bits"),
        );
    }

    let blen = usize::try_from((bits + 7) / 8).unwrap_or(0);
    let mut b: Vec<byte> = alloc::vec![0u8; blen];
    loop {
        let err = read_with_reader(rand, &mut b);
        if !err.IsNil() {
            return (nil_bytes(), err);
        }
        // Clear the most significant bits to reach the desired size.
        let excess = uint::try_from(int::try_from(blen).unwrap_or(0) * 8 - bits).unwrap_or(0);
        b[0] &= 0b1111_1111u8 >> excess;

        // Don't let the value be too small: set the most significant two
        // bits so two such values multiplied are never one bit short.
        if excess < 7 {
            b[0] |= 0b1100_0000u8 >> excess;
        } else {
            b[0] |= 0b0000_0001u8;
            b[1] |= 0b1000_0000u8;
        }

        // Make the value odd — an even number certainly isn't prime.
        b[blen - 1] |= 1;

        if isPrime(&b) {
            return (slice::<byte>::__from_vec(b), errors::nil);
        }
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/keygen.go:240-308 isPrime
// goishlint:ignore GOISH023 - the Miller-Rabin `loop` is diverging;
// every exit is an explicit `return`, exactly as in Go's `for { … }`.
/// `isPrime` runs the Miller-Rabin Probabilistic Primality Test from
/// FIPS 186-5, Appendix B.3.1. `w` must be a random odd integer greater
/// than three, big-endian. It may return false positives for
/// adversarially chosen values, and is not constant-time.
fn isPrime(w: &[byte]) -> bool {
    let mr = match millerRabinSetup(w) {
        Err(_) => return false, // w is zero, one, or even.
        Ok(mr) => mr,
    };

    // Before Miller-Rabin, rule out most composites with trial divisions.
    let mut i = 0usize;
    while i < PRIMES.len() {
        let p1 = PRIMES[i];
        let p2 = PRIMES[i + 1];
        let p3 = PRIMES[i + 2];
        let mut wNat = mr.w.Nat();
        let r = wNat.DivShortVarTime(p1 * p2 * p3);
        if r % p1 == 0 || r % p2 == 0 || r % p3 == 0 {
            return false;
        }
        i += 3;
    }

    // iterations is the number of Miller-Rabin rounds. Since w is
    // randomly selected (RSA key generation), a smaller count suffices.
    let bits = mr.w.BitLen();
    let mut iterations: int = if bits >= 3747 {
        3
    } else if bits >= 1345 {
        4
    } else if bits >= 476 {
        5
    } else if bits >= 400 {
        6
    } else if bits >= 347 {
        7
    } else if bits >= 308 {
        8
    } else if bits >= 55 {
        27
    } else {
        34
    };

    let blen = usize::try_from((bits + 7) / 8).unwrap_or(0);
    let mut b: Vec<byte> = alloc::vec![0u8; blen];
    loop {
        drbg_read(&mut b);
        let excess = uint::try_from(int::try_from(blen).unwrap_or(0) * 8 - bits).unwrap_or(0);
        b[0] &= 0b1111_1111u8 >> excess;
        match millerRabinIteration(&mr, &b) {
            Err(_) => continue, // b was rejected.
            Ok(result) => {
                if result == millerRabinCOMPOSITE {
                    return false;
                }
                iterations -= 1;
                if iterations == 0 {
                    return true;
                }
            }
        }
    }
}

/// `primes` are the first prime numbers (except 2), such that the
/// product of any three primes fits in a uint32.
static PRIMES: [uint; 255] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
    1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
    1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279,
    1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
    1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
    1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613,
    1619,
];

// go: sdk 1.25.5 crypto/internal/fips140/rsa/keygen.go:340-344 millerRabin
/// `millerRabin` — state reused across iterations of the Miller-Rabin
/// test.
struct millerRabin {
    w: Modulus,
    a: uint,
    m: Vec<byte>,
}

// go: sdk 1.25.5 crypto/internal/fips140/rsa/keygen.go:348-377 millerRabinSetup
/// `millerRabinSetup` prepares state that's reused across multiple
/// iterations of the Miller-Rabin test.
fn millerRabinSetup(w: &[byte]) -> Result<millerRabin, error> {
    // Check that w is odd, and precompute Montgomery parameters.
    let (wm, err) = Modulus::NewModulus(slice::<byte>::__from_vec(w.to_vec()));
    if !err.IsNil() {
        return Err(err);
    }
    if wm.Nat().IsOdd() == 0 {
        return Err(errors::New("candidate is even"));
    }

    // Compute m = (w-1)/2^a, where m is odd.
    let mut wMinus1 = wm.Nat();
    wMinus1.SubOne(&wm);
    if wMinus1.IsZero() == 1 {
        return Err(errors::New("candidate is one"));
    }
    let a = wMinus1.TrailingZeroBitsVarTime();

    // Store m as a big-endian byte slice with leading zero bytes removed.
    let mut mShifted = wMinus1.clone();
    mShifted.ShiftRightVarTime(a);
    let mBytes = mShifted.Bytes(&wm);
    let mut m = mBytes.to_vec();
    while !m.is_empty() && m[0] == 0 {
        m.remove(0);
    }

    return Ok(millerRabin { w: wm, a, m });
}

const millerRabinCOMPOSITE: bool = false;
const millerRabinPOSSIBLYPRIME: bool = true;

// go: sdk 1.25.5 crypto/internal/fips140/rsa/keygen.go:382-419 millerRabinIteration
/// `millerRabinIteration` runs one round of Miller-Rabin with base `bb`.
fn millerRabinIteration(mr: &millerRabin, bb: &[byte]) -> Result<bool, error> {
    // Reject b ≤ 1 or b ≥ w − 1.
    if int::try_from(bb.len()).unwrap_or(0) != (mr.w.BitLen() + 7) / 8 {
        return Err(errors::New("incorrect length"));
    }
    let mut bScratch = Nat::NewNat();
    let (b, err) = bScratch.SetBytes(slice::<byte>::__from_vec(bb.to_vec()), &mr.w);
    if !err.IsNil() {
        return Err(err);
    }
    if b.IsZero() == 1 || b.IsOne() == 1 || b.IsMinusOne(&mr.w) == 1 {
        return Err(errors::New("out-of-range candidate"));
    }

    // Compute b^(m*2^i) mod w for successive i. If b^m mod w = 1, b is a
    // possible prime. If b^(m*2^i) mod w = -1 for some 0 <= i < a, b is
    // a possible prime. Otherwise b is composite.

    // Start by computing and checking b^m mod w (also the i = 0 case).
    let mut z = Nat::NewNat();
    z.Exp(&b, slice::<byte>::__from_vec(mr.m.clone()), &mr.w);
    if z.IsOne() == 1 || z.IsMinusOne(&mr.w) == 1 {
        return Ok(millerRabinPOSSIBLYPRIME);
    }

    // Check b^(m*2^i) mod w = -1 for 0 < i < a.
    let mut iter: uint = 0;
    while iter < mr.a - 1 {
        let zc = z.clone();
        z.Mul(&zc, &mr.w);
        if z.IsMinusOne(&mr.w) == 1 {
            return Ok(millerRabinPOSSIBLYPRIME);
        }
        if z.IsOne() == 1 {
            // Future squaring will not turn z == 1 into -1.
            break;
        }
        iter += 1;
    }

    return Ok(millerRabinCOMPOSITE);
}
