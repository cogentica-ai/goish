// go: file crypto/dsa/dsa.go decls: GenerateParameters, GenerateKey, fermatInverse, Sign, Verify
//
// Package dsa implements the Digital Signature Algorithm, as defined in
// FIPS 186-3.
//
// The DSA operations in this package are not implemented using
// constant-time algorithms.
//
// Deprecated: DSA is a legacy algorithm, and modern alternatives such as
// Ed25519 (implemented by package crypto/ed25519) or ECDSA (implemented by
// packages crypto/ecdsa and crypto/ecdh) should be used instead.
//
// Deviations from dsa[go] @ Go 1.25.5:
//
//   * `Sign` returns `(*big.Int, *big.Int, error)` with nil values on the
//     error paths; `Int` has no nil, so it returns zero values alongside
//     the error, which callers already have to check.
//   * `Verify` tests `w == nil` after `new(big.Int).ModInverse(s, pub.Q)`.
//     goish's ModInverse returns `&mut Self` and leaves the receiver
//     unchanged when no inverse exists (it never stores garbage), so the
//     coprimality it stands for is checked directly with `GCD` — the same
//     acceptance set, spelled out.
//   * Go's `GeneratePrimes:` labelled break becomes a flag; Rust has
//     labelled breaks, but not out of a `for` into an outer `for` across
//     the intervening `if`, in a shape that reads like the original.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::internal::fips140only;
use crate::crypto::internal::randutil;
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::io;
use crate::math::big::{Int, NewInt};
use crate::types::{byte, int};

// Go: dsa.go:21-24
//   type Parameters struct { P, Q, G *big.Int }
/// The domain parameters for a set of DSA keys.
#[derive(Clone, Default)]
pub struct Parameters {
    pub P: Int,
    pub Q: Int,
    pub G: Int,
}

// Go: dsa.go:26-30
//   type PublicKey struct { Parameters; Y *big.Int }
/// Represents a DSA public key.
#[derive(Clone, Default)]
pub struct PublicKey {
    /// Go embeds `Parameters`; goish names the field, and the P/Q/G
    /// accessors below stand in for Go's promoted fields.
    pub Parameters: Parameters,
    pub Y: Int,
}

// Go: dsa.go:32-36
//   type PrivateKey struct { PublicKey; X *big.Int }
/// Represents a DSA private key.
#[derive(Clone, Default)]
pub struct PrivateKey {
    pub PublicKey: PublicKey,
    pub X: Int,
}

// Go: dsa.go:38-39
//   var ErrInvalidPublicKey = errors.New("crypto/dsa: invalid public key")
goish::var! {
    /// Results from a call to `Verify` with a public key that is not usable.
    pub ErrInvalidPublicKey: error = "crypto/dsa: invalid public key";
}

// Go: dsa.go:41-42 — `type ParameterSizes int`
/// A choice of key size, as specified in FIPS 186-3.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ParameterSizes(pub int);

// Go: dsa.go:44-51 — `const ( L1024N160 ParameterSizes = iota; … )`
pub const L1024N160: ParameterSizes = ParameterSizes(0);
pub const L2048N224: ParameterSizes = ParameterSizes(1);
pub const L2048N256: ParameterSizes = ParameterSizes(2);
pub const L3072N256: ParameterSizes = ParameterSizes(3);

// Go: dsa.go:53-54
//   const numMRTests = 64
/// The number of Miller-Rabin primality tests that we perform. We pick the
/// largest recommended number from table C.1 of FIPS 186-3.
const numMRTests: int = 64;

// go: sdk 1.25.5 crypto/dsa/dsa.go:66-160 GenerateParameters
// goishlint:ignore GOISH023 — Go's body is a labelled `for`/`break
// GeneratePrimes`; Rust spells the unconditional loops as `loop { … }`,
// which parses as the tail expression.
/// Puts a random, valid set of DSA parameters into params. This function
/// can take many seconds, even on fast machines.
pub fn GenerateParameters(
    params: &mut Parameters,
    rand: &mut (dyn io::Reader + Send + Sync + 'static),
    sizes: ParameterSizes,
) -> error {
    if fips140only::Enabled {
        return errors::New("crypto/dsa: use of DSA is not allowed in FIPS 140-only mode");
    }

    // This function doesn't follow FIPS 186-3 exactly in that it doesn't
    // use a verification seed to generate the primes. The verification seed
    // doesn't appear to be exported or used by other code and omitting it
    // makes the code cleaner.

    let L: int;
    let N: int;
    if sizes == L1024N160 {
        L = 1024;
        N = 160;
    } else if sizes == L2048N224 {
        L = 2048;
        N = 224;
    } else if sizes == L2048N256 {
        L = 2048;
        N = 256;
    } else if sizes == L3072N256 {
        L = 3072;
        N = 256;
    } else {
        return errors::New("crypto/dsa: invalid ParameterSizes");
    }

    let mut qBytes = slice::__from_vec(alloc::vec![0u8; (N / 8) as usize]);
    let mut pBytes = slice::__from_vec(alloc::vec![0u8; (L / 8) as usize]);
    let mut q = Int::default();
    let mut p = Int::default();
    let mut rem = Int::default();
    let mut one = Int::default();
    one.SetInt64(1);

    // Go: GeneratePrimes: for { … break GeneratePrimes … }
    let mut generated = false;
    while !generated {
        let (_, err) = io::ReadFull(rand, &mut qBytes);
        if err != crate::nil {
            return err;
        }

        {
            let b: &mut [byte] = &mut qBytes;
            let last = b.len() - 1;
            b[last] |= 1;
            b[0] |= 0x80;
        }
        q.SetBytes(qBytes.clone());

        if !q.ProbablyPrime(numMRTests) {
            continue;
        }

        let mut i: int = 0;
        while i < 4 * L {
            i += 1;
            let (_, err) = io::ReadFull(rand, &mut pBytes);
            if err != crate::nil {
                return err;
            }

            {
                let b: &mut [byte] = &mut pBytes;
                let last = b.len() - 1;
                b[last] |= 1;
                b[0] |= 0x80;
            }

            p.SetBytes(pBytes.clone());
            rem.Mod(&p, &q);
            let r2 = rem.clone();
            rem.Sub(&r2, &one);
            let p2 = p.clone();
            p.Sub(&p2, &rem);
            if p.BitLen() < L {
                continue;
            }

            if !p.ProbablyPrime(numMRTests) {
                continue;
            }

            params.P = p.clone();
            params.Q = q.clone();
            generated = true;
            break;
        }
    }

    let mut h = Int::default();
    h.SetInt64(2);
    let mut g = Int::default();

    let mut pm1 = Int::default();
    pm1.Sub(&p, &one);
    let mut e = Int::default();
    e.Div(&pm1, &q);

    loop {
        g.Exp(&h, &e, &p);
        if g.Cmp(&one) == 0 {
            let h2 = h.clone();
            h.Add(&h2, &one);
            continue;
        }

        params.G = g;
        return crate::nil.into();
    }
}

// go: sdk 1.25.5 crypto/dsa/dsa.go:164-191 GenerateKey
/// Generate a public&private key pair. The Parameters of the [PrivateKey]
/// must already be valid (see [GenerateParameters]).
pub fn GenerateKey(
    priv_: &mut PrivateKey,
    rand: &mut (dyn io::Reader + Send + Sync + 'static),
) -> error {
    if fips140only::Enabled {
        return errors::New("crypto/dsa: use of DSA is not allowed in FIPS 140-only mode");
    }

    let params = priv_.PublicKey.Parameters.clone();
    if params.P.Sign() == 0 || params.Q.Sign() == 0 || params.G.Sign() == 0 {
        return errors::New("crypto/dsa: parameters not set up before generating key");
    }

    let mut x = Int::default();
    let mut xBytes = slice::__from_vec(alloc::vec![0u8; (params.Q.BitLen() / 8) as usize]);
    loop {
        let (_, err) = io::ReadFull(rand, &mut xBytes);
        if err != crate::nil {
            return err;
        }
        x.SetBytes(xBytes.clone());
        if x.Sign() != 0 && x.Cmp(&params.Q) < 0 {
            break;
        }
    }

    priv_.X = x.clone();
    let mut y = Int::default();
    y.Exp(&params.G, &x, &params.P);
    priv_.PublicKey.Y = y;
    return crate::nil.into();
}

// go: sdk 1.25.5 crypto/dsa/dsa.go:197-201 fermatInverse
/// Calculate the inverse of k in GF(P) using Fermat's method (exponentiation
/// modulo P - 2, per Euler's theorem). This has better constant-time
/// properties than Euclid's method (implemented in math/big.Int.ModInverse
/// and FIPS 186-3, Appendix C.1) although math/big itself isn't strictly
/// constant-time so it's not perfect.
fn fermatInverse(k: &Int, P: &Int) -> Int {
    let two = NewInt(2);
    let mut pMinus2 = Int::default();
    pMinus2.Sub(P, &two);
    let mut out = Int::default();
    out.Exp(k, &pMinus2, P);
    return out;
}

// go: sdk 1.25.5 crypto/dsa/dsa.go:214-278 Sign
/// Sign a hash (which should be the result of hashing a larger message)
/// using the private key, priv. If the hash is longer than the bit-length
/// of the private key's curve order, the hash will be truncated to that
/// length. It returns the signature as a pair of integers.
///
/// Note that FIPS 186-3 section 4.6 specifies that the hash should be
/// truncated to the byte-length of the subgroup. This function does not
/// perform that truncation itself.
pub fn Sign(
    rand: &mut (dyn io::Reader + Send + Sync + 'static),
    priv_: &PrivateKey,
    hash: &slice<byte>,
) -> (Int, Int, error) {
    if fips140only::Enabled {
        return (
            Int::default(),
            Int::default(),
            errors::New("crypto/dsa: use of DSA is not allowed in FIPS 140-only mode"),
        );
    }

    randutil::MaybeReadByte(rand);

    // FIPS 186-3, section 4.6
    let params = priv_.PublicKey.Parameters.clone();
    let mut n = params.Q.BitLen();
    if params.Q.Sign() <= 0
        || params.P.Sign() <= 0
        || params.G.Sign() <= 0
        || priv_.X.Sign() <= 0
        || n % 8 != 0
    {
        return (Int::default(), Int::default(), ErrInvalidPublicKey.into());
    }
    n >>= 3;

    let mut r = Int::default();
    let mut s = Int::default();
    let mut attempts: int = 10;
    while attempts > 0 {
        let mut k = Int::default();
        let mut buf = slice::__from_vec(alloc::vec![0u8; n as usize]);
        loop {
            let (_, err) = io::ReadFull(rand, &mut buf);
            if err != crate::nil {
                return (Int::default(), Int::default(), err);
            }
            k.SetBytes(buf.clone());
            if k.Sign() > 0 && k.Cmp(&params.Q) < 0 {
                break;
            }
        }

        let kInv = fermatInverse(&k, &params.Q);

        r.Exp(&params.G, &k, &params.P);
        let r2 = r.clone();
        r.Mod(&r2, &params.Q);

        if r.Sign() == 0 {
            attempts -= 1;
            continue;
        }

        // Go reuses k's storage: `z := k.SetBytes(hash)`.
        k.SetBytes(hash.clone());
        let z = k.clone();

        s.Mul(&priv_.X, &r);
        let s2 = s.clone();
        s.Add(&s2, &z);
        let s2 = s.clone();
        s.Mod(&s2, &params.Q);
        let s2 = s.clone();
        s.Mul(&s2, &kInv);
        let s2 = s.clone();
        s.Mod(&s2, &params.Q);

        if s.Sign() != 0 {
            return (r, s, crate::nil.into());
        }
        attempts -= 1;
    }

    // Only degenerate private keys will require more than a handful of
    // attempts.
    return (Int::default(), Int::default(), ErrInvalidPublicKey.into());
}

// go: sdk 1.25.5 crypto/dsa/dsa.go:286-326 Verify
/// Verify the signature in r, s of hash using the public key, pub. It
/// reports whether the signature is valid.
///
/// Note that FIPS 186-3 section 4.6 specifies that the hash should be
/// truncated to the byte-length of the subgroup. This function does not
/// perform that truncation itself.
pub fn Verify(pubKey: &PublicKey, hash: &slice<byte>, r: &Int, s: &Int) -> bool {
    if fips140only::Enabled {
        panic!("crypto/dsa: use of DSA is not allowed in FIPS 140-only mode");
    }

    // FIPS 186-3, section 4.7
    let params = pubKey.Parameters.clone();

    if params.P.Sign() == 0 {
        return false;
    }

    if r.Sign() < 1 || r.Cmp(&params.Q) >= 0 {
        return false;
    }
    if s.Sign() < 1 || s.Cmp(&params.Q) >= 0 {
        return false;
    }

    // Go: w := new(big.Int).ModInverse(s, pub.Q); if w == nil { return false }
    //
    // goish's ModInverse leaves the receiver unchanged when s and Q are not
    // coprime, so the condition it stands for is checked directly.
    let mut d = Int::default();
    let mut xc = Int::default();
    d.GCD(&mut xc, crate::nilval::nil, s, &params.Q);
    let mut one = Int::default();
    one.SetInt64(1);
    if d.Cmp(&one) != 0 {
        return false;
    }
    let mut w = Int::default();
    w.ModInverse(s, &params.Q);

    let n = params.Q.BitLen();
    if n % 8 != 0 {
        return false;
    }
    let mut z = Int::default();
    z.SetBytes(hash.clone());

    let mut u1 = Int::default();
    u1.Mul(&z, &w);
    let t = u1.clone();
    u1.Mod(&t, &params.Q);
    let mut u2 = Int::default();
    u2.Mul(r, &w);
    let t = u2.clone();
    u2.Mod(&t, &params.Q);
    let mut v = Int::default();
    let t = u1.clone();
    v.Exp(&params.G, &t, &params.P);
    let t = u2.clone();
    u2.Exp(&pubKey.Y, &t, &params.P);
    let t = v.clone();
    v.Mul(&t, &u2);
    let t = v.clone();
    v.Mod(&t, &params.P);
    let t = v.clone();
    v.Mod(&t, &params.Q);

    return v.Cmp(r) == 0;
}

// Keep the Vec import honest: the byte buffers above are built from one.
const _: fn() -> Vec<byte> = Vec::new;
