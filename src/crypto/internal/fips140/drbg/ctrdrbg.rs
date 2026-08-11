// go: file crypto/internal/fips140/drbg/ctrdrbg.go decls: NewCounter, Counter.update, increment, Counter.Reseed, Counter.Generate
//
// An SP 800-90A Rev. 1 CTR_DRBG instantiated with AES-256.
//
// Per Table 3 it has a security strength of 256 bits, a seed size of 384
// bits, a counter length of 128 bits, a reseed interval of 2^48 requests,
// and a maximum request size of 2^19 bits (64 KiB).
//
// A narrow range of parameters is supported, matching what the RNG needs:
// AES-256, no derivation function, no personalization string, no
// prediction resistance, and 384-bit additional input.
//
// WARNING: this type provides tightly scoped support for the DRBG
// functionality FIPS 140-3 needs, and _only_ that. It should not be used
// outside the FIPS 140-3 module for any other purpose. In particular, as
// documented, `Counter` supports neither the derivation function nor
// personalization strings, both of which are necessary to use this DRBG
// safely for generic purposes without leaking sensitive values.
//
// Deviation: `fips140.RecordApproved()` calls are dropped — goish's
// fips140 stub has no service indicator.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140::aes;
use crate::crypto::internal::fips140deps::byteorder;
use crate::goslice::slice;
use crate::math::bits;
use crate::types::{byte, uint64};

extern crate alloc;
use alloc::vec::Vec;

/// Go: `keySize = 256 / 8`
const keySize: usize = 256 / 8;
/// Go: `SeedSize = keySize + aes.BlockSize`
pub const SeedSize: usize = keySize + 16;
/// Go: `reseedInterval = 1 << 48`
const reseedInterval: uint64 = 1 << 48;
/// Go: `maxRequestSize = (1 << 19) / 8`
pub const maxRequestSize: usize = (1 << 19) / 8;

// Go: ctrdrbg.go:32
//   type Counter struct { c aes.CTR; reseedCounter uint64 }
/// `drbg.Counter` — the CTR_DRBG state. `c` is instantiated with K as the
/// key and V as the counter.
#[derive(Clone)]
pub struct Counter {
    c: aes::CTR,
    reseedCounter: uint64,
}

// go: sdk 1.25.5 crypto/internal/fips140/drbg/ctrdrbg.go:46-67 NewCounter
/// `drbg.NewCounter(entropy)` — CTR_DRBG_Instantiate_algorithm, per
/// SP 800-90A §10.2.1.3.1.
pub fn NewCounter(entropy: &[byte; SeedSize]) -> Counter {
    // Go: K := make([]byte, keySize); V := make([]byte, aes.BlockSize)
    let K: Vec<byte> = alloc::vec![0u8; keySize];
    let mut V: Vec<byte> = alloc::vec![0u8; 16];

    // Go: V[len(V)-1] = 1
    //
    // V starts at 0 but is incremented in CTR_DRBG_Update before each
    // use, unlike AES-CTR where it is incremented after each use.
    V[15] = 1;

    // Go: cipher, err := aes.New(K); if err != nil { panic(err) }
    let (cipher, err) = aes::New(slice::__from_vec(K));
    if err != crate::errors::nil {
        panic!("crypto/drbg: internal error: AES-256 key rejected");
    }
    let cipher = cipher.unwrap();

    // Go: c := &Counter{}; c.c = *aes.NewCTR(cipher, V)
    let mut c = Counter {
        c: aes::NewCTR(&cipher, &slice::__from_vec(V)),
        reseedCounter: 0,
    };
    // Go: c.update(entropy); c.reseedCounter = 1
    c.update(entropy);
    c.reseedCounter = 1;
    return c;
}

impl Counter {
    // go: sdk 1.25.5 crypto/internal/fips140/drbg/ctrdrbg.go:69-85 update
    /// CTR_DRBG_Update, per SP 800-90A §10.2.1.2.
    fn update(&mut self, seed: &[byte; SeedSize]) {
        // Go: temp := make([]byte, SeedSize); c.c.XORKeyStream(temp, seed[:])
        let mut temp = slice::__from_vec(alloc::vec![0u8; SeedSize]);
        self.c
            .XORKeyStream(&mut temp, &slice::__from_vec(seed.to_vec()));

        // Go: K := temp[:keySize]; V := temp[keySize:]
        let raw: &[byte] = &temp;
        let K: Vec<byte> = raw[..keySize].to_vec();
        let mut V = [0u8; 16];
        V.copy_from_slice(&raw[keySize..]);

        // Go: increment((*[aes.BlockSize]byte)(V))
        //
        // Again, V is pre-incremented, as in NewCounter.
        increment(&mut V);

        // Go: cipher, err := aes.New(K); if err != nil { panic(err) }
        let (cipher, err) = aes::New(slice::__from_vec(K));
        if err != crate::errors::nil {
            panic!("crypto/drbg: internal error: AES-256 key rejected");
        }
        let cipher = cipher.unwrap();
        // Go: c.c = *aes.NewCTR(cipher, V)
        self.c = aes::NewCTR(&cipher, &slice::__from_vec(V.to_vec()));
    }

    // go: sdk 1.25.5 crypto/internal/fips140/drbg/ctrdrbg.go:96-104 Reseed
    /// CTR_DRBG_Reseed_algorithm, per SP 800-90A §10.2.1.4.1.
    pub fn Reseed(&mut self, entropy: &[byte; SeedSize], additionalInput: &[byte; SeedSize]) {
        // Go: var seed [SeedSize]byte
        //     subtle.XORBytes(seed[:], entropy[:], additionalInput[:])
        let mut seed = [0u8; SeedSize];
        let mut i: usize = 0;
        while i < SeedSize {
            seed[i] = entropy[i] ^ additionalInput[i];
            i += 1;
        }
        // Go: c.update(&seed); c.reseedCounter = 1
        self.update(&seed);
        self.reseedCounter = 1;
    }

    // go: sdk 1.25.5 crypto/internal/fips140/drbg/ctrdrbg.go:107-143 Generate
    /// CTR_DRBG_Generate_algorithm, per SP 800-90A §10.2.1.5.1. Produces
    /// at most `maxRequestSize` bytes into `out`, and reports whether a
    /// reseed is required before the next call.
    ///
    /// Go takes `additionalInput *[SeedSize]byte` and distinguishes nil
    /// from a zero array; goish spells that `Option<&[byte; SeedSize]>`.
    pub fn Generate(
        &mut self,
        out: &mut [byte],
        additionalInput: Option<&[byte; SeedSize]>,
    ) -> bool {
        // Go: if len(out) > maxRequestSize { panic(…) }
        if out.len() > maxRequestSize {
            panic!("crypto/drbg: internal error: request size exceeds maximum");
        }

        // Step 1.
        // Go: if c.reseedCounter > reseedInterval { return true }
        if self.reseedCounter > reseedInterval {
            return true;
        }

        // Step 2.
        // Go: if additionalInput != nil { c.update(additionalInput) } else { … }
        //
        // If the additional input is null the first CTR_DRBG_Update is
        // skipped, but the additional input is replaced with an all-zero
        // string for the second CTR_DRBG_Update.
        let zero = [0u8; SeedSize];
        let ai: [byte; SeedSize] = match additionalInput {
            Some(a) => {
                self.update(a);
                *a
            }
            None => zero,
        };

        // Steps 3-5.
        // Go: clear(out); c.c.XORKeyStream(out, out); aes.RoundToBlock(&c.c)
        let mut i: usize = 0;
        while i < out.len() {
            out[i] = 0;
            i += 1;
        }
        let mut dst = slice::__from_vec(alloc::vec![0u8; out.len()]);
        let src = slice::__from_vec(alloc::vec![0u8; out.len()]);
        self.c.XORKeyStream(&mut dst, &src);
        let dr: &[byte] = &dst;
        out.copy_from_slice(dr);
        aes::RoundToBlock(&mut self.c);

        // Step 6.
        // Go: c.update(additionalInput)
        self.update(&ai);

        // Step 7.
        // Go: c.reseedCounter++
        self.reseedCounter += 1;

        // Step 8.
        // Go: return false
        return false;
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/drbg/ctrdrbg.go:87-94 increment
/// Go: `func increment(v *[aes.BlockSize]byte)` — treat `v` as a 128-bit
/// big-endian integer and add one.
fn increment(v: &mut [byte; 16]) {
    // Go: hi := byteorder.BEUint64(v[:8]); lo := byteorder.BEUint64(v[8:])
    let hi = byteorder::BEUint64(slice::__from_vec(v[..8].to_vec()));
    let lo = byteorder::BEUint64(slice::__from_vec(v[8..].to_vec()));
    // Go: lo, c := bits.Add64(lo, 1, 0); hi, _ = bits.Add64(hi, 0, c)
    let (lo, carry) = bits::Add64(lo, 1, 0);
    let (hi, _) = bits::Add64(hi, 0, carry);
    // Go: byteorder.BEPutUint64(v[:8], hi); byteorder.BEPutUint64(v[8:], lo)
    let mut w = slice::__from_vec(alloc::vec![0u8; 8]);
    byteorder::BEPutUint64(&mut w, hi);
    let wr: &[byte] = &w;
    v[..8].copy_from_slice(wr);
    let mut w = slice::__from_vec(alloc::vec![0u8; 8]);
    byteorder::BEPutUint64(&mut w, lo);
    let wr: &[byte] = &w;
    v[8..].copy_from_slice(wr);
}
