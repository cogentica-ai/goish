// go: file crypto/internal/fips140/aes/gcm/cmac.go decls: NewCMAC, CMAC.deriveSubkeys, CMAC.MAC, shiftLeft
//
// CMAC (NIST SP 800-38B).
//
// Optimized for use in Counter KDF (SP 800-108r1) and XAES-256-GCM
// (https://c2sp.org/XAES-256-GCM) rather than for exposing to
// applications as a stand-alone MAC.
//
// Deviation: `fips140.RecordApproved()` is dropped — goish's fips140
// stub has no service indicator.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140::aes;
use crate::goslice::slice;
use crate::types::byte;

extern crate alloc;

// Go: cmac.go:16
//   type CMAC struct { b aes.Block; k1, k2 [aes.BlockSize]byte }
/// `gcm.CMAC` — CMAC mode over an AES block cipher.
#[derive(Clone)]
pub struct CMAC {
    b: aes::Block,
    k1: [byte; 16],
    k2: [byte; 16],
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/cmac.go:24-28 NewCMAC
/// `gcm.NewCMAC(b)` — a new CMAC keyed by `b`.
pub fn NewCMAC(b: &aes::Block) -> CMAC {
    // Go: c := &CMAC{b: *b}; c.deriveSubkeys(); return c
    let mut c = CMAC {
        b: b.clone(),
        k1: [0; 16],
        k2: [0; 16],
    };
    c.deriveSubkeys();
    return c;
}

impl CMAC {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/cmac.go:30-38 CMAC.deriveSubkeys
    /// Derive the two CMAC subkeys from the block cipher.
    fn deriveSubkeys(&mut self) {
        // Go: aes.EncryptBlockInternal(&c.b, c.k1[:], c.k1[:])
        encryptInPlace(&self.b, &mut self.k1);
        // Go: msb := shiftLeft(&c.k1); c.k1[15] ^= msb * 0b10000111
        let msb = shiftLeft(&mut self.k1);
        self.k1[15] ^= msb.wrapping_mul(0b10000111);

        // Go: c.k2 = c.k1; msb = shiftLeft(&c.k2); c.k2[15] ^= msb * 0b10000111
        self.k2 = self.k1;
        let msb = shiftLeft(&mut self.k2);
        self.k2[15] ^= msb.wrapping_mul(0b10000111);
    }

    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/cmac.go:40-68 CMAC.MAC
    /// `(*CMAC).MAC(m)` — the CMAC tag over `m`.
    pub fn MAC(&self, m: slice<byte>) -> [byte; 16] {
        // Go: fips140.RecordApproved() — no-op in goish.
        // Go: var x [aes.BlockSize]byte
        let mut x = [0u8; 16];
        let raw: &[byte] = &m;
        let bs = aes::BlockSize as usize;

        // Go: if len(m) == 0 { … single empty partial final block … }
        if raw.is_empty() {
            x = self.k2;
            x[0] ^= 0b10000000;
            encryptInPlace(&self.b, &mut x);
            return x;
        }

        // Go: for len(m) >= aes.BlockSize { … }
        let mut off: usize = 0;
        while raw.len() - off >= bs {
            // Go: subtle.XORBytes(x[:], m[:aes.BlockSize], x[:])
            let mut k: usize = 0;
            while k < bs {
                x[k] ^= raw[off + k];
                k += 1;
            }
            // Go: if len(m) == aes.BlockSize { subtle.XORBytes(x[:], c.k1[:], x[:]) }
            if raw.len() - off == bs {
                let mut k: usize = 0;
                while k < bs {
                    x[k] ^= self.k1[k];
                    k += 1;
                }
            }
            encryptInPlace(&self.b, &mut x);
            // Go: m = m[aes.BlockSize:]
            off += bs;
        }

        // Go: if len(m) > 0 { … final incomplete block … }
        if off < raw.len() {
            let rem = raw.len() - off;
            // Go: subtle.XORBytes(x[:], m, x[:])
            let mut k: usize = 0;
            while k < rem {
                x[k] ^= raw[off + k];
                k += 1;
            }
            // Go: subtle.XORBytes(x[:], c.k2[:], x[:])
            let mut k: usize = 0;
            while k < bs {
                x[k] ^= self.k2[k];
                k += 1;
            }
            // Go: x[len(m)] ^= 0b10000000
            x[rem] ^= 0b10000000;
            encryptInPlace(&self.b, &mut x);
        }

        // Go: return x
        return x;
    }
}

// go: none — goish idiom: aes::EncryptBlockInternal takes `slice<byte>`
// per AGENTS.md §3, while CMAC works on fixed 16-byte arrays. One
// conversion point rather than six.
fn encryptInPlace(b: &aes::Block, x: &mut [byte; 16]) {
    let mut d = slice::__from_vec(alloc::vec![0u8; 16]);
    aes::EncryptBlockInternal(b, &mut d, slice::__from_vec(x.to_vec()));
    let r: &[byte] = &d;
    x.copy_from_slice(r);
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/cmac.go:71-77 shiftLeft
/// Set `x` to `x << 1` and return MSB₁(x).
fn shiftLeft(x: &mut [byte; 16]) -> byte {
    // Go: var msb byte; for i := len(x) - 1; i >= 0; i-- { msb, x[i] = x[i]>>7, x[i]<<1|msb }
    let mut msb: byte = 0;
    let mut i: isize = 15;
    while i >= 0 {
        let cur = x[i as usize];
        x[i as usize] = (cur << 1) | msb;
        msb = cur >> 7;
        i -= 1;
    }
    return msb;
}
