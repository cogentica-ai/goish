// go: file crypto/internal/fips140/aes/gcm/ctrkdf.go decls: NewCounterKDF, CounterKDF.DeriveKey
//
// A KDF in Counter Mode instantiated with CMAC-AES, per NIST SP 800-108
// Revision 1 Update 1, Section 4.1.
//
// Produces a 256-bit output from an 8-bit Label and a 96-bit Context,
// using a 16-bit counter placed before the fixed data. The fixed data is
// `Label || 0x00 || Context`. The L field is omitted, since the output
// key length is fixed.
//
// Optimized for use in XAES-256-GCM (https://c2sp.org/XAES-256-GCM)
// rather than as a stand-alone KDF.
//
// Deviation: `fips140.RecordApproved()` is dropped — goish's fips140
// stub has no service indicator.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::crypto::internal::fips140::aes;
use crate::goslice::slice;
use crate::types::byte;

use super::cmac::{NewCMAC, CMAC};

// Go: ctrkdf.go:19
//   type CounterKDF struct { mac CMAC }
/// `gcm.CounterKDF` — SP 800-108r1 Counter Mode KDF over CMAC-AES.
#[derive(Clone)]
pub struct CounterKDF {
    mac: CMAC,
}

// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/ctrkdf.go:24-26 NewCounterKDF
/// `gcm.NewCounterKDF(b)` — a new CounterKDF with the given key.
pub fn NewCounterKDF(b: &aes::Block) -> CounterKDF {
    // Go: return &CounterKDF{mac: *NewCMAC(b)}
    return CounterKDF { mac: NewCMAC(b) };
}

impl CounterKDF {
    // go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/ctrkdf.go:29-45 DeriveKey
    /// `(*CounterKDF).DeriveKey(label, context)` — derive a 256-bit key.
    pub fn DeriveKey(&self, label: byte, context: [byte; 12]) -> [byte; 32] {
        // Go: fips140.RecordApproved() — no-op in goish.
        // Go: var output [32]byte; var input [aes.BlockSize]byte
        //     input[2] = label; copy(input[4:], context[:])
        let mut output = [0u8; 32];
        let mut input = [0u8; 16];
        input[2] = label;
        input[4..16].copy_from_slice(&context);

        // Go: input[1] = 0x01; K1 := kdf.mac.MAC(input[:])
        input[1] = 0x01;
        let K1 = self.mac.MAC(slice::__from_vec(input.to_vec()));

        // Go: input[1] = 0x02; K2 := kdf.mac.MAC(input[:])
        input[1] = 0x02;
        let K2 = self.mac.MAC(slice::__from_vec(input.to_vec()));

        // Go: copy(output[:], K1[:]); copy(output[aes.BlockSize:], K2[:])
        output[..16].copy_from_slice(&K1);
        output[16..].copy_from_slice(&K2);
        return output;
    }
}
