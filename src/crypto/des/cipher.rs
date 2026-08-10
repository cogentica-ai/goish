// goishlint:ignore GOISH021 — Go's unexported desCipher/tripleDESCipher are
// exported here as Cipher/TripleDESCipher: Go hides them behind the
// cipher.Block interface return, which goish cannot do for a value type.
// go: file crypto/des/cipher.go decls: KeySizeError.Error, NewCipher, desCipher.BlockSize, desCipher.Encrypt, desCipher.Decrypt, NewTripleDESCipher, tripleDESCipher.BlockSize, tripleDESCipher.Encrypt, tripleDESCipher.Decrypt
//
// DES + TripleDES block ciphers (FIPS 46-3). DES is cryptographically
// broken; goish ships it for protocol compatibility (NTLM, legacy
// Kerberos, PKCS#12) and to round out the symmetric-cipher surface.
//
// Deviations from cipher.go @ Go 1.25.5:
//
//   * `NewCipher` / `NewTripleDESCipher` return `(Option<Cipher>, error)`
//     / `(Option<TripleDESCipher>, error)`; Go returns
//     `(cipher.Block, error)`. Goish has no nullable trait object, so
//     `Option<T>` carries the value (or `None` on error), matching
//     crypto::aes and crypto::rc4.
//   * `desCipher` / `tripleDESCipher` are exported as `Cipher` /
//     `TripleDESCipher`: the Go constructors return them behind the
//     `cipher.Block` interface, which goish cannot do for a value type.
//   * No `fips140only.Enabled` branch — goish has no FIPS 140-only mode
//     (DES is unconditionally rejected upstream when that flag is on).
//   * No `alias.InexactOverlap` panic — goish `slice<T>` does not expose
//     the pointer arithmetic that check needs.
//   * `Cipher` / `TripleDESCipher` are value types; `cipher::Block` takes
//     `&self`, matching Go's `*desCipher` receiver (round keys are
//     immutable after key setup).

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use crate::crypto::cipher::Block as BlockTrait;
use crate::errors::{ErrorTrait, Wrap, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strconv;
use crate::types::{byte, int};

use super::block::{
    bePutUint64, beUint64, cryptBlock, feistel, generateSubkeys, permuteFinalBlock,
    permuteInitialBlock,
};

// Go: cipher.go:17 — const BlockSize = 8.
/// The DES block size in bytes.
pub const BlockSize: int = 8;

// Go: cipher.go:19 — type KeySizeError int.
/// `des.KeySizeError` — error returned by `NewCipher` /
/// `NewTripleDESCipher` when the supplied key length is wrong (8 for
/// DES, 24 for 3DES).
#[derive(Clone)]
pub struct KeySizeError(pub int);

impl ErrorTrait for KeySizeError {
    // go: sdk 1.25.5 crypto/des/cipher.go:21-23 Error
    //   func (k KeySizeError) Error() string {
    //       return "crypto/des: invalid key size " + strconv.Itoa(int(k))
    //   }
    fn Error(&self) -> string {
        let mut s = string::from_static("crypto/des: invalid key size ");
        s = s + strconv::Itoa(self.0);
        s
    }
}

// go: sdk 1.25.5 crypto/des/cipher.go:26-28 desCipher
//
//   type desCipher struct {
//       subkeys [16]uint64
//   }
/// `des.Cipher` — a single-DES key schedule (Go: unexported `desCipher`,
/// returned behind `cipher.Block`). Build one with `NewCipher`.
#[derive(Clone)]
pub struct Cipher {
    pub(crate) subkeys: [u64; 16],
}

// go: sdk 1.25.5 crypto/des/cipher.go:31-43 NewCipher
//
//   func NewCipher(key []byte) (cipher.Block, error) {
//       if fips140only.Enabled { ... }
//       if len(key) != 8 { return nil, KeySizeError(len(key)) }
//       c := new(desCipher)
//       c.generateSubkeys(key)
//       return c, nil
//   }
/// `des.NewCipher` — create a new DES `cipher::Block`. The key must be
/// exactly 8 bytes; otherwise a `KeySizeError` is returned.
pub fn NewCipher(key: slice<byte>) -> (Option<Cipher>, error) {
    // Go: cipher.go:36 — if len(key) != 8 { return nil, KeySizeError(len(key)) }
    if key.Len() != 8 {
        return (None, Wrap(KeySizeError(key.Len())));
    }
    let mut c = Cipher { subkeys: [0u64; 16] };
    generateSubkeys(&mut c, &key);
    (Some(c), nil)
}

impl BlockTrait for Cipher {
    // go: sdk 1.25.5 crypto/des/cipher.go:45-45 BlockSize
    // Go: cipher.go:45 — func (c *desCipher) BlockSize() int { return BlockSize }
    fn BlockSize(&self) -> int {
        BlockSize
    }

    // go: sdk 1.25.5 crypto/des/cipher.go:47-58 Encrypt
    //   func (c *desCipher) Encrypt(dst, src []byte) {
    //       if len(src) < BlockSize { panic("crypto/des: input not full block") }
    //       if len(dst) < BlockSize { panic("crypto/des: output not full block") }
    //       cryptBlock(c.subkeys[:], dst, src, false)
    //   }
    fn Encrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        if src.Len() < BlockSize {
            panic!("crypto/des: input not full block");
        }
        if dst.Len() < BlockSize {
            panic!("crypto/des: output not full block");
        }
        cryptBlock(&self.subkeys, dst, &src, false);
    }

    // go: sdk 1.25.5 crypto/des/cipher.go:60-71 Decrypt
    //   func (c *desCipher) Decrypt(dst, src []byte) {
    //       if len(src) < BlockSize { panic("crypto/des: input not full block") }
    //       if len(dst) < BlockSize { panic("crypto/des: output not full block") }
    //       cryptBlock(c.subkeys[:], dst, src, true)
    //   }
    fn Decrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        if src.Len() < BlockSize {
            panic!("crypto/des: input not full block");
        }
        if dst.Len() < BlockSize {
            panic!("crypto/des: output not full block");
        }
        cryptBlock(&self.subkeys, dst, &src, true);
    }
}

// ─── tripleDESCipher ────────────────────────────────────────────────

// Go: cipher.go:74
//   type tripleDESCipher struct {
//       cipher1, cipher2, cipher3 desCipher
//   }
/// `des.TripleDESCipher` — three-key 3DES (EDE) key schedule. Use
/// `NewTripleDESCipher` to build one. Implements `cipher::Block`.
#[derive(Clone)]
pub struct TripleDESCipher {
    cipher1: Cipher,
    cipher2: Cipher,
    cipher3: Cipher,
}

// go: sdk 1.25.5 crypto/des/cipher.go:79-93 NewTripleDESCipher
//   func NewTripleDESCipher(key []byte) (cipher.Block, error) {
//       if fips140only.Enabled { ... }
//       if len(key) != 24 { return nil, KeySizeError(len(key)) }
//       c := new(tripleDESCipher)
//       c.cipher1.generateSubkeys(key[:8])
//       c.cipher2.generateSubkeys(key[8:16])
//       c.cipher3.generateSubkeys(key[16:])
//       return c, nil
//   }
/// `des.NewTripleDESCipher` — creates and returns a new 3DES
/// `cipher::Block`. The key must be exactly 24 bytes (three 8-byte
/// DES sub-keys concatenated); otherwise a `KeySizeError` is returned.
pub fn NewTripleDESCipher(key: slice<byte>) -> (Option<TripleDESCipher>, error) {
    // Go: cipher.go:84 — if len(key) != 24 { return nil, KeySizeError(len(key)) }
    if key.Len() != 24 {
        return (None, Wrap(KeySizeError(key.Len())));
    }
    let mut c = TripleDESCipher {
        cipher1: Cipher { subkeys: [0u64; 16] },
        cipher2: Cipher { subkeys: [0u64; 16] },
        cipher3: Cipher { subkeys: [0u64; 16] },
    };
    let k1 = key.slice(0, 8);
    let k2 = key.slice(8, 16);
    let k3 = key.slice(16, 24);
    generateSubkeys(&mut c.cipher1, &k1);
    generateSubkeys(&mut c.cipher2, &k2);
    generateSubkeys(&mut c.cipher3, &k3);
    (Some(c), nil)
}

impl BlockTrait for TripleDESCipher {
    // go: sdk 1.25.5 crypto/des/cipher.go:95-95
    // Go: cipher.go:95 — func (c *tripleDESCipher) BlockSize() int { return BlockSize }
    fn BlockSize(&self) -> int {
        BlockSize
    }

    // go: sdk 1.25.5 crypto/des/cipher.go:97-97
    // Go: cipher.go:97 — Encrypt: 8 rounds c1 forward, 8 rounds c2
    //   reversed, 8 rounds c3 forward.
    fn Encrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        if src.Len() < BlockSize {
            panic!("crypto/des: input not full block");
        }
        if dst.Len() < BlockSize {
            panic!("crypto/des: output not full block");
        }

        // Go: cipher.go:108 — b := byteorder.BEUint64(src)
        let mut b = beUint64(&src);
        // Go: cipher.go:109 — b = permuteInitialBlock(b)
        b = permuteInitialBlock(b);
        // Go: cipher.go:110 — left, right := uint32(b>>32), uint32(b)
        let mut left = (b >> 32) as u32;
        let mut right = b as u32;

        // Go: cipher.go:112 — left = (left << 1) | (left >> 31); right = ...
        left = (left << 1) | (left >> 31);
        right = (right << 1) | (right >> 31);

        // Go: cipher.go:115 — c1 forward
        for i in 0..8usize {
            let (l, r) = feistel(
                left,
                right,
                self.cipher1.subkeys[2 * i],
                self.cipher1.subkeys[2 * i + 1],
            );
            left = l;
            right = r;
        }
        // Go: cipher.go:118 — c2 reversed (swap left/right)
        for i in 0..8usize {
            let (r2, l2) = feistel(
                right,
                left,
                self.cipher2.subkeys[15 - 2 * i],
                self.cipher2.subkeys[15 - (2 * i + 1)],
            );
            right = r2;
            left = l2;
        }
        // Go: cipher.go:121 — c3 forward
        for i in 0..8usize {
            let (l, r) = feistel(
                left,
                right,
                self.cipher3.subkeys[2 * i],
                self.cipher3.subkeys[2 * i + 1],
            );
            left = l;
            right = r;
        }

        // Go: cipher.go:125 — left = (left << 31) | (left >> 1); right = ...
        left = (left << 31) | (left >> 1);
        right = (right << 31) | (right >> 1);

        // Go: cipher.go:128 — preOutput := (uint64(right) << 32) | uint64(left)
        let preOutput: u64 = ((right as u64) << 32) | (left as u64);
        // Go: cipher.go:129 — byteorder.BEPutUint64(dst, permuteFinalBlock(preOutput))
        bePutUint64(dst, permuteFinalBlock(preOutput));
    }

    // go: sdk 1.25.5 crypto/des/cipher.go:132-132
    // Go: cipher.go:132 — Decrypt: c3 reversed, c2 forward, c1 reversed.
    fn Decrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        if src.Len() < BlockSize {
            panic!("crypto/des: input not full block");
        }
        if dst.Len() < BlockSize {
            panic!("crypto/des: output not full block");
        }

        let mut b = beUint64(&src);
        b = permuteInitialBlock(b);
        let mut left = (b >> 32) as u32;
        let mut right = b as u32;

        left = (left << 1) | (left >> 31);
        right = (right << 1) | (right >> 31);

        // Go: cipher.go:150 — c3 reversed
        for i in 0..8usize {
            let (l, r) = feistel(
                left,
                right,
                self.cipher3.subkeys[15 - 2 * i],
                self.cipher3.subkeys[15 - (2 * i + 1)],
            );
            left = l;
            right = r;
        }
        // Go: cipher.go:153 — c2 forward (swap)
        for i in 0..8usize {
            let (r2, l2) = feistel(
                right,
                left,
                self.cipher2.subkeys[2 * i],
                self.cipher2.subkeys[2 * i + 1],
            );
            right = r2;
            left = l2;
        }
        // Go: cipher.go:156 — c1 reversed
        for i in 0..8usize {
            let (l, r) = feistel(
                left,
                right,
                self.cipher1.subkeys[15 - 2 * i],
                self.cipher1.subkeys[15 - (2 * i + 1)],
            );
            left = l;
            right = r;
        }

        left = (left << 31) | (left >> 1);
        right = (right << 31) | (right >> 1);

        let preOutput: u64 = ((right as u64) << 32) | (left as u64);
        bePutUint64(dst, permuteFinalBlock(preOutput));
    }
}
