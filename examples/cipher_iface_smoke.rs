// cipher_iface_smoke — exercise crypto/cipher trait declarations.
//
// Proves the four trait shapes (Block, Stream, BlockMode, AEAD) are
// usable as bounds and that fake impls satisfy each contract.
//
// References:
//   /share/go/src/crypto/cipher/cipher.go (interfaces)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::crypto::cipher::{AEAD, Block, BlockMode, Stream};
use goish::errors::{error, nil};
use goish::types::{byte, int};
use goish::{slice, syscall, Println};

// ─── Fake Block — XOR each byte with a fixed key byte. ──────────────────
struct XorBlock {
    key: byte,
    block_size: int,
}

impl Block for XorBlock {
    fn BlockSize(&self) -> int {
        self.block_size
    }

    fn Encrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        let n = self.block_size;
        for i in 0..n {
            dst[i] = src[i] ^ self.key;
        }
    }

    fn Decrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        // XOR is symmetric.
        let n = self.block_size;
        for i in 0..n {
            dst[i] = src[i] ^ self.key;
        }
    }
}

// ─── Fake Stream — running counter XORed in. ────────────────────────────
struct CounterStream {
    counter: byte,
}

impl Stream for CounterStream {
    fn XORKeyStream(&mut self, dst: &mut slice<byte>, src: slice<byte>) {
        let n = src.Len();
        for i in 0..n {
            dst[i] = src[i] ^ self.counter;
            self.counter = self.counter.wrapping_add(1);
        }
    }
}

// ─── Fake BlockMode — XOR every byte with the running key. ──────────────
struct XorBlockMode {
    key: byte,
    block_size: int,
}

impl BlockMode for XorBlockMode {
    fn BlockSize(&self) -> int {
        self.block_size
    }

    fn CryptBlocks(&mut self, dst: &mut slice<byte>, src: slice<byte>) {
        let n = src.Len();
        for i in 0..n {
            dst[i] = src[i] ^ self.key;
        }
    }
}

// ─── Fake AEAD — append payload XORed with key, prepend tag. ────────────
struct ToyAEAD {
    key: byte,
}

impl AEAD for ToyAEAD {
    fn NonceSize(&self) -> int {
        4
    }

    fn Overhead(&self) -> int {
        1 // single tag byte
    }

    fn Seal(
        &self,
        dst: slice<byte>,
        _nonce: slice<byte>,
        plaintext: slice<byte>,
        _additionalData: slice<byte>,
    ) -> slice<byte> {
        let mut v: alloc::vec::Vec<byte> = dst.__into_vec();
        // tag byte = key
        v.push(self.key);
        // ciphertext = plaintext XOR key
        let n = plaintext.Len();
        for i in 0..n {
            v.push(plaintext[i] ^ self.key);
        }
        slice::__from_vec(v)
    }

    fn Open(
        &self,
        dst: slice<byte>,
        _nonce: slice<byte>,
        ciphertext: slice<byte>,
        _additionalData: slice<byte>,
    ) -> (slice<byte>, error) {
        if ciphertext.Len() < 1 {
            return (
                slice::new(),
                goish::errors::New("toy AEAD: ciphertext too short"),
            );
        }
        if ciphertext[0] != self.key {
            return (
                slice::new(),
                goish::errors::New("toy AEAD: bad tag"),
            );
        }
        let mut v: alloc::vec::Vec<byte> = dst.__into_vec();
        let n = ciphertext.Len();
        for i in 1..n {
            v.push(ciphertext[i] ^ self.key);
        }
        (slice::__from_vec(v), nil.into())
    }
}

// ─── Generic helpers — prove the traits work as bounds. ─────────────────
fn block_size_of<B: Block>(b: &B) -> int {
    b.BlockSize()
}

fn nonce_size_of<A: AEAD>(a: &A) -> int {
    a.NonceSize()
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Block::Encrypt + Decrypt round-trip via generic bound.
    {
        let b = XorBlock { key: 0x5A, block_size: 4 };
        if block_size_of(&b) != 4 {
            Println!("[ 1] Block::BlockSize bound      FAIL");
            failed += 1;
        } else {
            let src: slice<byte> =
                slice::__from_vec(alloc::vec![0x10, 0x20, 0x30, 0x40]);
            let mut enc: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; 4]);
            b.Encrypt(&mut enc, src.clone());
            let mut dec: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; 4]);
            b.Decrypt(&mut dec, enc);
            let dec_v: alloc::vec::Vec<byte> = dec.__into_vec();
            let src_v: alloc::vec::Vec<byte> = src.__into_vec();
            if dec_v == src_v {
                Println!("[ 1] Block enc/dec RT           PASS");
            } else {
                Println!("[ 1] Block enc/dec RT           FAIL");
                failed += 1;
            }
        }
    }

    // 2. Stream::XORKeyStream advances internal state.
    {
        let mut s = CounterStream { counter: 0 };
        let src: slice<byte> =
            slice::__from_vec(alloc::vec![0u8; 4]);
        let mut dst: slice<byte> =
            slice::__from_vec(alloc::vec![0u8; 4]);
        s.XORKeyStream(&mut dst, src);
        let dst_v: alloc::vec::Vec<byte> = dst.__into_vec();
        let want: alloc::vec::Vec<byte> = alloc::vec![0, 1, 2, 3];
        if dst_v != want {
            Println!("[ 2] Stream first call          FAIL");
            failed += 1;
        } else {
            // Second call must continue counter from 4, not reset.
            let src2: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; 3]);
            let mut dst2: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; 3]);
            s.XORKeyStream(&mut dst2, src2);
            let dst2_v: alloc::vec::Vec<byte> = dst2.__into_vec();
            let want2: alloc::vec::Vec<byte> = alloc::vec![4, 5, 6];
            if dst2_v == want2 {
                Println!("[ 2] Stream maintains state     PASS");
            } else {
                Println!("[ 2] Stream maintains state     FAIL");
                failed += 1;
            }
        }
    }

    // 3. BlockMode round-trip + BlockSize().
    {
        let mut m = XorBlockMode { key: 0xA5, block_size: 8 };
        if m.BlockSize() != 8 {
            Println!("[ 3] BlockMode::BlockSize       FAIL");
            failed += 1;
        } else {
            let src: slice<byte> = slice::__from_vec(
                alloc::vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            );
            let mut enc: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; 8]);
            m.CryptBlocks(&mut enc, src.clone());
            // XOR is symmetric — encrypting again yields plaintext.
            let mut dec: slice<byte> =
                slice::__from_vec(alloc::vec![0u8; 8]);
            m.CryptBlocks(&mut dec, enc);
            if dec.__into_vec() == src.__into_vec() {
                Println!("[ 3] BlockMode XOR RT           PASS");
            } else {
                Println!("[ 3] BlockMode XOR RT           FAIL");
                failed += 1;
            }
        }
    }

    // 4. AEAD::Seal + Open round-trip via generic bound.
    {
        let a = ToyAEAD { key: 0x42 };
        if nonce_size_of(&a) != 4 || a.Overhead() != 1 {
            Println!("[ 4] AEAD sizes                 FAIL");
            failed += 1;
        } else {
            let nonce: slice<byte> =
                slice::__from_vec(alloc::vec![1, 2, 3, 4]);
            let plain: slice<byte> =
                slice::__from_vec(alloc::vec![b'h', b'i', b'!']);
            let aad: slice<byte> = slice::new();
            let ct = a.Seal(slice::new(), nonce.clone(), plain.clone(), aad.clone());
            let (got, err) = a.Open(slice::new(), nonce, ct, aad);
            if err.IsNil() && got.__into_vec() == plain.__into_vec() {
                Println!("[ 4] AEAD seal/open RT          PASS");
            } else {
                Println!("[ 4] AEAD seal/open RT          FAIL");
                failed += 1;
            }
        }
    }

    // 5. AEAD::Seal preserves dst prefix (Go contract — appends).
    {
        let a = ToyAEAD { key: 0x42 };
        let prefix: slice<byte> =
            slice::__from_vec(alloc::vec![b'>', b' ']);
        let plain: slice<byte> = slice::__from_vec(alloc::vec![b'X']);
        let nonce: slice<byte> =
            slice::__from_vec(alloc::vec![0, 0, 0, 0]);
        let aad: slice<byte> = slice::new();
        let out = a.Seal(prefix, nonce, plain, aad);
        let out_v: alloc::vec::Vec<byte> = out.__into_vec();
        // First two bytes must still be the prefix.
        if out_v.len() == 4 && out_v[0] == b'>' && out_v[1] == b' ' {
            Println!("[ 5] AEAD::Seal preserves dst   PASS");
        } else {
            Println!("[ 5] AEAD::Seal preserves dst   FAIL");
            failed += 1;
        }
    }

    // 6. AEAD::Open returns error on bad tag.
    {
        let a = ToyAEAD { key: 0x42 };
        let nonce: slice<byte> =
            slice::__from_vec(alloc::vec![0, 0, 0, 0]);
        let bad: slice<byte> =
            slice::__from_vec(alloc::vec![0x00, b'X']);
        let aad: slice<byte> = slice::new();
        let (_got, err) = a.Open(slice::new(), nonce, bad, aad);
        if !err.IsNil() {
            Println!("[ 6] AEAD::Open bad tag → err   PASS");
        } else {
            Println!("[ 6] AEAD::Open bad tag → err   FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
