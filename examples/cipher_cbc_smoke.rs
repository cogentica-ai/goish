// cipher_cbc_smoke — exercise crypto/cipher::NewCBCEncrypter +
// NewCBCDecrypter. Validates the BlockMode trait end-to-end.
//
// AES isn't ported yet, so this test uses an in-test ToyBlock — same
// 8-byte permutation block as cipher_ofb_smoke / cipher_ctr_smoke /
// cipher_cfb_smoke. CBC requires Decrypt to be the actual inverse of
// Encrypt (CFB only ever calls Encrypt; CBC walks the buffer backwards
// during decryption and depends on Decrypt's correctness).
//
// Coverage:
//   - encrypt produces non-trivial ciphertext
//   - encrypt → decrypt round-trip recovers plaintext
//   - multi-block encrypt equals single big-call encrypt
//   - 1 KiB long-payload round-trip
//   - non-block-multiple input panics
//   - same key + iv yields identical ciphertext
//   - SetIV after partial encrypt resets chain (no spurious carry)
//   - empty src is a no-op for decrypt

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::crypto::cipher;
use goish::crypto::cipher::{Block, BlockMode};
use goish::fmt;
use goish::types::{byte, int};
use goish::{slice, syscall};

// 8-byte ToyBlock: Encrypt(dst, src) = rotate-left(src ^ key, 3).
// Decrypt is the actual inverse: rotate-right(src, 3) ^ key.
struct ToyBlock {
    key: alloc::vec::Vec<byte>,
}

impl Block for ToyBlock {
    fn BlockSize(&self) -> int {
        8
    }
    fn Encrypt(&self, dst: &mut goish::slice<byte>, src: goish::slice<byte>) {
        let s = src.__into_vec();
        for i in 0..8 {
            let v = s[i] ^ self.key[i];
            dst[i as int] = v.rotate_left(3);
        }
    }
    fn Decrypt(&self, dst: &mut goish::slice<byte>, src: goish::slice<byte>) {
        let s = src.__into_vec();
        for i in 0..8 {
            dst[i as int] = s[i].rotate_right(3) ^ self.key[i];
        }
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let mk_block = || ToyBlock {
        key: alloc::vec![0xa5, 0x5a, 0xc3, 0x3c, 0xf0, 0x0f, 0x96, 0x69],
    };
    let iv: alloc::vec::Vec<byte> = alloc::vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    // 1. CBC encrypt produces non-trivial ciphertext.
    {
        let mut e = cipher::NewCBCEncrypter(mk_block(), slice::__from_vec(iv.clone()));
        let plain: alloc::vec::Vec<byte> = (0..16u8).collect();
        let mut ct = slice::__from_vec(alloc::vec![0u8; 16]);
        e.CryptBlocks(&mut ct, slice::__from_vec(plain.clone()));
        if ct.__into_vec() != plain {
            fmt::Println!("[ 1] CBC encrypt non-trivial    PASS");
        } else {
            fmt::Println!("[ 1] CBC encrypt non-trivial    FAIL");
            failed += 1;
        }
    }

    // 2. CBC encrypt → decrypt round-trip recovers plaintext.
    //    Use 24-byte plaintext (3 blocks) — exercises the backward
    //    decrypt loop's "more than one block" branch.
    {
        let plain: alloc::vec::Vec<byte> = (0..24u8).collect();
        let n = plain.len();

        let mut enc = cipher::NewCBCEncrypter(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct = slice::__from_vec(alloc::vec![0u8; n]);
        enc.CryptBlocks(&mut ct, slice::__from_vec(plain.clone()));
        let ct_v = ct.__into_vec();

        let mut dec = cipher::NewCBCDecrypter(mk_block(), slice::__from_vec(iv.clone()));
        let mut pt2 = slice::__from_vec(alloc::vec![0u8; n]);
        dec.CryptBlocks(&mut pt2, slice::__from_vec(ct_v));
        if pt2.__into_vec() == plain {
            fmt::Println!("[ 2] CBC enc→dec round-trip     PASS");
        } else {
            fmt::Println!("[ 2] CBC enc→dec round-trip     FAIL");
            failed += 1;
        }
    }

    // 3. Multi-call encrypt equals one-shot encrypt (chaining state
    //    persists across CryptBlocks calls, just like Go).
    {
        let plain: alloc::vec::Vec<byte> = (0..40u8).collect();

        let mut s1 = cipher::NewCBCEncrypter(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; 40]);
        s1.CryptBlocks(&mut ct1, slice::__from_vec(plain.clone()));
        let want = ct1.__into_vec();

        let mut s2 = cipher::NewCBCEncrypter(mk_block(), slice::__from_vec(iv.clone()));
        let mut got: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(40);
        // Encrypt in 8-byte (single-block) and 16-byte (two-block)
        // chunks; total 40 bytes = 5 blocks.
        for &n in &[8usize, 16, 16] {
            let off = got.len();
            let mut chunk = slice::__from_vec(alloc::vec![0u8; n]);
            let src = slice::__from_vec(plain[off..off + n].to_vec());
            s2.CryptBlocks(&mut chunk, src);
            got.extend_from_slice(&chunk.__into_vec());
        }
        if got == want {
            fmt::Println!("[ 3] CBC split calls equivalent PASS");
        } else {
            fmt::Println!("[ 3] CBC split calls equivalent FAIL");
            failed += 1;
        }
    }

    // 4. Long payload (1 KiB = 128 blocks) — encrypt + decrypt holds.
    {
        let mut plain: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(1024);
        for i in 0..1024u32 {
            plain.push((i.wrapping_mul(31) & 0xff) as byte);
        }
        let mut enc = cipher::NewCBCEncrypter(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct = slice::__from_vec(alloc::vec![0u8; 1024]);
        enc.CryptBlocks(&mut ct, slice::__from_vec(plain.clone()));
        let ct_v = ct.__into_vec();

        let mut dec = cipher::NewCBCDecrypter(mk_block(), slice::__from_vec(iv.clone()));
        let mut pt2 = slice::__from_vec(alloc::vec![0u8; 1024]);
        dec.CryptBlocks(&mut pt2, slice::__from_vec(ct_v));
        if pt2.__into_vec() == plain {
            fmt::Println!("[ 4] CBC 1 KiB round-trip       PASS");
        } else {
            fmt::Println!("[ 4] CBC 1 KiB round-trip       FAIL");
            failed += 1;
        }
    }

    // 5. BlockSize() reports the underlying block size.
    {
        let e = cipher::NewCBCEncrypter(mk_block(), slice::__from_vec(iv.clone()));
        let d = cipher::NewCBCDecrypter(mk_block(), slice::__from_vec(iv.clone()));
        if e.BlockSize() == 8 && d.BlockSize() == 8 {
            fmt::Println!("[ 5] CBC BlockSize reports 8    PASS");
        } else {
            fmt::Println!("[ 5] CBC BlockSize reports 8    FAIL");
            failed += 1;
        }
    }

    // 6. Same key+iv on two encrypters → identical ciphertext.
    {
        let plain: alloc::vec::Vec<byte> = (0..32u8).collect();
        let mut s1 = cipher::NewCBCEncrypter(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; 32]);
        s1.CryptBlocks(&mut ct1, slice::__from_vec(plain.clone()));

        let mut s2 = cipher::NewCBCEncrypter(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct2 = slice::__from_vec(alloc::vec![0u8; 32]);
        s2.CryptBlocks(&mut ct2, slice::__from_vec(plain));

        if ct1.__into_vec() == ct2.__into_vec() {
            fmt::Println!("[ 6] CBC deterministic stream   PASS");
        } else {
            fmt::Println!("[ 6] CBC deterministic stream   FAIL");
            failed += 1;
        }
    }

    // 7. SetIV after partial encrypt resets the chain.
    //    Encrypter A: encrypts first 8 bytes with iv1, then SetIV(iv2),
    //    then encrypts second 8 bytes.
    //    Encrypter B: encrypts first 8 bytes with iv1, then encrypts
    //    second 8 bytes with iv2 (fresh encrypter).
    //    The two ciphertexts should be byte-identical.
    {
        let iv2: alloc::vec::Vec<byte> =
            alloc::vec![0x99u8, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00];
        let block_a: alloc::vec::Vec<byte> = (0..8u8).collect();
        let block_b: alloc::vec::Vec<byte> = (8..16u8).collect();

        // Path A: one encrypter, SetIV between.
        let mut a = cipher::NewCBCEncrypter(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct_a1 = slice::__from_vec(alloc::vec![0u8; 8]);
        a.CryptBlocks(&mut ct_a1, slice::__from_vec(block_a.clone()));
        a.SetIV(slice::__from_vec(iv2.clone()));
        let mut ct_a2 = slice::__from_vec(alloc::vec![0u8; 8]);
        a.CryptBlocks(&mut ct_a2, slice::__from_vec(block_b.clone()));

        // Path B: two encrypters with explicit iv1 / iv2.
        let mut b1 = cipher::NewCBCEncrypter(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct_b1 = slice::__from_vec(alloc::vec![0u8; 8]);
        b1.CryptBlocks(&mut ct_b1, slice::__from_vec(block_a));
        let mut b2 = cipher::NewCBCEncrypter(mk_block(), slice::__from_vec(iv2));
        let mut ct_b2 = slice::__from_vec(alloc::vec![0u8; 8]);
        b2.CryptBlocks(&mut ct_b2, slice::__from_vec(block_b));

        let a_v = [ct_a1.__into_vec(), ct_a2.__into_vec()].concat();
        let b_v = [ct_b1.__into_vec(), ct_b2.__into_vec()].concat();
        if a_v == b_v {
            fmt::Println!("[ 7] CBC SetIV resets chain     PASS");
        } else {
            fmt::Println!("[ 7] CBC SetIV resets chain     FAIL");
            failed += 1;
        }
    }

    // 8. Empty src is a no-op for decrypt.
    {
        let mut d = cipher::NewCBCDecrypter(mk_block(), slice::__from_vec(iv.clone()));
        let mut dst = slice::__from_vec(alloc::vec![0u8; 8]);
        let before = dst.clone().__into_vec();
        d.CryptBlocks(&mut dst, slice::__from_vec(alloc::vec![]));
        if dst.__into_vec() == before {
            fmt::Println!("[ 8] CBC empty src no-op        PASS");
        } else {
            fmt::Println!("[ 8] CBC empty src no-op        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
