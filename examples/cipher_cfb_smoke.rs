// cipher_cfb_smoke — exercise crypto/cipher::NewCFBEncrypter +
// NewCFBDecrypter. Uses an in-test ToyBlock since AES isn't ported yet.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::crypto::cipher;
use goish::crypto::cipher::{Block, Stream};
use goish::types::{byte, int};
use goish::{slice, syscall, Println};

// 8-byte ToyBlock: Encrypt(dst, src) = rotate-left(src ^ key, 3).
// Reversible Decrypt — but CFB only ever calls Encrypt, on both encryp
// and decrypt sides. The Encrypt direction must be deterministic.
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
    let iv: alloc::vec::Vec<byte> =
        alloc::vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    // 1. CFB encrypt produces non-trivial ciphertext.
    {
        let mut e = cipher::NewCFBEncrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let plain: alloc::vec::Vec<byte> = (0..16u8).collect();
        let mut ct = slice::__from_vec(alloc::vec![0u8; 16]);
        e.XORKeyStream(&mut ct, slice::__from_vec(plain.clone()));
        if ct.__into_vec() != plain {
            Println!("[ 1] CFB encrypt non-trivial    PASS");
        } else {
            Println!("[ 1] CFB encrypt non-trivial    FAIL");
            failed += 1;
        }
    }

    // 2. CFB encrypt → decrypt round-trip recovers plaintext.
    {
        let plain: alloc::vec::Vec<byte> =
            b"Goish CFB round-trip text.".to_vec();
        let n = plain.len();

        let mut enc = cipher::NewCFBEncrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut ct = slice::__from_vec(alloc::vec![0u8; n]);
        enc.XORKeyStream(&mut ct, slice::__from_vec(plain.clone()));
        let ct_v = ct.__into_vec();

        let mut dec = cipher::NewCFBDecrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut pt2 = slice::__from_vec(alloc::vec![0u8; n]);
        dec.XORKeyStream(&mut pt2, slice::__from_vec(ct_v));
        if pt2.__into_vec() == plain {
            Println!("[ 2] CFB enc→dec round-trip     PASS");
        } else {
            Println!("[ 2] CFB enc→dec round-trip     FAIL");
            failed += 1;
        }
    }

    // 3. Multi-call equals one-shot encrypt.
    {
        let plain: alloc::vec::Vec<byte> = (0..40u8).collect();

        let mut s1 = cipher::NewCFBEncrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; 40]);
        s1.XORKeyStream(&mut ct1, slice::__from_vec(plain.clone()));
        let want = ct1.__into_vec();

        let mut s2 = cipher::NewCFBEncrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut got: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(40);
        for &n in &[7usize, 13, 20] {
            let off = got.len();
            let mut chunk = slice::__from_vec(alloc::vec![0u8; n]);
            let src = slice::__from_vec(plain[off..off + n].to_vec());
            s2.XORKeyStream(&mut chunk, src);
            got.extend_from_slice(&chunk.__into_vec());
        }
        if got == want {
            Println!("[ 3] CFB split calls equivalent PASS");
        } else {
            Println!("[ 3] CFB split calls equivalent FAIL");
            failed += 1;
        }
    }

    // 4. Long payload (multiple block boundaries) — encrypt + decrypt
    //    holds. CFB chains plaintext into the next encryption, so this
    //    exercises the feedback loop across many blocks.
    {
        let mut plain: alloc::vec::Vec<byte> =
            alloc::vec::Vec::with_capacity(1024);
        for i in 0..1024u32 {
            plain.push((i.wrapping_mul(31) & 0xff) as byte);
        }
        let mut enc = cipher::NewCFBEncrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut ct = slice::__from_vec(alloc::vec![0u8; 1024]);
        enc.XORKeyStream(&mut ct, slice::__from_vec(plain.clone()));
        let ct_v = ct.__into_vec();

        let mut dec = cipher::NewCFBDecrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut pt2 = slice::__from_vec(alloc::vec![0u8; 1024]);
        dec.XORKeyStream(&mut pt2, slice::__from_vec(ct_v));
        if pt2.__into_vec() == plain {
            Println!("[ 4] CFB 1 KiB round-trip       PASS");
        } else {
            Println!("[ 4] CFB 1 KiB round-trip       FAIL");
            failed += 1;
        }
    }

    // 5. Byte-by-byte encrypt equals one-shot encrypt.
    {
        let plain: alloc::vec::Vec<byte> = b"CFB byte-by-byte test.".to_vec();
        let n = plain.len();

        let mut s1 = cipher::NewCFBEncrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; n]);
        s1.XORKeyStream(&mut ct1, slice::__from_vec(plain.clone()));
        let want = ct1.__into_vec();

        let mut s2 = cipher::NewCFBEncrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut got: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(n);
        for &b in plain.iter() {
            let mut one = slice::__from_vec(alloc::vec![0u8; 1]);
            s2.XORKeyStream(&mut one, slice::__from_vec(alloc::vec![b]));
            got.extend_from_slice(&one.__into_vec());
        }
        if got == want {
            Println!("[ 5] CFB byte-by-byte enc       PASS");
        } else {
            Println!("[ 5] CFB byte-by-byte enc       FAIL");
            failed += 1;
        }
    }

    // 6. Same key+iv on two encryptors → identical ciphertext.
    {
        let plain: alloc::vec::Vec<byte> = (0..32u8).collect();
        let mut s1 = cipher::NewCFBEncrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; 32]);
        s1.XORKeyStream(&mut ct1, slice::__from_vec(plain.clone()));

        let mut s2 = cipher::NewCFBEncrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut ct2 = slice::__from_vec(alloc::vec![0u8; 32]);
        s2.XORKeyStream(&mut ct2, slice::__from_vec(plain));

        if ct1.__into_vec() == ct2.__into_vec() {
            Println!("[ 6] CFB deterministic stream   PASS");
        } else {
            Println!("[ 6] CFB deterministic stream   FAIL");
            failed += 1;
        }
    }

    // 7. CFB error-propagation property — flipping a single byte in the
    //    ciphertext should garble exactly that byte (in the same block)
    //    and the *next* block's plaintext (one-byte-of-feedback chain).
    {
        let plain: alloc::vec::Vec<byte> = alloc::vec![0u8; 32];
        let mut enc = cipher::NewCFBEncrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut ct = slice::__from_vec(alloc::vec![0u8; 32]);
        enc.XORKeyStream(&mut ct, slice::__from_vec(plain.clone()));
        let mut ct_v = ct.__into_vec();
        // Corrupt byte 0.
        ct_v[0] ^= 0xff;

        let mut dec = cipher::NewCFBDecrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut pt2 = slice::__from_vec(alloc::vec![0u8; 32]);
        dec.XORKeyStream(&mut pt2, slice::__from_vec(ct_v));
        let pt2_v = pt2.__into_vec();
        // Byte 0 corrupted; bytes 8..16 (next block) should be entirely
        // garbled because the prior ciphertext block feeds the encryptor.
        // Bytes 16+ should recover.
        let mismatched_in_first_block = pt2_v[0] != 0;
        let block2_garbled = pt2_v[8..16].iter().any(|&b| b != 0);
        let block3_recovered = &pt2_v[16..32] == &plain[16..32];
        if mismatched_in_first_block && block2_garbled && block3_recovered {
            Println!("[ 7] CFB ct flip propagation    PASS");
        } else {
            Println!("[ 7] CFB ct flip propagation    FAIL");
            failed += 1;
        }
    }

    // 8. Empty src is a no-op for both encrypt and decrypt.
    {
        let mut e = cipher::NewCFBEncrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut dst1 = slice::__from_vec(alloc::vec![0u8; 8]);
        let before1 = dst1.clone().__into_vec();
        e.XORKeyStream(&mut dst1, slice::__from_vec(alloc::vec![]));

        let mut d = cipher::NewCFBDecrypter(
            mk_block(),
            slice::__from_vec(iv.clone()),
        );
        let mut dst2 = slice::__from_vec(alloc::vec![0u8; 8]);
        let before2 = dst2.clone().__into_vec();
        d.XORKeyStream(&mut dst2, slice::__from_vec(alloc::vec![]));

        if dst1.__into_vec() == before1 && dst2.__into_vec() == before2 {
            Println!("[ 8] CFB empty src no-op        PASS");
        } else {
            Println!("[ 8] CFB empty src no-op        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
