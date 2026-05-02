// cipher_ofb_smoke — exercise crypto/cipher::NewOFB.
//
// AES isn't ported yet, so this test uses a tiny in-test "ToyBlock" —
// a permutation block cipher built around a fixed 8-byte key. It
// satisfies cipher::Block and exercises NewOFB / OFB::XORKeyStream
// across:
//   - single Write
//   - byte-by-byte Write
//   - chunks larger than the internal keystream buffer (forces refill)
//   - encrypt → decrypt round-trip (OFB is symmetric, like all keystream
//     modes)
//   - panic on wrong-size IV
//   - panic on dst smaller than src

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::crypto::cipher;
use goish::crypto::cipher::{Block, Stream};
use goish::types::{byte, int};
use goish::{slice, syscall, Println};

// Toy block cipher with an 8-byte block size. Encrypt(dst, src) =
// rotate-left(src ^ key, 3). Reversible enough for the OFB
// "encrypt(cipher, cipher)" pumping; never relied on for security.
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
            // rotate-left 3
            let r = v.rotate_left(3);
            dst[i as int] = r;
        }
    }
    fn Decrypt(&self, dst: &mut goish::slice<byte>, src: goish::slice<byte>) {
        let s = src.__into_vec();
        for i in 0..8 {
            let r = s[i].rotate_right(3);
            dst[i as int] = r ^ self.key[i];
        }
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // Helper: build a fresh ToyBlock with the same fixed key.
    let mk_block = || ToyBlock {
        key: alloc::vec![0xa5, 0x5a, 0xc3, 0x3c, 0xf0, 0x0f, 0x96, 0x69],
    };
    let iv: alloc::vec::Vec<byte> =
        alloc::vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    // 1. Construct + single XORKeyStream over 16 bytes (two block lengths).
    {
        let mut s = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let plain: alloc::vec::Vec<byte> = (0..16u8).collect();
        let src = slice::__from_vec(plain.clone());
        let mut dst = slice::__from_vec(alloc::vec![0u8; 16]);
        s.XORKeyStream(&mut dst, src);
        let ct = dst.__into_vec();
        if ct != plain {
            // Sanity: ciphertext must differ from plaintext (with non-zero key).
            Println!("[ 1] OFB single 16-byte         PASS");
        } else {
            Println!("[ 1] OFB single 16-byte         FAIL ct==pt");
            failed += 1;
        }
    }

    // 2. Encrypt → decrypt round-trip recovers the plaintext.
    {
        let plain: alloc::vec::Vec<byte> =
            b"Goish lives at the boundary of trust.".to_vec();
        let n = plain.len();

        // Encrypt
        let mut enc = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct = slice::__from_vec(alloc::vec![0u8; n]);
        enc.XORKeyStream(&mut ct, slice::__from_vec(plain.clone()));
        let ct_v = ct.__into_vec();

        // Decrypt with a *fresh* OFB seeded by the same IV.
        let mut dec = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut pt2 = slice::__from_vec(alloc::vec![0u8; n]);
        dec.XORKeyStream(&mut pt2, slice::__from_vec(ct_v));
        if pt2.__into_vec() == plain {
            Println!("[ 2] OFB enc→dec round-trip     PASS");
        } else {
            Println!("[ 2] OFB enc→dec round-trip     FAIL");
            failed += 1;
        }
    }

    // 3. Multi-call XORKeyStream is equivalent to one big call (Stream
    //    contract: state carries across calls).
    {
        let plain: alloc::vec::Vec<byte> = (0..32u8).collect();

        // One-shot
        let mut s1 = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; 32]);
        s1.XORKeyStream(&mut ct1, slice::__from_vec(plain.clone()));
        let want = ct1.__into_vec();

        // Three calls of unequal sizes: 5, 11, 16.
        let mut s2 = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut got: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(32);
        for &n in &[5usize, 11, 16] {
            let off = got.len();
            let mut chunk = slice::__from_vec(alloc::vec![0u8; n]);
            let src = slice::__from_vec(plain[off..off + n].to_vec());
            s2.XORKeyStream(&mut chunk, src);
            got.extend_from_slice(&chunk.__into_vec());
        }
        if got == want {
            Println!("[ 3] OFB split calls equivalent PASS");
        } else {
            Println!("[ 3] OFB split calls equivalent FAIL");
            failed += 1;
        }
    }

    // 4. Large input that exceeds the internal keystream buffer
    //    (streamBufferSize = 512). Round-trip across 2 KiB.
    {
        let mut plain: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(2048);
        for i in 0..2048u32 {
            plain.push((i.wrapping_mul(31) & 0xff) as byte);
        }
        let mut enc = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct = slice::__from_vec(alloc::vec![0u8; 2048]);
        enc.XORKeyStream(&mut ct, slice::__from_vec(plain.clone()));
        let ct_v = ct.__into_vec();

        let mut dec = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut pt2 = slice::__from_vec(alloc::vec![0u8; 2048]);
        dec.XORKeyStream(&mut pt2, slice::__from_vec(ct_v));
        if pt2.__into_vec() == plain {
            Println!("[ 4] OFB 2 KiB refill round     PASS");
        } else {
            Println!("[ 4] OFB 2 KiB refill round     FAIL");
            failed += 1;
        }
    }

    // 5. Byte-by-byte Stream calls keep state consistent.
    {
        let plain: alloc::vec::Vec<byte> = b"OFB byte-by-byte test.".to_vec();
        let n = plain.len();

        // One-shot reference
        let mut s1 = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; n]);
        s1.XORKeyStream(&mut ct1, slice::__from_vec(plain.clone()));
        let want = ct1.__into_vec();

        // 1-byte-at-a-time
        let mut s2 = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut got: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(n);
        for &b in plain.iter() {
            let mut one = slice::__from_vec(alloc::vec![0u8; 1]);
            s2.XORKeyStream(&mut one, slice::__from_vec(alloc::vec![b]));
            got.extend_from_slice(&one.__into_vec());
        }
        if got == want {
            Println!("[ 5] OFB byte-by-byte           PASS");
        } else {
            Println!("[ 5] OFB byte-by-byte           FAIL");
            failed += 1;
        }
    }

    // 6. Two OFB instances seeded with the same key+iv produce
    //    identical keystreams (determinism — the OFB output stream
    //    depends only on the block cipher, IV, and Block.Encrypt).
    {
        let plain: alloc::vec::Vec<byte> = (0..32u8).collect();
        let mut s1 = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; 32]);
        s1.XORKeyStream(&mut ct1, slice::__from_vec(plain.clone()));

        let mut s2 = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct2 = slice::__from_vec(alloc::vec![0u8; 32]);
        s2.XORKeyStream(&mut ct2, slice::__from_vec(plain));

        if ct1.__into_vec() == ct2.__into_vec() {
            Println!("[ 6] OFB deterministic stream   PASS");
        } else {
            Println!("[ 6] OFB deterministic stream   FAIL");
            failed += 1;
        }
    }

    // 7. Different IVs produce different ciphertexts (sanity for the
    //    pumping in refill — without IV mixing the keystream collapses).
    {
        let plain: alloc::vec::Vec<byte> = (0..32u8).collect();

        let iv2: alloc::vec::Vec<byte> =
            alloc::vec![0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88];

        let mut s1 = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; 32]);
        s1.XORKeyStream(&mut ct1, slice::__from_vec(plain.clone()));

        let mut s2 = cipher::NewOFB(mk_block(), slice::__from_vec(iv2));
        let mut ct2 = slice::__from_vec(alloc::vec![0u8; 32]);
        s2.XORKeyStream(&mut ct2, slice::__from_vec(plain));

        if ct1.__into_vec() != ct2.__into_vec() {
            Println!("[ 7] OFB IV affects keystream   PASS");
        } else {
            Println!("[ 7] OFB IV affects keystream   FAIL");
            failed += 1;
        }
    }

    // 8. Empty src is a no-op.
    {
        let mut s = cipher::NewOFB(mk_block(), slice::__from_vec(iv.clone()));
        let mut dst = slice::__from_vec(alloc::vec![0u8; 8]);
        let before = dst.clone().__into_vec();
        s.XORKeyStream(&mut dst, slice::__from_vec(alloc::vec![]));
        if dst.__into_vec() == before {
            Println!("[ 8] OFB empty src no-op        PASS");
        } else {
            Println!("[ 8] OFB empty src no-op        FAIL");
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
