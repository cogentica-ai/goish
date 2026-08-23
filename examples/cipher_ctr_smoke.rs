// cipher_ctr_smoke — exercise crypto/cipher::NewCTR.
//
// AES isn't ported yet, so this test uses an in-test ToyBlock — a
// permutation block cipher built around a fixed 8-byte key. It
// satisfies cipher::Block and exercises NewCTR / CTR::XORKeyStream
// across:
//   - single Write
//   - multi-call equivalence to one big call
//   - chunks larger than the internal keystream buffer (forces refill)
//   - byte-by-byte
//   - encrypt → decrypt round-trip (CTR is symmetric)
//   - counter increment determinism (same iv → same keystream)
//   - counter wrap behaviour with all-0xff iv
//   - empty src no-op

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::crypto::cipher;
use goish::crypto::cipher::{Block, Stream};
use goish::fmt;
use goish::types::{byte, int};
use goish::{slice, syscall};

// 8-byte ToyBlock: Encrypt(dst, src) = rotate-left(src ^ key, 3).
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

    // 1. Single 16-byte XORKeyStream produces non-trivial ciphertext.
    {
        let mut s = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let plain: alloc::vec::Vec<byte> = (0..16u8).collect();
        let mut dst = slice::__from_vec(alloc::vec![0u8; 16]);
        s.XORKeyStream(&mut dst, slice::__from_vec(plain.clone()));
        if dst.__into_vec() != plain {
            fmt::Println!("[ 1] CTR single 16-byte         PASS");
        } else {
            fmt::Println!("[ 1] CTR single 16-byte         FAIL ct==pt");
            failed += 1;
        }
    }

    // 2. Encrypt → decrypt round-trip recovers the plaintext.
    {
        let plain: alloc::vec::Vec<byte> = b"Goish CTR round-trip text.".to_vec();
        let n = plain.len();

        let mut enc = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct = slice::__from_vec(alloc::vec![0u8; n]);
        enc.XORKeyStream(&mut ct, slice::__from_vec(plain.clone()));
        let ct_v = ct.__into_vec();

        let mut dec = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let mut pt2 = slice::__from_vec(alloc::vec![0u8; n]);
        dec.XORKeyStream(&mut pt2, slice::__from_vec(ct_v));
        if pt2.__into_vec() == plain {
            fmt::Println!("[ 2] CTR enc→dec round-trip     PASS");
        } else {
            fmt::Println!("[ 2] CTR enc→dec round-trip     FAIL");
            failed += 1;
        }
    }

    // 3. Multi-call equals one-shot (Stream concatenation contract).
    {
        let plain: alloc::vec::Vec<byte> = (0..40u8).collect();

        let mut s1 = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; 40]);
        s1.XORKeyStream(&mut ct1, slice::__from_vec(plain.clone()));
        let want = ct1.__into_vec();

        let mut s2 = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let mut got: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(40);
        for &n in &[7usize, 13, 20] {
            let off = got.len();
            let mut chunk = slice::__from_vec(alloc::vec![0u8; n]);
            let src = slice::__from_vec(plain[off..off + n].to_vec());
            s2.XORKeyStream(&mut chunk, src);
            got.extend_from_slice(&chunk.__into_vec());
        }
        if got == want {
            fmt::Println!("[ 3] CTR split calls equivalent PASS");
        } else {
            fmt::Println!("[ 3] CTR split calls equivalent FAIL");
            failed += 1;
        }
    }

    // 4. 4 KiB payload — exceeds streamBufferSize (512), forces multiple
    //    refills. Round-trip recovery verifies counter advancement.
    {
        let mut plain: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(4096);
        for i in 0..4096u32 {
            plain.push((i.wrapping_mul(31) & 0xff) as byte);
        }
        let mut enc = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct = slice::__from_vec(alloc::vec![0u8; 4096]);
        enc.XORKeyStream(&mut ct, slice::__from_vec(plain.clone()));
        let ct_v = ct.__into_vec();

        let mut dec = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let mut pt2 = slice::__from_vec(alloc::vec![0u8; 4096]);
        dec.XORKeyStream(&mut pt2, slice::__from_vec(ct_v));
        if pt2.__into_vec() == plain {
            fmt::Println!("[ 4] CTR 4 KiB refill round     PASS");
        } else {
            fmt::Println!("[ 4] CTR 4 KiB refill round     FAIL");
            failed += 1;
        }
    }

    // 5. Byte-by-byte equals one-shot.
    {
        let plain: alloc::vec::Vec<byte> = b"CTR byte-by-byte test.".to_vec();
        let n = plain.len();

        let mut s1 = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; n]);
        s1.XORKeyStream(&mut ct1, slice::__from_vec(plain.clone()));
        let want = ct1.__into_vec();

        let mut s2 = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let mut got: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(n);
        for &b in plain.iter() {
            let mut one = slice::__from_vec(alloc::vec![0u8; 1]);
            s2.XORKeyStream(&mut one, slice::__from_vec(alloc::vec![b]));
            got.extend_from_slice(&one.__into_vec());
        }
        if got == want {
            fmt::Println!("[ 5] CTR byte-by-byte           PASS");
        } else {
            fmt::Println!("[ 5] CTR byte-by-byte           FAIL");
            failed += 1;
        }
    }

    // 6. Same key+iv → identical keystream (CTR determinism).
    {
        let plain: alloc::vec::Vec<byte> = (0..32u8).collect();
        let mut s1 = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct1 = slice::__from_vec(alloc::vec![0u8; 32]);
        s1.XORKeyStream(&mut ct1, slice::__from_vec(plain.clone()));

        let mut s2 = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let mut ct2 = slice::__from_vec(alloc::vec![0u8; 32]);
        s2.XORKeyStream(&mut ct2, slice::__from_vec(plain));

        if ct1.__into_vec() == ct2.__into_vec() {
            fmt::Println!("[ 6] CTR deterministic stream   PASS");
        } else {
            fmt::Println!("[ 6] CTR deterministic stream   FAIL");
            failed += 1;
        }
    }

    // 7. Counter wrap — iv = ff…ff increments to 00…00 on second block,
    //    no panic, round-trip holds.
    {
        let iv_max: alloc::vec::Vec<byte> = alloc::vec![0xffu8; 8];
        let plain: alloc::vec::Vec<byte> = (0..32u8).collect();

        let mut enc = cipher::NewCTR(mk_block(), slice::__from_vec(iv_max.clone()));
        let mut ct = slice::__from_vec(alloc::vec![0u8; 32]);
        enc.XORKeyStream(&mut ct, slice::__from_vec(plain.clone()));
        let ct_v = ct.__into_vec();

        let mut dec = cipher::NewCTR(mk_block(), slice::__from_vec(iv_max));
        let mut pt2 = slice::__from_vec(alloc::vec![0u8; 32]);
        dec.XORKeyStream(&mut pt2, slice::__from_vec(ct_v));
        if pt2.__into_vec() == plain {
            fmt::Println!("[ 7] CTR ctr wrap holds         PASS");
        } else {
            fmt::Println!("[ 7] CTR ctr wrap holds         FAIL");
            failed += 1;
        }
    }

    // 8. Empty src is a no-op.
    {
        let mut s = cipher::NewCTR(mk_block(), slice::__from_vec(iv.clone()));
        let mut dst = slice::__from_vec(alloc::vec![0u8; 8]);
        let before = dst.clone().__into_vec();
        s.XORKeyStream(&mut dst, slice::__from_vec(alloc::vec![]));
        if dst.__into_vec() == before {
            fmt::Println!("[ 8] CTR empty src no-op        PASS");
        } else {
            fmt::Println!("[ 8] CTR empty src no-op        FAIL");
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
