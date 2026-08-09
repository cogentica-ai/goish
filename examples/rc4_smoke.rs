// rc4_smoke — exercise crypto/rc4 against published test vectors.
//
// References:
//   /share/go/src/crypto/rc4/rc4_test.go (golden cypherpunk + Wikipedia
//                                         vectors)
//   /share/go/src/crypto/rc4/rc4.go      (port target)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::crypto::cipher::Stream;
use goish::crypto::rc4;
use goish::errors;
use goish::{slice, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Golden vector #1 — cypherpunk posting:
    //    key      = 01 23 45 67 89 ab cd ef
    //    keystream = 74 94 c2 e7 10 4b 08 79 (XOR over 8 zero bytes)
    {
        let key = slice::__from_vec(alloc::vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        ]);
        let want = alloc::vec![0x74, 0x94, 0xc2, 0xe7, 0x10, 0x4b, 0x08, 0x79];
        let (mut c, err) = rc4::NewCipher(key);
        if !err.IsNil() || c.is_none() {
            fmt::Println!("[ 1] cypherpunk vector #1       FAIL");
            failed += 1;
        } else {
            let cipher = c.as_mut().unwrap();
            let src = slice::__from_vec(alloc::vec![0u8; 8]);
            let mut dst = slice::__from_vec(alloc::vec![0u8; 8]);
            cipher.XORKeyStream(&mut dst, src);
            if dst.__into_vec() == want {
                fmt::Println!("[ 1] cypherpunk vector #1       PASS");
            } else {
                fmt::Println!("[ 1] cypherpunk vector #1       FAIL");
                failed += 1;
            }
        }
    }

    // 2. Golden vector #2 — all-zero key:
    //    key       = 00 × 8
    //    keystream = de 18 89 41 a3 37 5d 3a
    {
        let key = slice::__from_vec(alloc::vec![0u8; 8]);
        let want = alloc::vec![0xde, 0x18, 0x89, 0x41, 0xa3, 0x37, 0x5d, 0x3a];
        let (mut c, err) = rc4::NewCipher(key);
        if !err.IsNil() || c.is_none() {
            fmt::Println!("[ 2] all-zero key vector        FAIL");
            failed += 1;
        } else {
            let cipher = c.as_mut().unwrap();
            let src = slice::__from_vec(alloc::vec![0u8; 8]);
            let mut dst = slice::__from_vec(alloc::vec![0u8; 8]);
            cipher.XORKeyStream(&mut dst, src);
            if dst.__into_vec() == want {
                fmt::Println!("[ 2] all-zero key vector        PASS");
            } else {
                fmt::Println!("[ 2] all-zero key vector        FAIL");
                failed += 1;
            }
        }
    }

    // 3. Golden vector #3 — short key, longer stream:
    //    key       = ef 01 23 45
    //    keystream = d6 a1 41 a7 ec 3c 38 df bd 61
    {
        let key = slice::__from_vec(alloc::vec![0xef, 0x01, 0x23, 0x45]);
        let want = alloc::vec![
            0xd6, 0xa1, 0x41, 0xa7, 0xec, 0x3c, 0x38, 0xdf, 0xbd, 0x61
        ];
        let (mut c, err) = rc4::NewCipher(key);
        if !err.IsNil() || c.is_none() {
            fmt::Println!("[ 3] short key + 10-byte stream FAIL");
            failed += 1;
        } else {
            let cipher = c.as_mut().unwrap();
            let src = slice::__from_vec(alloc::vec![0u8; 10]);
            let mut dst = slice::__from_vec(alloc::vec![0u8; 10]);
            cipher.XORKeyStream(&mut dst, src);
            if dst.__into_vec() == want {
                fmt::Println!("[ 3] short key + 10-byte stream PASS");
            } else {
                fmt::Println!("[ 3] short key + 10-byte stream FAIL");
                failed += 1;
            }
        }
    }

    // 4. Wikipedia "Key" vector:
    //    key       = 4b 65 79  ("Key")
    //    keystream = eb 9f 77 81 b7 34 ca 72 a7 19
    {
        let key = slice::__from_vec(alloc::vec![0x4b, 0x65, 0x79]);
        let want = alloc::vec![
            0xeb, 0x9f, 0x77, 0x81, 0xb7, 0x34, 0xca, 0x72, 0xa7, 0x19
        ];
        let (mut c, err) = rc4::NewCipher(key);
        if !err.IsNil() || c.is_none() {
            fmt::Println!("[ 4] Wikipedia 'Key' vector     FAIL");
            failed += 1;
        } else {
            let cipher = c.as_mut().unwrap();
            let src = slice::__from_vec(alloc::vec![0u8; 10]);
            let mut dst = slice::__from_vec(alloc::vec![0u8; 10]);
            cipher.XORKeyStream(&mut dst, src);
            if dst.__into_vec() == want {
                fmt::Println!("[ 4] Wikipedia 'Key' vector     PASS");
            } else {
                fmt::Println!("[ 4] Wikipedia 'Key' vector     FAIL");
                failed += 1;
            }
        }
    }

    // 5. Wikipedia "Wiki" vector:
    //    key       = 57 69 6b 69
    //    keystream = 60 44 db 6d 41 b7
    {
        let key = slice::__from_vec(alloc::vec![0x57, 0x69, 0x6b, 0x69]);
        let want = alloc::vec![0x60, 0x44, 0xdb, 0x6d, 0x41, 0xb7];
        let (mut c, err) = rc4::NewCipher(key);
        if !err.IsNil() || c.is_none() {
            fmt::Println!("[ 5] Wikipedia 'Wiki' vector    FAIL");
            failed += 1;
        } else {
            let cipher = c.as_mut().unwrap();
            let src = slice::__from_vec(alloc::vec![0u8; 6]);
            let mut dst = slice::__from_vec(alloc::vec![0u8; 6]);
            cipher.XORKeyStream(&mut dst, src);
            if dst.__into_vec() == want {
                fmt::Println!("[ 5] Wikipedia 'Wiki' vector    PASS");
            } else {
                fmt::Println!("[ 5] Wikipedia 'Wiki' vector    FAIL");
                failed += 1;
            }
        }
    }

    // 6. Round-trip — encrypt then decrypt yields the plaintext.
    //    RC4 is symmetric: keystream is the same on both sides.
    {
        let key = slice::__from_vec(alloc::vec![b'k', b'e', b'y']);
        let plain = alloc::vec![
            b'h', b'e', b'l', b'l', b'o', b' ', b'w', b'o', b'r', b'l', b'd'
        ];

        let (mut c1, _) = rc4::NewCipher(key.clone());
        let mut enc = slice::__from_vec(alloc::vec![0u8; plain.len()]);
        c1.as_mut()
            .unwrap()
            .XORKeyStream(&mut enc, slice::__from_vec(plain.clone()));

        let (mut c2, _) = rc4::NewCipher(key);
        let mut dec = slice::__from_vec(alloc::vec![0u8; plain.len()]);
        c2.as_mut().unwrap().XORKeyStream(&mut dec, enc);

        if dec.__into_vec() == plain {
            fmt::Println!("[ 6] enc/dec round-trip         PASS");
        } else {
            fmt::Println!("[ 6] enc/dec round-trip         FAIL");
            failed += 1;
        }
    }

    // 7. Maintains state across calls — splitting the keystream by 1 byte
    //    must yield the same output as calling once for N.
    {
        let key = slice::__from_vec(alloc::vec![0x4b, 0x65, 0x79]);
        let want_full = alloc::vec![
            0xeb, 0x9f, 0x77, 0x81, 0xb7, 0x34, 0xca, 0x72, 0xa7, 0x19
        ];
        let (mut c, _) = rc4::NewCipher(key);
        let cipher = c.as_mut().unwrap();
        let mut got: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(10);
        let mut k: i64 = 0;
        while k < 10 {
            let src = slice::__from_vec(alloc::vec![0u8; 1]);
            let mut dst = slice::__from_vec(alloc::vec![0u8; 1]);
            cipher.XORKeyStream(&mut dst, src);
            got.extend_from_slice(&dst.__into_vec());
            k += 1;
        }
        if got == want_full {
            fmt::Println!("[ 7] state across 1-byte calls  PASS");
        } else {
            fmt::Println!("[ 7] state across 1-byte calls  FAIL");
            failed += 1;
        }
    }

    // 8. NewCipher rejects an empty key.
    {
        let empty: goish::slice<u8> = slice::new();
        let (c, err) = rc4::NewCipher(empty);
        if c.is_none() && !err.IsNil() {
            // Make sure errors::As recovers the typed error.
            let typed = errors::As::<rc4::KeySizeError>(err);
            if typed.is_some() && typed.unwrap().0 == 0 {
                fmt::Println!("[ 8] NewCipher empty key err    PASS");
            } else {
                fmt::Println!("[ 8] NewCipher empty key err    FAIL");
                failed += 1;
            }
        } else {
            fmt::Println!("[ 8] NewCipher empty key err    FAIL");
            failed += 1;
        }
    }

    // 9. NewCipher rejects an oversized key (>256 bytes).
    {
        let big = slice::__from_vec(alloc::vec![0u8; 257]);
        let (c, err) = rc4::NewCipher(big);
        if c.is_none() && !err.IsNil() {
            let msg = err.Error();
            if msg == "crypto/rc4: invalid key size 257" {
                fmt::Println!("[ 9] NewCipher 257-byte err     PASS");
            } else {
                fmt::Println!("[ 9] NewCipher 257-byte err     FAIL");
                failed += 1;
            }
        } else {
            fmt::Println!("[ 9] NewCipher 257-byte err     FAIL");
            failed += 1;
        }
    }

    // 10. Reset — after Reset the cipher state is zeroed; subsequent
    //     XORKeyStream calls produce a deterministic (but arbitrary)
    //     stream — we simply verify Reset doesn't panic and yields
    //     the same output across two reset cycles.
    {
        let key = slice::__from_vec(alloc::vec![0x4b, 0x65, 0x79]);
        let (mut c, _) = rc4::NewCipher(key);
        let cipher = c.as_mut().unwrap();

        // Drain 5 bytes.
        let src = slice::__from_vec(alloc::vec![0u8; 5]);
        let mut dst = slice::__from_vec(alloc::vec![0u8; 5]);
        cipher.XORKeyStream(&mut dst, src);

        cipher.Reset();
        // Run keystream A.
        let src_a = slice::__from_vec(alloc::vec![0u8; 4]);
        let mut a = slice::__from_vec(alloc::vec![0u8; 4]);
        cipher.XORKeyStream(&mut a, src_a);

        cipher.Reset();
        // Run keystream B.
        let src_b = slice::__from_vec(alloc::vec![0u8; 4]);
        let mut b = slice::__from_vec(alloc::vec![0u8; 4]);
        cipher.XORKeyStream(&mut b, src_b);

        if a.__into_vec() == b.__into_vec() {
            fmt::Println!("[10] Reset is deterministic     PASS");
        } else {
            fmt::Println!("[10] Reset is deterministic     FAIL");
            failed += 1;
        }
    }

    // 11. Use rc4::Cipher behind a generic `Stream` bound — proves the
    //     cipher trait surface (declared in iteration 11) accepts rc4.
    fn xor_via_stream<S: Stream>(s: &mut S, src: goish::slice<u8>) -> goish::slice<u8> {
        let n = src.Len();
        let mut dst = slice::__from_vec(alloc::vec![0u8; n as usize]);
        s.XORKeyStream(&mut dst, src);
        dst
    }
    {
        let key = slice::__from_vec(alloc::vec![0x4b, 0x65, 0x79]);
        let want = alloc::vec![
            0xeb, 0x9f, 0x77, 0x81, 0xb7, 0x34, 0xca, 0x72, 0xa7, 0x19
        ];
        let (mut c, _) = rc4::NewCipher(key);
        let zeros = slice::__from_vec(alloc::vec![0u8; 10]);
        let out = xor_via_stream(c.as_mut().unwrap(), zeros);
        if out.__into_vec() == want {
            fmt::Println!("[11] cipher::Stream bound       PASS");
        } else {
            fmt::Println!("[11] cipher::Stream bound       FAIL");
            failed += 1;
        }
    }

    // 12. Empty src is a no-op (early return path in XORKeyStream).
    {
        let key = slice::__from_vec(alloc::vec![0x4b, 0x65, 0x79]);
        let (mut c, _) = rc4::NewCipher(key);
        let cipher = c.as_mut().unwrap();
        let empty: goish::slice<u8> = slice::new();
        let mut dst: goish::slice<u8> = slice::new();
        cipher.XORKeyStream(&mut dst, empty);
        // Subsequent call must still produce the proper keystream
        // (state untouched by the empty call).
        let src = slice::__from_vec(alloc::vec![0u8; 1]);
        let mut got = slice::__from_vec(alloc::vec![0u8; 1]);
        cipher.XORKeyStream(&mut got, src);
        let v = got.__into_vec();
        if v.len() == 1 && v[0] == 0xeb {
            fmt::Println!("[12] empty src no-op            PASS");
        } else {
            fmt::Println!("[12] empty src no-op            FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
