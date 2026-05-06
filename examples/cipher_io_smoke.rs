// cipher_io_smoke — exercise crypto/cipher::StreamReader / StreamWriter
// (io.go) end-to-end via rc4::Cipher as the Stream implementor.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::error;
use goish::bytes;
use goish::crypto::cipher;
use goish::crypto::rc4;
use goish::errors;
use goish::io;
use goish::io::{Closer, Reader, Writer};
use goish::types::byte;
use goish::{slice, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. StreamReader — decrypt the cypherpunk vector through io::Read.
    //    plaintext = 8 zero bytes
    //    key       = 01 23 45 67 89 ab cd ef
    //    keystream = 74 94 c2 e7 10 4b 08 79
    //    ciphertext = keystream (since plaintext is zero).
    {
        let key: slice<byte> = goish::slice::__from_vec(alloc::vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        ]);
        let (cipher_opt, err) = rc4::NewCipher(key);
        if !err.IsNil() || cipher_opt.is_none() {
            Println!("[ 1] StreamReader cypherpunk    FAIL setup");
            failed += 1;
        } else {
            // Provide ciphertext to the reader; XORKeyStream re-XORs to
            // recover plaintext.
            let ct: slice<byte> = goish::slice::__from_vec(alloc::vec![
                0x74, 0x94, 0xc2, 0xe7, 0x10, 0x4b, 0x08, 0x79
            ]);
            let r = bytes::NewReader(ct);
            let mut sr = cipher::StreamReader { S: cipher_opt.unwrap(), R: r };
            let mut out: slice<byte> =
                goish::slice::__from_vec(alloc::vec![0u8; 8]);
            let (n, rerr) = sr.Read(&mut out);
            let mut got = out.__into_vec();
            got.truncate(n as usize);
            if rerr.IsNil() && got == alloc::vec![0u8; 8] {
                Println!("[ 1] StreamReader cypherpunk    PASS");
            } else {
                Println!("[ 1] StreamReader cypherpunk    FAIL");
                failed += 1;
            }
        }
    }

    // 2. StreamReader — short-buffer multi-Read across two cipher calls
    //    keeps cipher state coherent.
    {
        let key: slice<byte> = goish::slice::__from_vec(alloc::vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        ]);
        let (cipher_opt, _) = rc4::NewCipher(key);

        // 16-byte ciphertext = first 16 bytes of keystream over zero
        // plaintext.  We don't know the values; instead synthesize the
        // ciphertext via a parallel rc4 instance, then verify Read
        // recovers the original zeros.
        let key2: slice<byte> = goish::slice::__from_vec(alloc::vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        ]);
        let (cipher_opt2, _) = rc4::NewCipher(key2);
        let mut c2 = cipher_opt2.unwrap();
        let zero: slice<byte> = goish::slice::__from_vec(alloc::vec![0u8; 16]);
        let mut ct: slice<byte> =
            goish::slice::__from_vec(alloc::vec![0u8; 16]);
        {
            use goish::crypto::cipher::Stream;
            c2.XORKeyStream(&mut ct, zero);
        }

        let r = bytes::NewReader(ct);
        let mut sr = cipher::StreamReader { S: cipher_opt.unwrap(), R: r };
        // Read 6, then 10, then 0/EOF.
        let mut buf1: slice<byte> =
            goish::slice::__from_vec(alloc::vec![0u8; 6]);
        let (n1, _) = sr.Read(&mut buf1);
        let mut got: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
        got.extend_from_slice(&buf1.__into_vec()[..n1 as usize]);
        let mut buf2: slice<byte> =
            goish::slice::__from_vec(alloc::vec![0u8; 10]);
        let (n2, _) = sr.Read(&mut buf2);
        got.extend_from_slice(&buf2.__into_vec()[..n2 as usize]);
        if got == alloc::vec![0u8; 16] {
            Println!("[ 2] StreamReader split reads   PASS");
        } else {
            Println!("[ 2] StreamReader split reads   FAIL");
            failed += 1;
        }
    }

    // 3. StreamReader — io::ReadAll drains until EOF.
    {
        let key: slice<byte> = goish::slice::__from_vec(alloc::vec![0u8; 8]);
        let (cipher_opt, _) = rc4::NewCipher(key);
        // Ciphertext = first 8 bytes of keystream (see rc4_smoke vec #2).
        let ct: slice<byte> = goish::slice::__from_vec(alloc::vec![
            0xde, 0x18, 0x89, 0x41, 0xa3, 0x37, 0x5d, 0x3a
        ]);
        let r = bytes::NewReader(ct);
        let mut sr = cipher::StreamReader { S: cipher_opt.unwrap(), R: r };
        let (got, err) = io::ReadAll(&mut sr);
        if err.IsNil() && got.__into_vec() == alloc::vec![0u8; 8] {
            Println!("[ 3] StreamReader ReadAll       PASS");
        } else {
            Println!("[ 3] StreamReader ReadAll       FAIL");
            failed += 1;
        }
    }

    // 4. StreamWriter — encrypt via io::Write into a bytes::Buffer.
    {
        let key: slice<byte> = goish::slice::__from_vec(alloc::vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        ]);
        let (cipher_opt, _) = rc4::NewCipher(key);
        let buf = bytes::Buffer::new();
        let mut sw = cipher::StreamWriter {
            S: cipher_opt.unwrap(),
            W: buf,
            Err: errors::nil.clone(),
        };
        let pt: slice<byte> = goish::slice::__from_vec(alloc::vec![0u8; 8]);
        let (n, werr) = sw.Write(pt);
        let want = alloc::vec![0x74, 0x94, 0xc2, 0xe7, 0x10, 0x4b, 0x08, 0x79];
        let got = sw.W.Bytes().__into_vec();
        if werr.IsNil() && n == 8 && got == want {
            Println!("[ 4] StreamWriter encrypt       PASS");
        } else {
            Println!("[ 4] StreamWriter encrypt       FAIL");
            failed += 1;
        }
    }

    // 5. StreamWriter — multi-Write keeps cipher state coherent
    //    (concatenation contract from the Stream trait).
    {
        let key: slice<byte> = goish::slice::__from_vec(alloc::vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
        ]);
        let (cipher_opt, _) = rc4::NewCipher(key);
        let buf = bytes::Buffer::new();
        let mut sw = cipher::StreamWriter {
            S: cipher_opt.unwrap(),
            W: buf,
            Err: errors::nil.clone(),
        };
        // Two halves of the same 8-byte zero plaintext.
        let pt1: slice<byte> = goish::slice::__from_vec(alloc::vec![0u8; 3]);
        let pt2: slice<byte> = goish::slice::__from_vec(alloc::vec![0u8; 5]);
        let _ = sw.Write(pt1);
        let _ = sw.Write(pt2);
        let want = alloc::vec![0x74, 0x94, 0xc2, 0xe7, 0x10, 0x4b, 0x08, 0x79];
        let got = sw.W.Bytes().__into_vec();
        if got == want {
            Println!("[ 5] StreamWriter split writes  PASS");
        } else {
            Println!("[ 5] StreamWriter split writes  FAIL");
            failed += 1;
        }
    }

    // 6. StreamReader↔StreamWriter round-trip — encrypt with one pair,
    //    decrypt with another (RC4 is symmetric).
    {
        let key1: slice<byte> = goish::slice::__from_vec(alloc::vec![
            0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce
        ]);
        let (c_enc, _) = rc4::NewCipher(key1);
        let key2: slice<byte> = goish::slice::__from_vec(alloc::vec![
            0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce
        ]);
        let (c_dec, _) = rc4::NewCipher(key2);

        let plain: alloc::vec::Vec<byte> = b"Goish lives at the boundary.".to_vec();

        // Encrypt
        let buf = bytes::Buffer::new();
        let mut sw = cipher::StreamWriter {
            S: c_enc.unwrap(),
            W: buf,
            Err: errors::nil.clone(),
        };
        let _ = sw.Write(goish::slice::__from_vec(plain.clone()));
        let ct = sw.W.Bytes();

        // Decrypt
        let r = bytes::NewReader(ct);
        let mut sr = cipher::StreamReader { S: c_dec.unwrap(), R: r };
        let (recovered, err) = io::ReadAll(&mut sr);
        if err.IsNil() && recovered.__into_vec() == plain {
            Println!("[ 6] StreamWriter→Reader RT     PASS");
        } else {
            Println!("[ 6] StreamWriter→Reader RT     FAIL");
            failed += 1;
        }
    }

    // 7. StreamReader — empty source returns (0, EOF) without touching
    //    the cipher (n=0 path).
    {
        let key: slice<byte> =
            goish::slice::__from_vec(alloc::vec![0x42; 4]);
        let (cipher_opt, _) = rc4::NewCipher(key);
        let r = bytes::NewReader(goish::slice::__from_vec(alloc::vec![]));
        let mut sr = cipher::StreamReader { S: cipher_opt.unwrap(), R: r };
        let mut buf: slice<byte> =
            goish::slice::__from_vec(alloc::vec![0u8; 4]);
        let (n, err) = sr.Read(&mut buf);
        if n == 0 && goish::errors::Is(err.clone(), io::EOF) {
            Println!("[ 7] StreamReader empty src     PASS");
        } else {
            Println!("[ 7] StreamReader empty src     FAIL");
            failed += 1;
        }
    }

    // 8. StreamWriter::Close — when W is a Closer, forwards Close.
    //    Use a tiny CloseTrackingWriter that records Close was called.
    {
        struct Tracker {
            closed: bool,
            buf: alloc::vec::Vec<byte>,
        }
        impl io::Writer for Tracker {
            fn Write(&mut self, p: slice<byte>) -> (goish::types::int, error) {
                let v = p.__into_vec();
                let n = v.len() as goish::types::int;
                self.buf.extend_from_slice(&v);
                (n, errors::nil.clone())
            }
        }
        impl io::Closer for Tracker {
            fn Close(&mut self) -> error {
                self.closed = true;
                errors::nil.clone()
            }
        }

        let key: slice<byte> = goish::slice::__from_vec(alloc::vec![1, 2, 3, 4]);
        let (cipher_opt, _) = rc4::NewCipher(key);
        let mut sw = cipher::StreamWriter {
            S: cipher_opt.unwrap(),
            W: Tracker { closed: false, buf: alloc::vec::Vec::new() },
            Err: errors::nil.clone(),
        };
        let _ = sw.Write(goish::slice::__from_vec(alloc::vec![1u8, 2, 3]));
        let cerr = sw.Close();
        if cerr.IsNil() && sw.W.closed && sw.W.buf.len() == 3 {
            Println!("[ 8] StreamWriter::Close fwd    PASS");
        } else {
            Println!("[ 8] StreamWriter::Close fwd    FAIL");
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
