// hex_stream_smoke — exercise hex.NewEncoder + hex.NewDecoder.
// (encoding/hex/hex.go:166-237)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::encoding::hex::{NewDecoder, NewEncoder};
use goish::goslice::slice;
use goish::io::{Reader, Writer};
use goish::types::byte;
use goish::{convert, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Encoder writes hex of input bytes.
    {
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut enc = NewEncoder(&mut buf);
        let _ = enc.Write(slice::__from_vec(alloc::vec![0xde, 0xad, 0xbe, 0xef]));
        let s = buf.String();
        if s == "deadbeef" {
            Println!("[ 1] basic encode            PASS");
        } else {
            Println!("[ 1] basic encode            FAIL got {}", s);
            failed += 1;
        }
    }

    // 2. Encoder n returned = bytes consumed (not chars written).
    {
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut enc = NewEncoder(&mut buf);
        let (n, e) = enc.Write(slice::__from_vec(alloc::vec![0x00, 0x11, 0x22]));
        if n == 3 && e.IsNil() {
            Println!("[ 2] encode return n         PASS");
        } else {
            Println!("[ 2] encode return n         FAIL n={}", n);
            failed += 1;
        }
    }

    // 3. Decoder reads hex stream.
    {
        let src = bytes::NewBuffer(convert::bytes("deadbeef"));
        let mut dec = NewDecoder(src);
        let mut out: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4]);
        let (n, e) = dec.Read(&mut out);
        let raw: &[byte] = &out;
        let want: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        if n == 4 && e.IsNil() && raw == want {
            Println!("[ 3] basic decode            PASS");
        } else {
            Println!("[ 3] basic decode            FAIL n={}", n);
            failed += 1;
        }
    }

    // 4. Decoder partial read.
    {
        let src = bytes::NewBuffer(convert::bytes("0102030405"));
        let mut dec = NewDecoder(src);
        let mut out: slice<byte> = slice::__from_vec(alloc::vec![0u8; 3]);
        let (n, e) = dec.Read(&mut out);
        let raw: &[byte] = &out;
        let want: &[u8] = &[0x01, 0x02, 0x03];
        if n == 3 && e.IsNil() && raw == want {
            Println!("[ 4] partial decode          PASS");
        } else {
            Println!("[ 4] partial decode          FAIL n={}", n);
            failed += 1;
        }
    }

    // 5. Decoder odd-length input → error reported on final read.
    //    Go drains valid pairs first (returns nil), then errors on the
    //    next Read once EOF is observed and an odd char is left over.
    {
        let src = bytes::NewBuffer(convert::bytes("aabbc"));
        let mut dec = NewDecoder(src);
        let mut out: slice<byte> = slice::__from_vec(alloc::vec![0u8; 8]);
        let (_n1, _e1) = dec.Read(&mut out);
        let (_n2, e2) = dec.Read(&mut out);
        if !e2.IsNil() {
            Println!("[ 5] odd length err          PASS");
        } else {
            Println!("[ 5] odd length err          FAIL");
            failed += 1;
        }
    }

    // 6. Decoder invalid char → error.
    {
        let src = bytes::NewBuffer(convert::bytes("aaZZ"));
        let mut dec = NewDecoder(src);
        let mut out: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4]);
        let (_n, e) = dec.Read(&mut out);
        if !e.IsNil() {
            Println!("[ 6] invalid char err        PASS");
        } else {
            Println!("[ 6] invalid char err        FAIL");
            failed += 1;
        }
    }

    // 7. Encoder + Decoder round-trip.
    {
        let original: alloc::vec::Vec<byte> = alloc::vec![0x00, 0xff, 0x55, 0xaa, 0x12, 0x34];
        let mut enc_buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        {
            let mut enc = NewEncoder(&mut enc_buf);
            let _ = enc.Write(slice::__from_vec(original.clone()));
        }
        let hex_data = enc_buf.String();
        let src = bytes::NewBuffer(convert::bytes("placeholder"));
        let _ = src; // unused
        let src = bytes::NewBufferString(hex_data);
        let mut dec = NewDecoder(src);
        let mut out: slice<byte> = slice::__from_vec(alloc::vec![0u8; original.len()]);
        let (n, e) = dec.Read(&mut out);
        let raw: &[byte] = &out;
        if n == original.len() as i64 && e.IsNil() && raw == &original[..] {
            Println!("[ 7] round-trip              PASS");
        } else {
            Println!("[ 7] round-trip              FAIL n={}", n);
            failed += 1;
        }
    }

    // 8. Encoder large write → multiple internal chunks (BUFFER_SIZE=1024).
    {
        let mut data = alloc::vec::Vec::with_capacity(2048);
        for i in 0..2048u32 {
            data.push((i & 0xff) as byte);
        }
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut enc = NewEncoder(&mut buf);
        let (n, e) = enc.Write(slice::__from_vec(data));
        let s = buf.String();
        if n == 2048 && e.IsNil() && s.Len() == 4096 {
            Println!("[ 8] large encode chunked    PASS");
        } else {
            Println!("[ 8] large encode chunked    FAIL n={}", n);
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
