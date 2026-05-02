// ascii85_stream_smoke — exercise streaming NewEncoder + NewDecoder
// from encoding/ascii85 (ascii85.go:88-307).
//
// The one-shot Encode/Decode are covered by ascii85_smoke. This file
// focuses on the io::Writer / io::Reader streaming wrappers, including
// partial writes, byte-by-byte, and round-trips through both ends.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::encoding::ascii85;
use goish::io;
use goish::types::byte;
use goish::{slice, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. NewEncoder — single Write that covers a clean 4-byte block.
    //    "abcd" → ascii85 = "@:E_W"  (the canonical 'a','b','c','d' block)
    {
        let mut buf = bytes::Buffer::new();
        {
            let mut e = ascii85::NewEncoder(&mut buf);
            let payload: slice<byte> =
                goish::slice::__from_vec(b"abcd".to_vec());
            let (_, werr) = e.Write(payload);
            let cerr = e.Close();
            if !werr.IsNil() || !cerr.IsNil() {
                Println!("[ 1] NewEncoder single block    FAIL write/close err");
                failed += 1;
            }
        }
        let got = buf.String();
        let want: goish::string = "@:E_W".into();
        if got == want {
            Println!("[ 1] NewEncoder single block    PASS");
        } else {
            Println!("[ 1] NewEncoder single block    FAIL got=", got);
            failed += 1;
        }
    }

    // 2. NewEncoder — empty input → empty output (Close must not panic).
    {
        let mut buf = bytes::Buffer::new();
        {
            let mut e = ascii85::NewEncoder(&mut buf);
            let _ = e.Close();
        }
        let got = buf.String();
        if got == "" {
            Println!("[ 2] NewEncoder empty input     PASS");
        } else {
            Println!("[ 2] NewEncoder empty input     FAIL got=", got);
            failed += 1;
        }
    }

    // 3. NewEncoder — short tail (1..3 bytes) gets flushed by Close.
    //    Compare against one-shot Encode of same input.
    {
        let payload = b"hello".to_vec(); // 5 bytes — 1 block + 1-byte tail
        let mut buf = bytes::Buffer::new();
        {
            let mut e = ascii85::NewEncoder(&mut buf);
            let p: slice<byte> = goish::slice::__from_vec(payload.clone());
            let _ = e.Write(p);
            let _ = e.Close();
        }
        let stream_out = buf.String();

        // One-shot reference.
        let dst = goish::slice::__from_vec(alloc::vec![0u8; 32]);
        let src = goish::slice::__from_vec(payload);
        let (out, n) = ascii85::Encode(dst, src);
        let mut out_v = out.__into_vec();
        out_v.truncate(n as usize);
        let want = goish::string::from_bytes(&out_v);

        if stream_out == want {
            Println!("[ 3] NewEncoder short tail      PASS");
        } else {
            Println!("[ 3] NewEncoder short tail      FAIL got=", stream_out);
            failed += 1;
        }
    }

    // 4. NewEncoder — byte-by-byte writes must buffer correctly across
    //    Write boundaries.
    {
        let mut buf = bytes::Buffer::new();
        {
            let mut e = ascii85::NewEncoder(&mut buf);
            for &b in b"abcdefgh" {
                let one: slice<byte> = goish::slice::__from_vec(alloc::vec![b]);
                let _ = e.Write(one);
            }
            let _ = e.Close();
        }
        let got = buf.String();
        // "abcdefgh" → two clean 4-byte blocks, no special-case zero.
        // Reference via one-shot Encode.
        let dst = goish::slice::__from_vec(alloc::vec![0u8; 32]);
        let src = goish::slice::__from_vec(b"abcdefgh".to_vec());
        let (out, n) = ascii85::Encode(dst, src);
        let mut out_v = out.__into_vec();
        out_v.truncate(n as usize);
        let want = goish::string::from_bytes(&out_v);
        if got == want {
            Println!("[ 4] NewEncoder byte-by-byte    PASS");
        } else {
            Println!("[ 4] NewEncoder byte-by-byte    FAIL got=", got);
            failed += 1;
        }
    }

    // 5. NewEncoder — large interior chunks (>1 KiB triggers the inner
    //    "len(out)/5*4" loop branch).
    {
        // Build 1500 bytes of incrementing pattern.
        let mut payload: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(1500);
        for i in 0..1500u32 {
            payload.push((i & 0xff) as byte);
        }

        let mut buf = bytes::Buffer::new();
        {
            let mut e = ascii85::NewEncoder(&mut buf);
            let p: slice<byte> = goish::slice::__from_vec(payload.clone());
            let _ = e.Write(p);
            let _ = e.Close();
        }
        let got = buf.String();

        // Reference via one-shot.
        let dst = goish::slice::__from_vec(alloc::vec![0u8; 2048]);
        let src = goish::slice::__from_vec(payload);
        let (out, n) = ascii85::Encode(dst, src);
        let mut out_v = out.__into_vec();
        out_v.truncate(n as usize);
        let want = goish::string::from_bytes(&out_v);
        if got == want {
            Println!("[ 5] NewEncoder large interior  PASS");
        } else {
            Println!("[ 5] NewEncoder large interior  FAIL");
            failed += 1;
        }
    }

    // 6. NewEncoder — all-zero input triggers the special-case 'z' run.
    {
        let mut buf = bytes::Buffer::new();
        {
            let mut e = ascii85::NewEncoder(&mut buf);
            let p: slice<byte> = goish::slice::__from_vec(alloc::vec![0u8; 8]);
            let _ = e.Write(p);
            let _ = e.Close();
        }
        let got = buf.String();
        let want: goish::string = "zz".into();
        if got == want {
            Println!("[ 6] NewEncoder zero special    PASS");
        } else {
            Println!("[ 6] NewEncoder zero special    FAIL got=", got);
            failed += 1;
        }
    }

    // 7. NewDecoder — single Read covers full input.
    {
        let enc: slice<byte> =
            goish::slice::__from_vec(b"@:E_W".to_vec()); // "abcd"
        let r = bytes::NewReader(enc);
        let mut dec = ascii85::NewDecoder(r);
        let mut out: slice<byte> = goish::slice::__from_vec(alloc::vec![0u8; 16]);
        let (n, err) = dec.Read(&mut out);
        let mut got_v = out.__into_vec();
        got_v.truncate(n as usize);
        if err.IsNil() && got_v == b"abcd".to_vec() {
            Println!("[ 7] NewDecoder single Read     PASS");
        } else {
            Println!("[ 7] NewDecoder single Read     FAIL");
            failed += 1;
        }
    }

    // 8. NewDecoder — io::ReadAll drains until EOF.
    {
        let enc: slice<byte> =
            goish::slice::__from_vec(b"@:E_WBl/Q+87bRm".to_vec()); // "abcdefgh\0\0" 12 chars
        // Reference: encode "abcdefghijkl" then decode.
        let plain = b"abcdefghijkl".to_vec();
        let dst = goish::slice::__from_vec(alloc::vec![0u8; 32]);
        let src = goish::slice::__from_vec(plain.clone());
        let (out, n) = ascii85::Encode(dst, src);
        let mut enc_v = out.__into_vec();
        enc_v.truncate(n as usize);
        let _ = enc;

        let r = bytes::NewReader(goish::slice::__from_vec(enc_v));
        let mut dec = ascii85::NewDecoder(r);
        let (got, err) = io::ReadAll(&mut dec);
        if err.IsNil() && got.__into_vec() == plain {
            Println!("[ 8] NewDecoder ReadAll         PASS");
        } else {
            Println!("[ 8] NewDecoder ReadAll         FAIL");
            failed += 1;
        }
    }

    // 9. NewDecoder — short destination buffer forces outbuf staging.
    {
        // Plain 12 bytes → 15 ascii85 chars across multiple decode rounds.
        let plain = b"Goish! Stream".to_vec(); // 13 bytes
        let dst_buf = goish::slice::__from_vec(alloc::vec![0u8; 32]);
        let (enc_slice, n) =
            ascii85::Encode(dst_buf, goish::slice::__from_vec(plain.clone()));
        let mut enc_v = enc_slice.__into_vec();
        enc_v.truncate(n as usize);

        let r = bytes::NewReader(goish::slice::__from_vec(enc_v));
        let mut dec = ascii85::NewDecoder(r);
        // Read in 1-byte chunks → forces decoder to stage in outbuf.
        let mut got: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
        loop {
            let mut tmp: slice<byte> =
                goish::slice::__from_vec(alloc::vec![0u8; 1]);
            let (k, err) = dec.Read(&mut tmp);
            let v = tmp.__into_vec();
            if k > 0 {
                got.extend_from_slice(&v[..k as usize]);
            }
            if !err.IsNil() {
                break;
            }
            if k == 0 {
                break;
            }
        }
        if got == plain {
            Println!("[ 9] NewDecoder 1-byte staging  PASS");
        } else {
            Println!("[ 9] NewDecoder 1-byte staging  FAIL");
            failed += 1;
        }
    }

    // 10. NewDecoder — whitespace and control characters in input are
    //     ignored (Go contract).
    {
        // "@:E_W" with stray tabs/newlines interspersed.
        let mixed = b"@:\tE_\nW".to_vec();
        let r = bytes::NewReader(goish::slice::__from_vec(mixed));
        let mut dec = ascii85::NewDecoder(r);
        let (got, err) = io::ReadAll(&mut dec);
        if err.IsNil() && got.__into_vec() == b"abcd".to_vec() {
            Println!("[10] NewDecoder ignores ws      PASS");
        } else {
            Println!("[10] NewDecoder ignores ws      FAIL");
            failed += 1;
        }
    }

    // 11. NewEncoder → NewDecoder round-trip on a 257-byte payload
    //     (forces multi-block plus a 1-byte trailing fringe).
    {
        let mut payload: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(257);
        for i in 0..257u32 {
            payload.push((i.wrapping_mul(31) & 0xff) as byte);
        }
        let mut buf = bytes::Buffer::new();
        {
            let mut e = ascii85::NewEncoder(&mut buf);
            let p: slice<byte> = goish::slice::__from_vec(payload.clone());
            let _ = e.Write(p);
            let _ = e.Close();
        }
        let enc_str = buf.Bytes();
        let r = bytes::NewReader(enc_str);
        let mut dec = ascii85::NewDecoder(r);
        let (got, err) = io::ReadAll(&mut dec);
        if err.IsNil() && got.__into_vec() == payload {
            Println!("[11] enc→dec 257-byte RT        PASS");
        } else {
            Println!("[11] enc→dec 257-byte RT        FAIL");
            failed += 1;
        }
    }

    // 12. NewDecoder — corrupt byte produces an error from Read.
    {
        // 0x01 is a control char (≤ ' '), so it's IGNORED.
        // Use 'v' (0x76) which is past the legal '!'..'u' range.
        let bad = b"@:Ev!".to_vec();
        let r = bytes::NewReader(goish::slice::__from_vec(bad));
        let mut dec = ascii85::NewDecoder(r);
        let mut tmp: slice<byte> =
            goish::slice::__from_vec(alloc::vec![0u8; 16]);
        let mut saw_err = false;
        for _ in 0..4 {
            let (_, err) = dec.Read(&mut tmp);
            if !err.IsNil() {
                // Confirm it's our typed corrupt-input error.
                if goish::errors::As::<ascii85::CorruptInputError>(err).is_some() {
                    saw_err = true;
                }
                break;
            }
        }
        if saw_err {
            Println!("[12] NewDecoder rejects corrupt PASS");
        } else {
            Println!("[12] NewDecoder rejects corrupt FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
