// base64_decoder_smoke — exercise streaming base64 NewDecoder.
//
// References:
//   /share/go/src/encoding/base64/base64.go:435-650 (Decoder)
//   /share/go/src/encoding/base64/base64.go:622-645 (newlineFiltering)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::convert;
use goish::encoding::base64;
use goish::io;
use goish::types::byte;
use goish::{slice, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. NewDecoder — single Read covers full input.
    {
        let src = bytes::NewReader(slice::__from_vec(
            b"SGVsbG8sIFdvcmxkIQ==".to_vec(),
        ));
        let mut dec = base64::NewDecoder(base64::StdEncoding, src);
        let mut out = goish::make!([]byte, 64);
        let (n, _err) = dec.Read(&mut out);
        let got = out.slice(0, n);
        let want_str: goish::string = "Hello, World!".into();
        if goish::string::from_bytes(&got) == want_str {
            Println!("[ 1] Decoder single Read        PASS");
        } else {
            Println!(
                "[ 1] Decoder single Read        FAIL got=",
                goish::string::from_bytes(&got)
            );
            failed += 1;
        }
    }

    // 2. NewDecoder via io::ReadAll — drains until EOF.
    {
        let src = bytes::NewReader(slice::__from_vec(
            b"SGVsbG8sIFdvcmxkIQ==".to_vec(),
        ));
        let mut dec = base64::NewDecoder(base64::StdEncoding, src);
        let (got, err) = io::ReadAll(&mut dec);
        let want_str: goish::string = "Hello, World!".into();
        if err.IsNil() && goish::string::from_bytes(&got) == want_str {
            Println!("[ 2] Decoder + io::ReadAll      PASS");
        } else {
            Println!(
                "[ 2] Decoder + io::ReadAll      FAIL got=",
                goish::string::from_bytes(&got)
            );
            failed += 1;
        }
    }

    // 3. NewDecoder — small destination buffer (forces outbuf staging).
    {
        let src = bytes::NewReader(slice::__from_vec(
            b"SGVsbG8sIFdvcmxkIQ==".to_vec(),
        ));
        let mut dec = base64::NewDecoder(base64::StdEncoding, src);
        // Read into a 1-byte buffer repeatedly; collect all output.
        let mut collected: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
        loop {
            let mut tmp = goish::make!([]byte, 1);
            let (n, err) = dec.Read(&mut tmp);
            for i in 0..n {
                collected.push(tmp[i]);
            }
            if !err.IsNil() {
                break;
            }
            if n == 0 {
                break;
            }
        }
        let got = goish::string::from_bytes(&collected);
        let want: goish::string = "Hello, World!".into();
        if got == want {
            Println!("[ 3] Decoder byte-by-byte       PASS");
        } else {
            Println!("[ 3] Decoder byte-by-byte       FAIL got=", got);
            failed += 1;
        }
    }

    // 4. NewDecoder — empty input → 0 bytes + EOF on next Read.
    {
        let src = bytes::NewReader(slice::new());
        let mut dec = base64::NewDecoder(base64::StdEncoding, src);
        let mut out = goish::make!([]byte, 8);
        let (n, err) = dec.Read(&mut out);
        let eof = io::EOF();
        if n == 0 && goish::errors::Is(err, eof) {
            Println!("[ 4] Decoder empty input → EOF  PASS");
        } else {
            Println!("[ 4] Decoder empty input → EOF  FAIL");
            failed += 1;
        }
    }

    // 5. NewDecoder — newline tolerance ('\n' between blocks).
    {
        let src = bytes::NewReader(slice::__from_vec(
            b"SGVsbG8s\nIFdvcmxk\nIQ==".to_vec(),
        ));
        let mut dec = base64::NewDecoder(base64::StdEncoding, src);
        let (got, err) = io::ReadAll(&mut dec);
        let want: goish::string = "Hello, World!".into();
        if err.IsNil() && goish::string::from_bytes(&got) == want {
            Println!("[ 5] Decoder \\n tolerance       PASS");
        } else {
            Println!(
                "[ 5] Decoder \\n tolerance       FAIL got=",
                goish::string::from_bytes(&got)
            );
            failed += 1;
        }
    }

    // 6. NewDecoder — \r\n tolerance (CRLF, stripped).
    {
        let src = bytes::NewReader(slice::__from_vec(
            b"SGVsbG8s\r\nIFdvcmxk\r\nIQ==".to_vec(),
        ));
        let mut dec = base64::NewDecoder(base64::StdEncoding, src);
        let (got, err) = io::ReadAll(&mut dec);
        let want: goish::string = "Hello, World!".into();
        if err.IsNil() && goish::string::from_bytes(&got) == want {
            Println!("[ 6] Decoder CRLF tolerance     PASS");
        } else {
            Println!(
                "[ 6] Decoder CRLF tolerance     FAIL got=",
                goish::string::from_bytes(&got)
            );
            failed += 1;
        }
    }

    // 7. NewDecoder — RawStdEncoding (unpadded final fragment).
    {
        // "Hi" → "SGk" (3 chars, no padding).
        let src = bytes::NewReader(slice::__from_vec(b"SGk".to_vec()));
        let mut dec = base64::NewDecoder(base64::RawStdEncoding, src);
        let (got, err) = io::ReadAll(&mut dec);
        let want: goish::string = "Hi".into();
        if err.IsNil() && goish::string::from_bytes(&got) == want {
            Println!("[ 7] Decoder RawStdEncoding     PASS");
        } else {
            Println!(
                "[ 7] Decoder RawStdEncoding     FAIL got=",
                goish::string::from_bytes(&got)
            );
            failed += 1;
        }
    }

    // 8. NewDecoder — large input crosses multiple internal refills.
    {
        // 2049 bytes of (i & 0xff) — exceeds the 768-byte outbuf and
        // 1024-byte inbuf, so triggers multiple decode passes.
        let mut payload_v: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
        for i in 0..2049 {
            payload_v.push((i & 0xff) as byte);
        }
        let encoded = base64::StdEncoding.EncodeToString(&payload_v);
        let src = bytes::NewReader(convert::bytes(encoded));
        let mut dec = base64::NewDecoder(base64::StdEncoding, src);
        let (got, err) = io::ReadAll(&mut dec);
        let got_v = got.__into_vec();
        if err.IsNil() && got_v == payload_v {
            Println!("[ 8] Decoder 2049 bytes         PASS");
        } else {
            Println!(
                "[ 8] Decoder 2049 bytes         FAIL got_len=",
                got_v.len() as goish::types::int
            );
            failed += 1;
        }
    }

    // 9. NewDecoder — invalid input surfaces error.
    {
        let src = bytes::NewReader(slice::__from_vec(b"!!!!".to_vec()));
        let mut dec = base64::NewDecoder(base64::StdEncoding, src);
        let mut out = goish::make!([]byte, 8);
        let (_n, err) = dec.Read(&mut out);
        // Must surface a non-nil, non-EOF error (corrupt input).
        let eof = io::EOF();
        if !err.IsNil() && !goish::errors::Is(err.clone(), eof) {
            Println!("[ 9] Decoder corrupt input      PASS");
        } else {
            Println!("[ 9] Decoder corrupt input      FAIL");
            failed += 1;
        }
    }

    // 10. NewDecoder — round-trip via NewEncoder + NewDecoder.
    {
        let original = b"The quick brown fox jumps over the lazy dog.";
        let mut buf = bytes::Buffer::new();
        {
            let mut e = base64::NewEncoder(base64::StdEncoding, &mut buf);
            let payload: slice<byte> =
                slice::__from_vec(original.to_vec());
            let _ = e.Write(payload);
            let _ = e.Close();
        }
        let encoded_str = buf.String();
        let src = bytes::NewReader(convert::bytes(encoded_str));
        let mut dec = base64::NewDecoder(base64::StdEncoding, src);
        let (got, err) = io::ReadAll(&mut dec);
        let got_v = got.__into_vec();
        if err.IsNil() && got_v == original.to_vec() {
            Println!("[10] NewEncoder→NewDecoder rt   PASS");
        } else {
            Println!("[10] NewEncoder→NewDecoder rt   FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
