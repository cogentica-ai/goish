// base64_stream_smoke — exercise base64 streaming Encoder + new
// goish-style Encode/Decode/AppendEncode/AppendDecode methods.
//
// References:
//   /share/go/src/encoding/base64/base64.go:145-294 (Encode + encoder)
//   /share/go/src/encoding/base64/base64.go:413     (AppendDecode)
//   /share/go/src/encoding/base64/base64.go:518     (Decode)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::encoding::base64;
use goish::types::byte;
use goish::{slice, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Encode (in-place) — round-trip vs EncodeToString.
    {
        let src_bytes = b"Hello, World!".to_vec();
        let src: slice<byte> = goish::slice::__from_vec(src_bytes);
        let mut dst: slice<byte> = slice::new();
        base64::StdEncoding.Encode(&mut dst, src.clone());
        let want_str = base64::StdEncoding.EncodeToString(b"Hello, World!");
        let got_str = goish::string::from_bytes(&dst);
        if got_str == want_str {
            Println!("[ 1] Encode in-place            PASS");
        } else {
            Println!("[ 1] Encode in-place            FAIL got=", got_str);
            failed += 1;
        }
    }

    // 2. AppendEncode — encoded data appended to existing buffer.
    {
        let prefix_bytes = b"data:".to_vec();
        let prefix: slice<byte> = goish::slice::__from_vec(prefix_bytes);
        let payload: slice<byte> = goish::slice::__from_vec(b"Hi".to_vec());
        let out = base64::StdEncoding.AppendEncode(prefix, payload);
        let s = goish::string::from_bytes(&out);
        let want: goish::string = "data:SGk=".into();
        if s == want {
            Println!("[ 2] AppendEncode               PASS");
        } else {
            Println!("[ 2] AppendEncode               FAIL got=", s);
            failed += 1;
        }
    }

    // 3. Decode (in-place) — round-trip.
    {
        let enc_bytes = b"SGVsbG8=".to_vec();
        let enc_slice: slice<byte> = goish::slice::__from_vec(enc_bytes);
        let mut dst: slice<byte> = slice::new();
        let (n, err) = base64::StdEncoding.Decode(&mut dst, enc_slice);
        let want_dec: goish::string = "Hello".into();
        if err.IsNil() && n == 5 && goish::string::from_bytes(&dst) == want_dec {
            Println!("[ 3] Decode in-place            PASS");
        } else {
            Println!("[ 3] Decode in-place            FAIL n=", n);
            failed += 1;
        }
    }

    // 4. AppendDecode — decoded data appended to existing buffer.
    {
        let prefix: slice<byte> = goish::slice::__from_vec(b">> ".to_vec());
        let enc: slice<byte> = goish::slice::__from_vec(b"SGk=".to_vec());
        let (out, err) = base64::StdEncoding.AppendDecode(prefix, enc);
        let s = goish::string::from_bytes(&out);
        let want: goish::string = ">> Hi".into();
        if err.IsNil() && s == want {
            Println!("[ 4] AppendDecode               PASS");
        } else {
            Println!("[ 4] AppendDecode               FAIL got=", s);
            failed += 1;
        }
    }

    // 5. NewEncoder — single Write covers full input.
    {
        let mut buf = bytes::Buffer::new();
        {
            let mut e = base64::NewEncoder(base64::StdEncoding, &mut buf);
            let payload: slice<byte> =
                goish::slice::__from_vec(b"Hello, World!".to_vec());
            let (_, werr) = e.Write(payload);
            let cerr = e.Close();
            if !werr.IsNil() || !cerr.IsNil() {
                Println!("[ 5] NewEncoder single Write    FAIL write/close errored");
                failed += 1;
                // fall through to next test
            }
        }
        let got = buf.String();
        let want: goish::string = "SGVsbG8sIFdvcmxkIQ==".into();
        if got == want {
            Println!("[ 5] NewEncoder single Write    PASS");
        } else {
            Println!("[ 5] NewEncoder single Write    FAIL got=", got);
            failed += 1;
        }
    }

    // 6. NewEncoder — small writes split mid-block, must buffer.
    {
        let mut buf = bytes::Buffer::new();
        {
            let mut e = base64::NewEncoder(base64::StdEncoding, &mut buf);
            // Write byte-by-byte to stress the partial-block buffer.
            for &b in b"Hello, World!" {
                let one: slice<byte> = goish::slice::__from_vec(alloc::vec![b]);
                let _ = e.Write(one);
            }
            let _ = e.Close();
        }
        let got = buf.String();
        let want: goish::string = "SGVsbG8sIFdvcmxkIQ==".into();
        if got == want {
            Println!("[ 6] NewEncoder byte-by-byte    PASS");
        } else {
            Println!("[ 6] NewEncoder byte-by-byte    FAIL got=", got);
            failed += 1;
        }
    }

    // 7. NewEncoder — empty input → empty output.
    {
        let mut buf = bytes::Buffer::new();
        {
            let mut e = base64::NewEncoder(base64::StdEncoding, &mut buf);
            let _ = e.Close();
        }
        let got = buf.String();
        if got == "" {
            Println!("[ 7] NewEncoder empty input     PASS");
        } else {
            Println!("[ 7] NewEncoder empty input     FAIL got=", got);
            failed += 1;
        }
    }

    // 8. NewEncoder — Raw (unpadded) variant.
    {
        let mut buf = bytes::Buffer::new();
        {
            let mut e = base64::NewEncoder(base64::RawStdEncoding, &mut buf);
            let payload: slice<byte> =
                goish::slice::__from_vec(b"Hi".to_vec()); // 2 bytes → 3 chars no pad
            let _ = e.Write(payload);
            let _ = e.Close();
        }
        let got = buf.String();
        let want: goish::string = "SGk".into();
        if got == want {
            Println!("[ 8] NewEncoder RawStdEncoding  PASS");
        } else {
            Println!("[ 8] NewEncoder RawStdEncoding  FAIL got=", got);
            failed += 1;
        }
    }

    // 9. NewEncoder — large input crosses multiple internal flushes.
    {
        let mut payload_v: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
        // 2049 bytes — forces at least two interior flushes (out buf
        // is 1024 bytes ≈ 768 src bytes per pass).
        for i in 0..2049 {
            payload_v.push((i & 0xff) as byte);
        }
        let payload_slice: slice<byte> =
            goish::slice::__from_vec(payload_v.clone());

        let want = base64::StdEncoding.EncodeToString(&payload_v);

        let mut buf = bytes::Buffer::new();
        {
            let mut e = base64::NewEncoder(base64::StdEncoding, &mut buf);
            let _ = e.Write(payload_slice);
            let _ = e.Close();
        }
        let got = buf.String();
        if got == want {
            Println!("[ 9] NewEncoder 2049 bytes      PASS");
        } else {
            Println!("[ 9] NewEncoder 2049 bytes      FAIL");
            failed += 1;
        }
    }

    // 10. AppendDecode — invalid input surfaces error.
    {
        let prefix: slice<byte> = slice::new();
        let enc: slice<byte> =
            goish::slice::__from_vec(b"!!!!".to_vec()); // not in alphabet
        let (_out, err) = base64::StdEncoding.AppendDecode(prefix, enc);
        if !err.IsNil() {
            Println!("[10] AppendDecode error path    PASS");
        } else {
            Println!("[10] AppendDecode error path    FAIL no error");
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
