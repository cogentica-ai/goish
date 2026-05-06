// qp_smoke — exercise mime/quotedprintable.
// (mime/quotedprintable/{reader.go, writer.go})

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::convert;
use goish::goslice::slice;
use goish::io::{self, Closer, Reader, Writer};
use goish::mime::quotedprintable::{NewReader, NewWriter};
use goish::strings;
use goish::types::byte;
use goish::{string, syscall, Println};

fn read_all<R: Reader>(r: &mut R) -> alloc::vec::Vec<byte> {
    let mut out: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 256]);
    loop {
        let (n, e) = r.Read(&mut buf);
        if n > 0 {
            for i in 0..n as usize {
                out.push(buf[i as i64]);
            }
        }
        if !e.IsNil() {
            break;
        }
    }
    out
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Encode literal printable bytes.
    {
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut w = NewWriter(&mut buf);
        let _ = w.Write(convert::bytes("Hello, World!\nfoo\tbar=baz"));
        let _ = w.Close();
        let s = buf.String();
        // Go reference: "Hello, World!\r\nfoo\tbar=3Dbaz"
        if s == string("Hello, World!\r\nfoo\tbar=3Dbaz") {
            Println!("[ 1] encode mixed            PASS");
        } else {
            Println!("[ 1] encode mixed            FAIL got {}", s);
            failed += 1;
        }
    }

    // 2. Decode hex-escaped bytes.
    {
        let src = bytes::NewBufferString(string("=68=65=6C=6C=6F\r\n"));
        let mut r = NewReader(src);
        let out = read_all(&mut r);
        let want: &[u8] = b"hello\r\n";
        if out.as_slice() == want {
            Println!("[ 2] decode hex              PASS");
        } else {
            Println!("[ 2] decode hex              FAIL");
            failed += 1;
        }
    }

    // 3. Decode soft line break "=\r\n".
    {
        let src = bytes::NewBufferString(string("foo=\r\nbar"));
        let mut r = NewReader(src);
        let out = read_all(&mut r);
        let want: &[u8] = b"foobar";
        if out.as_slice() == want {
            Println!("[ 3] decode soft break       PASS");
        } else {
            Println!("[ 3] decode soft break       FAIL");
            failed += 1;
        }
    }

    // 4. Decode soft line break "=\n" (LF-only).
    {
        let src = bytes::NewBufferString(string("foo=\nbar"));
        let mut r = NewReader(src);
        let out = read_all(&mut r);
        let want: &[u8] = b"foobar";
        if out.as_slice() == want {
            Println!("[ 4] decode soft break LF    PASS");
        } else {
            Println!("[ 4] decode soft break LF    FAIL");
            failed += 1;
        }
    }

    // 5. Encode binary chars (high bytes).
    {
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut w = NewWriter(&mut buf);
        let _ = w.Write(slice::__from_vec(alloc::vec![0xde, 0xad, 0xbe, 0xef]));
        let _ = w.Close();
        let s = buf.String();
        // Each byte becomes =XX
        if s == string("=DE=AD=BE=EF") {
            Println!("[ 5] encode binary           PASS");
        } else {
            Println!("[ 5] encode binary           FAIL got {}", s);
            failed += 1;
        }
    }

    // 6. Decode binary back from encoded form.
    {
        let src = bytes::NewBufferString(string("=DE=AD=BE=EF"));
        let mut r = NewReader(src);
        let out = read_all(&mut r);
        let want: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
        if out.as_slice() == want {
            Println!("[ 6] decode binary           PASS");
        } else {
            Println!("[ 6] decode binary           FAIL");
            failed += 1;
        }
    }

    // 7. Encode wraps at 76 chars with soft-break.
    {
        let long_input: alloc::vec::Vec<u8> = alloc::vec![b'A'; 100];
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut w = NewWriter(&mut buf);
        let _ = w.Write(slice::__from_vec(long_input));
        let _ = w.Close();
        let s = buf.String();
        // The encoded should contain at least one soft break "=\r\n".
        if strings::Contains(s.clone(), string("=\r\n")) {
            Println!("[ 7] encode wraps at 76      PASS");
        } else {
            Println!("[ 7] encode wraps at 76      FAIL");
            failed += 1;
        }
    }

    // 8. Lowercase hex digits accepted on decode.
    {
        let src = bytes::NewBufferString(string("=ab=cd"));
        let mut r = NewReader(src);
        let out = read_all(&mut r);
        let want: &[u8] = &[0xab, 0xcd];
        if out.as_slice() == want {
            Println!("[ 8] decode lowercase hex    PASS");
        } else {
            Println!("[ 8] decode lowercase hex    FAIL");
            failed += 1;
        }
    }

    // 9. Round-trip through encoder + decoder for ASCII printable.
    {
        let original = "The quick brown fox jumps over the lazy dog. 0123456789!";
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut w = NewWriter(&mut buf);
        let _ = w.Write(convert::bytes(original));
        let _ = w.Close();
        let mut r = NewReader(buf);
        let out = read_all(&mut r);
        if out.as_slice() == original.as_bytes() {
            Println!("[ 9] round-trip ASCII        PASS");
        } else {
            Println!("[ 9] round-trip ASCII        FAIL");
            failed += 1;
        }
    }

    // 10. Trailing whitespace before line break is encoded.
    {
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut w = NewWriter(&mut buf);
        let _ = w.Write(convert::bytes("foo \nbar"));
        let _ = w.Close();
        let s = buf.String();
        // Trailing space before \n should be encoded as =20.
        if strings::Contains(s.clone(), string("=20")) {
            Println!("[10] encode trailing space   PASS");
        } else {
            Println!("[10] encode trailing space   FAIL got {}", s);
            failed += 1;
        }
    }

    // 11. Decoding empty input → empty output, EOF.
    {
        let src = bytes::NewBufferString(string(""));
        let mut r = NewReader(src);
        let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 16]);
        let (n, e) = r.Read(&mut buf);
        if n == 0 && goish::errors::Is(e, io::EOF) {
            Println!("[11] decode empty            PASS");
        } else {
            Println!("[11] decode empty            FAIL n={}", n);
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 11/11");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 11");
        syscall::Exit(1);
    }
}
