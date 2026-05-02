// textproto_reader_smoke — exercise net/textproto.Reader (line + MIMEHeader).
// (net/textproto/reader.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bufio;
use goish::bytes;
use goish::errors;
use goish::io;
use goish::net::textproto;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ReadLine — strips trailing \r\n.
    {
        let buf = bytes::NewBufferString(string("Hello world\r\nSecond\n"));
        let br = bufio::NewReader(buf);
        let mut r = textproto::NewReader(br);
        let (l1, e1) = r.ReadLine();
        let (l2, e2) = r.ReadLine();
        if e1.IsNil()
            && e2.IsNil()
            && l1 == string("Hello world")
            && l2 == string("Second")
        {
            Println!("[ 1] ReadLine                PASS");
        } else {
            Println!("[ 1] ReadLine                FAIL got '{}'/'{}'", l1, l2);
            failed += 1;
        }
    }

    // 2. ReadLine returns io.EOF after end.
    {
        let buf = bytes::NewBufferString(string("only\n"));
        let br = bufio::NewReader(buf);
        let mut r = textproto::NewReader(br);
        let (_, _) = r.ReadLine();
        let (_, e2) = r.ReadLine();
        if errors::Is(e2, io::EOF()) {
            Println!("[ 2] ReadLine EOF            PASS");
        } else {
            Println!("[ 2] ReadLine EOF            FAIL");
            failed += 1;
        }
    }

    // 3. ReadContinuedLine — folds " continued..." into preceding line.
    {
        let buf = bytes::NewBufferString(string("Line 1\r\n  continued...\r\nLine 2\r\n"));
        let br = bufio::NewReader(buf);
        let mut r = textproto::NewReader(br);
        let (l1, e1) = r.ReadContinuedLine();
        let (l2, e2) = r.ReadContinuedLine();
        if e1.IsNil()
            && e2.IsNil()
            && l1 == string("Line 1 continued...")
            && l2 == string("Line 2")
        {
            Println!("[ 3] ReadContinuedLine       PASS");
        } else {
            Println!("[ 3] ReadContinuedLine       FAIL got '{}'/'{}'", l1, l2);
            failed += 1;
        }
    }

    // 4. ReadMIMEHeader — single-value, multi-value, canonical key.
    {
        let buf = bytes::NewBufferString(string(
            "My-Key: Value 1\r\nLong-Key: Even\r\n       Longer Value\r\nMy-Key: Value 2\r\n\r\n",
        ));
        let br = bufio::NewReader(buf);
        let mut r = textproto::NewReader(br);
        let (h, err) = r.ReadMIMEHeader();
        let mk_vals = if h.Has(string("My-Key")) {
            h[string("My-Key")].clone()
        } else {
            goish::goslice::slice::__from_vec(alloc::vec::Vec::new())
        };
        let lk_vals = if h.Has(string("Long-Key")) {
            h[string("Long-Key")].clone()
        } else {
            goish::goslice::slice::__from_vec(alloc::vec::Vec::new())
        };
        let ok = err.IsNil()
            && mk_vals.Len() == 2
            && mk_vals[0i64] == string("Value 1")
            && mk_vals[1i64] == string("Value 2")
            && lk_vals.Len() == 1
            && lk_vals[0i64] == string("Even Longer Value");
        if ok {
            Println!("[ 4] ReadMIMEHeader basic    PASS");
        } else {
            Println!("[ 4] ReadMIMEHeader basic    FAIL");
            failed += 1;
        }
    }

    // 5. ReadMIMEHeader canonicalizes lowercase keys.
    {
        let buf = bytes::NewBufferString(string("content-type: text/html\r\n\r\n"));
        let br = bufio::NewReader(buf);
        let mut r = textproto::NewReader(br);
        let (h, err) = r.ReadMIMEHeader();
        let v = textproto::Get(&h, string("content-type"));
        if err.IsNil() && v == string("text/html") && h.Has(string("Content-Type")) {
            Println!("[ 5] MIMEHeader canonical    PASS");
        } else {
            Println!("[ 5] MIMEHeader canonical    FAIL got {}", v);
            failed += 1;
        }
    }

    // 6. ReadMIMEHeader rejects malformed (missing colon).
    {
        let buf = bytes::NewBufferString(string("BadLineNoColon\r\n\r\n"));
        let br = bufio::NewReader(buf);
        let mut r = textproto::NewReader(br);
        let (_, err) = r.ReadMIMEHeader();
        if !err.IsNil() {
            Println!("[ 6] MIMEHeader bad line     PASS");
        } else {
            Println!("[ 6] MIMEHeader bad line     FAIL");
            failed += 1;
        }
    }

    // 7. ReadMIMEHeader rejects leading whitespace before first header.
    {
        let buf = bytes::NewBufferString(string(" My-Key: value\r\n\r\n"));
        let br = bufio::NewReader(buf);
        let mut r = textproto::NewReader(br);
        let (_, err) = r.ReadMIMEHeader();
        if !err.IsNil() {
            Println!("[ 7] MIMEHeader bad first    PASS");
        } else {
            Println!("[ 7] MIMEHeader bad first    FAIL");
            failed += 1;
        }
    }

    // 8. validHeaderFieldByte / validHeaderValueByte sanity.
    {
        let f_ok =
            textproto::validHeaderFieldByte(b'A') && textproto::validHeaderFieldByte(b'!');
        let f_bad = !textproto::validHeaderFieldByte(b' ')
            && !textproto::validHeaderFieldByte(b':')
            && !textproto::validHeaderFieldByte(0x80);
        let v_ok = textproto::validHeaderValueByte(b' ')
            && textproto::validHeaderValueByte(b'\t')
            && textproto::validHeaderValueByte(b'~');
        let v_bad =
            !textproto::validHeaderValueByte(b'\n') && !textproto::validHeaderValueByte(0x7f);
        if f_ok && f_bad && v_ok && v_bad {
            Println!("[ 8] valid byte predicates   PASS");
        } else {
            Println!("[ 8] valid byte predicates   FAIL");
            failed += 1;
        }
    }

    // 9. Empty input → ReadMIMEHeader returns empty map + EOF.
    {
        let buf = bytes::NewBufferString(string(""));
        let br = bufio::NewReader(buf);
        let mut r = textproto::NewReader(br);
        let (h, err) = r.ReadMIMEHeader();
        if errors::Is(err, io::EOF()) && h.Len() == 0 {
            Println!("[ 9] MIMEHeader empty input  PASS");
        } else {
            Println!("[ 9] MIMEHeader empty input  FAIL");
            failed += 1;
        }
    }

    // 10. ReadLineBytes returns the raw bytes (no trailing CRLF).
    {
        let buf = bytes::NewBufferString(string("hello\r\n"));
        let br = bufio::NewReader(buf);
        let mut r = textproto::NewReader(br);
        let (b, err) = r.ReadLineBytes();
        let raw: &[u8] = b.as_ref();
        if err.IsNil() && raw == b"hello" {
            Println!("[10] ReadLineBytes           PASS");
        } else {
            Println!("[10] ReadLineBytes           FAIL");
            failed += 1;
        }
    }

    // 11. ReadMIMEHeader stops at blank \r\n line and leaves body intact.
    {
        let buf = bytes::NewBufferString(string("A: 1\r\nB: 2\r\n\r\nbody-bytes"));
        let br = bufio::NewReader(buf);
        let mut r = textproto::NewReader(br);
        let (h, err) = r.ReadMIMEHeader();
        // After header, remaining bytes should still be readable as a line.
        let (rest, _) = r.ReadLine();
        if err.IsNil()
            && h.Len() == 2
            && h.Has(string("A"))
            && h.Has(string("B"))
            && rest == string("body-bytes")
        {
            Println!("[11] header then body        PASS");
        } else {
            Println!("[11] header then body        FAIL rest='{}'", rest);
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
