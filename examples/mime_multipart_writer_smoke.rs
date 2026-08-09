// mime_multipart_writer_smoke — exercise mime/multipart::Writer
// (slim line-by-line port of writer.go).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::fmt;
use goish::convert::bytes;
use goish::mime::multipart;
use goish::types::byte;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Boundary is non-empty + 60 chars (30 bytes hex-encoded).
    {
        let mut buf =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(Vec::new()));
        let w = multipart::NewWriter(&mut buf);
        let b = w.Boundary();
        if b.Len() == 60 {
            fmt::Println!("[ 1] random boundary len       PASS");
        } else {
            fmt::Println!("[ 1] random boundary len       FAIL got={}", b.Len());
            failed += 1;
        }
    }

    // 2. SetBoundary + FormDataContentType.
    {
        let mut buf =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(Vec::new()));
        let mut w = multipart::NewWriter(&mut buf);
        let err = w.SetBoundary(string("X-myBoundary-1"));
        let ct = w.FormDataContentType();
        if err.IsNil() && ct == "multipart/form-data; boundary=X-myBoundary-1" {
            fmt::Println!("[ 2] SetBoundary + Content-T   PASS");
        } else {
            fmt::Println!("[ 2] SetBoundary + Content-T   FAIL ct={}", ct);
            failed += 1;
        }
    }

    // 3. Boundary too long → error.
    {
        let mut buf =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(Vec::new()));
        let mut w = multipart::NewWriter(&mut buf);
        let too_long = string(
            "12345678901234567890123456789012345678901234567890123456789012345678901",
        );
        let err = w.SetBoundary(too_long);
        if !err.IsNil() {
            fmt::Println!("[ 3] boundary too long → err   PASS");
        } else {
            fmt::Println!("[ 3] boundary too long → err   FAIL");
            failed += 1;
        }
    }

    // 4. WriteField round-trip.
    {
        let mut buf =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(Vec::new()));
        {
            let mut w = multipart::NewWriter(&mut buf);
            let _ = w.SetBoundary(string("BOUND"));
            let _ = w.WriteField(string("name"), string("alice"));
            let _ = w.WriteField(string("age"), string("30"));
            let _ = w.Close();
        }
        let on_wire = buf.Bytes();
        let mut v: Vec<u8> = Vec::with_capacity(on_wire.Len() as usize);
        for i in 0..on_wire.Len() {
            v.push(on_wire[i]);
        }
        let s = goish::string::from_bytes(&v);
        let want_head_a =
            "--BOUND\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nalice";
        let want_head_b =
            "\r\n--BOUND\r\nContent-Disposition: form-data; name=\"age\"\r\n\r\n30";
        let want_tail = "\r\n--BOUND--\r\n";
        let has_a = goish::strings::Contains(s.clone(), string(want_head_a));
        let has_b = goish::strings::Contains(s.clone(), string(want_head_b));
        let has_t = goish::strings::HasSuffix(s.clone(), string(want_tail));
        if has_a && has_b && has_t {
            fmt::Println!("[ 4] WriteField wire           PASS");
        } else {
            fmt::Println!(
                "[ 4] WriteField wire           FAIL a={} b={} t={}",
                has_a, has_b, has_t
            );
            failed += 1;
        }
    }

    // 5. WriteFile produces Content-Type + filename.
    {
        let mut buf =
            goish::bytes::NewBuffer(goish::goslice::slice::<u8>::__from_vec(Vec::new()));
        {
            let mut w = multipart::NewWriter(&mut buf);
            let _ = w.SetBoundary(string("X"));
            let _ = w.WriteFile(string("file"), string("hello.bin"), bytes("BINBYTES"));
            let _ = w.Close();
        }
        let on_wire = buf.Bytes();
        let mut v: Vec<u8> = Vec::with_capacity(on_wire.Len() as usize);
        for i in 0..on_wire.Len() {
            v.push(on_wire[i]);
        }
        let s = goish::string::from_bytes(&v);
        let has_disp = goish::strings::Contains(
            s.clone(),
            string("Content-Disposition: form-data; name=\"file\"; filename=\"hello.bin\""),
        );
        let has_ct = goish::strings::Contains(
            s.clone(),
            string("Content-Type: application/octet-stream"),
        );
        let has_body = goish::strings::Contains(s.clone(), string("BINBYTES"));
        if has_disp && has_ct && has_body {
            fmt::Println!("[ 5] WriteFile wire            PASS");
        } else {
            fmt::Println!(
                "[ 5] WriteFile wire            FAIL d={} c={} b={}",
                has_disp, has_ct, has_body
            );
            failed += 1;
        }
    }

    // 6. FileContentDisposition free fn.
    {
        let s =
            multipart::FileContentDisposition(string("up\\load"), string("foo\".bin"));
        if s == "form-data; name=\"up\\\\load\"; filename=\"foo\\\".bin\"" {
            fmt::Println!("[ 6] FileContentDisposition    PASS");
        } else {
            fmt::Println!("[ 6] FileContentDisposition    FAIL got={}", s);
            failed += 1;
        }
    }

    // 7. crypto/rand.Read fills with non-zero bytes (probabilistic
    //    but the chance of 8 zero bytes from a CSPRNG is < 2^-64).
    {
        let mut b = goish::make!([]byte, 8);
        let (n, err) = goish::crypto::rand::Read(&mut b);
        let mut all_zero = true;
        for i in 0..n {
            if b[i] != 0 {
                all_zero = false;
                break;
            }
        }
        if err.IsNil() && n == 8 && !all_zero {
            fmt::Println!("[ 7] crypto/rand.Read          PASS");
        } else {
            fmt::Println!("[ 7] crypto/rand.Read          FAIL n={} zero={}", n, all_zero);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 7", failed);
        syscall::Exit(1);
    }
}
