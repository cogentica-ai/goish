// mail_message_smoke — exercise net/mail.ReadMessage + Header.
// (net/mail/message.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::errors;
use goish::io::{self, Reader};
use goish::net::mail;
use goish::{string, syscall, Println};

fn read_all_body(r: &mut alloc::boxed::Box<dyn Reader>) -> alloc::vec::Vec<u8> {
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut buf: goish::goslice::slice<u8> =
        goish::goslice::slice::__from_vec(alloc::vec![0u8; 256]);
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

    // 1. Basic ReadMessage: parse Header + Body.
    {
        let raw = string(
            "From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Hello\r\n\r\nMessage body here.",
        );
        let src = bytes::NewBufferString(raw);
        let (msg, err) = mail::ReadMessage(src);
        let m = msg.expect("expected message");
        let from = m.Header.Get(string("From"));
        let subj = m.Header.Get(string("Subject"));
        let mut body_box = m.Body;
        let body = read_all_body(&mut body_box);
        if err.IsNil()
            && from == string("alice@example.com")
            && subj == string("Hello")
            && body.as_slice() == b"Message body here."
        {
            Println!("[ 1] ReadMessage basic       PASS");
        } else {
            Println!("[ 1] ReadMessage basic       FAIL");
            failed += 1;
        }
    }

    // 2. Header.Get is case-insensitive (canonicalizes).
    {
        let raw = string("from: a@b\r\n\r\n");
        let src = bytes::NewBufferString(raw);
        let (msg, err) = mail::ReadMessage(src);
        let m = msg.expect("expected message");
        let v1 = m.Header.Get(string("From"));
        let v2 = m.Header.Get(string("FROM"));
        let v3 = m.Header.Get(string("from"));
        if err.IsNil() && v1 == string("a@b") && v1 == v2 && v2 == v3 {
            Println!("[ 2] Header.Get canonical    PASS");
        } else {
            Println!("[ 2] Header.Get canonical    FAIL");
            failed += 1;
        }
    }

    // 3. Continued (folded) header lines are concatenated.
    {
        let raw = string("Subject: Long\r\n  continuation\r\n  more\r\n\r\nbody");
        let src = bytes::NewBufferString(raw);
        let (msg, err) = mail::ReadMessage(src);
        let m = msg.expect("expected message");
        let s = m.Header.Get(string("Subject"));
        if err.IsNil() && s == string("Long continuation more") {
            Println!("[ 3] Header continuation     PASS");
        } else {
            Println!("[ 3] Header continuation     FAIL got '{}'", s);
            failed += 1;
        }
    }

    // 4. Multi-valued header (e.g., Received) preserves all values.
    {
        let raw = string("Received: from a\r\nReceived: from b\r\n\r\n");
        let src = bytes::NewBufferString(raw);
        let (msg, err) = mail::ReadMessage(src);
        let m = msg.expect("expected message");
        let inner = m.Header.0;
        let vs = if inner.Has(string("Received")) {
            inner[string("Received")].clone()
        } else {
            goish::goslice::slice::__from_vec(alloc::vec::Vec::new())
        };
        if err.IsNil()
            && vs.Len() == 2
            && vs[0i64] == string("from a")
            && vs[1i64] == string("from b")
        {
            Println!("[ 4] Header multi-value      PASS");
        } else {
            Println!("[ 4] Header multi-value      FAIL");
            failed += 1;
        }
    }

    // 5. Empty Header.Get returns "".
    {
        let raw = string("From: a\r\n\r\n");
        let src = bytes::NewBufferString(raw);
        let (msg, _) = mail::ReadMessage(src);
        let m = msg.expect("expected message");
        let v = m.Header.Get(string("Missing"));
        if v == string("") {
            Println!("[ 5] Header.Get missing      PASS");
        } else {
            Println!("[ 5] Header.Get missing      FAIL");
            failed += 1;
        }
    }

    // 6. Header without trailing body still parses (EOF after blank line).
    {
        let raw = string("Subject: alone\r\n\r\n");
        let src = bytes::NewBufferString(raw);
        let (msg, err) = mail::ReadMessage(src);
        let m = msg.expect("expected message");
        let s = m.Header.Get(string("Subject"));
        if err.IsNil() && s == string("alone") {
            Println!("[ 6] Header w/o body         PASS");
        } else {
            Println!("[ 6] Header w/o body         FAIL");
            failed += 1;
        }
    }

    // 7. Malformed header (no colon) returns error.
    {
        let raw = string("BadLine\r\n\r\n");
        let src = bytes::NewBufferString(raw);
        let (_, err) = mail::ReadMessage(src);
        if !err.IsNil() {
            Println!("[ 7] Malformed header        PASS");
        } else {
            Println!("[ 7] Malformed header        FAIL");
            failed += 1;
        }
    }

    // 8. Initial leading-whitespace line is rejected.
    {
        let raw = string(" From: a@b\r\n\r\n");
        let src = bytes::NewBufferString(raw);
        let (_, err) = mail::ReadMessage(src);
        if !err.IsNil() {
            Println!("[ 8] Leading whitespace      PASS");
        } else {
            Println!("[ 8] Leading whitespace      FAIL");
            failed += 1;
        }
    }

    // 9. Header.Has reports presence canonically.
    {
        let raw = string("Content-Type: text/plain\r\n\r\n");
        let src = bytes::NewBufferString(raw);
        let (msg, _) = mail::ReadMessage(src);
        let m = msg.expect("expected message");
        if m.Header.Has(string("content-type")) && !m.Header.Has(string("X-None")) {
            Println!("[ 9] Header.Has              PASS");
        } else {
            Println!("[ 9] Header.Has              FAIL");
            failed += 1;
        }
    }

    // 10. ErrHeaderNotPresent is a distinct singleton (errors::Is works).
    {
        let e1 = mail::ErrHeaderNotPresent();
        let e2 = mail::ErrHeaderNotPresent();
        if errors::Is(e1.clone(), e2.clone()) && !errors::Is(e1, io::EOF()) {
            Println!("[10] ErrHeaderNotPresent     PASS");
        } else {
            Println!("[10] ErrHeaderNotPresent     FAIL");
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
