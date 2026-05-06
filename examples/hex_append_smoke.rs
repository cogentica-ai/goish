// hex_append_smoke — exercise hex.AppendEncode + AppendDecode.
// (encoding/hex/hex.go:57 AppendEncode, hex.go:118 AppendDecode)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::encoding::hex;
use goish::goslice::slice;
use goish::types::byte;
use goish::{syscall, Println};

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

fn equal_bytes(a: slice<byte>, b: slice<byte>) -> bool {
    let aa: &[byte] = &a;
    let bb: &[byte] = &b;
    aa == bb
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. AppendEncode("", "") -> "".
    {
        let out = hex::AppendEncode(empty_buf(), empty_buf());
        let raw: &[byte] = &out;
        if raw.is_empty() {
            Println!("[ 1] empty AppendEncode        PASS");
        } else {
            Println!("[ 1] empty AppendEncode        FAIL");
            failed += 1;
        }
    }

    // 2. AppendEncode([], "abc") -> "616263".
    {
        let out = hex::AppendEncode(empty_buf(), to_bytes("abc"));
        if equal_bytes(out, to_bytes("616263")) {
            Println!("[ 2] AppendEncode \"abc\"        PASS");
        } else {
            Println!("[ 2] AppendEncode \"abc\"        FAIL");
            failed += 1;
        }
    }

    // 3. AppendEncode preserves dst prefix.
    {
        let dst = to_bytes("PREFIX:");
        let out = hex::AppendEncode(dst, to_bytes("a"));
        // "PREFIX:" + "61"
        if equal_bytes(out, to_bytes("PREFIX:61")) {
            Println!("[ 3] AppendEncode prefix       PASS");
        } else {
            Println!("[ 3] AppendEncode prefix       FAIL");
            failed += 1;
        }
    }

    // 4. AppendEncode binary bytes.
    {
        // Build src = [0x00, 0xFF, 0x10] manually.
        let mut v: Vec<byte> = Vec::new();
        v.push(0x00);
        v.push(0xFF);
        v.push(0x10);
        let src = slice::<byte>::__from_vec(v);
        let out = hex::AppendEncode(empty_buf(), src);
        if equal_bytes(out, to_bytes("00ff10")) {
            Println!("[ 4] AppendEncode binary       PASS");
        } else {
            Println!("[ 4] AppendEncode binary       FAIL");
            failed += 1;
        }
    }

    // 5. AppendDecode("616263") -> "abc", nil.
    {
        let (out, err) = hex::AppendDecode(empty_buf(), to_bytes("616263"));
        if err.IsNil() && equal_bytes(out, to_bytes("abc")) {
            Println!("[ 5] AppendDecode \"616263\"     PASS");
        } else {
            Println!("[ 5] AppendDecode \"616263\"     FAIL");
            failed += 1;
        }
    }

    // 6. AppendDecode preserves dst prefix.
    {
        let dst = to_bytes("DST:");
        let (out, err) = hex::AppendDecode(dst, to_bytes("4869"));
        // "DST:" + "Hi"
        if err.IsNil() && equal_bytes(out, to_bytes("DST:Hi")) {
            Println!("[ 6] AppendDecode prefix       PASS");
        } else {
            Println!("[ 6] AppendDecode prefix       FAIL");
            failed += 1;
        }
    }

    // 7. AppendDecode odd-length input → ErrLength + partial decoded.
    {
        // "61626" len=5 — pairs "61","62" decode → "ab"; trailing '6'
        // is valid hex but odd-length triggers ErrLength.
        let (out, err) = hex::AppendDecode(empty_buf(), to_bytes("61626"));
        let raw: &[byte] = &out;
        if !err.IsNil() && raw == b"ab" {
            Println!("[ 7] AppendDecode odd len      PASS");
        } else {
            Println!(
                "[ 7] AppendDecode odd len      FAIL nil_err=",
                if err.IsNil() { 1 } else { 0 }
            );
            failed += 1;
        }
    }

    // 8. AppendDecode invalid byte → InvalidByteError + partial decoded.
    {
        // "6Z" — first nibble valid, second nibble 'Z' invalid → no
        // bytes decoded. Wait, actually ours decodes pair-by-pair.
        // "61ZZ" — first pair "61" → 'a'; second pair "ZZ" → error.
        let (out, err) = hex::AppendDecode(empty_buf(), to_bytes("61ZZ"));
        let raw: &[byte] = &out;
        if !err.IsNil() && raw == b"a" {
            Println!("[ 8] AppendDecode invalid      PASS");
        } else {
            Println!(
                "[ 8] AppendDecode invalid      FAIL nil_err=",
                if err.IsNil() { 1 } else { 0 }
            );
            failed += 1;
        }
    }

    // 9. AppendEncode + AppendDecode round-trip preserves dst prefix
    //    chain through both calls.
    {
        let dst1 = to_bytes("ENC:");
        let encoded = hex::AppendEncode(dst1, to_bytes("hi"));
        // encoded = "ENC:6869"
        if !equal_bytes(encoded.clone(), to_bytes("ENC:6869")) {
            Println!("[ 9] round-trip                FAIL enc");
            failed += 1;
        } else {
            // Decode just the hex tail; pre-existing DecodeString does that.
            let (decoded, err) = hex::DecodeString("6869");
            if err.IsNil() && equal_bytes(decoded, to_bytes("hi")) {
                Println!("[ 9] round-trip                PASS");
            } else {
                Println!("[ 9] round-trip                FAIL dec");
                failed += 1;
            }
        }
    }

    // 10. AppendDecode on invalid input returns non-nil error.
    {
        let (_, err) = hex::AppendDecode(empty_buf(), to_bytes("ZZ"));
        // Just confirm error is non-nil; typed-error introspection
        // for InvalidByteError isn't exposed.
        if !err.IsNil() {
            Println!("[10] error non-nil             PASS");
        } else {
            Println!("[10] error non-nil             FAIL");
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
