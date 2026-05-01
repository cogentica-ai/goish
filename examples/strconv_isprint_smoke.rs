// strconv_isprint_smoke — exercise strconv.IsPrint + IsGraphic
// (quote.go:522 + 568, slim Latin-1 + valid-Unicode rune fallback).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::strconv;
use goish::types::rune;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Printable ASCII range.
    {
        let mut all_ok = true;
        let mut r: rune = 0x20;
        while r <= 0x7E {
            if !strconv::IsPrint(r) {
                all_ok = false;
                break;
            }
            r += 1;
        }
        if all_ok {
            Println!("[ 1] IsPrint ASCII printable   PASS");
        } else {
            Println!("[ 1] IsPrint ASCII printable   FAIL");
            failed += 1;
        }
    }

    // 2. ASCII control chars not printable.
    {
        if !strconv::IsPrint(0x00) && !strconv::IsPrint(0x07) && !strconv::IsPrint(0x1F)
            && !strconv::IsPrint(0x7F) && !strconv::IsPrint(0x80)
        {
            Println!("[ 2] IsPrint ASCII control     PASS");
        } else {
            Println!("[ 2] IsPrint ASCII control     FAIL");
            failed += 1;
        }
    }

    // 3. 0xA1..0xFF range printable, 0xAD (soft hyphen) excluded.
    {
        if strconv::IsPrint(0xA1) && strconv::IsPrint(0xFF) && !strconv::IsPrint(0xAD) {
            Println!("[ 3] IsPrint Latin-1 + soft    PASS");
        } else {
            Println!("[ 3] IsPrint Latin-1 + soft    FAIL");
            failed += 1;
        }
    }

    // 4. Latin-1 0x80..0xA0 (control region) not printable.
    {
        if !strconv::IsPrint(0x80) && !strconv::IsPrint(0xA0) {
            Println!("[ 4] IsPrint Latin-1 ctrl      PASS");
        } else {
            Println!("[ 4] IsPrint Latin-1 ctrl      FAIL");
            failed += 1;
        }
    }

    // 5. Surrogate range never printable.
    {
        if !strconv::IsPrint(0xD800) && !strconv::IsPrint(0xDFFF) {
            Println!("[ 5] IsPrint surrogate         PASS");
        } else {
            Println!("[ 5] IsPrint surrogate         FAIL");
            failed += 1;
        }
    }

    // 6. Out-of-range > 0x10FFFF not printable.
    {
        if !strconv::IsPrint(0x110000) && !strconv::IsPrint(-1) {
            Println!("[ 6] IsPrint out-of-range      PASS");
        } else {
            Println!("[ 6] IsPrint out-of-range      FAIL");
            failed += 1;
        }
    }

    // 7. CJK / emoji range valid → slim accepts as printable.
    {
        if strconv::IsPrint(0x4E2D) /* 中 */ && strconv::IsPrint(0x1F600) /* 😀 */ {
            Println!("[ 7] IsPrint slim CJK + emoji  PASS");
        } else {
            Println!("[ 7] IsPrint slim CJK + emoji  FAIL");
            failed += 1;
        }
    }

    // 8. IsGraphic same as IsPrint per slim defer.
    {
        if strconv::IsGraphic(0x41) && strconv::IsGraphic(0xA1) && !strconv::IsGraphic(0x00)
            && !strconv::IsGraphic(0xD800)
        {
            Println!("[ 8] IsGraphic parity          PASS");
        } else {
            Println!("[ 8] IsGraphic parity          FAIL");
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
