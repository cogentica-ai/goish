// base32_smoke — exercise encoding/base32.
// (encoding/base32/base32.go)
//
// Vectors from RFC 4648 §10 (test vectors for base32) and goish's
// existing base64 smoke style.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::{bytes as to_bytes, string as to_string};
use goish::encoding::base32;
use goish::fmt;
use goish::goslice::slice;
use goish::syscall;
use goish::types::byte;

fn raw(s: &slice<byte>) -> &[byte] {
    s
}

fn str_eq(a: &goish::gostring::string, b: &str) -> bool {
    a.Len() as usize == b.len() && {
        // Compare via byte conversion through public API.
        let conv = goish::convert::bytes(a.clone());
        let raw: &[byte] = &conv;
        raw == b.as_bytes()
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let std = base32::StdEncoding();
    let hex = base32::HexEncoding();

    // RFC 4648 §10 test vectors:
    // ""       ->  ""
    // "f"      ->  "MY======"
    // "fo"     ->  "MZXQ===="
    // "foo"    ->  "MZXW6==="
    // "foob"   ->  "MZXW6YQ="
    // "fooba"  ->  "MZXW6YTB"
    // "foobar" ->  "MZXW6YTBOI======"

    // 1. EncodeToString empty.
    {
        let s = std.EncodeToString(to_bytes(""));
        if str_eq(&s, "") {
            fmt::Println!("[ 1] EncodeToString empty      PASS");
        } else {
            fmt::Println!("[ 1] EncodeToString empty      FAIL");
            failed += 1;
        }
    }

    // 2. EncodeToString "f".
    {
        let s = std.EncodeToString(to_bytes("f"));
        if str_eq(&s, "MY======") {
            fmt::Println!("[ 2] EncodeToString \"f\"       PASS");
        } else {
            fmt::Println!("[ 2] EncodeToString \"f\"       FAIL");
            failed += 1;
        }
    }

    // 3. EncodeToString "fo".
    {
        let s = std.EncodeToString(to_bytes("fo"));
        if str_eq(&s, "MZXQ====") {
            fmt::Println!("[ 3] EncodeToString \"fo\"      PASS");
        } else {
            fmt::Println!("[ 3] EncodeToString \"fo\"      FAIL");
            failed += 1;
        }
    }

    // 4. EncodeToString "foo".
    {
        let s = std.EncodeToString(to_bytes("foo"));
        if str_eq(&s, "MZXW6===") {
            fmt::Println!("[ 4] EncodeToString \"foo\"     PASS");
        } else {
            fmt::Println!("[ 4] EncodeToString \"foo\"     FAIL");
            failed += 1;
        }
    }

    // 5. EncodeToString "foob".
    {
        let s = std.EncodeToString(to_bytes("foob"));
        if str_eq(&s, "MZXW6YQ=") {
            fmt::Println!("[ 5] EncodeToString \"foob\"    PASS");
        } else {
            fmt::Println!("[ 5] EncodeToString \"foob\"    FAIL");
            failed += 1;
        }
    }

    // 6. EncodeToString "fooba".
    {
        let s = std.EncodeToString(to_bytes("fooba"));
        if str_eq(&s, "MZXW6YTB") {
            fmt::Println!("[ 6] EncodeToString \"fooba\"   PASS");
        } else {
            fmt::Println!("[ 6] EncodeToString \"fooba\"   FAIL");
            failed += 1;
        }
    }

    // 7. EncodeToString "foobar".
    {
        let s = std.EncodeToString(to_bytes("foobar"));
        if str_eq(&s, "MZXW6YTBOI======") {
            fmt::Println!("[ 7] EncodeToString \"foobar\"  PASS");
        } else {
            fmt::Println!("[ 7] EncodeToString \"foobar\"  FAIL");
            failed += 1;
        }
    }

    // 8. DecodeString round-trip.
    {
        let (out, err) = std.DecodeString(to_string("MZXW6YTBOI======"));
        if err.IsNil() && raw(&out) == b"foobar" {
            fmt::Println!("[ 8] DecodeString round-trip   PASS");
        } else {
            fmt::Println!("[ 8] DecodeString round-trip   FAIL");
            failed += 1;
        }
    }

    // 9. DecodeString "" -> [].
    {
        let (out, err) = std.DecodeString(to_string(""));
        if err.IsNil() && out.Len() == 0 {
            fmt::Println!("[ 9] DecodeString empty        PASS");
        } else {
            fmt::Println!("[ 9] DecodeString empty        FAIL");
            failed += 1;
        }
    }

    // 10. DecodeString "MY======" -> "f".
    {
        let (out, err) = std.DecodeString(to_string("MY======"));
        if err.IsNil() && raw(&out) == b"f" {
            fmt::Println!("[10] DecodeString \"f\"         PASS");
        } else {
            fmt::Println!("[10] DecodeString \"f\"         FAIL");
            failed += 1;
        }
    }

    // 11. DecodeString invalid input returns non-nil err.
    {
        let (_out, err) = std.DecodeString(to_string("M!XW6==="));
        if !err.IsNil() {
            fmt::Println!("[11] Decode invalid -> err     PASS");
        } else {
            fmt::Println!("[11] Decode invalid -> err     FAIL");
            failed += 1;
        }
    }

    // 12. EncodedLen / DecodedLen round trip.
    {
        let n = std.EncodedLen(6); // 6 bytes -> 16-byte base32 (incl. padding).
        let m = std.DecodedLen(16);
        if n == 16 && m == 10 {
            // DecodedLen for padded 16 bytes = 16/8*5 = 10 (max). The
            // actual decoded payload size depends on padding count.
            fmt::Println!("[12] EncodedLen/DecodedLen     PASS");
        } else {
            fmt::Println!("[12] EncodedLen/DecodedLen     FAIL");
            failed += 1;
        }
    }

    // 13. HexEncoding round-trip ("foobar" -> "CPNMUOJ1E8======").
    {
        let s = hex.EncodeToString(to_bytes("foobar"));
        if str_eq(&s, "CPNMUOJ1E8======") {
            // Decode it back.
            let (out, err) = hex.DecodeString(to_string("CPNMUOJ1E8======"));
            if err.IsNil() && raw(&out) == b"foobar" {
                fmt::Println!("[13] HexEncoding round-trip    PASS");
            } else {
                fmt::Println!("[13] HexEncoding round-trip    FAIL");
                failed += 1;
            }
        } else {
            fmt::Println!("[13] HexEncoding round-trip    FAIL");
            failed += 1;
        }
    }

    // 14. AppendEncode preserves prefix.
    {
        let dst = to_bytes("PRE:");
        let out = std.AppendEncode(dst, to_bytes("f"));
        let r = raw(&out);
        if r.starts_with(b"PRE:") && &r[4..] == b"MY======" {
            fmt::Println!("[14] AppendEncode prefix       PASS");
        } else {
            fmt::Println!("[14] AppendEncode prefix       FAIL");
            failed += 1;
        }
    }

    // 15. AppendDecode preserves prefix.
    {
        let dst = to_bytes("PRE:");
        let (out, err) = std.AppendDecode(dst, to_bytes("MZXW6YTBOI======"));
        let r = raw(&out);
        if err.IsNil() && r.starts_with(b"PRE:") && &r[4..] == b"foobar" {
            fmt::Println!("[15] AppendDecode prefix       PASS");
        } else {
            fmt::Println!("[15] AppendDecode prefix       FAIL");
            failed += 1;
        }
    }

    // 16. Newlines are ignored in input.
    {
        let (out, err) = std.DecodeString(to_string("MZXW6\nYTBOI=\r\n====="));
        if err.IsNil() && raw(&out) == b"foobar" {
            fmt::Println!("[16] Decode strip newlines     PASS");
        } else {
            fmt::Println!("[16] Decode strip newlines     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 16/16");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 16");
        syscall::Exit(1);
    }
}
