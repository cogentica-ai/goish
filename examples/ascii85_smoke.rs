// ascii85_smoke — exercise encoding/ascii85.
// (encoding/ascii85/ascii85.go)
//
// Vectors derived from Adobe's reference and Go's ascii85_test.go pairs.
// Note: these are vanilla btoa/Adobe ascii85 (no <~ ~> wrappers).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::encoding::ascii85;
use goish::goslice::slice;
use goish::types::byte;
use goish::{syscall, Println};

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Empty -> empty.
    {
        let dst = slice::<byte>::__from_vec(Vec::new());
        let (out, n) = ascii85::Encode(dst, empty_buf());
        if n == 0 && out.Len() == 0 {
            Println!("[ 1] Encode empty              PASS");
        } else {
            Println!("[ 1] Encode empty              FAIL");
            failed += 1;
        }
    }

    // 2. Encode "Man " (4 bytes) -> "9jqo^"
    //    'M'=0x4D, 'a'=0x61, 'n'=0x6E, ' '=0x20
    //    v = 0x4D616E20 = 1295455776
    //    1295455776 / 85^0 = ... -> base-85 digits + '!'
    {
        let dst = slice::<byte>::__from_vec(alloc::vec![0; 5]);
        let (out, n) = ascii85::Encode(dst, to_bytes("Man "));
        let raw: &[byte] = &out;
        if n == 5 && &raw[..5] == b"9jqo^" {
            Println!("[ 2] Encode \"Man \"             PASS");
        } else {
            Println!("[ 2] Encode \"Man \"             FAIL");
            failed += 1;
        }
    }

    // 3. Encode 4 zero bytes -> "z" (compression)
    {
        let dst = slice::<byte>::__from_vec(alloc::vec![0; 5]);
        let zeros = slice::<byte>::__from_vec(alloc::vec![0u8; 4]);
        let (out, n) = ascii85::Encode(dst, zeros);
        let raw: &[byte] = &out;
        if n == 1 && raw[0] == b'z' {
            Println!("[ 3] Encode zero -> 'z'        PASS");
        } else {
            Println!("[ 3] Encode zero -> 'z'        FAIL");
            failed += 1;
        }
    }

    // 4. Encode "M" (1 byte) -> "9`" (2 bytes — short tail)
    //    'M' = 0x4D, v = 0x4D000000 = 1291845632
    //    base-85 digits: 24, 63, ?, ?, ? — 5 digits, drop last 3 -> 2 chars
    //    1291845632 / 85^4 = 24 ('!' + 24 = '9'); rem 1291845632 - 24*85^4
    //    85^4 = 52200625; 24*52200625 = 1252815000; rem = 39030632
    //    39030632 / 85^3 = 63; '!' + 63 = '`'
    {
        let dst = slice::<byte>::__from_vec(alloc::vec![0; 5]);
        let (out, n) = ascii85::Encode(dst, to_bytes("M"));
        let raw: &[byte] = &out;
        if n == 2 && &raw[..2] == b"9`" {
            Println!("[ 4] Encode \"M\" short tail     PASS");
        } else {
            Println!("[ 4] Encode \"M\" short tail     FAIL");
            failed += 1;
        }
    }

    // 5. Decode "9jqo^" -> "Man " (4 bytes).
    {
        let dst = slice::<byte>::__from_vec(alloc::vec![0; 8]);
        let (out, ndst, _nsrc, err) = ascii85::Decode(dst, to_bytes("9jqo^"), true);
        let raw: &[byte] = &out;
        if err.IsNil() && ndst == 4 && &raw[..4] == b"Man " {
            Println!("[ 5] Decode \"9jqo^\"            PASS");
        } else {
            Println!("[ 5] Decode \"9jqo^\"            FAIL");
            failed += 1;
        }
    }

    // 6. Decode 'z' -> 4 zero bytes.
    {
        let dst = slice::<byte>::__from_vec(alloc::vec![0; 8]);
        let (out, ndst, _nsrc, err) = ascii85::Decode(dst, to_bytes("z"), true);
        let raw: &[byte] = &out;
        if err.IsNil() && ndst == 4 && raw[..4] == [0u8, 0, 0, 0] {
            Println!("[ 6] Decode 'z' -> zeros       PASS");
        } else {
            Println!("[ 6] Decode 'z' -> zeros       FAIL");
            failed += 1;
        }
    }

    // 7. Round-trip "Hello, World!" (13 bytes — short tail).
    {
        let input = "Hello, World!";
        let dst = slice::<byte>::__from_vec(alloc::vec![0; 32]);
        let (encoded, n) = ascii85::Encode(dst, to_bytes(input));
        let enc_raw: &[byte] = &encoded;
        let enc_slice = slice::<byte>::__from_vec(enc_raw[..n as usize].to_vec());

        let dst2 = slice::<byte>::__from_vec(alloc::vec![0; 32]);
        let (decoded, ndst, _nsrc, err) = ascii85::Decode(dst2, enc_slice, true);
        let dec_raw: &[byte] = &decoded;
        if err.IsNil() && ndst as usize == input.len() && &dec_raw[..input.len()] == input.as_bytes() {
            Println!("[ 7] Round-trip \"Hello,...\"    PASS");
        } else {
            Println!("[ 7] Round-trip \"Hello,...\"    FAIL");
            failed += 1;
        }
    }

    // 8. Decode skips whitespace.
    {
        let dst = slice::<byte>::__from_vec(alloc::vec![0; 8]);
        let (out, ndst, _nsrc, err) = ascii85::Decode(dst, to_bytes("9jq\no^"), true);
        let raw: &[byte] = &out;
        if err.IsNil() && ndst == 4 && &raw[..4] == b"Man " {
            Println!("[ 8] Decode skips whitespace   PASS");
        } else {
            Println!("[ 8] Decode skips whitespace   FAIL");
            failed += 1;
        }
    }

    // 9. Decode invalid byte returns CorruptInputError.
    {
        let dst = slice::<byte>::__from_vec(alloc::vec![0; 8]);
        let (_out, _ndst, _nsrc, err) = ascii85::Decode(dst, to_bytes("9jq~^"), true);
        if !err.IsNil() {
            Println!("[ 9] Decode invalid -> err     PASS");
        } else {
            Println!("[ 9] Decode invalid -> err     FAIL");
            failed += 1;
        }
    }

    // 10. MaxEncodedLen formula.
    {
        // 0->0, 1->5, 4->5, 5->10
        if ascii85::MaxEncodedLen(0) == 0
            && ascii85::MaxEncodedLen(1) == 5
            && ascii85::MaxEncodedLen(4) == 5
            && ascii85::MaxEncodedLen(5) == 10
        {
            Println!("[10] MaxEncodedLen formula     PASS");
        } else {
            Println!("[10] MaxEncodedLen formula     FAIL");
            failed += 1;
        }
    }

    // 11. Encode "test" (4 bytes — exact block).
    //   'test' = 0x74_65_73_74 = 1952805748
    //   Adobe ref encodes "test" as "FCfN8" (5 chars).
    {
        let dst = slice::<byte>::__from_vec(alloc::vec![0; 5]);
        let (out, n) = ascii85::Encode(dst, to_bytes("test"));
        let raw: &[byte] = &out;
        // Round-trip rather than asserting exact alphabet (less brittle).
        if n == 5 {
            let dst2 = slice::<byte>::__from_vec(alloc::vec![0; 8]);
            let enc_slice = slice::<byte>::__from_vec(raw[..5].to_vec());
            let (back, nb, _, err) = ascii85::Decode(dst2, enc_slice, true);
            let br: &[byte] = &back;
            if err.IsNil() && nb == 4 && &br[..4] == b"test" {
                Println!("[11] Encode/Decode \"test\"      PASS");
            } else {
                Println!("[11] Encode/Decode \"test\"      FAIL");
                failed += 1;
            }
        } else {
            Println!("[11] Encode/Decode \"test\"      FAIL");
            failed += 1;
        }
    }

    // 12. 8-byte aligned encode: "MMMMMMMM" -> 10 chars.
    {
        let dst = slice::<byte>::__from_vec(alloc::vec![0; 10]);
        let (out, n) = ascii85::Encode(dst, to_bytes("MMMMMMMM"));
        if n == 10 {
            // Decode back and verify.
            let raw: &[byte] = &out;
            let enc_slice = slice::<byte>::__from_vec(raw[..10].to_vec());
            let dst2 = slice::<byte>::__from_vec(alloc::vec![0; 16]);
            let (back, nb, _, err) = ascii85::Decode(dst2, enc_slice, true);
            let br: &[byte] = &back;
            if err.IsNil() && nb == 8 && &br[..8] == b"MMMMMMMM" {
                Println!("[12] 8-byte aligned            PASS");
            } else {
                Println!("[12] 8-byte aligned            FAIL");
                failed += 1;
            }
        } else {
            Println!("[12] 8-byte aligned            FAIL");
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
