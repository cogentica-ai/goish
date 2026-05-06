// utf16_smoke — exercise unicode/utf16.
// (unicode/utf16/utf16.go:30, 37, 47, 57, 69, 100, 116)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::goslice::slice;
use goish::types::rune;
use goish::unicode::utf16;
use goish::{syscall, Println};

fn slice_u16(v: Vec<u16>) -> slice<u16> {
    slice::<u16>::__from_vec(v)
}

fn slice_rune(v: Vec<rune>) -> slice<rune> {
    slice::<rune>::__from_vec(v)
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. IsSurrogate — d800..dfff is the surrogate range.
    {
        if utf16::IsSurrogate(0xD800)
            && utf16::IsSurrogate(0xDC00)
            && utf16::IsSurrogate(0xDFFF)
            && !utf16::IsSurrogate(0xD7FF)
            && !utf16::IsSurrogate(0xE000)
            && !utf16::IsSurrogate('A' as rune)
        {
            Println!("[ 1] IsSurrogate                PASS");
        } else {
            Println!("[ 1] IsSurrogate                FAIL");
            failed += 1;
        }
    }

    // 2. EncodeRune / DecodeRune round-trip — U+1F600 (😀).
    {
        let r: rune = 0x1F600;
        let (r1, r2) = utf16::EncodeRune(r);
        // 0x1F600 -> high surrogate 0xD83D, low 0xDE00.
        if r1 == 0xD83D && r2 == 0xDE00 && utf16::DecodeRune(r1, r2) == r {
            Println!("[ 2] Encode/DecodeRune trip     PASS");
        } else {
            Println!("[ 2] Encode/DecodeRune trip     FAIL");
            failed += 1;
        }
    }

    // 3. EncodeRune — non-supplementary returns U+FFFD pair.
    {
        let (r1, r2) = utf16::EncodeRune('A' as rune);
        if r1 == 0xFFFD && r2 == 0xFFFD {
            Println!("[ 3] Encode BMP rejected        PASS");
        } else {
            Println!("[ 3] Encode BMP rejected        FAIL");
            failed += 1;
        }
    }

    // 4. EncodeRune — invalid (>0x10FFFF) returns U+FFFD pair.
    {
        let (r1, r2) = utf16::EncodeRune(0x110000);
        if r1 == 0xFFFD && r2 == 0xFFFD {
            Println!("[ 4] Encode invalid             PASS");
        } else {
            Println!("[ 4] Encode invalid             FAIL");
            failed += 1;
        }
    }

    // 5. DecodeRune — invalid pair returns U+FFFD.
    {
        if utf16::DecodeRune(0x0041, 0x0042) == 0xFFFD {
            Println!("[ 5] Decode bad pair            PASS");
        } else {
            Println!("[ 5] Decode bad pair            FAIL");
            failed += 1;
        }
    }

    // 6. RuneLen — 1 for BMP non-surrogate, 2 for supplementary, -1 invalid.
    {
        if utf16::RuneLen('A' as rune) == 1
            && utf16::RuneLen(0xD7FF) == 1
            && utf16::RuneLen(0xE000) == 1
            && utf16::RuneLen(0x1F600) == 2
            && utf16::RuneLen(0xD800) == -1
            && utf16::RuneLen(0x110000) == -1
            && utf16::RuneLen(-1) == -1
        {
            Println!("[ 6] RuneLen                    PASS");
        } else {
            Println!("[ 6] RuneLen                    FAIL");
            failed += 1;
        }
    }

    // 7. Encode — round-trip "Hi😀!".
    {
        let mut runes_v: Vec<rune> = Vec::new();
        runes_v.push('H' as rune);
        runes_v.push('i' as rune);
        runes_v.push(0x1F600);
        runes_v.push('!' as rune);
        let encoded = utf16::Encode(slice_rune(runes_v));
        let raw: &[u16] = &encoded;
        // Expect: [0x48, 0x69, 0xD83D, 0xDE00, 0x21]
        if raw.len() == 5
            && raw[0] == 0x0048
            && raw[1] == 0x0069
            && raw[2] == 0xD83D
            && raw[3] == 0xDE00
            && raw[4] == 0x0021
        {
            Println!("[ 7] Encode mixed               PASS");
        } else {
            Println!("[ 7] Encode mixed               FAIL");
            failed += 1;
        }
    }

    // 8. Decode — restore "Hi😀!" runes.
    {
        let mut u: Vec<u16> = Vec::new();
        u.push(0x0048);
        u.push(0x0069);
        u.push(0xD83D);
        u.push(0xDE00);
        u.push(0x0021);
        let decoded = utf16::Decode(slice_u16(u));
        let raw: &[rune] = &decoded;
        if raw.len() == 4
            && raw[0] == 'H' as rune
            && raw[1] == 'i' as rune
            && raw[2] == 0x1F600
            && raw[3] == '!' as rune
        {
            Println!("[ 8] Decode mixed               PASS");
        } else {
            Println!("[ 8] Decode mixed               FAIL");
            failed += 1;
        }
    }

    // 9. Decode — lone high surrogate becomes U+FFFD.
    {
        let mut u: Vec<u16> = Vec::new();
        u.push(0xD83D); // high surrogate followed by non-low → invalid
        u.push(0x0041);
        let decoded = utf16::Decode(slice_u16(u));
        let raw: &[rune] = &decoded;
        if raw.len() == 2 && raw[0] == 0xFFFD && raw[1] == 'A' as rune {
            Println!("[ 9] Decode lone high           PASS");
        } else {
            Println!("[ 9] Decode lone high           FAIL");
            failed += 1;
        }
    }

    // 10. AppendRune — BMP, supplementary, invalid in turn.
    {
        let mut a: slice<u16> = slice_u16(Vec::new());
        a = utf16::AppendRune(a, 'A' as rune);
        a = utf16::AppendRune(a, 0x1F600);
        a = utf16::AppendRune(a, 0x110000);
        let raw: &[u16] = &a;
        if raw.len() == 4
            && raw[0] == 0x0041
            && raw[1] == 0xD83D
            && raw[2] == 0xDE00
            && raw[3] == 0xFFFD
        {
            Println!("[10] AppendRune mixed           PASS");
        } else {
            Println!("[10] AppendRune mixed           FAIL");
            failed += 1;
        }
    }

    // 11. Encode — empty input → empty output.
    {
        let runes_v: Vec<rune> = Vec::new();
        let encoded = utf16::Encode(slice_rune(runes_v));
        let raw: &[u16] = &encoded;
        if raw.is_empty() {
            Println!("[11] Encode empty               PASS");
        } else {
            Println!("[11] Encode empty               FAIL");
            failed += 1;
        }
    }

    // 12. Encode — invalid rune is replaced with U+FFFD.
    {
        let mut runes_v: Vec<rune> = Vec::new();
        runes_v.push(-1);
        let encoded = utf16::Encode(slice_rune(runes_v));
        let raw: &[u16] = &encoded;
        if raw.len() == 1 && raw[0] == 0xFFFD {
            Println!("[12] Encode invalid replaced    PASS");
        } else {
            Println!("[12] Encode invalid replaced    FAIL");
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
