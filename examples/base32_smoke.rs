// base32_smoke — exercise encoding/base32.
// (encoding/base32/base32.go)
//
// Every expectation below is what a real Go 1.25.5 prints: they are the
// output of `tools/gen_base32_ref.go` run inside `encoding/base32` by
// `scripts/goref.sh`, which is how the streaming halves and the
// CorruptInputError offsets were obtained. RFC 4648 §10 supplies the
// one-shot vectors, and Go agrees with it.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::{bytes as to_bytes, rune as to_rune, string as to_string};
use goish::encoding::base32;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::syscall;
use goish::types::byte;

fn raw(s: &slice<byte>) -> &[byte] {
    s
}

fn gstr_eq(a: &string, b: &string) -> bool {
    let ca = goish::convert::bytes(a.clone());
    let cb = goish::convert::bytes(b.clone());
    let ra: &[byte] = &ca;
    let rb: &[byte] = &cb;
    ra == rb
}

fn str_eq(a: &string, b: &str) -> bool {
    a.Len() as usize == b.len() && {
        // Compare via byte conversion through the public API.
        let conv = goish::convert::bytes(a.clone());
        let r: &[byte] = &conv;
        r == b.as_bytes()
    }
}

// The nine inputs `gen_base32_ref.go` feeds every encoding.
const INPUTS: [&[u8]; 9] = [
    b"",
    b"f",
    b"fo",
    b"foo",
    b"foob",
    b"fooba",
    b"foobar",
    &[0x00, 0xff, 0xfe, 0x01],
    b"sure.~?",
];

#[goish::main]
fn main() {
    let mut failed = 0;
    let std = base32::StdEncoding;
    let hex = base32::HexEncoding;
    let raw_std = base32::StdEncoding.WithPadding(base32::NoPadding);
    let dot = base32::StdEncoding.WithPadding(to_rune(b'.'));

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

    // 12. Go's EncodedLen / DecodedLen table for the padded StdEncoding,
    //     n = 0..11. Note DecodedLen is 0 below a full 8-byte quantum.
    {
        let want_enc: [i64; 12] = [0, 8, 8, 8, 8, 8, 16, 16, 16, 16, 16, 24];
        let want_dec: [i64; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 5, 5, 5, 5];
        let mut ok = true;
        let mut n = 0;
        while n < 12 {
            if std.EncodedLen(n as i64) != want_enc[n] || std.DecodedLen(n as i64) != want_dec[n] {
                ok = false;
            }
            n += 1;
        }
        if ok {
            fmt::Println!("[12] EncodedLen/DecodedLen     PASS");
        } else {
            fmt::Println!("[12] EncodedLen/DecodedLen     FAIL");
            failed += 1;
        }
    }

    // 13. HexEncoding round-trip ("foobar" -> "CPNMUOJ1E8======").
    {
        let s = hex.EncodeToString(to_bytes("foobar"));
        let (out, err) = hex.DecodeString(to_string("CPNMUOJ1E8======"));
        if str_eq(&s, "CPNMUOJ1E8======") && err.IsNil() && raw(&out) == b"foobar" {
            fmt::Println!("[13] HexEncoding round-trip    PASS");
        } else {
            fmt::Println!("[13] HexEncoding round-trip    FAIL");
            failed += 1;
        }
    }

    // 14. AppendEncode preserves prefix.
    {
        let dst = to_bytes("PRE:");
        let out = std.AppendEncode(dst, to_bytes("foobar"));
        let r = raw(&out);
        if r == b"PRE:MZXW6YTBOI======" {
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
        if err.IsNil() && raw(&out) == b"PRE:foobar" {
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

    // 17. WithPadding(NoPadding) — Go's `rawstd` column.
    {
        let want: [&str; 9] = [
            "",
            "MY",
            "MZXQ",
            "MZXW6",
            "MZXW6YQ",
            "MZXW6YTB",
            "MZXW6YTBOI",
            "AD774AI",
            "ON2XEZJOPY7Q",
        ];
        let mut ok = true;
        let mut i = 0;
        while i < 9 {
            let s = raw_std.EncodeToString(to_bytes(INPUTS[i]));
            if !str_eq(&s, want[i]) {
                ok = false;
            }
            let (back, err) = raw_std.DecodeString(s);
            if !err.IsNil() || raw(&back) != INPUTS[i] {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[17] WithPadding(NoPadding)    PASS");
        } else {
            fmt::Println!("[17] WithPadding(NoPadding)    FAIL");
            failed += 1;
        }
    }

    // 18. WithPadding('.') — a non-'=' pad character.
    {
        let want: [&str; 9] = [
            "",
            "MY......",
            "MZXQ....",
            "MZXW6...",
            "MZXW6YQ.",
            "MZXW6YTB",
            "MZXW6YTBOI......",
            "AD774AI.",
            "ON2XEZJOPY7Q....",
        ];
        let mut ok = true;
        let mut i = 0;
        while i < 9 {
            let s = dot.EncodeToString(to_bytes(INPUTS[i]));
            if !str_eq(&s, want[i]) {
                ok = false;
            }
            let (back, err) = dot.DecodeString(s);
            if !err.IsNil() || raw(&back) != INPUTS[i] {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[18] WithPadding('.')          PASS");
        } else {
            fmt::Println!("[18] WithPadding('.')          FAIL");
            failed += 1;
        }
    }

    // 19. The unpadded length formulas, which differ from the padded
    //     ones at every n that is not a multiple of the quantum.
    {
        let want_enc: [i64; 12] = [0, 2, 4, 5, 7, 8, 10, 12, 13, 15, 16, 18];
        let want_dec: [i64; 12] = [0, 0, 1, 1, 2, 3, 3, 4, 5, 5, 6, 6];
        let mut ok = true;
        let mut n = 0;
        while n < 12 {
            if raw_std.EncodedLen(n as i64) != want_enc[n]
                || raw_std.DecodedLen(n as i64) != want_dec[n]
            {
                ok = false;
            }
            n += 1;
        }
        if ok {
            fmt::Println!("[19] unpadded Encoded/Decoded  PASS");
        } else {
            fmt::Println!("[19] unpadded Encoded/Decoded  FAIL");
            failed += 1;
        }
    }

    // 20. NewEncoder, one Write per byte so every five-byte quantum
    //     boundary falls inside a Write, and Close flushes the tail.
    //     Must equal the one-shot encoding for all four encodings.
    {
        let encs = [std, hex, raw_std, dot];
        let mut ok = true;
        let mut e = 0;
        while e < 4 {
            let mut i = 0;
            while i < 9 {
                let mut buf = goish::bytes::Buffer::new();
                {
                    let mut w = base32::NewEncoder(encs[e], &mut buf);
                    let src = INPUTS[i];
                    let mut k = 0;
                    while k < src.len() {
                        let (_, err) = w.Write(to_bytes(&src[k..k + 1]));
                        if !err.IsNil() {
                            ok = false;
                        }
                        k += 1;
                    }
                    if !w.Close().IsNil() {
                        ok = false;
                    }
                }
                let want = encs[e].EncodeToString(to_bytes(INPUTS[i]));
                if !gstr_eq(&buf.String(), &want) {
                    ok = false;
                }
                i += 1;
            }
            e += 1;
        }
        if ok {
            fmt::Println!("[20] NewEncoder byte-at-a-time PASS");
        } else {
            fmt::Println!("[20] NewEncoder byte-at-a-time FAIL");
            failed += 1;
        }
    }

    // 21. NewDecoder round-trips every vector through io::ReadAll.
    {
        let encs = [std, hex, raw_std, dot];
        let mut ok = true;
        let mut e = 0;
        while e < 4 {
            let mut i = 0;
            while i < 9 {
                let text = encs[e].EncodeToString(to_bytes(INPUTS[i]));
                let mut src = goish::strings::NewReader(text);
                let mut dec = base32::NewDecoder(encs[e], &mut src);
                let (out, err) = goish::io::ReadAll(&mut dec);
                if !err.IsNil() || raw(&out) != INPUTS[i] {
                    ok = false;
                }
                i += 1;
            }
            e += 1;
        }
        if ok {
            fmt::Println!("[21] NewDecoder round-trip     PASS");
        } else {
            fmt::Println!("[21] NewDecoder round-trip     FAIL");
            failed += 1;
        }
    }

    // 22. The stream decoder's newlineFilteringReader: Go wraps the
    //     encoding of "foobar" with CRLF every three characters and
    //     still reads "foobar" back.
    {
        let mut src = goish::strings::NewReader(to_string("MZX\r\nW6Y\r\nTBO\r\nI==\r\n===\r\n="));
        let mut dec = base32::NewDecoder(std, &mut src);
        let (out, err) = goish::io::ReadAll(&mut dec);
        if err.IsNil() && raw(&out) == b"foobar" {
            fmt::Println!("[22] NewDecoder skips newlines PASS");
        } else {
            fmt::Println!("[22] NewDecoder skips newlines FAIL");
            failed += 1;
        }
    }

    // 23. readEncodedData turns a short read at EOF into
    //     io.ErrUnexpectedEOF — but only when the encoding is padded,
    //     and only after the complete quanta have been handed back.
    {
        let mut ok = true;

        // 15 of 16 characters: "fooba" comes out, then unexpected EOF.
        {
            let mut src = goish::strings::NewReader(to_string("MZXW6YTBOI====="));
            let mut dec = base32::NewDecoder(std, &mut src);
            let (out, err) = goish::io::ReadAll(&mut dec);
            if raw(&out) != b"fooba" || err.IsNil() {
                ok = false;
            }
        }
        // Three characters: nothing decodable at all.
        {
            let mut src = goish::strings::NewReader(to_string("MZX"));
            let mut dec = base32::NewDecoder(std, &mut src);
            let (out, err) = goish::io::ReadAll(&mut dec);
            if out.Len() != 0 || err.IsNil() {
                ok = false;
            }
        }
        // A whole quantum with no padding after it is not truncated.
        {
            let mut src = goish::strings::NewReader(to_string("MZXW6YTB"));
            let mut dec = base32::NewDecoder(std, &mut src);
            let (out, err) = goish::io::ReadAll(&mut dec);
            if raw(&out) != b"fooba" || !err.IsNil() {
                ok = false;
            }
        }
        if ok {
            fmt::Println!("[23] truncated -> unexpectedEOF PASS");
        } else {
            fmt::Println!("[23] truncated -> unexpectedEOF FAIL");
            failed += 1;
        }
    }

    // 24. CorruptInputError carries Go's exact offset and message.
    {
        let cases: [&str; 4] = ["M!XW6===", "MY=====", "MZX=====", "AAAAAAAA!"];
        let want: [&str; 4] = [
            "illegal base32 data at input byte 1",
            "illegal base32 data at input byte 7",
            "illegal base32 data at input byte 3",
            "illegal base32 data at input byte 8",
        ];
        let mut ok = true;
        let mut i = 0;
        while i < 4 {
            let (_out, err) = std.DecodeString(to_string(cases[i]));
            if err.IsNil() || !str_eq(&err.Error(), want[i]) {
                ok = false;
            }
            i += 1;
        }
        // Trailing data after the padding is silently ignored, as in Go.
        let (out, err) = std.DecodeString(to_string("MZXW6YTBOI======A"));
        if !err.IsNil() || raw(&out) != b"foobar" {
            ok = false;
        }
        if ok {
            fmt::Println!("[24] CorruptInputError offsets PASS");
        } else {
            fmt::Println!("[24] CorruptInputError offsets FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 24/24");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 24");
        syscall::Exit(1);
    }
}
