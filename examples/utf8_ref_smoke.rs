// utf8_ref_smoke — unicode/utf8 against a running Go.
// (unicode/utf8/utf8.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_utf8_ref.go` run in `package utf8_test`
// by `scripts/goref.sh` — external, because `testing` reaches
// `unicode/utf8` and an in-package ref file would be an import cycle.
//
// The interesting inputs are the invalid ones. Go rejects overlong
// encodings, surrogate halves and anything above U+10FFFF, and reports
// `(RuneError, 1)` for each — the size-1 part being what stops a caller
// looping forever. The encoders are the mirror image: a negative rune,
// a surrogate half or an out-of-range value all encode as RuneError's
// three bytes.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::fmt;
use goish::goslice::slice;
use goish::syscall;
use goish::types::{byte, int, rune};
use goish::unicode::utf8;

fn raw(s: &slice<byte>) -> &[byte] {
    return s;
}

// (input, DecodeRune, DecodeLastRune, FullRune, Valid, RuneCount)
//                     r        size   r        size
const DECODE: [(&[u8], rune, int, rune, int, bool, bool, int); 27] = [
    (b"", 0xFFFD, 0, 0xFFFD, 0, false, true, 0),
    (b"a", 97, 1, 97, 1, true, true, 1),
    (b"\x7f", 127, 1, 127, 1, true, true, 1),
    // Lone continuation bytes.
    (b"\x80", 0xFFFD, 1, 0xFFFD, 1, true, false, 1),
    (b"\xbf", 0xFFFD, 1, 0xFFFD, 1, true, false, 1),
    // Overlong encodings of NUL and of U+007F.
    (b"\xc0\x80", 0xFFFD, 1, 0xFFFD, 1, true, false, 2),
    (b"\xc1\xbf", 0xFFFD, 1, 0xFFFD, 1, true, false, 2),
    // U+0080 in its shortest form.
    (b"\xc2\x80", 128, 2, 128, 2, true, true, 1),
    (b"\xc3\xa9", 233, 2, 233, 2, true, true, 1),
    (b"\xe6\x97\xa5", 26085, 3, 26085, 3, true, true, 1),
    (b"\xf0\x9f\x98\x80", 128512, 4, 128512, 4, true, true, 1),
    // Overlong three-byte forms.
    (b"\xe0\x80\x80", 0xFFFD, 1, 0xFFFD, 1, true, false, 3),
    (b"\xe0\x9f\xbf", 0xFFFD, 1, 0xFFFD, 1, true, false, 3),
    // U+0800 in its shortest form.
    (b"\xe0\xa0\x80", 2048, 3, 2048, 3, true, true, 1),
    // Surrogate halves D800 and DFFF, which UTF-8 may not carry.
    (b"\xed\xa0\x80", 0xFFFD, 1, 0xFFFD, 1, true, false, 3),
    (b"\xed\xbf\xbf", 0xFFFD, 1, 0xFFFD, 1, true, false, 3),
    // Overlong four-byte form.
    (b"\xf0\x80\x80\x80", 0xFFFD, 1, 0xFFFD, 1, true, false, 4),
    (b"\xf0\x90\x80\x80", 65536, 4, 65536, 4, true, true, 1),
    (b"\xf4\x8f\xbf\xbf", 1114111, 4, 1114111, 4, true, true, 1),
    // Above U+10FFFF.
    (b"\xf4\x90\x80\x80", 0xFFFD, 1, 0xFFFD, 1, true, false, 4),
    (b"\xf5\x80\x80\x80", 0xFFFD, 1, 0xFFFD, 1, true, false, 4),
    (b"\xfe", 0xFFFD, 1, 0xFFFD, 1, true, false, 1),
    (b"\xff", 0xFFFD, 1, 0xFFFD, 1, true, false, 1),
    // Truncated sequences: not full, and not valid.
    (b"\xc2", 0xFFFD, 1, 0xFFFD, 1, false, false, 1),
    (b"\xe6\x97", 0xFFFD, 1, 0xFFFD, 1, false, false, 2),
    (b"\xf0\x9f\x98", 0xFFFD, 1, 0xFFFD, 1, false, false, 3),
    // Last rune of "a\xffb" is 'b', not the bad byte.
    (b"a\xffb", 97, 1, 98, 1, true, false, 3),
];

// (rune, RuneLen, encoded bytes, ValidRune)
const ENCODE: [(rune, int, &[u8], bool); 20] = [
    (-1, -1, b"\xef\xbf\xbd", false),
    (-2147483648, -1, b"\xef\xbf\xbd", false),
    (0, 1, b"\x00", true),
    (97, 1, b"a", true),
    (127, 1, b"\x7f", true),
    (128, 2, b"\xc2\x80", true),
    (2047, 2, b"\xdf\xbf", true),
    (2048, 3, b"\xe0\xa0\x80", true),
    (55295, 3, b"\xed\x9f\xbf", true),
    // The surrogate block: D800..DFFF are not encodable.
    (55296, -1, b"\xef\xbf\xbd", false),
    (56319, -1, b"\xef\xbf\xbd", false),
    (56320, -1, b"\xef\xbf\xbd", false),
    (57343, -1, b"\xef\xbf\xbd", false),
    (57344, 3, b"\xee\x80\x80", true),
    (65533, 3, b"\xef\xbf\xbd", true),
    (65535, 3, b"\xef\xbf\xbf", true),
    (65536, 4, b"\xf0\x90\x80\x80", true),
    (1114111, 4, b"\xf4\x8f\xbf\xbf", true),
    (1114112, -1, b"\xef\xbf\xbd", false),
    (2147483647, -1, b"\xef\xbf\xbd", false),
];

const RUNESTART: [(u8, bool); 7] = [
    (0x00, true),
    (0x41, true),
    (0x7f, true),
    (0x80, false),
    (0xbf, false),
    (0xc0, true),
    (0xff, true),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. DecodeRune over Go's 27 vectors: rune and size both.
    {
        let mut ok = true;
        let mut i = 0;
        while i < DECODE.len() {
            let (input, want_r, want_n, _, _, _, _, _) = DECODE[i];
            let (r, n) = utf8::DecodeRune(input);
            if r != want_r || n != want_n {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 1] DecodeRune 27 vectors    PASS");
        } else {
            fmt::Println!("[ 1] DecodeRune 27 vectors    FAIL");
            failed += 1;
        }
    }

    // 2. DecodeLastRune, which walks backwards over continuation bytes
    //    and must agree with DecodeRune on every one of the same inputs.
    {
        let mut ok = true;
        let mut i = 0;
        while i < DECODE.len() {
            let (input, _, _, want_r, want_n, _, _, _) = DECODE[i];
            let (r, n) = utf8::DecodeLastRune(input);
            if r != want_r || n != want_n {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 2] DecodeLastRune           PASS");
        } else {
            fmt::Println!("[ 2] DecodeLastRune           FAIL");
            failed += 1;
        }
    }

    // 3. FullRune tells a truncated sequence from a merely invalid one:
    //    "\xc2" is not full, "\x80" is (a lone continuation byte is a
    //    complete one-byte error).
    {
        let mut ok = true;
        let mut i = 0;
        while i < DECODE.len() {
            let (input, _, _, _, _, want_full, _, _) = DECODE[i];
            if utf8::FullRune(input) != want_full {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 3] FullRune                 PASS");
        } else {
            fmt::Println!("[ 3] FullRune                 FAIL");
            failed += 1;
        }
    }

    // 4. Valid and RuneCount. An invalid byte counts as one rune of
    //    width 1, so "\xf5\x80\x80\x80" counts as four.
    {
        let mut ok = true;
        let mut i = 0;
        while i < DECODE.len() {
            let (input, _, _, _, _, _, want_valid, want_count) = DECODE[i];
            if utf8::Valid(input) != want_valid || utf8::RuneCount(input) != want_count {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 4] Valid / RuneCount        PASS");
        } else {
            fmt::Println!("[ 4] Valid / RuneCount        FAIL");
            failed += 1;
        }
    }

    // 5. EncodeRune over Go's 20 runes, including every boundary of the
    //    surrogate block and both sides of U+10FFFF.
    {
        let mut ok = true;
        let mut i = 0;
        while i < ENCODE.len() {
            let (r, _, want, _) = ENCODE[i];
            let mut buf: [byte; 4] = [0; 4];
            let n = utf8::EncodeRune(&mut buf, r);
            if n as usize != want.len() || &buf[..n as usize] != want {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 5] EncodeRune 20 runes      PASS");
        } else {
            fmt::Println!("[ 5] EncodeRune 20 runes      FAIL");
            failed += 1;
        }
    }

    // 6. AppendRune must agree with EncodeRune and keep the prefix.
    {
        let mut ok = true;
        let mut i = 0;
        while i < ENCODE.len() {
            let (r, _, want, _) = ENCODE[i];
            let dst = slice::<byte>::__from_vec(alloc::vec![b'Z']);
            let out = utf8::AppendRune(dst, r);
            let mut expect: Vec<byte> = alloc::vec![b'Z'];
            expect.extend_from_slice(want);
            if raw(&out) != &expect[..] {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 6] AppendRune               PASS");
        } else {
            fmt::Println!("[ 6] AppendRune               FAIL");
            failed += 1;
        }
    }

    // 7. RuneLen and ValidRune. RuneLen is -1 for exactly the runes
    //    ValidRune rejects.
    {
        let mut ok = true;
        let mut i = 0;
        while i < ENCODE.len() {
            let (r, want_len, _, want_valid) = ENCODE[i];
            if utf8::RuneLen(r) != want_len || utf8::ValidRune(r) != want_valid {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 7] RuneLen / ValidRune      PASS");
        } else {
            fmt::Println!("[ 7] RuneLen / ValidRune      FAIL");
            failed += 1;
        }
    }

    // 8. RuneStart is a two-instruction test, and 0xc0 and 0xff both
    //    pass it even though neither can start a valid sequence.
    {
        let mut ok = true;
        let mut i = 0;
        while i < RUNESTART.len() {
            let (b, want) = RUNESTART[i];
            if utf8::RuneStart(b) != want {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 8] RuneStart                PASS");
        } else {
            fmt::Println!("[ 8] RuneStart                FAIL");
            failed += 1;
        }
    }

    // 9. The four exported constants.
    {
        if utf8::RuneError == 65533
            && utf8::RuneSelf == 128
            && utf8::MaxRune == 1114111
            && utf8::UTFMax == 4
        {
            fmt::Println!("[ 9] constants                PASS");
        } else {
            fmt::Println!("[ 9] constants                FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 9/9");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 9");
        syscall::Exit(1);
    }
}
