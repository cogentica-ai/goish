// utf16_ref_smoke — unicode/utf16 against a running Go.
// (unicode/utf16/utf16.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_utf16_ref.go` run in `package utf16_test`
// by `scripts/goref.sh`.
//
// Everything here is about the surrogate split. A code point above
// U+FFFF travels as a high half in U+D800..U+DBFF plus a low half in
// U+DC00..U+DFFF, and every function substitutes U+FFFD for a half that
// turns up alone, out of order, or paired with a non-surrogate.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::fmt;
use goish::goslice::slice;
use goish::syscall;
use goish::types::{int, rune};
use goish::unicode::utf16;

fn u16s(v: &[u16]) -> slice<u16> {
    return slice::<u16>::__from_vec(v.to_vec());
}

fn runes(v: &[rune]) -> slice<rune> {
    return slice::<rune>::__from_vec(v.to_vec());
}

fn eq_u16(got: &slice<u16>, want: &[u16]) -> bool {
    if got.Len() as usize != want.len() {
        return false;
    }
    let mut i = 0;
    while i < want.len() {
        if got[i as int] != want[i] {
            return false;
        }
        i += 1;
    }
    return true;
}

fn eq_rune(got: &slice<rune>, want: &[rune]) -> bool {
    if got.Len() as usize != want.len() {
        return false;
    }
    let mut i = 0;
    while i < want.len() {
        if got[i as int] != want[i] {
            return false;
        }
        i += 1;
    }
    return true;
}

// (rune, IsSurrogate, RuneLen, EncodeRune r1, r2)
const RUNES: [(rune, bool, int, rune, rune); 17] = [
    (-1, false, -1, 0xFFFD, 0xFFFD),
    (0, false, 1, 0xFFFD, 0xFFFD),
    (97, false, 1, 0xFFFD, 0xFFFD),
    (127, false, 1, 0xFFFD, 0xFFFD),
    (55295, false, 1, 0xFFFD, 0xFFFD),
    // The surrogate block itself: IsSurrogate, and RuneLen -1.
    (55296, true, -1, 0xFFFD, 0xFFFD),
    (56319, true, -1, 0xFFFD, 0xFFFD),
    (56320, true, -1, 0xFFFD, 0xFFFD),
    (57343, true, -1, 0xFFFD, 0xFFFD),
    (57344, false, 1, 0xFFFD, 0xFFFD),
    (65533, false, 1, 0xFFFD, 0xFFFD),
    // U+FFFF is one unit; EncodeRune only speaks about pairs, so it
    // still answers (U+FFFD, U+FFFD) for anything below U+10000.
    (65535, false, 1, 0xFFFD, 0xFFFD),
    (65536, false, 2, 55296, 56320),
    (128512, false, 2, 55357, 56832),
    (1114111, false, 2, 56319, 57343),
    (1114112, false, -1, 0xFFFD, 0xFFFD),
    (2147483647, false, -1, 0xFFFD, 0xFFFD),
];

// (r1, r2, DecodeRune)
const PAIRS: [(rune, rune, rune); 9] = [
    (55296, 56320, 65536),
    (55357, 56832, 128512),
    (56319, 57343, 1114111),
    // Two high halves, two low halves, and a reversed pair.
    (55296, 55296, 0xFFFD),
    (56320, 56320, 0xFFFD),
    (56320, 55296, 0xFFFD),
    // Non-surrogates, and one of each mixed with a surrogate.
    (97, 98, 0xFFFD),
    (55296, 97, 0xFFFD),
    (97, 56320, 0xFFFD),
];

// (input runes, Encode output, Decode of that output)
const ENCODE: [(&[rune], &[u16], &[rune]); 9] = [
    (&[], &[], &[]),
    (&[97, 98, 99], &[97, 98, 99], &[97, 98, 99]),
    (&[65536], &[55296, 56320], &[65536]),
    (
        &[97, 128512, 98],
        &[97, 55357, 56832, 98],
        &[97, 128512, 98],
    ),
    // A lone half on the way in becomes U+FFFD on the way out.
    (&[55296], &[65533], &[65533]),
    (&[56320], &[65533], &[65533]),
    (&[65535, 65536], &[65535, 55296, 56320], &[65535, 65536]),
    (&[-1], &[65533], &[65533]),
    (&[1114112], &[65533], &[65533]),
];

// (input units, Decode output) — sequences the encoder would never emit.
const DECODE: [(&[u16], &[rune]); 8] = [
    (&[], &[]),
    (&[97, 98], &[97, 98]),
    (&[55357, 56832], &[128512]),
    // A truncated pair, and a high half followed by ASCII: the half
    // becomes U+FFFD and the next unit is decoded on its own.
    (&[55357], &[65533]),
    (&[55357, 97], &[65533, 97]),
    (&[56832], &[65533]),
    (&[56832, 55357], &[65533, 65533]),
    (&[55357, 55357, 56832], &[65533, 128512]),
];

// (rune, AppendRune onto [0x5a])
const APPEND: [(rune, &[u16]); 4] = [
    (97, &[90, 97]),
    (65536, &[90, 55296, 56320]),
    (55296, &[90, 65533]),
    (1114112, &[90, 65533]),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. IsSurrogate and RuneLen over Go's 17 runes. RuneLen is 1 for a
    //    BMP scalar, 2 above U+FFFF, and -1 for a surrogate half or an
    //    out-of-range value.
    {
        let mut ok = true;
        let mut i = 0;
        while i < RUNES.len() {
            let (r, want_surr, want_len, _, _) = RUNES[i];
            if utf16::IsSurrogate(r) != want_surr || utf16::RuneLen(r) != want_len {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 1] IsSurrogate / RuneLen    PASS");
        } else {
            fmt::Println!("[ 1] IsSurrogate / RuneLen    FAIL");
            failed += 1;
        }
    }

    // 2. EncodeRune. Anything that is not a supplementary code point —
    //    including every BMP scalar — comes back as the pair
    //    (U+FFFD, U+FFFD).
    {
        let mut ok = true;
        let mut i = 0;
        while i < RUNES.len() {
            let (r, _, _, want1, want2) = RUNES[i];
            let (r1, r2) = utf16::EncodeRune(r);
            if r1 != want1 || r2 != want2 {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 2] EncodeRune               PASS");
        } else {
            fmt::Println!("[ 2] EncodeRune               FAIL");
            failed += 1;
        }
    }

    // 3. DecodeRune over nine pairs: only a high half followed by a low
    //    half decodes; every other combination is U+FFFD.
    {
        let mut ok = true;
        let mut i = 0;
        while i < PAIRS.len() {
            let (r1, r2, want) = PAIRS[i];
            if utf16::DecodeRune(r1, r2) != want {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 3] DecodeRune 9 pairs       PASS");
        } else {
            fmt::Println!("[ 3] DecodeRune 9 pairs       FAIL");
            failed += 1;
        }
    }

    // 4. Encode, and the Decode round-trip of its output.
    {
        let mut ok = true;
        let mut i = 0;
        while i < ENCODE.len() {
            let (input, want_enc, want_back) = ENCODE[i];
            let enc = utf16::Encode(runes(input));
            if !eq_u16(&enc, want_enc) {
                ok = false;
            }
            let back = utf16::Decode(enc);
            if !eq_rune(&back, want_back) {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 4] Encode + round-trip      PASS");
        } else {
            fmt::Println!("[ 4] Encode + round-trip      FAIL");
            failed += 1;
        }
    }

    // 5. Decode over eight unit sequences the encoder would never emit,
    //    including a high half immediately followed by another high
    //    half — the first becomes U+FFFD and the second still pairs
    //    with what follows.
    {
        let mut ok = true;
        let mut i = 0;
        while i < DECODE.len() {
            let (input, want) = DECODE[i];
            let got = utf16::Decode(u16s(input));
            if !eq_rune(&got, want) {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 5] Decode 8 raw sequences   PASS");
        } else {
            fmt::Println!("[ 5] Decode 8 raw sequences   FAIL");
            failed += 1;
        }
    }

    // 6. AppendRune keeps the prefix and appends one unit, two, or the
    //    single U+FFFD an unencodable rune becomes.
    {
        let mut ok = true;
        let mut i = 0;
        while i < APPEND.len() {
            let (r, want) = APPEND[i];
            let out = utf16::AppendRune(u16s(&[0x5a]), r);
            if !eq_u16(&out, want) {
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

    // 7. Encode then Decode is the identity for every rune that is
    //    neither a surrogate half nor out of range.
    {
        let mut ok = true;
        let sample: Vec<rune> = alloc::vec![
            0, 1, 97, 127, 128, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xfffd, 0xffff, 0x10000, 0x1f600,
            0x10ffff,
        ];
        let enc = utf16::Encode(slice::<rune>::__from_vec(sample.clone()));
        let back = utf16::Decode(enc);
        if !eq_rune(&back, &sample) {
            ok = false;
        }
        if ok {
            fmt::Println!("[ 7] round-trip identity      PASS");
        } else {
            fmt::Println!("[ 7] round-trip identity      FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
