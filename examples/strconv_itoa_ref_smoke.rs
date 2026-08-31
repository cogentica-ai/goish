// strconv_itoa_ref_smoke — strconv/itoa.go against a running Go.
// (strconv/itoa.go, strconv/atoi.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_strconv_itoa_ref.go` run in
// `package strconv_test` by `scripts/goref.sh`.
//
// Go funnels FormatInt, FormatUint, Itoa, AppendInt and AppendUint into
// one `formatBits`, and that function has THREE separate digit loops —
// a base-10 one built on the two-digit `smallsString` table, a
// shift-and-mask one for power-of-two bases, and a divide loop for
// everything else — plus a small-integer fast path that skips all three
// for `0 <= i < 100` in base 10. goish had a single divide loop and no
// fast path, so `smallsString`, `small`, `nSmalls`, `fastSmalls`,
// `host32bit`, `isPowerOfTwo` and `formatBits` itself were all absent
// from a file that reported itself ported. This pins each loop, both
// ends of the int64 range, and the one input whose negation overflows.
//
// `digits` also lived in the wrong file — atoi.rs, not itoa.rs — which
// is how the whole table went unnoticed; and `baseError`/`bitSizeError`
// hand-rolled their own decimal renderer instead of calling `Itoa`, so
// their message text was a second, unverified implementation of the
// same thing. Both are checked here through ParseInt/ParseUint.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::gostring::string;
use goish::strconv;
use goish::types::{byte, int, uint};
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// go: none — goish idiom: a `slice<byte>` holding the given bytes, so
//     the Append* checks can start from a non-empty destination and
//     prove the result is appended rather than replacing it.
fn bs(x: &str) -> slice<byte> {
    let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    v.extend_from_slice(x.as_bytes());
    return slice::__from_vec(v);
}

// FormatInt: 152 rows
const FORMAT_INT: [(int, int, &str); 152] = [
    (2, 0, "0"),
    (2, 1, "1"),
    (2, -1, "-1"),
    (2, 9, "1001"),
    (2, 10, "1010"),
    (2, 99, "1100011"),
    (2, 100, "1100100"),
    (2, 101, "1100101"),
    (2, 999, "1111100111"),
    (2, 1000, "1111101000"),
    (2, 999999999, "111011100110101100100111111111"),
    (2, 1000000000, "111011100110101100101000000000"),
    (2, 1000000001, "111011100110101100101000000001"),
    (
        2,
        123456789012345,
        "11100000100100010000110000011011101111101111001",
    ),
    (
        2,
        int::MAX,
        "111111111111111111111111111111111111111111111111111111111111111",
    ),
    (
        2,
        int::MIN,
        "-1000000000000000000000000000000000000000000000000000000000000000",
    ),
    (2, -100, "-1100100"),
    (2, -99, "-1100011"),
    (2, -9, "-1001"),
    (8, 0, "0"),
    (8, 1, "1"),
    (8, -1, "-1"),
    (8, 9, "11"),
    (8, 10, "12"),
    (8, 99, "143"),
    (8, 100, "144"),
    (8, 101, "145"),
    (8, 999, "1747"),
    (8, 1000, "1750"),
    (8, 999999999, "7346544777"),
    (8, 1000000000, "7346545000"),
    (8, 1000000001, "7346545001"),
    (8, 123456789012345, "3404420603357571"),
    (8, int::MAX, "777777777777777777777"),
    (8, int::MIN, "-1000000000000000000000"),
    (8, -100, "-144"),
    (8, -99, "-143"),
    (8, -9, "-11"),
    (10, 0, "0"),
    (10, 1, "1"),
    (10, -1, "-1"),
    (10, 9, "9"),
    (10, 10, "10"),
    (10, 99, "99"),
    (10, 100, "100"),
    (10, 101, "101"),
    (10, 999, "999"),
    (10, 1000, "1000"),
    (10, 999999999, "999999999"),
    (10, 1000000000, "1000000000"),
    (10, 1000000001, "1000000001"),
    (10, 123456789012345, "123456789012345"),
    (10, int::MAX, "9223372036854775807"),
    (10, int::MIN, "-9223372036854775808"),
    (10, -100, "-100"),
    (10, -99, "-99"),
    (10, -9, "-9"),
    (16, 0, "0"),
    (16, 1, "1"),
    (16, -1, "-1"),
    (16, 9, "9"),
    (16, 10, "a"),
    (16, 99, "63"),
    (16, 100, "64"),
    (16, 101, "65"),
    (16, 999, "3e7"),
    (16, 1000, "3e8"),
    (16, 999999999, "3b9ac9ff"),
    (16, 1000000000, "3b9aca00"),
    (16, 1000000001, "3b9aca01"),
    (16, 123456789012345, "7048860ddf79"),
    (16, int::MAX, "7fffffffffffffff"),
    (16, int::MIN, "-8000000000000000"),
    (16, -100, "-64"),
    (16, -99, "-63"),
    (16, -9, "-9"),
    (36, 0, "0"),
    (36, 1, "1"),
    (36, -1, "-1"),
    (36, 9, "9"),
    (36, 10, "a"),
    (36, 99, "2r"),
    (36, 100, "2s"),
    (36, 101, "2t"),
    (36, 999, "rr"),
    (36, 1000, "rs"),
    (36, 999999999, "gjdgxr"),
    (36, 1000000000, "gjdgxs"),
    (36, 1000000001, "gjdgxt"),
    (36, 123456789012345, "17rf9km92x"),
    (36, int::MAX, "1y2p0ij32e8e7"),
    (36, int::MIN, "-1y2p0ij32e8e8"),
    (36, -100, "-2s"),
    (36, -99, "-2r"),
    (36, -9, "-9"),
    (3, 0, "0"),
    (3, 1, "1"),
    (3, -1, "-1"),
    (3, 9, "100"),
    (3, 10, "101"),
    (3, 99, "10200"),
    (3, 100, "10201"),
    (3, 101, "10202"),
    (3, 999, "1101000"),
    (3, 1000, "1101001"),
    (3, 999999999, "2120200200021010000"),
    (3, 1000000000, "2120200200021010001"),
    (3, 1000000001, "2120200200021010002"),
    (3, 123456789012345, "121012010100112220011102010220"),
    (3, int::MAX, "2021110011022210012102010021220101220221"),
    (3, int::MIN, "-2021110011022210012102010021220101220222"),
    (3, -100, "-10201"),
    (3, -99, "-10200"),
    (3, -9, "-100"),
    (7, 0, "0"),
    (7, 1, "1"),
    (7, -1, "-1"),
    (7, 9, "12"),
    (7, 10, "13"),
    (7, 99, "201"),
    (7, 100, "202"),
    (7, 101, "203"),
    (7, 999, "2625"),
    (7, 1000, "2626"),
    (7, 999999999, "33531600615"),
    (7, 1000000000, "33531600616"),
    (7, 1000000001, "33531600620"),
    (7, 123456789012345, "35001313215035025"),
    (7, int::MAX, "22341010611245052052300"),
    (7, int::MIN, "-22341010611245052052301"),
    (7, -100, "-202"),
    (7, -99, "-201"),
    (7, -9, "-12"),
    (32, 0, "0"),
    (32, 1, "1"),
    (32, -1, "-1"),
    (32, 9, "9"),
    (32, 10, "a"),
    (32, 99, "33"),
    (32, 100, "34"),
    (32, 101, "35"),
    (32, 999, "v7"),
    (32, 1000, "v8"),
    (32, 999999999, "tplifv"),
    (32, 1000000000, "tplig0"),
    (32, 1000000001, "tplig1"),
    (32, 123456789012345, "3g9230rnrp"),
    (32, int::MAX, "7vvvvvvvvvvvv"),
    (32, int::MIN, "-8000000000000"),
    (32, -100, "-34"),
    (32, -99, "-33"),
    (32, -9, "-9"),
];
const FORMAT_UINT: [(int, uint, &str); 60] = [
    (2, 0u64, "0"),
    (2, 1u64, "1"),
    (2, 9u64, "1001"),
    (2, 10u64, "1010"),
    (2, 99u64, "1100011"),
    (2, 100u64, "1100100"),
    (2, 999999999u64, "111011100110101100100111111111"),
    (2, 1000000000u64, "111011100110101100101000000000"),
    (2, 1000000001u64, "111011100110101100101000000001"),
    (
        2,
        uint::MAX,
        "1111111111111111111111111111111111111111111111111111111111111111",
    ),
    (
        2,
        uint::MAX - 1,
        "1111111111111111111111111111111111111111111111111111111111111110",
    ),
    (
        2,
        9223372036854775808u64,
        "1000000000000000000000000000000000000000000000000000000000000000",
    ),
    (8, 0u64, "0"),
    (8, 1u64, "1"),
    (8, 9u64, "11"),
    (8, 10u64, "12"),
    (8, 99u64, "143"),
    (8, 100u64, "144"),
    (8, 999999999u64, "7346544777"),
    (8, 1000000000u64, "7346545000"),
    (8, 1000000001u64, "7346545001"),
    (8, uint::MAX, "1777777777777777777777"),
    (8, uint::MAX - 1, "1777777777777777777776"),
    (8, 9223372036854775808u64, "1000000000000000000000"),
    (10, 0u64, "0"),
    (10, 1u64, "1"),
    (10, 9u64, "9"),
    (10, 10u64, "10"),
    (10, 99u64, "99"),
    (10, 100u64, "100"),
    (10, 999999999u64, "999999999"),
    (10, 1000000000u64, "1000000000"),
    (10, 1000000001u64, "1000000001"),
    (10, uint::MAX, "18446744073709551615"),
    (10, uint::MAX - 1, "18446744073709551614"),
    (10, 9223372036854775808u64, "9223372036854775808"),
    (16, 0u64, "0"),
    (16, 1u64, "1"),
    (16, 9u64, "9"),
    (16, 10u64, "a"),
    (16, 99u64, "63"),
    (16, 100u64, "64"),
    (16, 999999999u64, "3b9ac9ff"),
    (16, 1000000000u64, "3b9aca00"),
    (16, 1000000001u64, "3b9aca01"),
    (16, uint::MAX, "ffffffffffffffff"),
    (16, uint::MAX - 1, "fffffffffffffffe"),
    (16, 9223372036854775808u64, "8000000000000000"),
    (36, 0u64, "0"),
    (36, 1u64, "1"),
    (36, 9u64, "9"),
    (36, 10u64, "a"),
    (36, 99u64, "2r"),
    (36, 100u64, "2s"),
    (36, 999999999u64, "gjdgxr"),
    (36, 1000000000u64, "gjdgxs"),
    (36, 1000000001u64, "gjdgxt"),
    (36, uint::MAX, "3w5e11264sgsf"),
    (36, uint::MAX - 1, "3w5e11264sgse"),
    (36, 9223372036854775808u64, "1y2p0ij32e8e8"),
];
const ITOA: [(int, &str); 7] = [
    (0, "0"),
    (9, "9"),
    (10, "10"),
    (99, "99"),
    (100, "100"),
    (-1, "-1"),
    (-99, "-99"),
];
const APPEND_INT: [(int, int, &str); 12] = [
    (10, 0, "<0"),
    (16, 0, "<0"),
    (10, 42, "<42"),
    (16, 42, "<2a"),
    (10, 99, "<99"),
    (16, 99, "<63"),
    (10, 100, "<100"),
    (16, 100, "<64"),
    (10, -42, "<-42"),
    (16, -42, "<-2a"),
    (10, int::MIN, "<-9223372036854775808"),
    (16, int::MIN, "<-8000000000000000"),
];
const APPEND_UINT: [(uint, &str); 5] = [
    (0u64, "<0"),
    (42u64, "<42"),
    (99u64, "<99"),
    (100u64, "<100"),
    (uint::MAX, "<18446744073709551615"),
];
const ROUNDTRIP: [(int, &str); 35] = [
    (2, "-10001111101110001111110110000010011001011"),
    (3, "-11101000122011021212121020"),
    (4, "-101331301332300103023"),
    (5, "-130211343334440443"),
    (6, "-2343052550243523"),
    (7, "-155123512630551"),
    (8, "-21756176602313"),
    (9, "-4330564255536"),
    (10, "-1234567890123"),
    (11, "-436639430627"),
    (12, "-17b3263565a3"),
    (13, "-8c55b136969"),
    (14, "-43a794b1bd1"),
    (15, "-221a9863583"),
    (16, "-11f71fb04cb"),
    (17, "-a6gb29ba88"),
    (18, "-6409df9caf"),
    (19, "-3fd2eh6d5h"),
    (20, "-284a296563"),
    (21, "-1bd9c6i3ff"),
    (22, "-10akglb1c7"),
    (23, "-fhdf05akm"),
    (24, "-b5458e7b3"),
    (25, "-826jijo4n"),
    (26, "-5nibl8p39"),
    (27, "-4a0h47ng6"),
    (28, "-37dpqqddf"),
    (29, "-2dgf2h33s"),
    (30, "-1qdf7qk43"),
    (31, "-1dr1ndct4"),
    (32, "-13tovm16b"),
    (33, "-svv2be4i"),
    (34, "-nh5ve6tp"),
    (35, "-j6krgcj8"),
    (36, "-fr5hugnf"),
];
const PARSE_ERR: [(bool, int, int, &str); 10] = [
    (
        true,
        1,
        64,
        "strconv.ParseInt: parsing \"12\": invalid base 1",
    ),
    (
        false,
        1,
        64,
        "strconv.ParseUint: parsing \"12\": invalid base 1",
    ),
    (
        true,
        37,
        64,
        "strconv.ParseInt: parsing \"12\": invalid base 37",
    ),
    (
        false,
        37,
        64,
        "strconv.ParseUint: parsing \"12\": invalid base 37",
    ),
    (
        true,
        -5,
        64,
        "strconv.ParseInt: parsing \"12\": invalid base -5",
    ),
    (
        false,
        -5,
        64,
        "strconv.ParseUint: parsing \"12\": invalid base -5",
    ),
    (
        true,
        10,
        65,
        "strconv.ParseInt: parsing \"12\": invalid bit size 65",
    ),
    (
        false,
        10,
        65,
        "strconv.ParseUint: parsing \"12\": invalid bit size 65",
    ),
    (
        true,
        10,
        -1,
        "strconv.ParseInt: parsing \"12\": invalid bit size -1",
    ),
    (
        false,
        10,
        -1,
        "strconv.ParseUint: parsing \"12\": invalid bit size -1",
    ),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. FormatInt over eight bases and nineteen values. Bases 2, 8, 16
    //    and 32 take the shift-and-mask loop, base 10 the smallsString
    //    loop, and 3, 7 and 36 the divide loop.
    {
        let mut ok = true;
        let mut i = 0;
        while i < FORMAT_INT.len() {
            let (base, v, want) = FORMAT_INT[i];
            if strconv::FormatInt(v, base) != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "FormatInt across all three loops");
    }

    // 2. FormatUint, including MaxUint64 — the value that a port
    //    routing unsigned formatting through a signed path renders as
    //    -1.
    {
        let mut ok = true;
        let mut i = 0;
        while i < FORMAT_UINT.len() {
            let (base, v, want) = FORMAT_UINT[i];
            if strconv::FormatUint(v, base) != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 2", "FormatUint (MaxUint64 included)");
    }

    // 3. Itoa. The 0..99 rows go through the `small` fast path and the
    //    rest do not, so this is where a wrong `nSmalls` boundary or a
    //    mis-indexed smallsString shows up.
    {
        let mut ok = true;
        let mut i = 0;
        while i < ITOA.len() {
            let (v, want) = ITOA[i];
            if strconv::Itoa(v) != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 3", "Itoa (small fast path)");
    }

    // 4. AppendInt and AppendUint append — the destination's existing
    //    bytes survive, and the fast path appends the same digits the
    //    slow one would.
    {
        let mut ok = true;
        let mut i = 0;
        while i < APPEND_INT.len() {
            let (base, v, want) = APPEND_INT[i];
            let got = strconv::AppendInt(bs("<"), v, base);
            if string::from_bytes(&got.__into_vec()) != s(want) {
                ok = false;
            }
            i += 1;
        }
        let mut j = 0;
        while j < APPEND_UINT.len() {
            let (v, want) = APPEND_UINT[j];
            let got = strconv::AppendUint(bs("<"), v, 10);
            if string::from_bytes(&got.__into_vec()) != s(want) {
                ok = false;
            }
            j += 1;
        }
        report(&mut failed, ok, " 4", "AppendInt/AppendUint extend dst");
    }

    // 5. Every base round-trips through ParseInt. This is the cheapest
    //    end-to-end check that the three digit loops and the parser
    //    agree on the same alphabet.
    {
        let mut ok = true;
        let v: int = -1234567890123;
        let mut i = 0;
        while i < ROUNDTRIP.len() {
            let (base, want) = ROUNDTRIP[i];
            let got = strconv::FormatInt(v, base);
            if got != s(want) {
                ok = false;
            }
            let (back, err) = strconv::ParseInt(got, base, 64);
            if !err.IsNil() || back != v {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 5", "all 35 bases round-trip");
    }

    // 6. baseError and bitSizeError render the offending number with
    //    Itoa, so their message text is part of itoa.go's contract.
    {
        let mut ok = true;
        let mut i = 0;
        while i < PARSE_ERR.len() {
            let (signed, base, bits, want) = PARSE_ERR[i];
            let err = if signed {
                let (_, e) = strconv::ParseInt("12", base, bits);
                e
            } else {
                let (_, e) = strconv::ParseUint("12", base, bits);
                e
            };
            if err.IsNil() || err.Error() != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 6", "base/bit-size error text");
    }

    // 7. IntSize is a declared constant, and `digits` covers the whole
    //    36-letter alphabet in order — base 36 of 35 is "z", not a byte
    //    off the end of a shorter table.
    {
        let mut ok = true;
        if strconv::IntSize != 64 {
            ok = false;
        }
        if strconv::FormatInt(35, 36) != s("z") || strconv::FormatInt(36, 36) != s("10") {
            ok = false;
        }
        // Go: formatuint base=36 v=18446744073709551615 "3w5e11264sgsf"
        if strconv::FormatUint(uint::MAX, 36) != s("3w5e11264sgsf") {
            ok = false;
        }
        report(&mut failed, ok, " 7", "IntSize and the digit alphabet");
    }

    // 8. ParseInt strips the sign before delegating to ParseUint, then
    //    RESHAPES whatever came back: the same wrapped Err, but
    //    Func="ParseInt" and Num set to the original string, sign and
    //    all. goish flattened every non-range error into a syntax
    //    error instead — the code said so, and called it "wrong-but-
    //    rare" — so `ParseInt("12", 1, 64)` reported invalid syntax for
    //    a perfectly well-formed "12".
    {
        let mut ok = true;
        // (input, base, want) — Go 1.25.5, verbatim.
        let cases: [(&str, int, &str); 12] = [
            (
                "-abc",
                10,
                "strconv.ParseInt: parsing \"-abc\": invalid syntax",
            ),
            (
                "-abc",
                1,
                "strconv.ParseInt: parsing \"-abc\": invalid base 1",
            ),
            (
                "+abc",
                10,
                "strconv.ParseInt: parsing \"+abc\": invalid syntax",
            ),
            (
                "+abc",
                1,
                "strconv.ParseInt: parsing \"+abc\": invalid base 1",
            ),
            (
                "abc",
                10,
                "strconv.ParseInt: parsing \"abc\": invalid syntax",
            ),
            (
                "abc",
                1,
                "strconv.ParseInt: parsing \"abc\": invalid base 1",
            ),
            ("-", 10, "strconv.ParseInt: parsing \"-\": invalid syntax"),
            // A bare sign is an EMPTY string by the time ParseUint sees
            // it, and ParseUint checks for empty before it checks the
            // base — so this one is a syntax error even at base 1.
            ("-", 1, "strconv.ParseInt: parsing \"-\": invalid syntax"),
            ("", 10, "strconv.ParseInt: parsing \"\": invalid syntax"),
            ("", 1, "strconv.ParseInt: parsing \"\": invalid syntax"),
            (
                "-99999999999999999999",
                10,
                "strconv.ParseInt: parsing \"-99999999999999999999\": value out of range",
            ),
            (
                "-99999999999999999999",
                1,
                "strconv.ParseInt: parsing \"-99999999999999999999\": invalid base 1",
            ),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (input, base, want) = cases[i];
            let (_, err) = strconv::ParseInt(input, base, 64);
            if err.IsNil() || err.Error() != s(want) {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 8", "ParseInt reshapes, never flattens");
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
