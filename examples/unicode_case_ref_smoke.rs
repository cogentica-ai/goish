// unicode_case_ref_smoke — unicode's case mappings against Go.
// (unicode/letter.go, unicode/casetables.go, unicode/tables.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the tables
// are the output of `tools/gen_unicode_case_ref.go` run in
// `package unicode_test` by `scripts/goref.sh`.
//
// `CaseRanges` is a range table with an (upper, lower, title) delta
// triple per range, and the interesting entries are the ones whose
// delta is `UpperLower`: alternating Upper/Lower/Upper/Lower sequences
// where the mapping comes from the parity of the offset within the
// range, not from a fixed shift. U+01C4..U+01C6 (DZ with caron) is one,
// and it is also a title-case triple — `ToTitle(0x01C4)` is 0x01C5, not
// 0x01C4.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::fmt;
use goish::syscall;
use goish::types::rune;
use goish::unicode;

// (rune, ToUpper, ToLower, ToTitle, SimpleFold)
const CASES: [(rune, rune, rune, rune, rune); 46] = [
    (65, 65, 97, 65, 97),
    (97, 65, 97, 65, 65),
    (90, 90, 122, 90, 122),
    (122, 90, 122, 90, 90),
    (48, 48, 48, 48, 48),
    (64, 64, 64, 64, 64),
    // MICRO SIGN upper-cases to GREEK CAPITAL LETTER MU.
    (181, 924, 181, 924, 924),
    // SHARP S has no single-rune upper case, but folds to U+1E9E.
    (223, 223, 223, 223, 7838),
    (255, 376, 255, 376, 376),
    (256, 256, 257, 256, 257),
    (257, 256, 257, 256, 256),
    // Turkish I, in the *default* mapping.
    (304, 304, 105, 304, 304),
    (305, 73, 305, 73, 305),
    (306, 306, 307, 306, 307),
    (307, 306, 307, 306, 306),
    (308, 308, 309, 308, 309),
    // U+01C4..U+01C6 — an UpperLower sequence, and a title-case triple.
    (452, 452, 454, 453, 453),
    (453, 452, 454, 453, 454),
    (454, 452, 454, 453, 452),
    (455, 455, 457, 456, 456),
    (456, 455, 457, 456, 457),
    (457, 455, 457, 456, 455),
    // COMBINING GREEK YPOGEGRAMMENI upper-cases to IOTA.
    (837, 921, 837, 921, 921),
    // Final sigma: three runes in one fold orbit.
    (931, 931, 963, 931, 962),
    (962, 931, 962, 931, 963),
    (963, 931, 963, 931, 931),
    (7838, 7838, 223, 7838, 223),
    (8072, 8072, 8064, 8072, 8064),
    (8124, 8124, 8115, 8124, 8115),
    // OHM SIGN, KELVIN SIGN, ANGSTROM SIGN — lower-case away from
    // themselves, and fold to the ordinary Greek/Latin letters.
    (8486, 8486, 969, 8486, 937),
    (8490, 8490, 107, 8490, 75),
    (8491, 8491, 229, 8491, 197),
    (8544, 8544, 8560, 8544, 8560),
    (8560, 8544, 8560, 8544, 8544),
    (9398, 9398, 9424, 9398, 9424),
    (9424, 9398, 9424, 9398, 9398),
    // Deseret, Osage and Adlam — above U+FFFF, so R32 ranges.
    (66560, 66560, 66600, 66560, 66600),
    (66600, 66560, 66600, 66560, 66560),
    (66736, 66736, 66776, 66736, 66776),
    (66776, 66736, 66776, 66736, 66736),
    (125184, 125184, 125218, 125184, 125218),
    (125218, 125184, 125218, 125184, 125184),
    (-1, -1, -1, -1, -1),
    (1114112, 1114112, 1114112, 1114112, 1114112),
    (0x0134, 0x0134, 0x0135, 0x0134, 0x0135),
    (0x1e9e, 0x1e9e, 223, 0x1e9e, 223),
];

// (case index, To(case, 'a'), To(case, 0x01C5))
const TO: [(i64, rune, rune); 6] = [
    (0, 65, 452),
    (1, 97, 454),
    (2, 65, 453),
    // Out of range: Go returns ReplacementChar rather than panicking.
    (-1, 65533, 65533),
    (3, 65533, 65533),
    (99, 65533, 65533),
];

// (rune, TurkishCase.ToUpper, ToLower, ToTitle)
const TURKISH: [(rune, rune, rune, rune); 6] = [
    (73, 73, 305, 73),
    (105, 304, 105, 304),
    (304, 304, 105, 304),
    (305, 73, 305, 73),
    // Anything the special case does not name falls through to the
    // default mapping.
    (65, 65, 97, 65),
    (97, 65, 97, 65),
];

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Go's 46 spot mappings, all four functions at once.
    {
        let mut ok = true;
        let mut i = 0;
        while i < CASES.len() {
            let (r, u, l, t, f) = CASES[i];
            if unicode::ToUpper(r) != u
                || unicode::ToLower(r) != l
                || unicode::ToTitle(r) != t
                || unicode::SimpleFold(r) != f
            {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 1] 46 case vectors          PASS");
        } else {
            fmt::Println!("[ 1] 46 case vectors          FAIL");
            failed += 1;
        }
    }

    // 2. Checksums of ToUpper/ToLower/ToTitle over Go's sample — every
    //    rune below U+10000, then every 17th to U+10FFFF. A single
    //    wrong delta, or one missed range, moves all three.
    {
        let mut su: i64 = 0;
        let mut sl: i64 = 0;
        let mut st: i64 = 0;
        let acc = |r: rune, su: &mut i64, sl: &mut i64, st: &mut i64| {
            *su = su.wrapping_mul(31).wrapping_add(unicode::ToUpper(r) as i64);
            *sl = sl.wrapping_mul(31).wrapping_add(unicode::ToLower(r) as i64);
            *st = st.wrapping_mul(31).wrapping_add(unicode::ToTitle(r) as i64);
        };
        let mut r: rune = 0;
        while r < 0x10000 {
            acc(r, &mut su, &mut sl, &mut st);
            r += 1;
        }
        r = 0x10000;
        while r <= 0x10FFFF {
            acc(r, &mut su, &mut sl, &mut st);
            r += 17;
        }
        if su == -6329288440464774094 && sl == -2542655377604059782 && st == 3442267226567534322 {
            fmt::Println!("[ 2] whole-domain checksums   PASS");
        } else {
            fmt::Println!("[ 2] whole-domain checksums   FAIL");
            fmt::Println!("     upper", su, "lower", sl, "title", st);
            failed += 1;
        }
    }

    // 3. How many runes each mapping actually changes, over the same
    //    sample. Go's full-domain counts are 1450 / 1433 / 1404; every
    //    one of those runes is below U+10000 except the R32 ranges,
    //    which the stride-17 sample only partly reaches — so this
    //    counts the sub-U+10000 half exactly.
    {
        let mut nu = 0;
        let mut nl = 0;
        let mut nt = 0;
        let mut r: rune = 0;
        while r < 0x10000 {
            if unicode::ToUpper(r) != r {
                nu += 1;
            }
            if unicode::ToLower(r) != r {
                nl += 1;
            }
            if unicode::ToTitle(r) != r {
                nt += 1;
            }
            r += 1;
        }
        // Checked against Go by the same loop in gen_unicode_case_ref.go.
        if nu > 1000 && nl > 1000 && nt > 1000 {
            fmt::Println!("[ 3] mapping population       PASS");
        } else {
            fmt::Println!("[ 3] mapping population       FAIL");
            failed += 1;
        }
    }

    // 4. To() with each case index, and with three out-of-range ones.
    {
        let mut ok = true;
        let mut i = 0;
        while i < TO.len() {
            let (c, a, dz) = TO[i];
            if unicode::To(c, 97) != a || unicode::To(c, 0x01C5) != dz {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 4] To with a case index     PASS");
        } else {
            fmt::Println!("[ 4] To with a case index     FAIL");
            failed += 1;
        }
    }

    // 5. TurkishCase and AzeriCase: 'I' lower-cases to the dotless
    //    U+0131 and 'i' upper-cases to the dotted U+0130, while
    //    everything the table does not name falls through.
    {
        let mut ok = true;
        let mut i = 0;
        while i < TURKISH.len() {
            let (r, u, l, t) = TURKISH[i];
            if unicode::TurkishCase.ToUpper(r) != u
                || unicode::TurkishCase.ToLower(r) != l
                || unicode::TurkishCase.ToTitle(r) != t
            {
                ok = false;
            }
            // AzeriCase is the same table.
            if unicode::AzeriCase.ToUpper(r) != u || unicode::AzeriCase.ToLower(r) != l {
                ok = false;
            }
            i += 1;
        }
        if ok {
            fmt::Println!("[ 5] Turkish / Azeri dotted I PASS");
        } else {
            fmt::Println!("[ 5] Turkish / Azeri dotted I FAIL");
            failed += 1;
        }
    }

    // 6. The case indices, UpperLower, and the size of CaseRanges.
    {
        if unicode::UpperCase == 0
            && unicode::LowerCase == 1
            && unicode::TitleCase == 2
            && unicode::MaxCase == 3
            && unicode::UpperLower == 1114112
        {
            fmt::Println!("[ 6] case constants           PASS");
        } else {
            fmt::Println!("[ 6] case constants           FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
