// regexp_class_ref_smoke — `regexp/syntax`'s character-class layer,
// stage 2b-i of §2c.
//
// A "class" here is a flat rune list of [lo, hi] pairs. It is what
// `Regexp.Rune` carries for `OpCharClass` and what `Inst.Rune` carries
// for `InstRune`, so it is the shape a match ultimately binary-searches
// — and every `[...]`, `\d`, `\pL` and case-fold in a pattern is built
// by the functions pinned here.
//
// This layer comes before the parser because it is the half that can be
// tested without one: rune lists in, rune lists out, no state machine
// and no input string.
//
// Four behaviours the reference exists to hold down:
//
//   * `appendRange` checks TWO ranges back, not one. Go's comment says
//     why — "this helps when appending case-folded alphabets, so that
//     one range can be expanding A-Z and the other expanding a-z" —
//     and rows 8 through 12 are the window's edges.
//   * `appendFoldedRange`'s three guards are not micro-optimisation.
//     The loop is per-RUNE, so `(?i).` without them walks 1.1 million
//     runes calling SimpleFold on each.
//   * `cleanClass` sorts by lo increasing and hi DECREASING, and the
//     tie-break does NOT change the answer. Deleting it leaves all 118
//     rows green, and that is correct rather than a gap in the table:
//     two million random classes were cleaned both ways with zero
//     differences, because the merge tracks a running maximum `hi`.
//     Reproduced because it is Go's, not because it is load-bearing —
//     see the note on `ranges::Less`.
//   * `appendNegatedTable` is not `negate(appendTable(...))`. A strided
//     run contributes a gap between each of ITS runes, so it walks the
//     table directly.
//
// The four synthetic RangeTables are built identically on both sides,
// so the rows do not depend on Go and goish carrying byte-identical
// Unicode data. Three rows then check exactly that, against `Zs` and
// `Mn`.
//
// 118 rows from `scripts/goref.sh regexp/syntax
// tools/gen_regexp_class_ref.go`.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::regexp::syntax::parse;
use goish::types::{int, rune};
use goish::unicode::{Range16, Range32, RangeTable};
use goish::{fmt, string, strconv};

static mut FAILED: int = 0;
static mut RUN: int = 0;

const GO: [&str; 118] = [
    r#"appendRange  0 [97 122]"#,
    r#"appendRange  1 [97 122 65 90]"#,
    r#"appendRange  2 [97 126]"#,
    r#"appendRange  3 [87 122]"#,
    r#"appendRange  4 [97 122]"#,
    r#"appendRange  5 [97 256]"#,
    r#"appendRange  6 [97 122 512 768]"#,
    r#"appendRange  7 [65 90 91 122]"#,
    r#"appendRange  8 [48 90 97 122]"#,
    r#"appendRange  9 [65 90 97 122 1 2]"#,
    r#"appendRange 10 [1 2 3 6 9 10]"#,
    r#"appendRange 11 [1 2 5 6 7 10]"#,
    r#"appendRange 12 [0 0]"#,
    r#"appendRange 13 [0 1114111]"#,
    r#"appendFoldedRange  0 [0 1114111]"#,
    r#"appendFoldedRange  1 [65 65 97 97]"#,
    r#"appendFoldedRange  2 [107 107 8490 8490 75 75]"#,
    r#"appendFoldedRange  3 [75 75 107 107 8490 8490]"#,
    r#"appendFoldedRange  4 [8490 8490 75 75 107 107]"#,
    r#"appendFoldedRange  5 [115 115 383 383 83 83]"#,
    r#"appendFoldedRange  6 [383 383 83 83 115 115]"#,
    r#"appendFoldedRange  7 [97 107 65 75 8490 8490 108 115 76 83 383 383 116 122 84 90]"#,
    r#"appendFoldedRange  8 [0 64]"#,
    r#"appendFoldedRange  9 [125252 125264]"#,
    r#"appendFoldedRange 10 [32 75 97 107 8490 8490 76 80 108 112]"#,
    r#"appendFoldedRange 11 [125252 125264 125232 125251 125198 125217]"#,
    r#"appendFoldedRange 12 [304 307]"#,
    r#"appendFoldedRange 13 [931 931 962 963]"#,
    r#"appendClass         0 []"#,
    r#"appendFoldedClass   0 []"#,
    r#"appendNegatedClass  0 [0 1114111]"#,
    r#"negateClass         0 [0 1114111]"#,
    r#"appendClass         1 [97 122]"#,
    r#"appendFoldedClass   1 [97 107 65 75 8490 8490 108 115 76 83 383 383 116 122 84 90]"#,
    r#"appendNegatedClass  1 [0 96 123 1114111]"#,
    r#"negateClass         1 [0 96 123 1114111]"#,
    r#"appendClass         2 [97 99 120 122]"#,
    r#"appendFoldedClass   2 [97 99 65 67 120 122 88 90]"#,
    r#"appendNegatedClass  2 [0 96 100 119 123 1114111]"#,
    r#"negateClass         2 [0 96 100 119 123 1114111]"#,
    r#"appendClass         3 [0 1114111]"#,
    r#"appendFoldedClass   3 [0 1114111]"#,
    r#"appendNegatedClass  3 []"#,
    r#"negateClass         3 []"#,
    r#"appendClass         4 [48 57 65 90 97 122]"#,
    r#"appendFoldedClass   4 [48 57 65 75 97 107 8490 8490 76 83 108 115 383 383 84 90 116 122 97 107 65 75 8490 8490 108 115 76 83 383 383 116 122 84 90]"#,
    r#"appendNegatedClass  4 [0 47 58 64 91 96 123 1114111]"#,
    r#"negateClass         4 [0 47 58 64 91 96 123 1114111]"#,
    r#"appendClass         5 [107 107]"#,
    r#"appendFoldedClass   5 [107 107 8490 8490 75 75]"#,
    r#"appendNegatedClass  5 [0 106 108 1114111]"#,
    r#"negateClass         5 [0 106 108 1114111]"#,
    r#"appendClass         6 [1 1]"#,
    r#"appendFoldedClass   6 [1 1]"#,
    r#"appendNegatedClass  6 [0 0 2 1114111]"#,
    r#"negateClass         6 [0 0 2 1114111]"#,
    r#"appendTable         0 [65 90]"#,
    r#"appendNegatedTable  0 [0 64 91 1114111]"#,
    r#"appendTable         1 [256 256 258 258 260 260 262 262 264 264 266 266 268 268 270 270 272 272]"#,
    r#"appendNegatedTable  1 [0 255 257 257 259 259 261 261 263 263 265 265 267 267 269 269 271 271 273 1114111]"#,
    r#"appendTable         2 [48 57 65 65 68 68 71 71 74 74 77 77 80 80 83 83 86 86 89 89 65536 65552 131072 131072 131077 131077 131082 131082]"#,
    r#"appendNegatedTable  2 [0 47 58 64 66 67 69 70 72 73 75 76 78 79 81 82 84 85 87 88 90 65535 65553 131071 131073 131076 131078 131081 131083 1114111]"#,
    r#"appendTable         3 [0 1114111]"#,
    r#"appendNegatedTable  3 []"#,
    r#"appendTable Zs [32 32 160 160 5760 5760 8192 8202 8239 8239 8287 8287 12288 12288]"#,
    r#"appendTable Mn.len 692"#,
    r#"appendNegatedTable Zs.len 16"#,
    r#"cleanClass  0 []"#,
    r#"cleanClass  1 [97 122]"#,
    r#"cleanClass  2 [97 99 120 122]"#,
    r#"cleanClass  3 [97 100]"#,
    r#"cleanClass  4 [97 122]"#,
    r#"cleanClass  5 [97 122]"#,
    r#"cleanClass  6 [97 100]"#,
    r#"cleanClass  7 [97 98 100 101]"#,
    r#"cleanClass  8 [1 6]"#,
    r#"cleanClass  9 [1 2 5 6 9 10]"#,
    r#"cleanClass 10 [0 1114111]"#,
    r#"cleanClass 11 [1 9]"#,
    r#"cleanClass 12 [1 1]"#,
    r#"inCharClass     47 false"#,
    r#"inCharClass     48 true"#,
    r#"inCharClass     53 true"#,
    r#"inCharClass     57 true"#,
    r#"inCharClass     58 false"#,
    r#"inCharClass     64 false"#,
    r#"inCharClass     65 true"#,
    r#"inCharClass     70 true"#,
    r#"inCharClass     71 false"#,
    r#"inCharClass     96 false"#,
    r#"inCharClass     97 true"#,
    r#"inCharClass    102 true"#,
    r#"inCharClass    103 false"#,
    r#"inCharClass    255 false"#,
    r#"inCharClass    256 true"#,
    r#"inCharClass    271 true"#,
    r#"inCharClass    272 false"#,
    r#"inCharClass     -1 false"#,
    r#"inCharClass-empty 0 false"#,
    r#"inCharClass-empty 1 false"#,
    r#"inCharClass-empty 97 false"#,
    r#"minFoldRune      97      65"#,
    r#"minFoldRune      65      65"#,
    r#"minFoldRune     107      75"#,
    r#"minFoldRune      75      75"#,
    r#"minFoldRune    8490      75"#,
    r#"minFoldRune     115      83"#,
    r#"minFoldRune      83      83"#,
    r#"minFoldRune     383      83"#,
    r#"minFoldRune      48      48"#,
    r#"minFoldRune      64      64"#,
    r#"minFoldRune  125251  125217"#,
    r#"minFoldRune  125252  125252"#,
    r#"minFoldRune     963     931"#,
    r#"minFoldRune     931     931"#,
    r#"minFoldRune     962     931"#,
    r#"minFoldRune      -1      -1"#,
    r#"minFoldRune 1114111 1114111"#,
];

// The four synthetic tables, built identically to the reference's.
static T1_R16: [Range16; 1] = [Range16 { Lo: 0x41, Hi: 0x5a, Stride: 1 }];
static T2_R16: [Range16; 1] = [Range16 { Lo: 0x100, Hi: 0x110, Stride: 2 }];
static T3_R16: [Range16; 2] = [
    Range16 { Lo: 0x30, Hi: 0x39, Stride: 1 },
    Range16 { Lo: 0x41, Hi: 0x5a, Stride: 3 },
];
static T3_R32: [Range32; 2] = [
    Range32 { Lo: 0x10000, Hi: 0x10010, Stride: 1 },
    Range32 { Lo: 0x20000, Hi: 0x2000a, Stride: 5 },
];
static T4_R16: [Range16; 1] = [Range16 { Lo: 0, Hi: 0xffff, Stride: 1 }];
static T4_R32: [Range32; 1] = [Range32 { Lo: 0x10000, Hi: 0x10ffff, Stride: 1 }];
static NO_R16: [Range16; 0] = [];
static NO_R32: [Range32; 0] = [];

static T1: RangeTable = RangeTable { R16: &T1_R16, R32: &NO_R32, LatinOffset: 0 };
static T2: RangeTable = RangeTable { R16: &T2_R16, R32: &NO_R32, LatinOffset: 0 };
static T3: RangeTable = RangeTable { R16: &T3_R16, R32: &T3_R32, LatinOffset: 0 };
static T4: RangeTable = RangeTable { R16: &T4_R16, R32: &T4_R32, LatinOffset: 0 };

fn line(ln: &mut usize, got: string) {
    unsafe { RUN += 1 };
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        unsafe { FAILED += 1 };
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!(
            "[!!] line %d\n  got  %q\n  want %q\n",
            *ln as int + 1,
            got,
            GO[*ln]
        );
        unsafe { FAILED += 1 };
    }
    *ln += 1;
}

/// The reference's `rs` — a rune list as `[a b c]`.
fn rs(r: &goish::goslice::slice<rune>) -> string {
    let mut out = string::from_static("[");
    let n = goish::len(r);
    let mut i: int = 0;
    while i < n {
        if i > 0 {
            out = out + string::from_static(" ");
        }
        out = out + strconv::Itoa(int::from(goish::int64(r[i])));
        i += 1;
    }
    return out + string::from_static("]");
}

/// `%Nd` — right-aligned.
fn d(v: i64, w: int) -> string {
    let mut out = strconv::Itoa(int::from(v));
    while out.Len() < w {
        out = string::from_static(" ") + out;
    }
    return out;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    // ── appendRange: the two-back coalescing ────────────────────────
    let ars: [(&[rune], rune, rune); 14] = [
        (&[], 'a' as rune, 'z' as rune),
        (&['a' as rune, 'z' as rune], 'A' as rune, 'Z' as rune),
        (&['a' as rune, 'z' as rune], '{' as rune, '~' as rune),
        (&['a' as rune, 'z' as rune], 'W' as rune, '`' as rune),
        (&['a' as rune, 'z' as rune], 'm' as rune, 'q' as rune),
        (&['a' as rune, 'z' as rune], 'x' as rune, 0x100),
        (&['a' as rune, 'z' as rune], 0x200, 0x300),
        (
            &['A' as rune, 'Z' as rune, 'a' as rune, 'z' as rune],
            '[' as rune,
            '`' as rune,
        ),
        (
            &['A' as rune, 'Z' as rune, 'a' as rune, 'z' as rune],
            0x30,
            0x40,
        ),
        (&['A' as rune, 'Z' as rune, 'a' as rune, 'z' as rune], 1, 2),
        (&[1, 2, 5, 6, 9, 10], 3, 4),
        (&[1, 2, 5, 6, 9, 10], 7, 8),
        (&[0, 0], 0, 0),
        (&[], 0, 0x10ffff),
    ];
    for (i, (start, lo, hi)) in ars.iter().enumerate() {
        line(
            &mut ln,
            string::from_static("appendRange ")
                + d(i as i64, int::from(2))
                + string::from_static(" ")
                + rs(&parse::__appendRange(start, *lo, *hi)),
        );
    }

    // ── appendFoldedRange ───────────────────────────────────────────
    let frs: [(rune, rune); 14] = [
        (0, 0x10ffff),
        (0x41, 0x41),
        ('k' as rune, 'k' as rune),
        ('K' as rune, 'K' as rune),
        (0x212a, 0x212a),
        ('s' as rune, 's' as rune),
        (0x17f, 0x17f),
        ('a' as rune, 'z' as rune),
        (0, 0x40),
        (0x1e944, 0x1e950),
        (0x20, 0x50),
        (0x1e930, 0x1e950),
        (0x130, 0x132),
        (0x3a3, 0x3a3),
    ];
    for (i, (lo, hi)) in frs.iter().enumerate() {
        line(
            &mut ln,
            string::from_static("appendFoldedRange ")
                + d(i as i64, int::from(2))
                + string::from_static(" ")
                + rs(&parse::__appendFoldedRange(&[], *lo, *hi)),
        );
    }

    // ── the four class builders, over the same inputs ───────────────
    let cls: [&[rune]; 7] = [
        &[],
        &['a' as rune, 'z' as rune],
        &['a' as rune, 'c' as rune, 'x' as rune, 'z' as rune],
        &[0, 0x10ffff],
        &[
            '0' as rune, '9' as rune, 'A' as rune, 'Z' as rune, 'a' as rune, 'z' as rune,
        ],
        &['k' as rune, 'k' as rune],
        &[1, 1],
    ];
    for (i, c) in cls.iter().enumerate() {
        let n = d(i as i64, int::from(2));
        line(
            &mut ln,
            string::from_static("appendClass        ")
                + n.clone()
                + string::from_static(" ")
                + rs(&parse::__appendClass(&[], c)),
        );
        line(
            &mut ln,
            string::from_static("appendFoldedClass  ")
                + n.clone()
                + string::from_static(" ")
                + rs(&parse::__appendFoldedClass(&[], c)),
        );
        line(
            &mut ln,
            string::from_static("appendNegatedClass ")
                + n.clone()
                + string::from_static(" ")
                + rs(&parse::__appendNegatedClass(&[], c)),
        );
        line(
            &mut ln,
            string::from_static("negateClass        ")
                + n
                + string::from_static(" ")
                + rs(&parse::__negateClass(c)),
        );
    }

    // ── appendTable / appendNegatedTable ────────────────────────────
    let tabs: [&RangeTable; 4] = [&T1, &T2, &T3, &T4];
    for (i, tb) in tabs.iter().enumerate() {
        let n = d(i as i64, int::from(2));
        line(
            &mut ln,
            string::from_static("appendTable        ")
                + n.clone()
                + string::from_static(" ")
                + rs(&parse::__appendTable(&[], tb)),
        );
        line(
            &mut ln,
            string::from_static("appendNegatedTable ")
                + n
                + string::from_static(" ")
                + rs(&parse::__appendNegatedTable(&[], tb)),
        );
    }
    // Two real tables, which also checks the two sides carry the same
    // Unicode data.
    line(
        &mut ln,
        string::from_static("appendTable Zs ")
            + rs(&parse::__appendTable(&[], goish::unicode::Zs)),
    );
    line(
        &mut ln,
        string::from_static("appendTable Mn.len ")
            + strconv::Itoa(goish::len(&parse::__appendTable(&[], goish::unicode::Mn))),
    );
    line(
        &mut ln,
        string::from_static("appendNegatedTable Zs.len ")
            + strconv::Itoa(goish::len(&parse::__appendNegatedTable(
                &[],
                goish::unicode::Zs,
            ))),
    );

    // ── cleanClass: the sort, the tie-break, the merge ──────────────
    let dirty: [&[rune]; 13] = [
        &[],
        &['a' as rune, 'z' as rune],
        &['x' as rune, 'z' as rune, 'a' as rune, 'c' as rune],
        &['a' as rune, 'c' as rune, 'b' as rune, 'd' as rune],
        &['a' as rune, 'z' as rune, 'a' as rune, 'c' as rune],
        &['a' as rune, 'c' as rune, 'a' as rune, 'z' as rune],
        &['a' as rune, 'b' as rune, 'c' as rune, 'd' as rune],
        &['a' as rune, 'b' as rune, 'd' as rune, 'e' as rune],
        &[5, 6, 1, 2, 3, 4],
        &[9, 10, 1, 2, 5, 6],
        &[0, 0x10ffff, 5, 6],
        &[3, 4, 1, 9, 5, 6],
        &[1, 1, 1, 1, 1, 1],
    ];
    for (i, c) in dirty.iter().enumerate() {
        line(
            &mut ln,
            string::from_static("cleanClass ")
                + d(i as i64, int::from(2))
                + string::from_static(" ")
                + rs(&parse::__cleanClass(c)),
        );
    }

    // ── inCharClass ─────────────────────────────────────────────────
    let cc: [rune; 8] = [
        '0' as rune, '9' as rune, 'A' as rune, 'F' as rune, 'a' as rune, 'f' as rune, 0x100,
        0x10f,
    ];
    let probes: [rune; 18] = [
        '/' as rune, '0' as rune, '5' as rune, '9' as rune, ':' as rune, '@' as rune,
        'A' as rune, 'F' as rune, 'G' as rune, '`' as rune, 'a' as rune, 'f' as rune,
        'g' as rune, 0xff, 0x100, 0x10f, 0x110, -1,
    ];
    for r in probes.iter() {
        line(
            &mut ln,
            string::from_static("inCharClass ")
                + d(goish::int64(*r), int::from(6))
                + string::from_static(" ")
                + fmt::Sprintf!("%v", parse::__inCharClass(*r, &cc)),
        );
    }
    for r in [0 as rune, 1 as rune, 'a' as rune].iter() {
        line(
            &mut ln,
            string::from_static("inCharClass-empty ")
                + strconv::Itoa(int::from(goish::int64(*r)))
                + string::from_static(" ")
                + fmt::Sprintf!("%v", parse::__inCharClass(*r, &[])),
        );
    }

    // ── minFoldRune ─────────────────────────────────────────────────
    let mf: [rune; 17] = [
        'a' as rune, 'A' as rune, 'k' as rune, 'K' as rune, 0x212a, 's' as rune, 'S' as rune,
        0x17f, '0' as rune, 0x40, 0x1e943, 0x1e944, 0x3c3, 0x3a3, 0x3c2, -1, 0x10ffff,
    ];
    for r in mf.iter() {
        line(
            &mut ln,
            string::from_static("minFoldRune ")
                + d(goish::int64(*r), int::from(7))
                + string::from_static(" ")
                + d(goish::int64(parse::__minFoldRune(*r)), int::from(7)),
        );
    }

    let run = unsafe { RUN };
    let f = unsafe { FAILED };
    if run != GO.len() as int {
        fmt::Printf!("\nFAIL ran %d of %d rows\n", run, GO.len() as int);
        goish::os::Exit(1);
    }
    if f == 0 {
        fmt::Printf!("\nok %d/%d\n", run, run);
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", f);
    goish::os::Exit(1);
}
