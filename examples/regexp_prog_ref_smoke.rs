// regexp_prog_ref_smoke — `regexp/syntax`'s compiled-program
// representation, stage 1 of §2c.
//
// §2c is the one open item with a denial of service behind it: goish's
// matcher backtracks over the AST, so `(a+)+$` against 22 'a's takes 27
// SECONDS where Go answers in under a millisecond, and each further
// character doubles it. Twenty-five bytes hang the process.
//
// The roadmap records why the two cheap fixes do not work. A step
// budget trades a hang for a WRONG answer. Memoisation — what Go's own
// backtrack.go does — needs a bounded key, and Go's is `pc*(end+1) +
// pos`: two small integers, because compiling to a program makes the
// continuation implicit in the pc. goish's matcher is
// continuation-passing over the AST, so its state is (node, pos, caps,
// CONTINUATION) and there is nothing bounded to key on.
//
// So the pc is the fix, and this file is where the pc comes from. It
// pins `Prog`, `Inst`, and the pure functions the NFA will run on —
// before any of it is wired to anything, so a later stage that breaks
// one of these fails HERE rather than as a mysterious mismatch in the
// engine.
//
// 166 rows, all Go 1.25.5's own output via `scripts/goref.sh
// regexp/syntax tools/gen_regexp_prog_ref.go`, transcribed
// programmatically. Four are worth knowing about:
//
//   * `InstOp(11).String()` is the EMPTY string, not a number and not
//     a panic.
//   * `Inst{Op: InstRune, Rune: nil}.String()` is
//     `rune <nil>rune "" -> 7` — Go writes the "shouldn't happen"
//     marker and then FALLS THROUGH to write the quoted form too. It
//     is reproduced rather than tidied, because a dump is evidence.
//   * `StartCond` of a program that starts with `fail` is 255, Go's
//     `^EmptyOp(0)` sentinel for "no match is possible".
//   * A FOLDED first rune is not a prefix: `Prefix()` of
//     `rune "a"/i` is `("", false)`, because a folded instruction
//     matches more than the rune it holds.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::regexp::syntax;
use goish::types::{int, rune};
use goish::{fmt, string};

static mut FAILED: int = 0;
static mut RUN: int = 0;

const GO: [&str; 214] = [
    r#"InstOp.String  0 "InstAlt""#,
    r#"InstOp.String  1 "InstAltMatch""#,
    r#"InstOp.String  2 "InstCapture""#,
    r#"InstOp.String  3 "InstEmptyWidth""#,
    r#"InstOp.String  4 "InstMatch""#,
    r#"InstOp.String  5 "InstFail""#,
    r#"InstOp.String  6 "InstNop""#,
    r#"InstOp.String  7 "InstRune""#,
    r#"InstOp.String  8 "InstRune1""#,
    r#"InstOp.String  9 "InstRuneAny""#,
    r#"InstOp.String 10 "InstRuneAnyNotNL""#,
    r#"InstOp.String 11 """#,
    r#"InstOp.String 12 """#,
    r#"IsWordChar     97 true"#,
    r#"IsWordChar    122 true"#,
    r#"IsWordChar     65 true"#,
    r#"IsWordChar     90 true"#,
    r#"IsWordChar     48 true"#,
    r#"IsWordChar     57 true"#,
    r#"IsWordChar     95 true"#,
    r#"IsWordChar     45 false"#,
    r#"IsWordChar     32 false"#,
    r#"IsWordChar     10 false"#,
    r#"IsWordChar    233 false"#,
    r#"IsWordChar  19968 false"#,
    r#"IsWordChar     -1 false"#,
    r#"IsWordChar      0 false"#,
    r#"EmptyOpContext   -1   -1 47"#,
    r#"EmptyOpContext   -1   97 21"#,
    r#"EmptyOpContext   -1   10 39"#,
    r#"EmptyOpContext   -1   32 37"#,
    r#"EmptyOpContext   97   -1 26"#,
    r#"EmptyOpContext   97   98 32"#,
    r#"EmptyOpContext   97   32 16"#,
    r#"EmptyOpContext   97   10 18"#,
    r#"EmptyOpContext   32   97 16"#,
    r#"EmptyOpContext   32   32 32"#,
    r#"EmptyOpContext   10   97 17"#,
    r#"EmptyOpContext   10   10 35"#,
    r#"EmptyOpContext   10   -1 43"#,
    r#"EmptyOpContext   95   57 32"#,
    r#"EmptyOpContext   57   45 16"#,
    r#"MatchRunePos len0         97  -1 false"#,
    r#"MatchRunePos len0          0  -1 false"#,
    r#"MatchRunePos len1        107   0 true"#,
    r#"MatchRunePos len1         75  -1 false"#,
    r#"MatchRunePos len1        106  -1 false"#,
    r#"MatchRunePos len1fold    107   0 true"#,
    r#"MatchRunePos len1fold     75   0 true"#,
    r#"MatchRunePos len1fold    106  -1 false"#,
    r#"MatchRunePos len1fold   8490   0 true"#,
    r#"MatchRunePos len1foldS   115   0 true"#,
    r#"MatchRunePos len1foldS    83   0 true"#,
    r#"MatchRunePos len1foldS   383   0 true"#,
    r#"MatchRunePos len1foldS   120  -1 false"#,
    r#"MatchRunePos len2         97   0 true"#,
    r#"MatchRunePos len2         99   0 true"#,
    r#"MatchRunePos len2        102   0 true"#,
    r#"MatchRunePos len2        103  -1 false"#,
    r#"MatchRunePos len2         96  -1 false"#,
    r#"MatchRunePos len4         47  -1 false"#,
    r#"MatchRunePos len4         48   0 true"#,
    r#"MatchRunePos len4         53   0 true"#,
    r#"MatchRunePos len4         57   0 true"#,
    r#"MatchRunePos len4         58  -1 false"#,
    r#"MatchRunePos len4         96  -1 false"#,
    r#"MatchRunePos len4         97   1 true"#,
    r#"MatchRunePos len4        102   1 true"#,
    r#"MatchRunePos len4        103  -1 false"#,
    r#"MatchRunePos len6         48   0 true"#,
    r#"MatchRunePos len6         77   1 true"#,
    r#"MatchRunePos len6        113   2 true"#,
    r#"MatchRunePos len6         95  -1 false"#,
    r#"MatchRunePos len6        123  -1 false"#,
    r#"MatchRunePos len8          0  -1 false"#,
    r#"MatchRunePos len8          1   0 true"#,
    r#"MatchRunePos len8          2   0 true"#,
    r#"MatchRunePos len8          3  -1 false"#,
    r#"MatchRunePos len8         15   1 true"#,
    r#"MatchRunePos len8        150   2 true"#,
    r#"MatchRunePos len8       1500   3 true"#,
    r#"MatchRunePos len8       2001  -1 false"#,
    r#"MatchRunePos len12         0  -1 false"#,
    r#"MatchRunePos len12         1   0 true"#,
    r#"MatchRunePos len12         2   0 true"#,
    r#"MatchRunePos len12         3  -1 false"#,
    r#"MatchRunePos len12         9  -1 false"#,
    r#"MatchRunePos len12        10   1 true"#,
    r#"MatchRunePos len12        20   1 true"#,
    r#"MatchRunePos len12        21  -1 false"#,
    r#"MatchRunePos len12        99  -1 false"#,
    r#"MatchRunePos len12       100   2 true"#,
    r#"MatchRunePos len12       200   2 true"#,
    r#"MatchRunePos len12       201  -1 false"#,
    r#"MatchRunePos len12       999  -1 false"#,
    r#"MatchRunePos len12      1000   3 true"#,
    r#"MatchRunePos len12      2000   3 true"#,
    r#"MatchRunePos len12      2001  -1 false"#,
    r#"MatchRunePos len12      4999  -1 false"#,
    r#"MatchRunePos len12      5000   4 true"#,
    r#"MatchRunePos len12      6000   4 true"#,
    r#"MatchRunePos len12      6001  -1 false"#,
    r#"MatchRunePos len12      8999  -1 false"#,
    r#"MatchRunePos len12      9000   5 true"#,
    r#"MatchRunePos len12      9999   5 true"#,
    r#"MatchRunePos len12     10000  -1 false"#,
    r#"MatchRunePos len16        47  -1 false"#,
    r#"MatchRunePos len16        48   0 true"#,
    r#"MatchRunePos len16        57   0 true"#,
    r#"MatchRunePos len16        58  -1 false"#,
    r#"MatchRunePos len16        64  -1 false"#,
    r#"MatchRunePos len16        65   1 true"#,
    r#"MatchRunePos len16        70   1 true"#,
    r#"MatchRunePos len16        71  -1 false"#,
    r#"MatchRunePos len16        96  -1 false"#,
    r#"MatchRunePos len16        97   2 true"#,
    r#"MatchRunePos len16       102   2 true"#,
    r#"MatchRunePos len16       103  -1 false"#,
    r#"MatchRunePos len16       255  -1 false"#,
    r#"MatchRunePos len16       256   3 true"#,
    r#"MatchRunePos len16       271   3 true"#,
    r#"MatchRunePos len16       272  -1 false"#,
    r#"MatchRunePos len16       767  -1 false"#,
    r#"MatchRunePos len16       768   4 true"#,
    r#"MatchRunePos len16       783   4 true"#,
    r#"MatchRunePos len16       784  -1 false"#,
    r#"MatchRunePos len16     19967  -1 false"#,
    r#"MatchRunePos len16     19968   5 true"#,
    r#"MatchRunePos len16     19983   5 true"#,
    r#"MatchRunePos len16     19984  -1 false"#,
    r#"MatchRunePos len16     128511  -1 false"#,
    r#"MatchRunePos len16     128512   6 true"#,
    r#"MatchRunePos len16     128527   6 true"#,
    r#"MatchRunePos len16     128528  -1 false"#,
    r#"MatchRunePos len16     65535  -1 false"#,
    r#"MatchRunePos len16     65536  -1 false"#,
    r#"MatchRunePos len16     65551  -1 false"#,
    r#"MatchRunePos len16     65552  -1 false"#,
    r#"MatchEmptyWidth  1   -1   97 true"#,
    r#"MatchEmptyWidth  1   97   -1 false"#,
    r#"MatchEmptyWidth  1   10   97 true"#,
    r#"MatchEmptyWidth  1   97   10 false"#,
    r#"MatchEmptyWidth  1   97   98 false"#,
    r#"MatchEmptyWidth  1   97   32 false"#,
    r#"MatchEmptyWidth  1   32   97 false"#,
    r#"MatchEmptyWidth  1   32   32 false"#,
    r#"MatchEmptyWidth  2   -1   97 false"#,
    r#"MatchEmptyWidth  2   97   -1 true"#,
    r#"MatchEmptyWidth  2   10   97 false"#,
    r#"MatchEmptyWidth  2   97   10 true"#,
    r#"MatchEmptyWidth  2   97   98 false"#,
    r#"MatchEmptyWidth  2   97   32 false"#,
    r#"MatchEmptyWidth  2   32   97 false"#,
    r#"MatchEmptyWidth  2   32   32 false"#,
    r#"MatchEmptyWidth  4   -1   97 true"#,
    r#"MatchEmptyWidth  4   97   -1 false"#,
    r#"MatchEmptyWidth  4   10   97 false"#,
    r#"MatchEmptyWidth  4   97   10 false"#,
    r#"MatchEmptyWidth  4   97   98 false"#,
    r#"MatchEmptyWidth  4   97   32 false"#,
    r#"MatchEmptyWidth  4   32   97 false"#,
    r#"MatchEmptyWidth  4   32   32 false"#,
    r#"MatchEmptyWidth  8   -1   97 false"#,
    r#"MatchEmptyWidth  8   97   -1 true"#,
    r#"MatchEmptyWidth  8   10   97 false"#,
    r#"MatchEmptyWidth  8   97   10 false"#,
    r#"MatchEmptyWidth  8   97   98 false"#,
    r#"MatchEmptyWidth  8   97   32 false"#,
    r#"MatchEmptyWidth  8   32   97 false"#,
    r#"MatchEmptyWidth  8   32   32 false"#,
    r#"MatchEmptyWidth 16   -1   97 true"#,
    r#"MatchEmptyWidth 16   97   -1 true"#,
    r#"MatchEmptyWidth 16   10   97 true"#,
    r#"MatchEmptyWidth 16   97   10 true"#,
    r#"MatchEmptyWidth 16   97   98 false"#,
    r#"MatchEmptyWidth 16   97   32 true"#,
    r#"MatchEmptyWidth 16   32   97 true"#,
    r#"MatchEmptyWidth 16   32   32 false"#,
    r#"MatchEmptyWidth 32   -1   97 false"#,
    r#"MatchEmptyWidth 32   97   -1 false"#,
    r#"MatchEmptyWidth 32   10   97 false"#,
    r#"MatchEmptyWidth 32   97   10 false"#,
    r#"MatchEmptyWidth 32   97   98 true"#,
    r#"MatchEmptyWidth 32   97   32 false"#,
    r#"MatchEmptyWidth 32   32   97 false"#,
    r#"MatchEmptyWidth 32   32   32 true"#,
    r#"Inst.String "alt -> 3, 7""#,
    r#"Inst.String "altmatch -> 3, 7""#,
    r#"Inst.String "cap 2 -> 4""#,
    r#"Inst.String "empty 4 -> 5""#,
    r#"Inst.String "match""#,
    r#"Inst.String "fail""#,
    r#"Inst.String "nop -> 6""#,
    r#"Inst.String "rune \"az\" -> 7""#,
    r#"Inst.String "rune \"k\"/i -> 7""#,
    r#"Inst.String "rune \"\\u00e9\\n\\u4e00\" -> 7""#,
    r#"Inst.String "rune <nil>rune \"\" -> 7""#,
    r#"Inst.String "rune1 \"x\" -> 8""#,
    r#"Inst.String "any -> 9""#,
    r#"Inst.String "anynotnl -> 10""#,
    r#"Prog 0 Prefix "abc" complete=true StartCond 0"#,
    r#"Prog 0 String "  0\tfail\n  1*\trune1 \"a\" -> 2\n  2\trune1 \"b\" -> 3\n  3\trune1 \"c\" -> 4\n  4\tmatch\n""#,
    r#"Prog 1 Prefix "h" complete=true StartCond 0"#,
    r#"Prog 1 String "  0\tfail\n  1*\tcap 0 -> 2\n  2\tnop -> 3\n  3\trune1 \"h\" -> 4\n  4\tmatch\n""#,
    r#"Prog 2 Prefix "" complete=false StartCond 0"#,
    r#"Prog 2 String "  0\tfail\n  1*\trune \"a\"/i -> 2\n  2\tmatch\n""#,
    r#"Prog 3 Prefix "" complete=false StartCond 5"#,
    r#"Prog 3 String "  0\tfail\n  1*\tempty 4 -> 2\n  2\tempty 1 -> 3\n  3\trune1 \"z\" -> 4\n  4\tmatch\n""#,
    r#"Prog 4 Prefix "" complete=false StartCond 255"#,
    r#"Prog 4 String "  0\tmatch\n  1*\tfail\n""#,
    r#"Prog 5 Prefix "" complete=true StartCond 0"#,
    r#"Prog 5 String "  0*\tmatch\n""#,
    r#"Prog 6 Prefix "" complete=false StartCond 0"#,
    r#"Prog 6 String "  0*\trune \"az\" -> 1\n  1\tmatch\n""#,
];

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

/// `%-Ns` — goish's Printf has no width for %s, so the pad is explicit.
fn padl(s: string, w: int) -> string {
    let mut out = s;
    while out.Len() < w {
        out = out + string::from_static(" ");
    }
    return out;
}

/// `%Nd` — right-aligned.
fn padr(s: string, w: int) -> string {
    let mut out = s;
    while out.Len() < w {
        out = string::from_static(" ") + out;
    }
    return out;
}

fn d(v: i64, w: int) -> string {
    return padr(goish::strconv::Itoa(int::from(v)), w);
}

fn inst(op: syntax::InstOp, out: u32, arg: u32, rs: &[rune]) -> syntax::Inst {
    let mut v: Vec<rune> = Vec::new();
    v.extend_from_slice(rs);
    return syntax::Inst {
        Op: op,
        Out: out,
        Arg: arg,
        Rune: v,
    };
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    // ── InstOp.String, including out of range ───────────────────────
    for i in 0..=12u8 {
        line(
            &mut ln,
            string::from_static("InstOp.String ")
                + d(i as i64, 2)
                + string::from_static(" ")
                + goish::strconv::Quote(syntax::InstOp(i).String()),
        );
    }

    // ── IsWordChar ──────────────────────────────────────────────────
    let wc: [rune; 14] = [
        'a' as rune,
        'z' as rune,
        'A' as rune,
        'Z' as rune,
        '0' as rune,
        '9' as rune,
        '_' as rune,
        '-' as rune,
        ' ' as rune,
        '\n' as rune,
        'é' as rune,
        0x4e00,
        -1,
        0,
    ];
    for r in wc.iter() {
        line(
            &mut ln,
            string::from_static("IsWordChar ")
                + d(*r as i64, 6)
                + string::from_static(" ")
                + fmt::Sprintf!("%v", syntax::IsWordChar(*r)),
        );
    }

    // ── EmptyOpContext ──────────────────────────────────────────────
    let pairs: [(rune, rune); 15] = [
        (-1, -1),
        (-1, 'a' as rune),
        (-1, '\n' as rune),
        (-1, ' ' as rune),
        ('a' as rune, -1),
        ('a' as rune, 'b' as rune),
        ('a' as rune, ' ' as rune),
        ('a' as rune, '\n' as rune),
        (' ' as rune, 'a' as rune),
        (' ' as rune, ' ' as rune),
        ('\n' as rune, 'a' as rune),
        ('\n' as rune, '\n' as rune),
        ('\n' as rune, -1),
        ('_' as rune, '9' as rune),
        ('9' as rune, '-' as rune),
    ];
    for (a, b) in pairs.iter() {
        line(
            &mut ln,
            string::from_static("EmptyOpContext ")
                + d(*a as i64, 4)
                + string::from_static(" ")
                + d(*b as i64, 4)
                + string::from_static(" ")
                + goish::strconv::Itoa(int::from(syntax::EmptyOpContext(*a, *b).0 as i64)),
        );
    }

    // ── MatchRunePos, one row per size class ────────────────────────
    let fold = syntax::FoldCase.0 as u32;
    let cases: [(&'static str, u32, &[rune], &[rune]); 10] = [
        ("len0", 0, &[], &['a' as rune, 0]),
        ("len1", 0, &['k' as rune], &['k' as rune, 'K' as rune, 'j' as rune]),
        (
            "len1fold",
            fold,
            &['k' as rune],
            &['k' as rune, 'K' as rune, 'j' as rune, 0x212A],
        ),
        (
            "len1foldS",
            fold,
            &['s' as rune],
            &['s' as rune, 'S' as rune, 0x17F, 'x' as rune],
        ),
        (
            "len2",
            0,
            &['a' as rune, 'f' as rune],
            &['a' as rune, 'c' as rune, 'f' as rune, 'g' as rune, '`' as rune],
        ),
        (
            "len4",
            0,
            &['0' as rune, '9' as rune, 'a' as rune, 'f' as rune],
            &[
                '/' as rune,
                '0' as rune,
                '5' as rune,
                '9' as rune,
                ':' as rune,
                '`' as rune,
                'a' as rune,
                'f' as rune,
                'g' as rune,
            ],
        ),
        (
            "len6",
            0,
            &['0' as rune, '9' as rune, 'A' as rune, 'Z' as rune, 'a' as rune, 'z' as rune],
            &['0' as rune, 'M' as rune, 'q' as rune, '_' as rune, '{' as rune],
        ),
        (
            "len8",
            0,
            &[1, 2, 10, 20, 100, 200, 1000, 2000],
            &[0, 1, 2, 3, 15, 150, 1500, 2001],
        ),
        // Probe EVERY range start and end, plus one either side: the
        // binary search's `c <= r` differs from `c < r` only AT a
        // start, so a table that misses the starts lets a real search
        // bug through. Measured: with the sparser table it did.
        (
            "len12",
            0,
            &[1, 2, 10, 20, 100, 200, 1000, 2000, 5000, 6000, 9000, 9999],
            &[
                0, 1, 2, 3, 9, 10, 20, 21, 99, 100, 200, 201, 999, 1000, 2000, 2001, 4999, 5000,
                6000, 6001, 8999, 9000, 9999, 10000,
            ],
        ),
        (
            "len16",
            0,
            &[
                '0' as rune, '9' as rune, 'A' as rune, 'F' as rune, 'a' as rune, 'f' as rune,
                0x100, 0x10f, 0x300, 0x30f, 0x4e00, 0x4e0f, 0x1f600, 0x1f60f, 0x10000, 0x1000f,
            ],
            &[
                '/' as rune, '0' as rune, '9' as rune, ':' as rune, '@' as rune, 'A' as rune,
                'F' as rune, 'G' as rune, '`' as rune, 'a' as rune, 'f' as rune, 'g' as rune,
                0xff, 0x100, 0x10f, 0x110, 0x2ff, 0x300, 0x30f, 0x310, 0x4dff, 0x4e00, 0x4e0f,
                0x4e10, 0x1f5ff, 0x1f600, 0x1f60f, 0x1f610, 0xffff, 0x10000, 0x1000f, 0x10010,
            ],
        ),
    ];
    for (name, arg, rs, probes) in cases.iter() {
        let i = inst(syntax::InstRune, 0, *arg, rs);
        for r in probes.iter() {
            line(
                &mut ln,
                string::from_static("MatchRunePos ")
                    + padl(string::from_static(name), 9)
                    + string::from_static(" ")
                    + d(*r as i64, 5)
                    + string::from_static(" ")
                    + d(i64::from(i.MatchRunePos(*r)), 3)
                    + string::from_static(" ")
                    + fmt::Sprintf!("%v", i.MatchRune(*r)),
            );
        }
    }

    // ── MatchEmptyWidth ─────────────────────────────────────────────
    let ops: [syntax::EmptyOp; 6] = [
        syntax::EmptyBeginLine,
        syntax::EmptyEndLine,
        syntax::EmptyBeginText,
        syntax::EmptyEndText,
        syntax::EmptyWordBoundary,
        syntax::EmptyNoWordBoundary,
    ];
    let ewpairs: [(rune, rune); 8] = [
        (-1, 'a' as rune),
        ('a' as rune, -1),
        ('\n' as rune, 'a' as rune),
        ('a' as rune, '\n' as rune),
        ('a' as rune, 'b' as rune),
        ('a' as rune, ' ' as rune),
        (' ' as rune, 'a' as rune),
        (' ' as rune, ' ' as rune),
    ];
    for op in ops.iter() {
        let i = inst(syntax::InstEmptyWidth, 0, op.0 as u32, &[]);
        for (a, b) in ewpairs.iter() {
            line(
                &mut ln,
                string::from_static("MatchEmptyWidth ")
                    + d(op.0 as i64, 2)
                    + string::from_static(" ")
                    + d(*a as i64, 4)
                    + string::from_static(" ")
                    + d(*b as i64, 4)
                    + string::from_static(" ")
                    + fmt::Sprintf!("%v", i.MatchEmptyWidth(*a, *b)),
            );
        }
    }

    // ── Inst.String, one per opcode ─────────────────────────────────
    let insts: [syntax::Inst; 14] = [
        inst(syntax::InstAlt, 3, 7, &[]),
        inst(syntax::InstAltMatch, 3, 7, &[]),
        inst(syntax::InstCapture, 4, 2, &[]),
        inst(
            syntax::InstEmptyWidth,
            5,
            syntax::EmptyBeginText.0 as u32,
            &[],
        ),
        inst(syntax::InstMatch, 0, 0, &[]),
        inst(syntax::InstFail, 0, 0, &[]),
        inst(syntax::InstNop, 6, 0, &[]),
        inst(syntax::InstRune, 7, 0, &['a' as rune, 'z' as rune]),
        inst(syntax::InstRune, 7, fold, &['k' as rune]),
        inst(
            syntax::InstRune,
            7,
            0,
            &['é' as rune, '\n' as rune, 0x4e00],
        ),
        inst(syntax::InstRune, 7, 0, &[]),
        inst(syntax::InstRune1, 8, 0, &['x' as rune]),
        inst(syntax::InstRuneAny, 9, 0, &[]),
        inst(syntax::InstRuneAnyNotNL, 10, 0, &[]),
    ];
    for i in insts.iter() {
        line(
            &mut ln,
            string::from_static("Inst.String ") + goish::strconv::Quote(i.String()),
        );
    }

    // ── Prog.String, Prefix, StartCond ──────────────────────────────
    let progs: [syntax::Prog; 7] = [
        mk(
            1,
            alloc::vec![
                inst(syntax::InstFail, 0, 0, &[]),
                inst(syntax::InstRune1, 2, 0, &['a' as rune]),
                inst(syntax::InstRune1, 3, 0, &['b' as rune]),
                inst(syntax::InstRune1, 4, 0, &['c' as rune]),
                inst(syntax::InstMatch, 0, 0, &[]),
            ],
        ),
        mk(
            1,
            alloc::vec![
                inst(syntax::InstFail, 0, 0, &[]),
                inst(syntax::InstCapture, 2, 0, &[]),
                inst(syntax::InstNop, 3, 0, &[]),
                inst(syntax::InstRune1, 4, 0, &['h' as rune]),
                inst(syntax::InstMatch, 0, 0, &[]),
            ],
        ),
        mk(
            1,
            alloc::vec![
                inst(syntax::InstFail, 0, 0, &[]),
                inst(syntax::InstRune, 2, fold, &['a' as rune]),
                inst(syntax::InstMatch, 0, 0, &[]),
            ],
        ),
        mk(
            1,
            alloc::vec![
                inst(syntax::InstFail, 0, 0, &[]),
                inst(
                    syntax::InstEmptyWidth,
                    2,
                    syntax::EmptyBeginText.0 as u32,
                    &[]
                ),
                inst(
                    syntax::InstEmptyWidth,
                    3,
                    syntax::EmptyBeginLine.0 as u32,
                    &[]
                ),
                inst(syntax::InstRune1, 4, 0, &['z' as rune]),
                inst(syntax::InstMatch, 0, 0, &[]),
            ],
        ),
        mk(
            1,
            alloc::vec![
                inst(syntax::InstMatch, 0, 0, &[]),
                inst(syntax::InstFail, 0, 0, &[]),
            ],
        ),
        mk(0, alloc::vec![inst(syntax::InstMatch, 0, 0, &[])]),
        mk(
            0,
            alloc::vec![
                inst(syntax::InstRune, 1, 0, &['a' as rune, 'z' as rune]),
                inst(syntax::InstMatch, 0, 0, &[]),
            ],
        ),
    ];
    for (n, p) in progs.iter().enumerate() {
        let (pre, complete) = p.Prefix();
        line(
            &mut ln,
            string::from_static("Prog ")
                + goish::strconv::Itoa(int::from(n as i64))
                + string::from_static(" Prefix ")
                + goish::strconv::Quote(pre)
                + string::from_static(" complete=")
                + fmt::Sprintf!("%v", complete)
                + string::from_static(" StartCond ")
                + goish::strconv::Itoa(int::from(p.StartCond().0 as i64)),
        );
        line(
            &mut ln,
            string::from_static("Prog ")
                + goish::strconv::Itoa(int::from(n as i64))
                + string::from_static(" String ")
                + goish::strconv::Quote(p.String()),
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

fn mk(start: i64, insts: Vec<syntax::Inst>) -> syntax::Prog {
    return syntax::Prog {
        Inst: insts,
        Start: int::from(start),
        NumCap: int::from(0),
    };
}
