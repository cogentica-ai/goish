// regexp_helpers_ref_smoke — `regexp/syntax`'s error type, limits,
// stateless helpers and named-group tables. Stage 2b-ii of §2c.
//
// Everything here is what the parser is BUILT FROM but does not need
// the parser to exercise: the `Error`/`ErrorCode` pair it returns, the
// four limits it enforces, the seven pure functions it calls on nodes,
// and the `\d`/`[:alpha:]` tables it looks names up in. Stage 2b-iii is
// `Parse` and the state machine that ties them together.
//
// Five rows worth reading:
//
//   * `Error.Expr` is the REMAINDER at the point of failure, not the
//     whole pattern — `checkUTF8("a\xffb")` quotes `\xffb`.
//   * `cleanAlt` turns a class covering every rune into `OpAnyChar`
//     and one covering everything but `\n` into `OpAnyCharNotNL`, so
//     `[^\n]` and `.` become the same node. Row 7 is the near miss
//     that must NOT: `MaxRune-1` instead of `MaxRune`.
//   * `mergeCharClass` of two literals that differ only in FLAGS still
//     makes a class — `a` and `(?i)a` are not the same literal.
//   * `repeatIsValid` bounds `((a{100}){100}){100}` without ever
//     computing the product: each repeat divides the budget.
//   * `asciiFoldTable` is ASCII PLUS the long s and the Kelvin sign —
//     the two non-ASCII runes that fold into it. Without them
//     `(?i)\p{ASCII}` would fail to match a K that `(?i)K` matches.
//
// 237 rows from `scripts/goref.sh regexp/syntax
// tools/gen_regexp_helpers_ref.go`.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::regexp::syntax;
use goish::regexp::syntax::parse;
use goish::types::{int, rune};
use goish::{fmt, string, strconv};

static mut FAILED: int = 0;
static mut RUN: int = 0;

const GO: [&str; 251] = [
    r#"ErrorCode "regexp/syntax: internal error""#,
    r#"Error     "error parsing regexp: regexp/syntax: internal error: `a**`""#,
    r#"ErrorCode "invalid character class""#,
    r#"Error     "error parsing regexp: invalid character class: `a**`""#,
    r#"ErrorCode "invalid character class range""#,
    r#"Error     "error parsing regexp: invalid character class range: `a**`""#,
    r#"ErrorCode "invalid escape sequence""#,
    r#"Error     "error parsing regexp: invalid escape sequence: `a**`""#,
    r#"ErrorCode "invalid named capture""#,
    r#"Error     "error parsing regexp: invalid named capture: `a**`""#,
    r#"ErrorCode "invalid or unsupported Perl syntax""#,
    r#"Error     "error parsing regexp: invalid or unsupported Perl syntax: `a**`""#,
    r#"ErrorCode "invalid nested repetition operator""#,
    r#"Error     "error parsing regexp: invalid nested repetition operator: `a**`""#,
    r#"ErrorCode "invalid repeat count""#,
    r#"Error     "error parsing regexp: invalid repeat count: `a**`""#,
    r#"ErrorCode "invalid UTF-8""#,
    r#"Error     "error parsing regexp: invalid UTF-8: `a**`""#,
    r#"ErrorCode "missing closing ]""#,
    r#"Error     "error parsing regexp: missing closing ]: `a**`""#,
    r#"ErrorCode "missing closing )""#,
    r#"Error     "error parsing regexp: missing closing ): `a**`""#,
    r#"ErrorCode "missing argument to repetition operator""#,
    r#"Error     "error parsing regexp: missing argument to repetition operator: `a**`""#,
    r#"ErrorCode "trailing backslash at end of expression""#,
    r#"Error     "error parsing regexp: trailing backslash at end of expression: `a**`""#,
    r#"ErrorCode "unexpected )""#,
    r#"Error     "error parsing regexp: unexpected ): `a**`""#,
    r#"ErrorCode "expression nests too deeply""#,
    r#"Error     "error parsing regexp: expression nests too deeply: `a**`""#,
    r#"ErrorCode "expression too large""#,
    r#"Error     "error parsing regexp: expression too large: `a**`""#,
    r#"Error-empty "error parsing regexp: expression too large: ``""#,
    r#"maxHeight 1000"#,
    r#"maxSize   3355443"#,
    r#"instSize  40"#,
    r#"maxRunes  33554432"#,
    r#"runeSize  4"#,
    r#"isValidCaptureName ""       false"#,
    r#"isValidCaptureName "a"      true"#,
    r#"isValidCaptureName "A"      true"#,
    r#"isValidCaptureName "_"      true"#,
    r#"isValidCaptureName "0"      true"#,
    r#"isValidCaptureName "a1"     true"#,
    r#"isValidCaptureName "a_1"    true"#,
    r#"isValidCaptureName "a-b"    false"#,
    r#"isValidCaptureName "a b"    false"#,
    r#"isValidCaptureName "a."     false"#,
    r#"isValidCaptureName "é"      false"#,
    r#"isValidCaptureName "abé"    false"#,
    r#"isValidCaptureName "1"      true"#,
    r#"isValidCaptureName "__"     true"#,
    r#"isValidCaptureName "a\x00b" false"#,
    r#"isalnum    48 true"#,
    r#"isalnum    57 true"#,
    r#"isalnum    65 true"#,
    r#"isalnum    90 true"#,
    r#"isalnum    97 true"#,
    r#"isalnum   122 true"#,
    r#"isalnum    95 false"#,
    r#"isalnum    45 false"#,
    r#"isalnum    47 false"#,
    r#"isalnum    58 false"#,
    r#"isalnum    64 false"#,
    r#"isalnum    91 false"#,
    r#"isalnum    96 false"#,
    r#"isalnum   123 false"#,
    r#"isalnum   233 false"#,
    r#"isalnum    -1 false"#,
    r#"isCharClass  0 true"#,
    r#"matchRune    0    97 true"#,
    r#"matchRune    0    98 false"#,
    r#"matchRune    0   121 false"#,
    r#"matchRune    0   122 false"#,
    r#"matchRune    0    10 false"#,
    r#"matchRune    0   256 false"#,
    r#"isCharClass  1 false"#,
    r#"matchRune    1    97 false"#,
    r#"matchRune    1    98 false"#,
    r#"matchRune    1   121 false"#,
    r#"matchRune    1   122 false"#,
    r#"matchRune    1    10 false"#,
    r#"matchRune    1   256 false"#,
    r#"isCharClass  2 true"#,
    r#"matchRune    2    97 true"#,
    r#"matchRune    2    98 true"#,
    r#"matchRune    2   121 true"#,
    r#"matchRune    2   122 true"#,
    r#"matchRune    2    10 false"#,
    r#"matchRune    2   256 false"#,
    r#"isCharClass  3 true"#,
    r#"matchRune    3    97 true"#,
    r#"matchRune    3    98 true"#,
    r#"matchRune    3   121 true"#,
    r#"matchRune    3   122 true"#,
    r#"matchRune    3    10 false"#,
    r#"matchRune    3   256 false"#,
    r#"isCharClass  4 true"#,
    r#"matchRune    4    97 false"#,
    r#"matchRune    4    98 false"#,
    r#"matchRune    4   121 false"#,
    r#"matchRune    4   122 false"#,
    r#"matchRune    4    10 false"#,
    r#"matchRune    4   256 false"#,
    r#"isCharClass  5 true"#,
    r#"matchRune    5    97 true"#,
    r#"matchRune    5    98 true"#,
    r#"matchRune    5   121 true"#,
    r#"matchRune    5   122 true"#,
    r#"matchRune    5    10 true"#,
    r#"matchRune    5   256 true"#,
    r#"isCharClass  6 true"#,
    r#"matchRune    6    97 true"#,
    r#"matchRune    6    98 true"#,
    r#"matchRune    6   121 true"#,
    r#"matchRune    6   122 true"#,
    r#"matchRune    6    10 false"#,
    r#"matchRune    6   256 true"#,
    r#"isCharClass  7 false"#,
    r#"matchRune    7    97 false"#,
    r#"matchRune    7    98 false"#,
    r#"matchRune    7   121 false"#,
    r#"matchRune    7   122 false"#,
    r#"matchRune    7    10 false"#,
    r#"matchRune    7   256 false"#,
    r#"isCharClass  8 false"#,
    r#"matchRune    8    97 false"#,
    r#"matchRune    8    98 false"#,
    r#"matchRune    8   121 false"#,
    r#"matchRune    8   122 false"#,
    r#"matchRune    8    10 false"#,
    r#"matchRune    8   256 false"#,
    r#"isCharClass  9 false"#,
    r#"matchRune    9    97 false"#,
    r#"matchRune    9    98 false"#,
    r#"matchRune    9   121 false"#,
    r#"matchRune    9   122 false"#,
    r#"matchRune    9    10 false"#,
    r#"matchRune    9   256 false"#,
    r#"appendLiteral    97 0 [97 97]"#,
    r#"appendLiteral    97 1 [97 97 65 65]"#,
    r#"appendLiteral   107 1 [107 107 8490 8490 75 75]"#,
    r#"appendLiteral    75 1 [75 75 107 107 8490 8490]"#,
    r#"appendLiteral  8490 1 [8490 8490 75 75 107 107]"#,
    r#"appendLiteral    48 1 [48 48]"#,
    r#"appendLiteral    48 0 [48 48]"#,
    r#"cleanAlt  0 op=6 flags=0 rune=[]"#,
    r#"cleanAlt  1 op=5 flags=0 rune=[]"#,
    r#"cleanAlt  2 op=4 flags=0 rune=[97 122]"#,
    r#"cleanAlt  3 op=4 flags=0 rune=[97 122]"#,
    r#"cleanAlt  4 op=6 flags=0 rune=[]"#,
    r#"cleanAlt  5 op=6 flags=0 rune=[]"#,
    r#"cleanAlt  6 op=4 flags=0 rune=[]"#,
    r#"cleanAlt  7 op=4 flags=0 rune=[0 9 11 1114110]"#,
    r#"cleanAlt  8 op=4 flags=0 rune=[1 9 11 1114111]"#,
    r#"cleanAlt  9 op=6 flags=0 rune=[]"#,
    r#"cleanAlt 10 op=4 flags=0 rune=[0 9 12 1114111]"#,
    r#"cleanAlt 11 op=4 flags=0 rune=[0 8 11 1114111]"#,
    r#"cleanAlt 12 op=4 flags=0 rune=[1 1114111]"#,
    r#"cleanAlt 13 op=4 flags=0 rune=[0 1114110]"#,
    r#"cleanAlt 14 op=4 flags=0 rune=[0 9 11 100 102 1114111]"#,
    r#"cleanAlt-nonclass op=3 flags=0 rune=[122 97]"#,
    r#"mergeCharClass  0 op=6 flags=0 rune=[]"#,
    r#"mergeCharClass  1 op=5 flags=0 rune=[]"#,
    r#"mergeCharClass  2 op=6 flags=0 rune=[]"#,
    r#"mergeCharClass  3 op=6 flags=0 rune=[]"#,
    r#"mergeCharClass  4 op=4 flags=0 rune=[97 99 120 120]"#,
    r#"mergeCharClass  5 op=4 flags=0 rune=[97 99 107 107 8490 8490 75 75]"#,
    r#"mergeCharClass  6 op=4 flags=0 rune=[97 99 120 122]"#,
    r#"mergeCharClass  7 op=3 flags=0 rune=[97]"#,
    r#"mergeCharClass  8 op=4 flags=0 rune=[97 98]"#,
    r#"mergeCharClass  9 op=4 flags=0 rune=[97 97 65 65]"#,
    r#"mergeCharClass 10 op=4 flags=1 rune=[107 107 8490 8490 75 75 115 115 383 383 83 83]"#,
    r#"mergeCharClass 11 op=3 flags=1 rune=[97]"#,
    r#"mergeCharClass 12 op=4 flags=1 rune=[97 97 65 65]"#,
    r#"mergeCharClass 13 op=4 flags=0 rune=[107 107 8490 8490 75 75]"#,
    r#"mergeCharClass 14 op=4 flags=1 rune=[107 107 8490 8490 75 75 107 107]"#,
    r#"mergeCharClass 15 op=3 flags=32 rune=[122]"#,
    r#"mergeCharClass 16 op=4 flags=32 rune=[122 122]"#,
    r#"literalRegexp ""         op=3 flags=212 rune=[]"#,
    r#"literalRegexp "a"        op=3 flags=212 rune=[97]"#,
    r#"literalRegexp "abc"      op=3 flags=212 rune=[97 98 99]"#,
    r#"literalRegexp "héllo"    op=3 flags=212 rune=[104 233 108 108 111]"#,
    r#"literalRegexp "😀"        op=3 flags=212 rune=[128512]"#,
    r#"literalRegexp "xxxxx"    op=3 flags=212 rune=[120 120 120 120 120]"#,
    r#"repeatIsValid "a{2}"         1000 true"#,
    r#"repeatIsValid "a{1000}"      1000 true"#,
    r#"repeatIsValid "(a{10}){10}"  1000 true"#,
    r#"repeatIsValid "(a{10}){10}"    99 false"#,
    r#"repeatIsValid "(a{10}){10}"   100 true"#,
    r#"repeatIsValid "((a{5}){5}){5}" 1000 true"#,
    r#"repeatIsValid "((a{5}){5}){5}"  124 false"#,
    r#"repeatIsValid "a{0}"            1 true"#,
    r#"repeatIsValid "a{0,}"        1000 true"#,
    r#"repeatIsValid "a{2,}"           1 false"#,
    r#"repeatIsValid "abc"             1 true"#,
    r#"repeatIsValid "(a|b)*"          1 true"#,
    r#"checkUTF8 ""         nil"#,
    r#"checkUTF8 "abc"      nil"#,
    r#"checkUTF8 "héllo"    nil"#,
    r#"checkUTF8 "\xff"     "error parsing regexp: invalid UTF-8: `\xff`""#,
    r#"checkUTF8 "a\xffb"   "error parsing regexp: invalid UTF-8: `\xffb`""#,
    r#"checkUTF8 "\xe4\xb8" "error parsing regexp: invalid UTF-8: `\xe4\xb8`""#,
    r#"checkUTF8 "一"        nil"#,
    r#"checkUTF8 "a\x00b"   nil"#,
    r#"perlGroup "\\d" +1 [48 57]"#,
    r#"perlGroup "\\D" -1 [48 57]"#,
    r#"perlGroup "\\s" +1 [9 10 12 13 32 32]"#,
    r#"perlGroup "\\S" -1 [9 10 12 13 32 32]"#,
    r#"perlGroup "\\w" +1 [48 57 65 90 95 95 97 122]"#,
    r#"perlGroup "\\W" -1 [48 57 65 90 95 95 97 122]"#,
    r#"perlGroup "\\x" absent"#,
    r#"perlGroup "\\" absent"#,
    r#"perlGroup "d"  absent"#,
    r#"posixGroup [:alnum:]     +1 [48 57 65 90 97 122]"#,
    r#"posixGroup [:^alnum:]    -1 [48 57 65 90 97 122]"#,
    r#"posixGroup [:alpha:]     +1 [65 90 97 122]"#,
    r#"posixGroup [:^alpha:]    -1 [65 90 97 122]"#,
    r#"posixGroup [:ascii:]     +1 [0 127]"#,
    r#"posixGroup [:^ascii:]    -1 [0 127]"#,
    r#"posixGroup [:blank:]     +1 [9 9 32 32]"#,
    r#"posixGroup [:^blank:]    -1 [9 9 32 32]"#,
    r#"posixGroup [:cntrl:]     +1 [0 31 127 127]"#,
    r#"posixGroup [:^cntrl:]    -1 [0 31 127 127]"#,
    r#"posixGroup [:digit:]     +1 [48 57]"#,
    r#"posixGroup [:^digit:]    -1 [48 57]"#,
    r#"posixGroup [:graph:]     +1 [33 126]"#,
    r#"posixGroup [:^graph:]    -1 [33 126]"#,
    r#"posixGroup [:lower:]     +1 [97 122]"#,
    r#"posixGroup [:^lower:]    -1 [97 122]"#,
    r#"posixGroup [:print:]     +1 [32 126]"#,
    r#"posixGroup [:^print:]    -1 [32 126]"#,
    r#"posixGroup [:punct:]     +1 [33 47 58 64 91 96 123 126]"#,
    r#"posixGroup [:^punct:]    -1 [33 47 58 64 91 96 123 126]"#,
    r#"posixGroup [:space:]     +1 [9 13 32 32]"#,
    r#"posixGroup [:^space:]    -1 [9 13 32 32]"#,
    r#"posixGroup [:upper:]     +1 [65 90]"#,
    r#"posixGroup [:^upper:]    -1 [65 90]"#,
    r#"posixGroup [:word:]      +1 [48 57 65 90 95 95 97 122]"#,
    r#"posixGroup [:^word:]     -1 [48 57 65 90 95 95 97 122]"#,
    r#"posixGroup [:xdigit:]    +1 [48 57 65 70 97 102]"#,
    r#"posixGroup [:^xdigit:]   -1 [48 57 65 70 97 102]"#,
    r#"posixGroup [:nope:]      absent"#,
    r#"posixGroup [::]          absent"#,
    r#"posixGroup [:]           absent"#,
    r#"posixGroup alnum         absent"#,
    r#"posixGroup [:alnum]      absent"#,
    r#"anyTable       2 0"#,
    r#"asciiTable     [0 127]"#,
    r#"asciiFoldTable [0 127 383 383 8490 8490]"#,
    r#"anyTable.head  [0 1114111]"#,
];

/// One AST node, argument order as the reference's dump.
fn n(
    op: u8,
    flags: u16,
    min: i64,
    max: i64,
    cap: i64,
    name: &'static str,
    runes: &[i32],
    sub: Vec<alloc::sync::Arc<syntax::Regexp>>,
) -> alloc::sync::Arc<syntax::Regexp> {
    let mut rs: Vec<rune> = Vec::new();
    rs.extend_from_slice(runes);
    return alloc::sync::Arc::new(syntax::Regexp {
        Op: syntax::Op(op),
        Flags: syntax::Flags(flags),
        Sub: sub,
        Rune: rs,
        Min: int::from(min),
        Max: int::from(max),
        Cap: int::from(cap),
        Name: string::from_static(name),
    });
}

/// The 12 `repeatIsValid` cases: pattern, budget, and the tree Go's
/// own parser produced for it — dumped by the reference and generated
/// back, because goish has no parser until stage 2b-iii.
fn repeat_cases() -> Vec<(&'static str, i64, alloc::sync::Arc<syntax::Regexp>)> {
    return alloc::vec![
        (
            "a{2}",
            1000,
            n(17, 212, 2, 2, 0, "", &[], alloc::vec![
                n(3, 212, 0, 0, 0, "", &[97], alloc::vec![
                ]),
            ]),
        ),
        (
            "a{1000}",
            1000,
            n(17, 212, 1000, 1000, 0, "", &[], alloc::vec![
                n(3, 212, 0, 0, 0, "", &[97], alloc::vec![
                ]),
            ]),
        ),
        (
            "(a{10}){10}",
            1000,
            n(17, 212, 10, 10, 0, "", &[], alloc::vec![
                n(13, 212, 0, 0, 1, "", &[], alloc::vec![
                    n(17, 212, 10, 10, 0, "", &[], alloc::vec![
                        n(3, 212, 0, 0, 0, "", &[97], alloc::vec![
                        ]),
                    ]),
                ]),
            ]),
        ),
        (
            "(a{10}){10}",
            99,
            n(17, 212, 10, 10, 0, "", &[], alloc::vec![
                n(13, 212, 0, 0, 1, "", &[], alloc::vec![
                    n(17, 212, 10, 10, 0, "", &[], alloc::vec![
                        n(3, 212, 0, 0, 0, "", &[97], alloc::vec![
                        ]),
                    ]),
                ]),
            ]),
        ),
        (
            "(a{10}){10}",
            100,
            n(17, 212, 10, 10, 0, "", &[], alloc::vec![
                n(13, 212, 0, 0, 1, "", &[], alloc::vec![
                    n(17, 212, 10, 10, 0, "", &[], alloc::vec![
                        n(3, 212, 0, 0, 0, "", &[97], alloc::vec![
                        ]),
                    ]),
                ]),
            ]),
        ),
        (
            "((a{5}){5}){5}",
            1000,
            n(17, 212, 5, 5, 0, "", &[], alloc::vec![
                n(13, 212, 0, 0, 1, "", &[], alloc::vec![
                    n(17, 212, 5, 5, 0, "", &[], alloc::vec![
                        n(13, 212, 0, 0, 2, "", &[], alloc::vec![
                            n(17, 212, 5, 5, 0, "", &[], alloc::vec![
                                n(3, 212, 0, 0, 0, "", &[97], alloc::vec![
                                ]),
                            ]),
                        ]),
                    ]),
                ]),
            ]),
        ),
        (
            "((a{5}){5}){5}",
            124,
            n(17, 212, 5, 5, 0, "", &[], alloc::vec![
                n(13, 212, 0, 0, 1, "", &[], alloc::vec![
                    n(17, 212, 5, 5, 0, "", &[], alloc::vec![
                        n(13, 212, 0, 0, 2, "", &[], alloc::vec![
                            n(17, 212, 5, 5, 0, "", &[], alloc::vec![
                                n(3, 212, 0, 0, 0, "", &[97], alloc::vec![
                                ]),
                            ]),
                        ]),
                    ]),
                ]),
            ]),
        ),
        (
            "a{0}",
            1,
            n(17, 212, 0, 0, 0, "", &[], alloc::vec![
                n(3, 212, 0, 0, 0, "", &[97], alloc::vec![
                ]),
            ]),
        ),
        (
            "a{0,}",
            1000,
            n(17, 212, 0, -1, 0, "", &[], alloc::vec![
                n(3, 212, 0, 0, 0, "", &[97], alloc::vec![
                ]),
            ]),
        ),
        (
            "a{2,}",
            1,
            n(17, 212, 2, -1, 0, "", &[], alloc::vec![
                n(3, 212, 0, 0, 0, "", &[97], alloc::vec![
                ]),
            ]),
        ),
        (
            "abc",
            1,
            n(3, 212, 0, 0, 0, "", &[97, 98, 99], alloc::vec![
            ]),
        ),
        (
            "(a|b)*",
            1,
            n(14, 212, 0, 0, 0, "", &[], alloc::vec![
                n(13, 212, 0, 0, 1, "", &[], alloc::vec![
                    n(4, 212, 0, 0, 0, "", &[97, 98], alloc::vec![
                    ]),
                ]),
            ]),
        ),
    ];
}

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

/// `%-Ns`.
///
/// Go's fmt measures a string's width in RUNES, not bytes — "For
/// strings, byte slices and byte arrays … width is measured in runes."
/// Padding by `Len()` gets `"é"` one space short, which is how this
/// was found.
fn l(s: string, w: int) -> string {
    let mut o = s;
    while goish::len(&goish::runes(o.clone())) < w {
        o = o + string::from_static(" ");
    }
    return o;
}

/// `%Nd`
fn d(v: i64, w: int) -> string {
    let mut o = strconv::Itoa(int::from(v));
    while o.Len() < w {
        o = string::from_static(" ") + o;
    }
    return o;
}

/// `%+d`
fn pd(v: int) -> string {
    if i64::from(v) >= 0 {
        return string::from_static("+") + strconv::Itoa(v);
    }
    return strconv::Itoa(v);
}

/// The reference's `zzrs`.
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

fn rsv(r: &[rune]) -> string {
    let mut out = string::from_static("[");
    for (i, v) in r.iter().enumerate() {
        if i > 0 {
            out = out + string::from_static(" ");
        }
        out = out + strconv::Itoa(int::from(goish::int64(*v)));
    }
    return out + string::from_static("]");
}

/// The reference's `zzre`.
fn re_(re: &syntax::Regexp) -> string {
    return string::from_static("op=")
        + strconv::Itoa(int::from(goish::int64(re.Op.0)))
        + string::from_static(" flags=")
        + strconv::Itoa(int::from(goish::int64(re.Flags.0)))
        + string::from_static(" rune=")
        + rsv(&re.Rune);
}

fn node(op: syntax::Op, runes: &[rune], flags: u16) -> syntax::Regexp {
    let mut r = syntax::Regexp::__new(op);
    r.Rune = {
        let mut v: Vec<rune> = Vec::new();
        v.extend_from_slice(runes);
        v
    };
    r.Flags = syntax::Flags(flags);
    return r;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let fold = syntax::FoldCase.0;

    // ── the error type ──────────────────────────────────────────────
    let codes: [syntax::parse::ErrorCode; 16] = [
        parse::ErrInternalError,
        parse::ErrInvalidCharClass,
        parse::ErrInvalidCharRange,
        parse::ErrInvalidEscape,
        parse::ErrInvalidNamedCapture,
        parse::ErrInvalidPerlOp,
        parse::ErrInvalidRepeatOp,
        parse::ErrInvalidRepeatSize,
        parse::ErrInvalidUTF8,
        parse::ErrMissingBracket,
        parse::ErrMissingParen,
        parse::ErrMissingRepeatArgument,
        parse::ErrTrailingBackslash,
        parse::ErrUnexpectedParen,
        parse::ErrNestingDepth,
        parse::ErrLarge,
    ];
    for c in codes.iter() {
        line(
            &mut ln,
            string::from_static("ErrorCode ") + strconv::Quote(c.String()),
        );
        let e = goish::errors::Wrap(parse::Error {
            Code: c.clone(),
            Expr: string::from_static("a**"),
        });
        line(
            &mut ln,
            string::from_static("Error     ") + strconv::Quote(e.Error()),
        );
    }
    let e = goish::errors::Wrap(parse::Error {
        Code: parse::ErrLarge,
        Expr: string::new(),
    });
    line(
        &mut ln,
        string::from_static("Error-empty ") + strconv::Quote(e.Error()),
    );

    // ── the limits ──────────────────────────────────────────────────
    let (mh, ms, is_, mr, rz) = parse::__limits();
    line(&mut ln, string::from_static("maxHeight ") + strconv::Itoa(mh));
    line(
        &mut ln,
        string::from_static("maxSize   ") + strconv::Itoa(int::from(ms)),
    );
    line(
        &mut ln,
        string::from_static("instSize  ") + strconv::Itoa(int::from(is_)),
    );
    line(
        &mut ln,
        string::from_static("maxRunes  ") + strconv::Itoa(int::from(mr)),
    );
    line(
        &mut ln,
        string::from_static("runeSize  ") + strconv::Itoa(int::from(rz)),
    );

    // ── isValidCaptureName / isalnum ────────────────────────────────
    let names: [&str; 15] = [
        "", "a", "A", "_", "0", "a1", "a_1", "a-b", "a b", "a.", "é", "abé", "1", "__", "a\0b",
    ];
    for n in names.iter() {
        let s = string::from_static(n);
        line(
            &mut ln,
            string::from_static("isValidCaptureName ")
                + l(strconv::Quote(s.clone()), int::from(8))
                + string::from_static(" ")
                + fmt::Sprintf!("%v", parse::__isValidCaptureName(&s)),
        );
    }
    let alnums: [rune; 17] = [
        '0' as rune, '9' as rune, 'A' as rune, 'Z' as rune, 'a' as rune, 'z' as rune,
        '_' as rune, '-' as rune, '/' as rune, ':' as rune, '@' as rune, '[' as rune,
        '`' as rune, '{' as rune, 0xe9, -1, 0,
    ];
    for c in alnums.iter().take(16) {
        line(
            &mut ln,
            string::from_static("isalnum ")
                + d(goish::int64(*c), int::from(5))
                + string::from_static(" ")
                + fmt::Sprintf!("%v", parse::__isalnum(*c)),
        );
    }

    // ── isCharClass / matchRune ─────────────────────────────────────
    let nodes: [syntax::Regexp; 10] = [
        node(syntax::OpLiteral, &['a' as rune], 0),
        node(syntax::OpLiteral, &['a' as rune, 'b' as rune], 0),
        node(syntax::OpCharClass, &['a' as rune, 'z' as rune], 0),
        node(
            syntax::OpCharClass,
            &['a' as rune, 'c' as rune, 'x' as rune, 'z' as rune],
            0,
        ),
        node(syntax::OpCharClass, &[], 0),
        node(syntax::OpAnyChar, &[], 0),
        node(syntax::OpAnyCharNotNL, &[], 0),
        node(syntax::OpEmptyMatch, &[], 0),
        node(syntax::OpConcat, &[], 0),
        node(syntax::OpStar, &[], 0),
    ];
    let probes: [rune; 6] = [
        'a' as rune, 'b' as rune, 'y' as rune, 'z' as rune, '\n' as rune, 0x100,
    ];
    for (i, re) in nodes.iter().enumerate() {
        line(
            &mut ln,
            string::from_static("isCharClass ")
                + d(i as i64, int::from(2))
                + string::from_static(" ")
                + fmt::Sprintf!("%v", parse::__isCharClass(re)),
        );
        for r in probes.iter() {
            line(
                &mut ln,
                string::from_static("matchRune   ")
                    + d(i as i64, int::from(2))
                    + string::from_static(" ")
                    + d(goish::int64(*r), int::from(5))
                    + string::from_static(" ")
                    + fmt::Sprintf!("%v", parse::__matchRune(re, *r)),
            );
        }
    }

    // ── appendLiteral ───────────────────────────────────────────────
    let lits: [(rune, u16); 7] = [
        ('a' as rune, 0),
        ('a' as rune, fold),
        ('k' as rune, fold),
        ('K' as rune, fold),
        (0x212a, fold),
        ('0' as rune, fold),
        ('0' as rune, 0),
    ];
    for (x, fl) in lits.iter() {
        line(
            &mut ln,
            string::from_static("appendLiteral ")
                + d(goish::int64(*x), int::from(5))
                + string::from_static(" ")
                + strconv::Itoa(int::from(*fl as i64))
                + string::from_static(" ")
                + rs(&parse::__appendLiteral(&[], *x, syntax::Flags(*fl))),
        );
    }

    // ── cleanAlt ────────────────────────────────────────────────────
    let mx = goish::unicode::MaxRune;
    let alts: [&[rune]; 15] = [
        &[0, mx],
        &[0, '\n' as rune - 1, '\n' as rune + 1, mx],
        &['a' as rune, 'z' as rune],
        &['a' as rune, 'c' as rune, 'a' as rune, 'z' as rune],
        &[0, mx, 'a' as rune, 'z' as rune],
        &[0, 5, 3, mx],
        &[],
        &[0, '\n' as rune - 1, '\n' as rune + 1, mx - 1],
        &[1, '\n' as rune - 1, '\n' as rune + 1, mx],
        &[0, '\n' as rune, '\n' as rune + 1, mx],
        &[0, '\n' as rune - 1, '\n' as rune + 2, mx],
        &[0, '\n' as rune - 2, '\n' as rune + 1, mx],
        &[1, mx],
        &[0, mx - 1],
        &[0, '\n' as rune - 1, '\n' as rune + 1, 100, 102, mx],
    ];
    for (i, c) in alts.iter().enumerate() {
        let mut re = node(syntax::OpCharClass, c, 0);
        parse::__cleanAlt(&mut re);
        line(
            &mut ln,
            string::from_static("cleanAlt ")
                + d(i as i64, int::from(2))
                + string::from_static(" ")
                + re_(&re),
        );
    }
    let mut nc = node(syntax::OpLiteral, &['z' as rune, 'a' as rune], 0);
    parse::__cleanAlt(&mut nc);
    line(
        &mut ln,
        string::from_static("cleanAlt-nonclass ") + re_(&nc),
    );

    // ── mergeCharClass: all four dst arms ───────────────────────────
    let mcs: [(syntax::Regexp, syntax::Regexp); 17] = [
        (
            node(syntax::OpAnyChar, &[], 0),
            node(syntax::OpLiteral, &['a' as rune], 0),
        ),
        (
            node(syntax::OpAnyCharNotNL, &[], 0),
            node(syntax::OpLiteral, &['a' as rune], 0),
        ),
        (
            node(syntax::OpAnyCharNotNL, &[], 0),
            node(syntax::OpLiteral, &['\n' as rune], 0),
        ),
        (
            node(syntax::OpAnyCharNotNL, &[], 0),
            node(syntax::OpAnyChar, &[], 0),
        ),
        (
            node(syntax::OpCharClass, &['a' as rune, 'c' as rune], 0),
            node(syntax::OpLiteral, &['x' as rune], 0),
        ),
        (
            node(syntax::OpCharClass, &['a' as rune, 'c' as rune], 0),
            node(syntax::OpLiteral, &['k' as rune], fold),
        ),
        (
            node(syntax::OpCharClass, &['a' as rune, 'c' as rune], 0),
            node(syntax::OpCharClass, &['x' as rune, 'z' as rune], 0),
        ),
        (
            node(syntax::OpLiteral, &['a' as rune], 0),
            node(syntax::OpLiteral, &['a' as rune], 0),
        ),
        (
            node(syntax::OpLiteral, &['a' as rune], 0),
            node(syntax::OpLiteral, &['b' as rune], 0),
        ),
        (
            node(syntax::OpLiteral, &['a' as rune], 0),
            node(syntax::OpLiteral, &['a' as rune], fold),
        ),
        (
            node(syntax::OpLiteral, &['k' as rune], fold),
            node(syntax::OpLiteral, &['s' as rune], fold),
        ),
        (
            node(syntax::OpLiteral, &['a' as rune], fold),
            node(syntax::OpLiteral, &['a' as rune], fold),
        ),
        (
            node(syntax::OpLiteral, &['a' as rune], fold),
            node(syntax::OpLiteral, &['a' as rune], 0),
        ),
        (
            node(syntax::OpLiteral, &['k' as rune], 0),
            node(syntax::OpLiteral, &['k' as rune], fold),
        ),
        (
            node(syntax::OpLiteral, &['k' as rune], fold),
            node(syntax::OpLiteral, &['k' as rune], 0),
        ),
        (
            node(syntax::OpLiteral, &['z' as rune], syntax::NonGreedy.0),
            node(syntax::OpLiteral, &['z' as rune], syntax::NonGreedy.0),
        ),
        (
            node(syntax::OpLiteral, &['z' as rune], syntax::NonGreedy.0),
            node(syntax::OpLiteral, &['z' as rune], syntax::Simple.0),
        ),
    ];
    for (i, (dst, src)) in mcs.iter().enumerate() {
        let mut d0 = dst.clone();
        parse::__mergeCharClass(&mut d0, src);
        line(
            &mut ln,
            string::from_static("mergeCharClass ")
                + d(i as i64, int::from(2))
                + string::from_static(" ")
                + re_(&d0),
        );
    }

    // ── literalRegexp ───────────────────────────────────────────────
    for s in ["", "a", "abc", "héllo", "😀", "xxxxx"].iter() {
        let src = string::from_static(s);
        line(
            &mut ln,
            string::from_static("literalRegexp ")
                + l(strconv::Quote(src.clone()), int::from(10))
                + string::from_static(" ")
                + re_(&parse::__literalRegexp(&src, syntax::Perl)),
        );
    }

    // ── repeatIsValid, over hand-built trees ────────────────────────
    for (pat, n, tree) in repeat_cases().iter() {
        line(
            &mut ln,
            string::from_static("repeatIsValid ")
                + l(strconv::Quote(string::from_static(pat)), int::from(14))
                + string::from_static(" ")
                + d(*n, int::from(4))
                + string::from_static(" ")
                + fmt::Sprintf!("%v", parse::__repeatIsValid(tree, int::from(*n))),
        );
    }

    // ── checkUTF8 ───────────────────────────────────────────────────
    let utf8s: [&[u8]; 8] = [
        b"",
        b"abc",
        "héllo".as_bytes(),
        b"\xff",
        b"a\xffb",
        b"\xe4\xb8",
        b"\xe4\xb8\x80",
        b"a\x00b",
    ];
    for s in utf8s.iter() {
        let src = string::from_bytes(s);
        let e = parse::__checkUTF8(&src);
        let body = if e.IsNil() {
            string::from_static("nil")
        } else {
            strconv::Quote(e.Error())
        };
        line(
            &mut ln,
            string::from_static("checkUTF8 ")
                + l(strconv::Quote(src), int::from(10))
                + string::from_static(" ")
                + body,
        );
    }

    // ── the perl and posix groups ───────────────────────────────────
    for k in ["\\d", "\\D", "\\s", "\\S", "\\w", "\\W", "\\x", "\\", "d"].iter() {
        let key = string::from_static(k);
        let tag = string::from_static("perlGroup ")
            + l(strconv::Quote(key.clone()), int::from(4))
            + string::from_static(" ");
        match parse::__perlGroup(&key) {
            Some((sign, class)) => {
                line(&mut ln, tag + pd(sign) + string::from_static(" ") + rs(&class))
            }
            None => line(&mut ln, tag + string::from_static("absent")),
        }
    }
    let pnames: [&str; 14] = [
        "alnum", "alpha", "ascii", "blank", "cntrl", "digit", "graph", "lower", "print",
        "punct", "space", "upper", "word", "xdigit",
    ];
    for n in pnames.iter() {
        for neg in [false, true].iter() {
            let key = if *neg {
                string::from_static("[:^") + string::from_static(n) + string::from_static(":]")
            } else {
                string::from_static("[:") + string::from_static(n) + string::from_static(":]")
            };
            let (sign, class) = match parse::__posixGroup(&key) {
                Some(g) => g,
                None => (int::from(0), goish::goslice::slice::new()),
            };
            line(
                &mut ln,
                string::from_static("posixGroup ")
                    + l(key, int::from(13))
                    + string::from_static(" ")
                    + pd(sign)
                    + string::from_static(" ")
                    + rs(&class),
            );
        }
    }
    for k in ["[:nope:]", "[::]", "[:]", "alnum", "[:alnum]"].iter() {
        let key = string::from_static(k);
        let present = parse::__posixGroup(&key).is_some();
        line(
            &mut ln,
            string::from_static("posixGroup ")
                + l(key, int::from(13))
                + string::from_static(" ")
                + if present {
                    string::from_static("present")
                } else {
                    string::from_static("absent")
                },
        );
    }

    // ── the three synthetic tables ──────────────────────────────────
    let (any, ascii, asciiFold) = parse::__tables();
    line(
        &mut ln,
        string::from_static("anyTable       ")
            + strconv::Itoa(goish::len(&parse::__appendTable(&[], any)))
            + string::from_static(" ")
            + strconv::Itoa(goish::len(&parse::__appendNegatedTable(&[], any))),
    );
    line(
        &mut ln,
        string::from_static("asciiTable     ") + rs(&parse::__appendTable(&[], ascii)),
    );
    line(
        &mut ln,
        string::from_static("asciiFoldTable ") + rs(&parse::__appendTable(&[], asciiFold)),
    );
    line(
        &mut ln,
        string::from_static("anyTable.head  ") + rs(&parse::__appendTable(&[], any)),
    );

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
