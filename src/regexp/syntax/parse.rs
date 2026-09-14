// Port of Go 1.25.5 regexp/syntax/parse.go.
//
// Ported so far: the `Flags` bitset (stage 1, because an `Inst.Arg`
// holds one) and the CHARACTER-CLASS LAYER (stage 2b-i) — the range
// algebra every `[...]`, `\d`, `\pL` and case-fold goes through.
//
// The class layer comes before the parser because it is the half that
// can be tested without one: rune lists in, rune lists out, no state
// machine and no input string. `Parse` and its `parser` state machine
// are stage 2b-ii.
//
// STILL UNPORTED, and blocked rather than deferred: `unicodeTable` and
// `canonicalName`, which resolve `\p{Han}`. They read
// `unicode.Categories`, `unicode.Scripts` and their Fold twins, and
// goish's `unicode` does not have those maps — see the GOISH021 waiver
// at the top of src/unicode/letter.rs. That is a unicode-package item,
// not a regexp one.
//
// The waivers below are the checklist, in the shape root_openat.rs
// established: these are UNPORTED, not waived.
//
// goishlint:ignore GOISH018 Error, Len, Less, Parse, String, Swap, alternate, appendClass, appendFoldedClass, appendFoldedRange, appendGroup, appendLiteral, appendNegatedClass, appendNegatedTable, appendRange, appendTable, calcHeight, calcSize, canonicalName, checkHeight, checkLimits, checkSize, checkUTF8, cleanAlt, cleanClass, collapse, concat, factor, inCharClass, initCategoryAliases, isCharClass, isValidCaptureName, isalnum, leadingRegexp, leadingString, literal, literalRegexp, matchRune, maybeConcat, mergeCharClass, minFoldRune, negateClass, newRegexp, nextRune, op, parse, parseClass, parseClassChar, parseEscape, parseInt, parseNamedClass, parsePerlClassEscape, parsePerlFlags, parseRepeat, parseRightParen, parseUnicodeClass, parseVerticalBar, push, removeLeadingRegexp, removeLeadingString, repeat, repeatIsValid, reuse, swapVerticalBar, unhex, unicodeTable — incremental port (§2c stage 2); these are unported, NOT waived. Stage 1 needs only `Flags`, which `Inst.Arg` carries.
//
// goishlint:ignore GOISH021 ErrInternalError, ErrInvalidCharClass, ErrInvalidCharRange, ErrInvalidEscape, ErrInvalidNamedCapture, ErrInvalidPerlOp, ErrInvalidRepeatOp, ErrInvalidRepeatSize, ErrInvalidUTF8, ErrLarge, ErrMissingBracket, ErrMissingParen, ErrMissingRepeatArgument, ErrNestingDepth, ErrTrailingBackslash, ErrUnexpectedParen, Error, ErrorCode, anyTable, asciiFoldTable, asciiTable, categoryAliases, charGroup, instSize, maxFold, maxHeight, maxRunes, maxSize, minFold, opLeftParen, opVerticalBar, parser, ranges, runeSize — same: parse.go's error codes, its `parser` state type and its class tables arrive with the parser in §2c stage 2.

use crate::types::int;

// go: sdk 1.25.5 regexp/syntax/parse.go:56-56 Flags
/// Go: "Flags control the behavior of the parser and record
/// information about regexp context."
///
/// A `uint16` bitset in Go. It is carried in an `Inst.Arg` for
/// `InstRune`, which is why `prog.rs` needs it.
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Flags(pub u16);

// go: none — goish idiom: Go's `Flags` is a defined integer type, so
//     `|`, `&`, `|=`, `&=` and `^` come for free. A Rust newtype has
//     to spell each one out; the bodies are the operator, nothing
//     more.
impl core::ops::BitOr for Flags {
    type Output = Flags;
    // go: none — goish idiom: see the note above this impl.
    fn bitor(self, o: Flags) -> Flags {
        return Flags(self.0 | o.0);
    }
}

// go: none — goish idiom: see the note on `BitOr`.
impl core::ops::BitAnd for Flags {
    type Output = Flags;
    // go: none — goish idiom: see the note above this impl.
    fn bitand(self, o: Flags) -> Flags {
        return Flags(self.0 & o.0);
    }
}

// go: none — goish idiom: see the note on `BitOr`.
impl core::ops::BitOrAssign for Flags {
    // go: none — goish idiom: see the note above this impl.
    fn bitor_assign(&mut self, o: Flags) {
        self.0 |= o.0;
    }
}

// go: none — goish idiom: see the note on `BitOr`.
impl core::ops::BitAndAssign for Flags {
    // go: none — goish idiom: see the note above this impl.
    fn bitand_assign(&mut self, o: Flags) {
        self.0 &= o.0;
    }
}

// go: none — goish idiom: see the note on `BitOr`.
impl core::ops::Not for Flags {
    type Output = Flags;
    // go: none — goish idiom: see the note above this impl.
    fn not(self) -> Flags {
        return Flags(!self.0);
    }
}

impl Flags {
    // go: none — goish idiom: Go writes `f&FoldCase != 0`. goish's
    //     `Flags` is a newtype, so the comparison needs a name rather
    //     than repeating `.0 != 0` at every site.
    /// Whether any bit of `f` is set in this value.
    pub fn __has(self, f: Flags) -> bool {
        return (self.0 & f.0) != 0;
    }
}

// go: none — goish idiom: Go writes `Flags(i.Arg)` — a conversion
//     between defined integer types. Rust needs the `From` impls; the
//     truncation to 16 bits is Go's, since `Flags` is a `uint16` and
//     `Inst.Arg` a `uint32`.
impl From<u32> for Flags {
    // go: none — goish idiom: see the note above this impl.
    fn from(v: u32) -> Flags {
        return Flags(crate::uint16(v));
    }
}

// go: none — goish idiom: see the note on `From<u32>`.
impl From<int> for Flags {
    // go: none — goish idiom: see the note above this impl.
    fn from(v: int) -> Flags {
        return Flags(crate::uint16(crate::uint32(i64::from(v))));
    }
}

// go: sdk 1.25.5 regexp/syntax/parse.go:59 FoldCase
/// Case-insensitive match.
pub const FoldCase: Flags = Flags(1 << 0);
// go: none — goish-only placement: Go declares the nine siblings below
//     in one `iota` block with `FoldCase` (parse.go lines 31-41), so
//     they share its anchor rather than each claiming a line of it.
/// Treat pattern as literal string.
pub const Literal: Flags = Flags(1 << 1);
/// Allow character classes like `[^a-z]` and `[[:space:]]` to match newline.
pub const ClassNL: Flags = Flags(1 << 2);
/// Allow `.` to match newline.
pub const DotNL: Flags = Flags(1 << 3);
/// Treat `^` and `$` as only matching at beginning and end of text.
pub const OneLine: Flags = Flags(1 << 4);
/// Make repetition operators default to non-greedy.
pub const NonGreedy: Flags = Flags(1 << 5);
/// Allow Perl extensions.
pub const PerlX: Flags = Flags(1 << 6);
/// Allow `\p{Han}`, `\P{Han}` for Unicode group and negation.
pub const UnicodeGroups: Flags = Flags(1 << 7);
/// Regexp `OpEndText` was `$`, not `\z`.
pub const WasDollar: Flags = Flags(1 << 8);
/// Regexp contains no counted repetition.
pub const Simple: Flags = Flags(1 << 9);

// go: none — goish-only placement: parse.go line 43, in the same block.
/// `ClassNL | DotNL`.
pub const MatchNL: Flags = Flags(ClassNL.0 | DotNL.0);
// go: none — goish-only placement: parse.go line 45.
/// As close to Perl as possible.
pub const Perl: Flags = Flags(ClassNL.0 | OneLine.0 | PerlX.0 | UnicodeGroups.0);
// go: none — goish-only placement: parse.go line 46.
/// POSIX syntax.
pub const POSIX: Flags = Flags(0);

// ─── the error type (stage 2b-ii) ────────────────────────────────────

// go: sdk 1.25.5 regexp/syntax/parse.go:15-20 Error
/// Go: "An Error describes a failure to parse a regular expression and
/// gives the offending expression."
///
/// `Expr` is the REMAINDER at the point of failure, not the whole
/// pattern, which is why `Parse("a**")`'s error quotes `a**` but
/// `Parse("(?P<>a)")`'s quotes only the offending name.
#[derive(Clone, PartialEq, Debug)]
pub struct Error {
    pub Code: ErrorCode,
    pub Expr: crate::gostring::string,
}

impl crate::errors::ErrorTrait for Error {
    // go: sdk 1.25.5 regexp/syntax/parse.go:22-24 Error.Error
    fn Error(&self) -> crate::gostring::string {
        return crate::gostring::string::from_static("error parsing regexp: ")
            + self.Code.String()
            + crate::gostring::string::from_static(": `")
            + self.Expr.clone()
            + crate::gostring::string::from_static("`");
    }
}

// go: sdk 1.25.5 regexp/syntax/parse.go:26-27 ErrorCode
/// Go: "An ErrorCode describes a failure to parse a regular
/// expression." A `string` in Go, so the code IS the message.
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ErrorCode(pub &'static str);

impl ErrorCode {
    // go: sdk 1.25.5 regexp/syntax/parse.go:51-53 ErrorCode.String
    /// Go: `return string(e)` — the code and its message are the same
    /// value.
    pub fn String(&self) -> crate::gostring::string {
        return crate::gostring::string::from_static(self.0);
    }
}

// go: sdk 1.25.5 regexp/syntax/parse.go:31 ErrInternalError
/// Unexpected error.
pub const ErrInternalError: ErrorCode = ErrorCode("regexp/syntax: internal error");
// go: none — goish-only placement: Go declares the fifteen parse errors
//     below in the same const block as `ErrInternalError` (parse.go
//     lines 29-49).
/// `invalid character class`
pub const ErrInvalidCharClass: ErrorCode = ErrorCode("invalid character class");
/// `invalid character class range`
pub const ErrInvalidCharRange: ErrorCode = ErrorCode("invalid character class range");
/// `invalid escape sequence`
pub const ErrInvalidEscape: ErrorCode = ErrorCode("invalid escape sequence");
/// `invalid named capture`
pub const ErrInvalidNamedCapture: ErrorCode = ErrorCode("invalid named capture");
/// `invalid or unsupported Perl syntax`
pub const ErrInvalidPerlOp: ErrorCode = ErrorCode("invalid or unsupported Perl syntax");
/// `invalid nested repetition operator`
pub const ErrInvalidRepeatOp: ErrorCode = ErrorCode("invalid nested repetition operator");
/// `invalid repeat count`
pub const ErrInvalidRepeatSize: ErrorCode = ErrorCode("invalid repeat count");
/// `invalid UTF-8`
pub const ErrInvalidUTF8: ErrorCode = ErrorCode("invalid UTF-8");
/// `missing closing ]`
pub const ErrMissingBracket: ErrorCode = ErrorCode("missing closing ]");
/// `missing closing )`
pub const ErrMissingParen: ErrorCode = ErrorCode("missing closing )");
/// `missing argument to repetition operator`
pub const ErrMissingRepeatArgument: ErrorCode =
    ErrorCode("missing argument to repetition operator");
/// `trailing backslash at end of expression`
pub const ErrTrailingBackslash: ErrorCode =
    ErrorCode("trailing backslash at end of expression");
/// `unexpected )`
pub const ErrUnexpectedParen: ErrorCode = ErrorCode("unexpected )");
/// `expression nests too deeply`
pub const ErrNestingDepth: ErrorCode = ErrorCode("expression nests too deeply");
/// `expression too large`
pub const ErrLarge: ErrorCode = ErrorCode("expression too large");

// ─── the parser's limits ─────────────────────────────────────────────

// go: sdk 1.25.5 regexp/syntax/parse.go:94-94 maxHeight
/// Go: "the maximum height of a regexp parse tree… large enough that no
/// one will actually hit in real use but at the same time small enough
/// that recursion on the Regexp tree will not hit the 1GB Go stack
/// limit."
pub(crate) const maxHeight: crate::int = 1000;

// go: sdk 1.25.5 regexp/syntax/parse.go:102-105 maxSize
/// Go: "the maximum size of a compiled regexp in Insts… 128 MB is
/// enough for a 3.3 million Inst structures, which roughly corresponds
/// to a 3.3 MB regexp."
pub(crate) const maxSize: i64 = (128 << 20) / instSize;
// go: none — goish-only placement: parse.go line 104, same const block.
/// Go: "byte, 2 uint32, slice is 5 64-bit words".
pub(crate) const instSize: i64 = 5 * 8;

// go: sdk 1.25.5 regexp/syntax/parse.go:122-125 maxRunes
/// Go: "the maximum number of runes allowed in a regexp tree counting
/// the runes in all the nodes… each `\pL` adds 1292 runes."
///
/// Go's comment explains why a cache would not remove the problem:
/// "consider something like `[\pL01234][\pL01235][\pL01236]…`. And
/// because the Rune slice is exposed directly in the Regexp, there is
/// not an opportunity to change the representation to allow partial
/// sharing between different character classes. So the limit is the
/// best we can do."
pub(crate) const maxRunes: i64 = (128 << 20) / runeSize;
// go: none — goish-only placement: parse.go line 124, same const block.
/// Go: "rune is int32".
pub(crate) const runeSize: i64 = 4;

// ─── stateless helpers (stage 2b-ii) ─────────────────────────────────

// go: sdk 1.25.5 regexp/syntax/parse.go:1260-1270 isValidCaptureName
/// Whether `(?P<name>…)` may use this name.
///
/// Go 1.22 widened this from "must look like a Go identifier" to
/// "anything but `_` and alphanumerics is out" — note it does NOT
/// reject a leading digit, so `(?P<1>a)` parses.
pub(crate) fn isValidCaptureName(name: &crate::gostring::string) -> bool {
    if name.Len() == 0 {
        return false;
    }
    let rs = crate::runes(name.clone());
    let n = crate::len(&rs);
    let mut i: crate::int = 0;
    while i < n {
        let c = rs[i];
        if c != rune('_') && !isalnum(c) {
            return false;
        }
        i += 1;
    }
    return true;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:2212-2214 isalnum
/// ASCII alphanumeric. Not `unicode.IsLetter`: this is the capture-name
/// rule, and it is deliberately ASCII.
pub(crate) fn isalnum(c: rune) -> bool {
    return rune('0') <= c && c <= rune('9')
        || rune('A') <= c && c <= rune('Z')
        || rune('a') <= c && c <= rune('z');
}

// go: sdk 1.25.5 regexp/syntax/parse.go:1302-1308 isCharClass
/// Whether `re` matches exactly one rune from a set — the shape
/// `mergeCharClass` can fold into another.
pub(crate) fn isCharClass(re: &super::regexp::Regexp) -> bool {
    use super::regexp::*;
    return re.Op == OpLiteral && re.Rune.len() == 1
        || re.Op == OpCharClass
        || re.Op == OpAnyCharNotNL
        || re.Op == OpAnyChar;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:1310-1328 matchRune
/// Whether the single-rune `re` matches `r`.
///
/// A LINEAR scan of the class, not the binary search `Inst.MatchRunePos`
/// does: at parse time the class is not yet sorted.
pub(crate) fn matchRune(re: &super::regexp::Regexp, r: rune) -> bool {
    use super::regexp::*;
    if re.Op == OpLiteral {
        return re.Rune.len() == 1 && re.Rune[0] == r;
    }
    if re.Op == OpCharClass {
        let mut i = 0usize;
        while i < re.Rune.len() {
            if re.Rune[i] <= r && r <= re.Rune[i + 1] {
                return true;
            }
            i += 2;
        }
        return false;
    }
    if re.Op == OpAnyCharNotNL {
        return r != rune('\n');
    }
    if re.Op == OpAnyChar {
        return true;
    }
    return false;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:1970-1976 appendLiteral
/// Append one rune to a class, folded if the flags say so.
fn appendLiteral(r: Vec<rune>, x: rune, flags: Flags) -> Vec<rune> {
    if flags.__has(FoldCase) {
        return appendFoldedRange(r, x, x);
    }
    return appendRange(r, x, x);
}

// go: sdk 1.25.5 regexp/syntax/parse.go:523-547 cleanAlt
/// Normalise a character class that came out of an alternation.
///
/// The two recognitions matter for `String()` and for the compiler:
/// a class covering every rune becomes `OpAnyChar`, and one covering
/// everything but `\n` becomes `OpAnyCharNotNL`, so `[^\n]` and `.`
/// are the same node.
///
/// Go's third branch reclaims storage when `cap - len > 100` by copying
/// into `Rune0`. goish has no `Rune0` (see the note in regexp.rs) and a
/// `Vec` that over-allocated is not a leak of the same shape, so there
/// is nothing to reclaim.
pub(crate) fn cleanAlt(re: &mut super::regexp::Regexp) {
    use super::regexp::*;
    if re.Op != OpCharClass {
        return;
    }
    re.Rune = cleanClass(&mut re.Rune);
    if re.Rune.len() == 2 && re.Rune[0] == 0 && re.Rune[1] == crate::unicode::MaxRune {
        re.Rune = Vec::new();
        re.Op = OpAnyChar;
        return;
    }
    if re.Rune.len() == 4
        && re.Rune[0] == 0
        && re.Rune[1] == rune('\n') - 1
        && re.Rune[2] == rune('\n') + 1
        && re.Rune[3] == crate::unicode::MaxRune
    {
        re.Rune = Vec::new();
        re.Op = OpAnyCharNotNL;
        return;
    }
}

// go: sdk 1.25.5 regexp/syntax/parse.go:1345-1373 mergeCharClass
/// Fold `src` into `dst`, both being single-rune matchers.
///
/// The four arms are ordered by how much `dst` already matches: an
/// `OpAnyChar` absorbs anything, an `OpAnyCharNotNL` widens only if
/// `src` matches `\n`, and two literals become a class only when they
/// actually differ — `a|a` stays one literal.
pub(crate) fn mergeCharClass(
    dst: &mut super::regexp::Regexp,
    src: &super::regexp::Regexp,
) {
    use super::regexp::*;
    if dst.Op == OpAnyChar {
        // Go: "src doesn't add anything."
        return;
    }
    if dst.Op == OpAnyCharNotNL {
        // Go: "src might add \n"
        if matchRune(src, rune('\n')) {
            dst.Op = OpAnyChar;
        }
        return;
    }
    if dst.Op == OpCharClass {
        // Go: "src is simpler, so either literal or char class"
        if src.Op == OpLiteral {
            let r = core::mem::take(&mut dst.Rune);
            dst.Rune = appendLiteral(r, src.Rune[0], src.Flags);
        } else {
            let r = core::mem::take(&mut dst.Rune);
            dst.Rune = appendClass(r, &src.Rune);
        }
        return;
    }
    if dst.Op == OpLiteral {
        // Go: "both literal"
        if src.Rune[0] == dst.Rune[0] && src.Flags == dst.Flags {
            return;
        }
        dst.Op = OpCharClass;
        let (d0, df) = (dst.Rune[0], dst.Flags);
        dst.Rune = appendLiteral(Vec::new(), d0, df);
        let r = core::mem::take(&mut dst.Rune);
        dst.Rune = appendLiteral(r, src.Rune[0], src.Flags);
    }
}

// go: sdk 1.25.5 regexp/syntax/parse.go:867-885 literalRegexp
/// An `OpLiteral` node holding every rune of `s`.
///
/// Go's loop exists only to fill `Rune0` before falling back to a heap
/// slice; goish has no `Rune0`, so the decode is direct.
pub(crate) fn literalRegexp(s: &crate::gostring::string, flags: Flags) -> super::regexp::Regexp {
    let mut re = super::regexp::Regexp::__new(super::regexp::OpLiteral);
    re.Flags = flags;
    let mut v: Vec<rune> = Vec::new();
    let rs = crate::runes(s.clone());
    let n = crate::len(&rs);
    let mut i: crate::int = 0;
    while i < n {
        v.push(rs[i]);
        i += 1;
    }
    re.Rune = v;
    return re;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:452-475 repeatIsValid
/// Whether the counted repetitions in `re` multiply out to at most `n`.
///
/// Go's guard against `((a{100}){100}){100}`: each `OpRepeat` divides
/// the budget by its own count before recursing, so the product is
/// bounded without ever computing it.
pub(crate) fn repeatIsValid(re: &super::regexp::Regexp, n: crate::int) -> bool {
    use super::regexp::*;
    let mut n = n;
    if re.Op == OpRepeat {
        let mut m = re.Max;
        if m == 0 {
            return true;
        }
        if m < 0 {
            m = re.Min;
        }
        if m > n {
            return false;
        }
        if m > 0 {
            n /= m;
        }
    }
    for sub in re.Sub.iter() {
        if !repeatIsValid(sub, n) {
            return false;
        }
    }
    return true;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:2193-2202 checkUTF8
/// Refuse a pattern that is not valid UTF-8.
///
/// `Expr` on the error is the REMAINDER from the bad byte on, not the
/// whole pattern.
pub(crate) fn checkUTF8(s: &crate::gostring::string) -> crate::errors::error {
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        let (r, size) = crate::unicode::utf8::DecodeRune(&b[i..]);
        if r == crate::unicode::utf8::RuneError && i64::from(size) == 1 {
            return crate::errors::Wrap(Error {
                Code: ErrInvalidUTF8,
                Expr: crate::gostring::string::from_bytes(&b[i..]),
            });
        }
        i += i64::from(size) as usize;
    }
    return crate::errors::nil;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:1575-1578 charGroup
/// Go: `type charGroup struct { sign int; class []rune }` — one named
/// class and whether the name was the negated spelling.
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, Copy)]
pub(crate) struct charGroup {
    pub sign: crate::int,
    pub class: &'static [rune],
}

// ─── the three synthetic tables (stage 2b-ii) ────────────────────────

// go: none — goish-only: Go writes these as `&unicode.RangeTable{…}`
//     composite literals (parse.go lines 1638-1656). A Rust `static`
//     cannot hold a reference to a temporary, so each table's two
//     halves are named first.
/// `anyTable`'s 16-bit half.
static anyTableR16: [crate::unicode::Range16; 1] = [crate::unicode::Range16 {
    Lo: 0,
    Hi: 0xffff,
    Stride: 1,
}];
// go: none — goish-only: see `anyTableR16`.
/// `anyTable`'s 32-bit half.
static anyTableR32: [crate::unicode::Range32; 1] = [crate::unicode::Range32 {
    Lo: 1 << 16,
    Hi: 0x10FFFF,
    Stride: 1,
}];
// go: none — goish-only: see `anyTableR16`.
/// The 0x00-0x7F half `asciiTable` and `asciiFoldTable` share the shape
/// of.
static asciiTableR16: [crate::unicode::Range16; 1] = [crate::unicode::Range16 {
    Lo: 0,
    Hi: 0x7F,
    Stride: 1,
}];
// go: none — goish-only: see `anyTableR16`.
/// `asciiFoldTable`'s three ranges.
static asciiFoldTableR16: [crate::unicode::Range16; 3] = [
    crate::unicode::Range16 { Lo: 0, Hi: 0x7F, Stride: 1 },
    // Go: Old English long s (ſ), folds to S/s.
    crate::unicode::Range16 { Lo: 0x017F, Hi: 0x017F, Stride: 1 },
    // Go: Kelvin K, folds to K/k.
    crate::unicode::Range16 { Lo: 0x212A, Hi: 0x212A, Stride: 1 },
];
// go: none — goish-only: see `anyTableR16`.
/// The empty 32-bit half the two ASCII tables need.
static noR32: [crate::unicode::Range32; 0] = [];

// go: sdk 1.25.5 regexp/syntax/parse.go:1638-1641 anyTable
/// Every rune, as a `RangeTable` — what `\p{Any}` resolves to.
pub(crate) static anyTable: crate::unicode::RangeTable = crate::unicode::RangeTable {
    R16: &anyTableR16,
    R32: &anyTableR32,
    LatinOffset: 0,
};

// go: sdk 1.25.5 regexp/syntax/parse.go:1643-1645 asciiTable
/// `\p{ASCII}`.
pub(crate) static asciiTable: crate::unicode::RangeTable = crate::unicode::RangeTable {
    R16: &asciiTableR16,
    R32: &noR32,
    LatinOffset: 0,
};

// go: sdk 1.25.5 regexp/syntax/parse.go:1647-1655 asciiFoldTable
/// `\p{ASCII}` under `(?i)`: ASCII plus the two non-ASCII runes that
/// fold INTO it. Getting this wrong makes `(?i)\p{ASCII}` fail to match
/// a Kelvin sign that `(?i)K` does match.
pub(crate) static asciiFoldTable: crate::unicode::RangeTable = crate::unicode::RangeTable {
    R16: &asciiFoldTableR16,
    R32: &noR32,
    LatinOffset: 0,
};

// ─── the character-class layer (stage 2b-i) ──────────────────────────
//
// Everything below operates on a "class": a flat `Vec<rune>` of
// [lo, hi] pairs, sorted and non-overlapping once `cleanClass` has run.
// It is the representation `Regexp.Rune` carries for `OpCharClass`, and
// `Inst.Rune` for `InstRune`, so this is the shape a match ultimately
// binary-searches.

use alloc::vec::Vec;

use crate::rune;

// go: none — goish-only: parse.go's `minFold`, hoisted here in stage 1
//     for `calcFlags` and now in its own file.
/// The lowest rune with a non-trivial simple fold.
pub(crate) const minFold: rune = 0x0041;
// go: none — goish-only: see `minFold`.
/// The highest rune with a non-trivial simple fold.
pub(crate) const maxFold: rune = 0x1e943;

// go: sdk 1.25.5 regexp/syntax/parse.go:1978-2000 appendRange
/// Go: "Expand last range or next to last range if it overlaps or
/// abuts."
///
/// Go checks TWO ranges back, not one, and its comment says why: "this
/// helps when appending case-folded alphabets, so that one range can be
/// expanding A-Z and the other expanding a-z." Checking only the last
/// would leave `appendFoldedRange`'s brute-force loop producing a pair
/// of ranges per letter.
fn appendRange(mut r: Vec<rune>, lo: rune, hi: rune) -> Vec<rune> {
    let n = r.len();
    // Go: for i := 2; i <= 4; i += 2 — twice, using i=2 then i=4.
    let mut i = 2usize;
    while i <= 4 {
        if n >= i {
            let rlo = r[n - i];
            let rhi = r[n - i + 1];
            if lo <= rhi + 1 && rlo <= hi + 1 {
                if lo < rlo {
                    r[n - i] = lo;
                }
                if hi > rhi {
                    r[n - i + 1] = hi;
                }
                return r;
            }
        }
        i += 2;
    }
    r.push(lo);
    r.push(hi);
    return r;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:2011-2042 appendFoldedRange
/// `[lo, hi]` plus every rune case-equivalent to one of them.
///
/// The three guards before the loop are not micro-optimisation: the
/// loop is per-RUNE, so without them `appendFoldedRange(0, MaxRune)` —
/// which `.` under `(?i)` produces — would walk 1.1 million runes
/// calling `SimpleFold` on each.
fn appendFoldedRange(mut r: Vec<rune>, mut lo: rune, mut hi: rune) -> Vec<rune> {
    // Go: "Range is full: folding can't add more."
    if lo <= minFold && hi >= maxFold {
        return appendRange(r, lo, hi);
    }
    // Go: "Range is outside folding possibilities."
    if hi < minFold || lo > maxFold {
        return appendRange(r, lo, hi);
    }
    if lo < minFold {
        // Go: "[lo, minFold-1] needs no folding."
        r = appendRange(r, lo, minFold - 1);
        lo = minFold;
    }
    if hi > maxFold {
        // Go: "[maxFold+1, hi] needs no folding."
        r = appendRange(r, maxFold + 1, hi);
        hi = maxFold;
    }

    // Go: "Brute force. Depend on appendRange to coalesce ranges on the
    // fly."
    let mut c = lo;
    while c <= hi {
        r = appendRange(r, c, c);
        let mut f = crate::unicode::SimpleFold(c);
        while f != c {
            r = appendRange(r, f, f);
            f = crate::unicode::SimpleFold(f);
        }
        c += 1;
    }
    return r;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:2046-2051 appendClass
/// Append every range of `x` to `r`.
fn appendClass(mut r: Vec<rune>, x: &[rune]) -> Vec<rune> {
    let mut i = 0usize;
    while i < x.len() {
        r = appendRange(r, x[i], x[i + 1]);
        i += 2;
    }
    return r;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:2054-2059 appendFoldedClass
/// Append every range of `x`, case-folded, to `r`.
fn appendFoldedClass(mut r: Vec<rune>, x: &[rune]) -> Vec<rune> {
    let mut i = 0usize;
    while i < x.len() {
        r = appendFoldedRange(r, x[i], x[i + 1]);
        i += 2;
    }
    return r;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:2063-2076 appendNegatedClass
/// Append the GAPS of `x` — every rune it does not contain.
///
/// `x` must already be sorted and merged; this walks it once writing
/// the space before each range and then the tail.
fn appendNegatedClass(mut r: Vec<rune>, x: &[rune]) -> Vec<rune> {
    let mut nextLo: rune = 0;
    let mut i = 0usize;
    while i < x.len() {
        let lo = x[i];
        let hi = x[i + 1];
        if nextLo <= lo - 1 {
            r = appendRange(r, nextLo, lo - 1);
        }
        nextLo = hi + 1;
        i += 2;
    }
    if nextLo <= crate::unicode::MaxRune {
        r = appendRange(r, nextLo, crate::unicode::MaxRune);
    }
    return r;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:2079-2101 appendTable
/// Append a `unicode.RangeTable` — both halves, honouring `Stride`.
///
/// A stride other than 1 means the table lists every Nth rune, not a
/// contiguous run, so those expand one rune at a time. `Lu` is full of
/// stride-2 runs: upper and lower case interleaved.
fn appendTable(
    mut r: Vec<rune>,
    x: &crate::unicode::RangeTable,
) -> Vec<rune> {
    for xr in x.R16.iter() {
        let lo = crate::int32(xr.Lo);
        let hi = crate::int32(xr.Hi);
        let stride = crate::int32(xr.Stride);
        if stride == 1 {
            r = appendRange(r, lo, hi);
            continue;
        }
        let mut c = lo;
        while c <= hi {
            r = appendRange(r, c, c);
            c += stride;
        }
    }
    for xr in x.R32.iter() {
        let lo = crate::int32(xr.Lo);
        let hi = crate::int32(xr.Hi);
        let stride = crate::int32(xr.Stride);
        if stride == 1 {
            r = appendRange(r, lo, hi);
            continue;
        }
        let mut c = lo;
        while c <= hi {
            r = appendRange(r, c, c);
            c += stride;
        }
    }
    return r;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:2104-2142 appendNegatedTable
/// Append the gaps of a `RangeTable`.
///
/// Note this is NOT `appendNegatedClass(appendTable(...))`: a strided
/// run contributes a gap between each of its runes, and this walks the
/// table directly rather than materialising it first.
fn appendNegatedTable(
    mut r: Vec<rune>,
    x: &crate::unicode::RangeTable,
) -> Vec<rune> {
    // Go: lo end of next class to add.
    let mut nextLo: rune = 0;
    for xr in x.R16.iter() {
        let lo = crate::int32(xr.Lo);
        let hi = crate::int32(xr.Hi);
        let stride = crate::int32(xr.Stride);
        if stride == 1 {
            if nextLo <= lo - 1 {
                r = appendRange(r, nextLo, lo - 1);
            }
            nextLo = hi + 1;
            continue;
        }
        let mut c = lo;
        while c <= hi {
            if nextLo <= c - 1 {
                r = appendRange(r, nextLo, c - 1);
            }
            nextLo = c + 1;
            c += stride;
        }
    }
    for xr in x.R32.iter() {
        let lo = crate::int32(xr.Lo);
        let hi = crate::int32(xr.Hi);
        let stride = crate::int32(xr.Stride);
        if stride == 1 {
            if nextLo <= lo - 1 {
                r = appendRange(r, nextLo, lo - 1);
            }
            nextLo = hi + 1;
            continue;
        }
        let mut c = lo;
        while c <= hi {
            if nextLo <= c - 1 {
                r = appendRange(r, nextLo, c - 1);
            }
            nextLo = c + 1;
            c += stride;
        }
    }
    if nextLo <= crate::unicode::MaxRune {
        r = appendRange(r, nextLo, crate::unicode::MaxRune);
    }
    return r;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:2146-2165 negateClass
/// Replace `r` with its complement, IN PLACE where it fits.
///
/// Go writes back over the same slice with a write index and then
/// `append`s at most one more pair — its comment: "It's possible for
/// the negation to have one more range - this one - than the original
/// class." The in-place write is why this takes and returns the Vec
/// rather than borrowing it.
fn negateClass(mut r: Vec<rune>) -> Vec<rune> {
    // Go: lo end of next class to add.
    let mut nextLo: rune = 0;
    // Go: write index.
    let mut w = 0usize;
    let mut i = 0usize;
    while i < r.len() {
        let lo = r[i];
        let hi = r[i + 1];
        if nextLo <= lo - 1 {
            r[w] = nextLo;
            r[w + 1] = lo - 1;
            w += 2;
        }
        nextLo = hi + 1;
        i += 2;
    }
    r.truncate(w);
    if nextLo <= crate::unicode::MaxRune {
        r.push(nextLo);
        r.push(crate::unicode::MaxRune);
    }
    return r;
}

// goishlint:ignore GOISH019 p — Go's only field is `p *[]rune`, the
// slice its three `sort.Interface` methods share. goish sorts with a
// comparator that takes the slice as a parameter, so there is nothing
// for the struct to hold, and a borrowed field would need a lifetime
// on a type that exists only to name an anchor.
// go: sdk 1.25.5 regexp/syntax/parse.go:2171-2173 ranges
/// Go: `type ranges struct { p *[]rune }` — the `sort.Interface` that
/// orders a class by lo increasing, hi DECREASING.
///
/// goish sorts with a comparator instead of an interface, so the one
/// method below is the comparator; the struct exists so the anchor has
/// something to name and so `Less` is written where Go writes it.
#[allow(non_camel_case_types)] // Go name
pub(crate) struct ranges;

impl ranges {
    // go: sdk 1.25.5 regexp/syntax/parse.go:2175-2180 ranges.Less
    /// Go: "Sort by lo increasing, hi decreasing to break ties."
    ///
    /// The tie-break is reproduced because it is Go's, and NOT because
    /// it changes the answer — it does not. Measured 2026-09-13: two
    /// million random classes cleaned with and without the
    /// hi-decreasing half, zero differences. It cannot matter, because
    /// the merge below tracks a running maximum `hi`, so a tied pair
    /// extends it in whichever order the two arrive.
    ///
    /// It is worth knowing that rather than guessing, because the
    /// obvious guess — that the widest range must come first or the
    /// narrower ones survive the merge — is what this comment said
    /// until the smoke's perturbation passed and the claim was
    /// actually checked.
    fn Less(p: &[rune], i: usize, j: usize) -> bool {
        let (i, j) = (i * 2, j * 2);
        return p[i] < p[j] || (p[i] == p[j] && p[i + 1] > p[j + 1]);
    }
}

// go: sdk 1.25.5 regexp/syntax/parse.go:1923-1951 cleanClass
/// Sort a class and merge every abutting or overlapping range.
///
/// Everything downstream assumes the result: `MatchRunePos` binary
/// searches it, `appendNegatedClass` walks it once, and
/// `Regexp.String` decides a class is negated by looking at its first
/// and last runes.
fn cleanClass(rp: &mut Vec<rune>) -> Vec<rune> {
    // Go: sort.Sort(ranges{rp}) — an insertion sort over PAIRS, which
    // is what `ranges` indexes. goish's `sort` has no pair-strided
    // adapter, so the sort is written out; the comparator is Go's.
    let n = rp.len() / 2;
    let mut i = 1usize;
    while i < n {
        let mut j = i;
        while j > 0 && ranges::Less(rp, j, j - 1) {
            rp.swap(2 * j, 2 * (j - 1));
            rp.swap(2 * j + 1, 2 * (j - 1) + 1);
            j -= 1;
        }
        i += 1;
    }

    let r = rp;
    if r.len() < 2 {
        return r.clone();
    }

    // Go: "Merge abutting, overlapping."
    let mut w = 2usize; // write index
    let mut i = 2usize;
    while i < r.len() {
        let lo = r[i];
        let hi = r[i + 1];
        if lo <= r[w - 1] + 1 {
            // Go: merge with previous range.
            if hi > r[w - 1] {
                r[w - 1] = hi;
            }
            i += 2;
            continue;
        }
        // Go: new disjoint range.
        r[w] = lo;
        r[w + 1] = hi;
        w += 2;
        i += 2;
    }

    let mut out = r.clone();
    out.truncate(w);
    return out;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:1955-1967 inCharClass
/// Whether `r` falls in the range-pair list `class`.
///
/// Go binary-searches with `sort.Find`; goish's `sort` has no `Find`,
/// so the search is written out.
pub(crate) fn inCharClass(r: rune, class: &[rune]) -> bool {
    let mut lo = 0usize;
    let mut hi = class.len() / 2;
    while lo < hi {
        let m = (lo + hi) / 2;
        if r > class[2 * m + 1] {
            lo = m + 1;
        } else if r < class[2 * m] {
            hi = m;
        } else {
            return true;
        }
    }
    return false;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:380-390 minFoldRune
/// The smallest rune case-equivalent to `r`.
///
/// The parser uses it to canonicalise a folded literal, so `(?i)K` and
/// `(?i)k` and `(?i)\x{212A}` all become the same node.
fn minFoldRune(r: rune) -> rune {
    if r < minFold || r > maxFold {
        return r;
    }
    let mut m = r;
    let r0 = r;
    let mut c = crate::unicode::SimpleFold(r);
    while c != r0 {
        if c < m {
            m = c;
        }
        c = crate::unicode::SimpleFold(c);
    }
    return m;
}

// ─── test hooks ──────────────────────────────────────────────────────
//
// Every function above is unexported in Go, so Go's own tests reach
// them from an internal test file. goish's references are EXAMPLES,
// which are external, so each needs a `__`-prefixed hook. They exist
// for `regexp_class_ref_smoke` and have no other caller.
//
// The hooks speak goish's public vocabulary — `&[rune]` in, `slice<rune>`
// out — where the internals use `Vec<rune>`, which is the shape
// `Regexp.Rune` and `Inst.Rune` already carry.

// go: none — goish-only: test hook for `appendRange`.
/// See [`appendRange`].
#[doc(hidden)]
pub fn __appendRange(r: &[rune], lo: rune, hi: rune) -> crate::goslice::slice<rune> {
    return __v(appendRange(__u(r), lo, hi));
}

// go: none — goish-only: test hook for `appendFoldedRange`.
/// See [`appendFoldedRange`].
#[doc(hidden)]
pub fn __appendFoldedRange(r: &[rune], lo: rune, hi: rune) -> crate::goslice::slice<rune> {
    return __v(appendFoldedRange(__u(r), lo, hi));
}

// go: none — goish-only: test hook for `appendClass`.
/// See [`appendClass`].
#[doc(hidden)]
pub fn __appendClass(r: &[rune], x: &[rune]) -> crate::goslice::slice<rune> {
    return __v(appendClass(__u(r), x));
}

// go: none — goish-only: test hook for `appendFoldedClass`.
/// See [`appendFoldedClass`].
#[doc(hidden)]
pub fn __appendFoldedClass(r: &[rune], x: &[rune]) -> crate::goslice::slice<rune> {
    return __v(appendFoldedClass(__u(r), x));
}

// go: none — goish-only: test hook for `appendNegatedClass`.
/// See [`appendNegatedClass`].
#[doc(hidden)]
pub fn __appendNegatedClass(r: &[rune], x: &[rune]) -> crate::goslice::slice<rune> {
    return __v(appendNegatedClass(__u(r), x));
}

// go: none — goish-only: test hook for `appendTable`.
/// See [`appendTable`].
#[doc(hidden)]
pub fn __appendTable(r: &[rune], x: &crate::unicode::RangeTable) -> crate::goslice::slice<rune> {
    return __v(appendTable(__u(r), x));
}

// go: none — goish-only: test hook for `appendNegatedTable`.
/// See [`appendNegatedTable`].
#[doc(hidden)]
pub fn __appendNegatedTable(
    r: &[rune],
    x: &crate::unicode::RangeTable,
) -> crate::goslice::slice<rune> {
    return __v(appendNegatedTable(__u(r), x));
}

// go: none — goish-only: test hook for `negateClass`.
/// See [`negateClass`].
#[doc(hidden)]
pub fn __negateClass(r: &[rune]) -> crate::goslice::slice<rune> {
    return __v(negateClass(__u(r)));
}

// go: none — goish-only: test hook for `cleanClass`.
/// See [`cleanClass`].
#[doc(hidden)]
pub fn __cleanClass(r: &[rune]) -> crate::goslice::slice<rune> {
    let mut v = __u(r);
    return __v(cleanClass(&mut v));
}

// go: none — goish-only: test hook for `inCharClass`.
/// See [`inCharClass`].
#[doc(hidden)]
pub fn __inCharClass(r: rune, class: &[rune]) -> bool {
    return inCharClass(r, class);
}

// go: none — goish-only: test hook for `minFoldRune`.
/// See [`minFoldRune`].
#[doc(hidden)]
pub fn __minFoldRune(r: rune) -> rune {
    return minFoldRune(r);
}

// go: none — goish-only: the two conversions the hooks above share.
/// `&[rune]` to the owned `Vec` the internals use.
fn __u(r: &[rune]) -> Vec<rune> {
    let mut o: Vec<rune> = Vec::new();
    o.extend_from_slice(r);
    return o;
}

// go: none — goish-only: see `__u`.
/// `Vec<rune>` to the `slice<rune>` a caller outside the crate sees.
fn __v(r: Vec<rune>) -> crate::goslice::slice<rune> {
    return crate::goslice::slice::__from_vec(r);
}

// go: none — goish-only: test hook for `isValidCaptureName`.
/// See [`isValidCaptureName`].
#[doc(hidden)]
pub fn __isValidCaptureName(name: &crate::gostring::string) -> bool {
    return isValidCaptureName(name);
}

// go: none — goish-only: test hook for `isalnum`.
/// See [`isalnum`].
#[doc(hidden)]
pub fn __isalnum(c: rune) -> bool {
    return isalnum(c);
}

// go: none — goish-only: test hook for `isCharClass`.
/// See [`isCharClass`].
#[doc(hidden)]
pub fn __isCharClass(re: &super::regexp::Regexp) -> bool {
    return isCharClass(re);
}

// go: none — goish-only: test hook for `matchRune`.
/// See [`matchRune`].
#[doc(hidden)]
pub fn __matchRune(re: &super::regexp::Regexp, r: rune) -> bool {
    return matchRune(re, r);
}

// go: none — goish-only: test hook for `appendLiteral`.
/// See [`appendLiteral`].
#[doc(hidden)]
pub fn __appendLiteral(r: &[rune], x: rune, flags: Flags) -> crate::goslice::slice<rune> {
    return __v(appendLiteral(__u(r), x, flags));
}

// go: none — goish-only: test hook for `cleanAlt`.
/// See [`cleanAlt`].
#[doc(hidden)]
pub fn __cleanAlt(re: &mut super::regexp::Regexp) {
    cleanAlt(re);
}

// go: none — goish-only: test hook for `mergeCharClass`.
/// See [`mergeCharClass`].
#[doc(hidden)]
pub fn __mergeCharClass(dst: &mut super::regexp::Regexp, src: &super::regexp::Regexp) {
    mergeCharClass(dst, src);
}

// go: none — goish-only: test hook for `literalRegexp`.
/// See [`literalRegexp`].
#[doc(hidden)]
pub fn __literalRegexp(s: &crate::gostring::string, flags: Flags) -> super::regexp::Regexp {
    return literalRegexp(s, flags);
}

// go: none — goish-only: test hook for `repeatIsValid`.
/// See [`repeatIsValid`].
#[doc(hidden)]
pub fn __repeatIsValid(re: &super::regexp::Regexp, n: crate::int) -> bool {
    return repeatIsValid(re, n);
}

// go: none — goish-only: test hook for `checkUTF8`.
/// See [`checkUTF8`].
#[doc(hidden)]
pub fn __checkUTF8(s: &crate::gostring::string) -> crate::errors::error {
    return checkUTF8(s);
}

// go: none — goish-only: test hook for `perl_groups::perlGroup`.
/// The group's sign and class, or `None` if the name is not one.
#[doc(hidden)]
pub fn __perlGroup(name: &crate::gostring::string) -> Option<(crate::int, crate::goslice::slice<rune>)> {
    return super::perl_groups::perlGroup(name).map(|g| (g.sign, __v(__u(g.class))));
}

// go: none — goish-only: test hook for `perl_groups::posixGroup`.
/// See [`__perlGroup`].
#[doc(hidden)]
pub fn __posixGroup(name: &crate::gostring::string) -> Option<(crate::int, crate::goslice::slice<rune>)> {
    return super::perl_groups::posixGroup(name).map(|g| (g.sign, __v(__u(g.class))));
}

// go: none — goish-only: test hooks for the four parser limits.
/// `(maxHeight, maxSize, instSize, maxRunes, runeSize)`.
#[doc(hidden)]
pub fn __limits() -> (crate::int, i64, i64, i64, i64) {
    return (maxHeight, maxSize, instSize, maxRunes, runeSize);
}

// go: none — goish-only: test hooks for the three synthetic tables.
/// `(anyTable, asciiTable, asciiFoldTable)`.
#[doc(hidden)]
pub fn __tables() -> (
    &'static crate::unicode::RangeTable,
    &'static crate::unicode::RangeTable,
    &'static crate::unicode::RangeTable,
) {
    return (&anyTable, &asciiTable, &asciiFoldTable);
}

// ─── the parser's node arena and stack machinery (stage 2b-iii) ──────
//
// Go's parser works on `*Regexp` and leans on that being a pointer in
// three ways the port has to reproduce, not just imitate:
//
//   * It MUTATES nodes in place — `re.Op = OpLiteral`, `re.Sub[0] =
//     sub`, `re.Rune = re.Rune[:1]` — while the same node is reachable
//     from the stack and from another node's `Sub`.
//   * It keeps a FREE LIST (`p.free`, linked through `re.Sub0[0]`) and
//     recycles nodes. That is not only an allocation trick: `numRegexp`
//     counts real allocations, and `checkSize`/`checkHeight` start
//     tracking only once it passes a threshold. A port that never
//     recycles counts higher, starts tracking sooner, and can report
//     `ErrLarge` where Go does not.
//   * It keys `p.height` and `p.size` on the pointer.
//
// `Arc<Regexp>` gives none of the three. So the parser works in an
// ARENA: nodes live in a `Vec`, and a `u32` index is the pointer. Every
// Go `*Regexp` is a `pref` here, the free list is a chain of indices,
// and the two maps are keyed on the index — which is the pointer, at
// the same granularity Go's map is.
//
// The public `Regexp` tree (with its `Arc` children) is materialised
// from the arena once, at the end of `Parse`.

// go: none — goish idiom: Go's `*Regexp` inside the parser. An index
//     into `parser.node`, so a node can be mutated while others refer
//     to it and so the free list and the two maps can key on identity.
/// A node reference: an index into the parser's arena.
#[allow(non_camel_case_types)] // reads as a type, like Go's *Regexp
pub(crate) type pref = u32;

// go: none — goish idiom: Go's nil `*Regexp`. `u32::MAX` rather than 0
//     because 0 is a valid arena index.
/// The absent node.
pub(crate) const pnil: pref = u32::MAX;

// go: none — goish idiom: the arena's element — Go's `Regexp` with
//     `Sub` as indices instead of pointers, plus the free-list link Go
//     hides in `Sub0[0]`.
/// One node in the parser's arena.
#[allow(non_camel_case_types)] // internal, lower-case like Go's parser
#[derive(Clone, Default)]
pub(crate) struct pnode {
    pub Op: super::regexp::Op,
    pub Flags: Flags,
    pub Sub: Vec<pref>,
    pub Rune: Vec<rune>,
    pub Min: crate::int,
    pub Max: crate::int,
    pub Cap: crate::int,
    pub Name: crate::gostring::string,
    /// Go threads its free list through `re.Sub0[0]`; an explicit field
    /// is the same chain without pretending a subexpression slot is a
    /// pointer.
    pub free_next: pref,
}

// goishlint:ignore GOISH019 size_on, height_on, node — `size_on` and
// `height_on` are Go's `p.size == nil` / `p.height == nil` tests, which
// a goish `map` cannot answer the same way; `node` is the arena that
// stands in for Go's `*Regexp` pointers. See the note above `pref`.
// go: sdk 1.25.5 regexp/syntax/parse.go:127-139 parser
/// Go: the parse state — flags, the expression stack, the free list,
/// the counters the limits are checked against, and the two lazily
/// built maps.
///
/// `wholeRegexp` is kept for the error messages: Go slices it to quote
/// the offending fragment.
#[allow(non_camel_case_types)] // Go name
pub(crate) struct parser {
    /// Parse mode flags.
    pub flags: Flags,
    /// Stack of parsed expressions.
    pub stack: Vec<pref>,
    pub free: pref,
    /// Number of capturing groups seen.
    pub numCap: crate::int,
    pub wholeRegexp: crate::gostring::string,
    /// Temporary char class work space.
    pub tmpClass: Vec<rune>,
    /// Number of regexps allocated.
    pub numRegexp: crate::int,
    /// Number of runes in char classes.
    pub numRunes: crate::int,
    /// Product of all repetitions seen.
    pub repeats: i64,
    /// Regexp height, for the height limit check.
    pub height: crate::gomap::map<pref, crate::int>,
    /// Regexp compiled size, for the size limit check.
    pub size: crate::gomap::map<pref, i64>,
    /// Whether `size` tracking has started. Go tests `p.size == nil`;
    /// a goish `map` has a nil state but the flag reads clearer beside
    /// `height_on`.
    pub size_on: bool,
    /// Whether `height` tracking has started.
    pub height_on: bool,
    // go: none — goish idiom: the arena Go does not need.
    /// Every node ever allocated, live or freed.
    pub node: Vec<pnode>,
}

// go: none — goish idiom: Go's `panic(ErrLarge)` unwinds to a
//     `recover` in `parse`. goish's `recover!()` does not resume, so
//     the limit checks RETURN the code instead and every caller
//     propagates it. The observable behaviour is the same error; what
//     differs is that the propagation is visible.
/// The error a limit check produces, or `None` when the check passes.
pub(crate) type limitErr = Option<ErrorCode>;

impl parser {
    // go: none — goish idiom: Go zero-values a `parser` and lets the
    //     maps be nil until needed.
    /// A parser over `whole`, with `flags`.
    pub(crate) fn __new(whole: crate::gostring::string, flags: Flags) -> parser {
        return parser {
            flags,
            stack: Vec::new(),
            free: pnil,
            numCap: 0,
            wholeRegexp: whole,
            tmpClass: Vec::new(),
            numRegexp: 0,
            numRunes: 0,
            repeats: 0,
            height: crate::gomap::map::new(),
            size: crate::gomap::map::new(),
            size_on: false,
            height_on: false,
            node: Vec::new(),
        };
    }

    // go: none — goish idiom: `*re` in Go. Two accessors because Rust
    //     will not hand out a `&mut` while another borrow of the arena
    //     is live, so call sites index rather than hold.
    /// The node at `r`.
    pub(crate) fn n(&self, r: pref) -> &pnode {
        return &self.node[r as usize];
    }

    // go: none — goish idiom: see `n`.
    /// The node at `r`, mutably.
    pub(crate) fn nm(&mut self, r: pref) -> &mut pnode {
        return &mut self.node[r as usize];
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:141-152 parser.newRegexp
    /// Go: pop the free list if it has one, else allocate and bump
    /// `numRegexp`.
    ///
    /// The counter is why the free list is ported at all: it gates when
    /// `checkSize` and `checkHeight` start tracking, so a parser that
    /// never recycles rejects patterns Go accepts.
    pub(crate) fn newRegexp(&mut self, op: super::regexp::Op) -> pref {
        let re = self.free;
        if re != pnil {
            self.free = self.node[re as usize].free_next;
            self.node[re as usize] = pnode::default();
        } else {
            self.node.push(pnode::default());
            self.numRegexp += 1;
        }
        let re = if re != pnil {
            re
        } else {
            (self.node.len() - 1) as pref
        };
        self.node[re as usize].Op = op;
        self.node[re as usize].free_next = pnil;
        return re;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:154-160 parser.reuse
    /// Return a node to the free list, dropping its height entry.
    ///
    /// Go does NOT drop the size entry, only the height one. Ported as
    /// written: a stale size for a recycled index is what Go carries.
    pub(crate) fn reuse(&mut self, re: pref) {
        if self.height_on {
            self.height.Delete(re);
        }
        self.node[re as usize].free_next = self.free;
        self.free = re;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:162-168 parser.checkLimits
    /// The three limits, in Go's order: runes, then size, then height.
    pub(crate) fn checkLimits(&mut self, re: pref) -> limitErr {
        if i64::from(self.numRunes) > maxRunes {
            return Some(ErrLarge);
        }
        if let Some(e) = self.checkSize(re) {
            return Some(e);
        }
        return self.checkHeight(re);
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:170-210 parser.checkSize
    /// Go: "We haven't started tracking size yet. Do a relatively cheap
    /// check to see if we need to start. Maintain the product of all
    /// the repeats we've seen and don't track if the total number of
    /// regexp nodes we've seen times the repeat product is in budget."
    pub(crate) fn checkSize(&mut self, re: pref) -> limitErr {
        if !self.size_on {
            if self.repeats == 0 {
                self.repeats = 1;
            }
            if self.n(re).Op == super::regexp::OpRepeat {
                let mut n = self.n(re).Max;
                if n == -1 {
                    n = self.n(re).Min;
                }
                if n <= 0 {
                    n = 1;
                }
                if i64::from(n) > maxSize / self.repeats {
                    self.repeats = maxSize;
                } else {
                    self.repeats *= i64::from(n);
                }
            }
            if i64::from(self.numRegexp) < maxSize / self.repeats {
                return None;
            }

            // Go: "We need to start tracking size. Make the map and
            // belatedly populate it with info about everything we've
            // constructed so far."
            self.size_on = true;
            let stack = self.stack.clone();
            for r in stack.iter() {
                if let Some(e) = self.checkSize(*r) {
                    return Some(e);
                }
            }
        }

        if self.calcSize(re, true) > maxSize {
            return Some(ErrLarge);
        }
        return None;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:212-256 parser.calcSize
    /// The number of `Inst`s `re` would compile to, memoised.
    ///
    /// Go's `OpStar` arm is pessimistic on purpose — "star can be 1+ or
    /// 2+; assume 2" — and the `OpRepeat` arm spells out the expansion
    /// `x{2,5} = xx(x(x(x)?)?)?`, which is where the `Max-Min` term
    /// comes from.
    pub(crate) fn calcSize(&mut self, re: pref, force: bool) -> i64 {
        use super::regexp::*;
        if !force {
            let (sz, ok) = self.size.Get(re);
            if ok {
                return sz;
            }
        }

        let mut size: i64 = 0;
        let op = self.n(re).Op;
        if op == OpLiteral {
            size = crate::int64(self.n(re).Rune.len());
        } else if op == OpCapture || op == OpStar {
            // Go: star can be 1+ or 2+; assume 2 pessimistically.
            let s0 = self.n(re).Sub[0];
            size = 2 + self.calcSize(s0, false);
        } else if op == OpPlus || op == OpQuest {
            let s0 = self.n(re).Sub[0];
            size = 1 + self.calcSize(s0, false);
        } else if op == OpConcat {
            let subs = self.n(re).Sub.clone();
            for s in subs.iter() {
                size += self.calcSize(*s, false);
            }
        } else if op == OpAlternate {
            let subs = self.n(re).Sub.clone();
            for s in subs.iter() {
                size += self.calcSize(*s, false);
            }
            if subs.len() > 1 {
                size += crate::int64(subs.len()) - 1;
            }
        } else if op == OpRepeat {
            let s0 = self.n(re).Sub[0];
            let sub = self.calcSize(s0, false);
            let (mn, mx) = (self.n(re).Min, self.n(re).Max);
            if mx == -1 {
                if mn == 0 {
                    size = 2 + sub; // x*
                } else {
                    size = 1 + i64::from(mn) * sub; // xxx+
                }
            } else {
                // Go: x{2,5} = xx(x(x(x)?)?)?
                size = i64::from(mx) * sub + i64::from(mx - mn);
            }
        }

        if size < 1 {
            size = 1;
        }
        self.size.Set(re, size);
        return size;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:258-271 parser.checkHeight
    /// Go: skip entirely until `numRegexp` reaches `maxHeight`, then
    /// build the map from the whole stack at once.
    pub(crate) fn checkHeight(&mut self, re: pref) -> limitErr {
        if self.numRegexp < maxHeight {
            return None;
        }
        if !self.height_on {
            self.height_on = true;
            let stack = self.stack.clone();
            for r in stack.iter() {
                if let Some(e) = self.checkHeight(*r) {
                    return Some(e);
                }
            }
        }
        if self.calcHeight(re, true) > maxHeight {
            return Some(ErrNestingDepth);
        }
        return None;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:273-291 parser.calcHeight
    /// One plus the tallest child, memoised.
    pub(crate) fn calcHeight(&mut self, re: pref, force: bool) -> crate::int {
        if !force {
            let (h, ok) = self.height.Get(re);
            if ok {
                return h;
            }
        }
        let mut h: crate::int = 1;
        let subs = self.n(re).Sub.clone();
        for s in subs.iter() {
            let hsub = self.calcHeight(*s, false);
            if h < 1 + hsub {
                h = 1 + hsub;
            }
        }
        self.height.Set(re, h);
        return h;
    }
}

impl parser {
    // go: sdk 1.25.5 regexp/syntax/parse.go:293-328 parser.push
    /// Push `re` and return it — or `pnil` when it was folded into the
    /// node below instead.
    ///
    /// The two recognitions before the push are how a class collapses
    /// back to a literal: `[a]` is `a`, and `[Aa]` — or `[Δδ]` — is a
    /// FOLDED `a`. The second is why `(?i)a` and `[Aa]` compile the
    /// same, and its condition is exact: the two runes must be each
    /// other's whole fold orbit, so `[Kk]` qualifies but `[Kk\x{212A}]`
    /// (three runes) does not.
    pub(crate) fn push(&mut self, re: pref) -> (pref, limitErr) {
        use super::regexp::*;
        self.numRunes += self.n(re).Rune.len() as crate::int;
        let nrune = self.n(re).Rune.len();
        let op = self.n(re).Op;
        let single = op == OpCharClass && nrune == 2 && self.n(re).Rune[0] == self.n(re).Rune[1];
        let folded_pair = op == OpCharClass
            && nrune == 4
            && self.n(re).Rune[0] == self.n(re).Rune[1]
            && self.n(re).Rune[2] == self.n(re).Rune[3]
            && crate::unicode::SimpleFold(self.n(re).Rune[0]) == self.n(re).Rune[2]
            && crate::unicode::SimpleFold(self.n(re).Rune[2]) == self.n(re).Rune[0]
            || op == OpCharClass
                && nrune == 2
                && self.n(re).Rune[0] + 1 == self.n(re).Rune[1]
                && crate::unicode::SimpleFold(self.n(re).Rune[0]) == self.n(re).Rune[1]
                && crate::unicode::SimpleFold(self.n(re).Rune[1]) == self.n(re).Rune[0];

        if single {
            // Go: single rune.
            let r0 = self.n(re).Rune[0];
            let fl = Flags(self.flags.0 & !FoldCase.0);
            if self.maybeConcat(r0, fl) {
                return (pnil, None);
            }
            self.nm(re).Op = OpLiteral;
            self.nm(re).Rune.truncate(1);
            self.nm(re).Flags = fl;
        } else if folded_pair {
            // Go: case-insensitive rune like [Aa] or [Δδ].
            let r0 = self.n(re).Rune[0];
            let fl = self.flags | FoldCase;
            if self.maybeConcat(r0, fl) {
                return (pnil, None);
            }
            // Go: rewrite as (case-insensitive) literal.
            self.nm(re).Op = OpLiteral;
            self.nm(re).Rune.truncate(1);
            self.nm(re).Flags = fl;
        } else {
            // Go: incremental concatenation.
            self.maybeConcat(-1, Flags(0));
        }

        self.stack.push(re);
        let e = self.checkLimits(re);
        return (re, e);
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:330-365 parser.maybeConcat
    /// Go: "implements incremental concatenation of literal runes into
    /// string nodes. The parser calls this before each push, so only
    /// the top fragment of the stack might need processing. Since this
    /// is called before a push, the topmost literal is no longer
    /// subject to operators like `*` (Otherwise `ab*` would turn into
    /// `(ab)*`.)"
    ///
    /// Returns whether `r` was pushed — into the node it just emptied,
    /// which is the reuse that makes this incremental rather than
    /// quadratic.
    pub(crate) fn maybeConcat(&mut self, r: rune, flags: Flags) -> bool {
        use super::regexp::*;
        let n = self.stack.len();
        if n < 2 {
            return false;
        }

        let re1 = self.stack[n - 1];
        let re2 = self.stack[n - 2];
        if self.n(re1).Op != OpLiteral
            || self.n(re2).Op != OpLiteral
            || (self.n(re1).Flags & FoldCase) != (self.n(re2).Flags & FoldCase)
        {
            return false;
        }

        // Go: push re1 into re2.
        let add = self.n(re1).Rune.clone();
        self.nm(re2).Rune.extend_from_slice(&add);

        // Go: reuse re1 if possible.
        if r >= 0 {
            self.nm(re1).Rune.clear();
            self.nm(re1).Rune.push(r);
            self.nm(re1).Flags = flags;
            return true;
        }

        self.stack.truncate(n - 1);
        self.reuse(re1);
        return false; // Go: did not push r
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:367-377 parser.literal
    /// Push a literal for `r`, canonicalising the fold orbit first so
    /// `(?i)K`, `(?i)k` and `(?i)\x{212A}` all become the same node.
    pub(crate) fn literal(&mut self, r: rune) -> limitErr {
        let re = self.newRegexp(super::regexp::OpLiteral);
        self.nm(re).Flags = self.flags;
        let mut r = r;
        if self.flags.__has(FoldCase) {
            r = minFoldRune(r);
        }
        self.nm(re).Rune.push(r);
        let (_, e) = self.push(re);
        return e;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:392-397 parser.op
    /// Push a bare node of the given op.
    pub(crate) fn op(&mut self, op: super::regexp::Op) -> (pref, limitErr) {
        let re = self.newRegexp(op);
        self.nm(re).Flags = self.flags;
        return self.push(re);
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:399-441 parser.repeat
    /// Replace the top of the stack with itself repeated.
    ///
    /// Go's two refusals are both about Perl, not about the tree: a
    /// stacked operator (`a**`) is a syntax error rather than a doubled
    /// star, and a count whose product exceeds 1000 copies is refused
    /// so the compiler cannot be asked to expand it.
    pub(crate) fn repeat(
        &mut self,
        op: super::regexp::Op,
        min: crate::int,
        max: crate::int,
        before: &crate::gostring::string,
        after: &crate::gostring::string,
        lastRepeat: &crate::gostring::string,
    ) -> (crate::gostring::string, crate::errors::error) {
        use super::regexp::*;
        let mut flags = self.flags;
        let mut after = after.clone();
        if self.flags.__has(PerlX) {
            if after.Len() > 0 && after.as_bytes()[0] == b'?' {
                after = after.slice(1, after.Len());
                flags = Flags(flags.0 ^ NonGreedy.0);
            }
            if lastRepeat.Len() != 0 {
                // Go: "In Perl it is not allowed to stack repetition
                // operators: a** is a syntax error, not a doubled star,
                // and a++ means something else entirely, which we don't
                // support!"
                return (
                    crate::gostring::string::new(),
                    crate::errors::Wrap(Error {
                        Code: ErrInvalidRepeatOp,
                        Expr: lastRepeat.slice(0, lastRepeat.Len() - after.Len()),
                    }),
                );
            }
        }
        let n = self.stack.len();
        if n == 0 {
            return (
                crate::gostring::string::new(),
                crate::errors::Wrap(Error {
                    Code: ErrMissingRepeatArgument,
                    Expr: before.slice(0, before.Len() - after.Len()),
                }),
            );
        }
        let sub = self.stack[n - 1];
        if self.n(sub).Op >= opPseudo {
            return (
                crate::gostring::string::new(),
                crate::errors::Wrap(Error {
                    Code: ErrMissingRepeatArgument,
                    Expr: before.slice(0, before.Len() - after.Len()),
                }),
            );
        }

        let re = self.newRegexp(op);
        self.nm(re).Min = min;
        self.nm(re).Max = max;
        self.nm(re).Flags = flags;
        self.nm(re).Sub = alloc::vec![sub];
        self.stack[n - 1] = re;
        if let Some(code) = self.checkLimits(re) {
            return (
                crate::gostring::string::new(),
                crate::errors::Wrap(Error {
                    Code: code,
                    Expr: self.wholeRegexp.clone(),
                }),
            );
        }

        if op == OpRepeat && (min >= 2 || max >= 2) && !self.__repeatIsValid(re, 1000) {
            return (
                crate::gostring::string::new(),
                crate::errors::Wrap(Error {
                    Code: ErrInvalidRepeatSize,
                    Expr: before.slice(0, before.Len() - after.Len()),
                }),
            );
        }

        return (after, crate::errors::nil);
    }

    // go: none — goish idiom: `repeatIsValid` over an arena reference.
    //     Go's takes a `*Regexp`; the free function above takes the
    //     public tree, which the parser does not have yet.
    /// See [`repeatIsValid`].
    fn __repeatIsValid(&self, re: pref, n: crate::int) -> bool {
        use super::regexp::*;
        let mut n = n;
        if self.n(re).Op == OpRepeat {
            let mut m = self.n(re).Max;
            if m == 0 {
                return true;
            }
            if m < 0 {
                m = self.n(re).Min;
            }
            if m > n {
                return false;
            }
            if m > 0 {
                n /= m;
            }
        }
        for s in self.n(re).Sub.iter() {
            if !self.__repeatIsValid(*s, n) {
                return false;
            }
        }
        return true;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:477-495 parser.concat
    /// Collapse everything above the topmost `|` or `(` into a concat.
    pub(crate) fn concat(&mut self) -> (pref, limitErr) {
        use super::regexp::*;
        self.maybeConcat(-1, Flags(0));

        // Go: scan down to find pseudo-operator | or (.
        let mut i = self.stack.len();
        while i > 0 && self.n(self.stack[i - 1]).Op < opPseudo {
            i -= 1;
        }
        let subs: Vec<pref> = self.stack[i..].to_vec();
        self.stack.truncate(i);

        // Go: empty concatenation is special case.
        if subs.is_empty() {
            let re = self.newRegexp(OpEmptyMatch);
            return self.push(re);
        }

        let c = self.collapse(&subs, OpConcat);
        return self.push(c);
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:497-520 parser.alternate
    /// Collapse everything above the topmost `(` into an alternation.
    ///
    /// Only the TOP class is cleaned here; Go's comment says the others
    /// already are, because `swapVerticalBar` cleans each as it is
    /// buried.
    pub(crate) fn alternate(&mut self) -> (pref, limitErr) {
        use super::regexp::*;
        // Go: scan down to find pseudo-operator (. There are no | above (.
        let mut i = self.stack.len();
        while i > 0 && self.n(self.stack[i - 1]).Op < opPseudo {
            i -= 1;
        }
        let subs: Vec<pref> = self.stack[i..].to_vec();
        self.stack.truncate(i);

        // Go: make sure top class is clean.
        if !subs.is_empty() {
            let last = subs[subs.len() - 1];
            self.__cleanAlt(last);
        }

        // Go: "Empty alternate is special case (shouldn't happen but
        // easy to handle)."
        if subs.is_empty() {
            let re = self.newRegexp(OpNoMatch);
            return self.push(re);
        }

        let c = self.collapse(&subs, OpAlternate);
        return self.push(c);
    }

    // go: none — goish idiom: `cleanAlt` over an arena reference.
    /// See [`cleanAlt`].
    fn __cleanAlt(&mut self, re: pref) {
        use super::regexp::*;
        if self.n(re).Op != OpCharClass {
            return;
        }
        let mut r = core::mem::take(&mut self.nm(re).Rune);
        r = cleanClass(&mut r);
        if r.len() == 2 && r[0] == 0 && r[1] == crate::unicode::MaxRune {
            self.nm(re).Rune = Vec::new();
            self.nm(re).Op = OpAnyChar;
            return;
        }
        if r.len() == 4
            && r[0] == 0
            && r[1] == rune('\n') - 1
            && r[2] == rune('\n') + 1
            && r[3] == crate::unicode::MaxRune
        {
            self.nm(re).Rune = Vec::new();
            self.nm(re).Op = OpAnyCharNotNL;
            return;
        }
        self.nm(re).Rune = r;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:549-587 parser.collapse
    /// Go: "returns the result of applying op to sub. If sub contains
    /// op nodes, they all get hoisted up so that there is never a
    /// concat of a concat or an alternate of an alternate."
    pub(crate) fn collapse(&mut self, subs: &[pref], op: super::regexp::Op) -> pref {
        use super::regexp::*;
        if subs.len() == 1 {
            return subs[0];
        }
        let re = self.newRegexp(op);
        let mut acc: Vec<pref> = Vec::new();
        for sub in subs.iter() {
            if self.n(*sub).Op == op {
                let inner = self.n(*sub).Sub.clone();
                acc.extend_from_slice(&inner);
                self.reuse(*sub);
            } else {
                acc.push(*sub);
            }
        }
        self.nm(re).Sub = acc;
        if op == OpAlternate {
            let s = self.n(re).Sub.clone();
            let f = self.factor(s);
            self.nm(re).Sub = f;
            if self.n(re).Sub.len() == 1 {
                let old = re;
                let only = self.n(re).Sub[0];
                self.reuse(old);
                return only;
            }
        }
        return re;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:589-776 parser.factor
    /// Go: "factors common prefixes from the alternation list sub."
    ///
    /// Go's own worked example, kept because nothing else explains the
    /// four rounds as well:
    ///
    /// ```text
    ///   ABC|ABD|AEF|BCX|BCY
    /// simplifies by literal prefix extraction to
    ///   A(B(C|D)|EF)|BC(X|Y)
    /// which simplifies by character class introduction to
    ///   A(B[CD]|EF)|BC[XY]
    /// ```
    ///
    /// Round 2's restriction is a correctness rule, not an
    /// optimisation: "Complex subexpressions (e.g. involving
    /// quantifiers) are not safe to factor because that collapses
    /// their distinct paths through the automaton."
    fn factor(&mut self, sub: Vec<pref>) -> Vec<pref> {
        use super::regexp::*;
        if sub.len() < 2 {
            return sub;
        }
        let mut sub = sub;

        // ── Round 1: factor out common literal prefixes ─────────────
        let mut str_: Vec<rune> = Vec::new();
        let mut strflags = Flags(0);
        let mut start = 0usize;
        let mut out: Vec<pref> = Vec::new();
        for i in 0..=sub.len() {
            // Go's invariant: sub[start:i] consists of regexps that all
            // begin with str as modified by strflags.
            let mut istr: Vec<rune> = Vec::new();
            let mut iflags = Flags(0);
            if i < sub.len() {
                let (a, b) = self.leadingString(sub[i]);
                istr = a;
                iflags = b;
                if iflags == strflags {
                    let mut same = 0usize;
                    while same < str_.len() && same < istr.len() && str_[same] == istr[same] {
                        same += 1;
                    }
                    if same > 0 {
                        // Go: "Matches at least one rune in current
                        // range. Keep going around."
                        str_.truncate(same);
                        continue;
                    }
                }
            }

            if i == start {
                // Go: nothing to do - run of length 0.
            } else if i == start + 1 {
                // Go: just one: don't bother factoring.
                out.push(sub[start]);
            } else {
                // Go: construct factored form: prefix(suffix1|suffix2|...)
                let prefix = self.newRegexp(OpLiteral);
                self.nm(prefix).Flags = strflags;
                self.nm(prefix).Rune = str_.clone();

                for j in start..i {
                    let nn = str_.len() as crate::int;
                    sub[j] = self.removeLeadingString(sub[j], nn);
                    let _ = self.checkLimits(sub[j]);
                }
                let run: Vec<pref> = sub[start..i].to_vec();
                let suffix = self.collapse(&run, OpAlternate); // Go: recurse

                let re = self.newRegexp(OpConcat);
                self.nm(re).Sub = alloc::vec![prefix, suffix];
                out.push(re);
            }

            start = i;
            str_ = istr;
            strflags = iflags;
        }
        sub = out;

        // ── Round 2: factor out common simple prefixes ──────────────
        start = 0;
        out = Vec::new();
        let mut first: pref = pnil;
        for i in 0..=sub.len() {
            let mut ifirst: pref = pnil;
            if i < sub.len() {
                ifirst = self.leadingRegexp(sub[i]);
                if first != pnil
                    && ifirst != pnil
                    && self.__equal(first, ifirst)
                    // Go: "first must be a character class OR a fixed
                    // repeat of a character class."
                    && (self.__isCharClass(first)
                        || (self.n(first).Op == OpRepeat
                            && self.n(first).Min == self.n(first).Max
                            && self.__isCharClass(self.n(first).Sub[0])))
                {
                    continue;
                }
            }

            if i == start {
                // Go: nothing to do.
            } else if i == start + 1 {
                out.push(sub[start]);
            } else {
                let prefix = first;
                for j in start..i {
                    // Go: prefix came from sub[start].
                    let reuse = j != start;
                    sub[j] = self.removeLeadingRegexp(sub[j], reuse);
                    let _ = self.checkLimits(sub[j]);
                }
                let run: Vec<pref> = sub[start..i].to_vec();
                let suffix = self.collapse(&run, OpAlternate); // Go: recurse

                let re = self.newRegexp(OpConcat);
                self.nm(re).Sub = alloc::vec![prefix, suffix];
                out.push(re);
            }

            start = i;
            first = ifirst;
        }
        sub = out;

        // ── Round 3: collapse runs of single literals into classes ──
        start = 0;
        out = Vec::new();
        for i in 0..=sub.len() {
            if i < sub.len() && self.__isCharClass(sub[i]) {
                continue;
            }

            if i == start {
                // Go: nothing to do.
            } else if i == start + 1 {
                out.push(sub[start]);
            } else {
                // Go: "Make new char class. Start with most complex
                // regexp in sub[start]."
                let mut mx = start;
                for j in (start + 1)..i {
                    if self.n(sub[mx]).Op < self.n(sub[j]).Op
                        || self.n(sub[mx]).Op == self.n(sub[j]).Op
                            && self.n(sub[mx]).Rune.len() < self.n(sub[j]).Rune.len()
                    {
                        mx = j;
                    }
                }
                sub.swap(start, mx);

                for j in (start + 1)..i {
                    self.__mergeCharClass(sub[start], sub[j]);
                    self.reuse(sub[j]);
                }
                self.__cleanAlt(sub[start]);
                out.push(sub[start]);
            }

            // Go: ... and then emit sub[i].
            if i < sub.len() {
                out.push(sub[i]);
            }
            start = i + 1;
        }
        sub = out;

        // ── Round 4: collapse runs of empty matches ─────────────────
        out = Vec::new();
        for i in 0..sub.len() {
            if i + 1 < sub.len()
                && self.n(sub[i]).Op == OpEmptyMatch
                && self.n(sub[i + 1]).Op == OpEmptyMatch
            {
                continue;
            }
            out.push(sub[i]);
        }
        sub = out;

        return sub;
    }

    // go: none — goish idiom: `isCharClass` over an arena reference.
    /// See [`isCharClass`].
    fn __isCharClass(&self, re: pref) -> bool {
        use super::regexp::*;
        let op = self.n(re).Op;
        return op == OpLiteral && self.n(re).Rune.len() == 1
            || op == OpCharClass
            || op == OpAnyCharNotNL
            || op == OpAnyChar;
    }

    // go: none — goish idiom: `Regexp.Equal` over two arena references.
    /// See [`super::regexp::Regexp::Equal`].
    fn __equal(&self, x: pref, y: pref) -> bool {
        use super::regexp::*;
        if self.n(x).Op != self.n(y).Op {
            return false;
        }
        let op = self.n(x).Op;
        if op == OpEndText {
            return (self.n(x).Flags & WasDollar) == (self.n(y).Flags & WasDollar);
        }
        if op == OpLiteral || op == OpCharClass {
            return self.n(x).Rune == self.n(y).Rune;
        }
        if op == OpAlternate || op == OpConcat {
            if self.n(x).Sub.len() != self.n(y).Sub.len() {
                return false;
            }
            for i in 0..self.n(x).Sub.len() {
                let (a, b) = (self.n(x).Sub[i], self.n(y).Sub[i]);
                if !self.__equal(a, b) {
                    return false;
                }
            }
            return true;
        }
        if op == OpStar || op == OpPlus || op == OpQuest {
            return (self.n(x).Flags & NonGreedy) == (self.n(y).Flags & NonGreedy)
                && self.__equal(self.n(x).Sub[0], self.n(y).Sub[0]);
        }
        if op == OpRepeat {
            return (self.n(x).Flags & NonGreedy) == (self.n(y).Flags & NonGreedy)
                && self.n(x).Min == self.n(y).Min
                && self.n(x).Max == self.n(y).Max
                && self.__equal(self.n(x).Sub[0], self.n(y).Sub[0]);
        }
        if op == OpCapture {
            return self.n(x).Cap == self.n(y).Cap
                && self.n(x).Name == self.n(y).Name
                && self.__equal(self.n(x).Sub[0], self.n(y).Sub[0]);
        }
        return true;
    }

    // go: none — goish idiom: `mergeCharClass` over arena references.
    /// See [`mergeCharClass`].
    fn __mergeCharClass(&mut self, dst: pref, src: pref) {
        use super::regexp::*;
        let dop = self.n(dst).Op;
        if dop == OpAnyChar {
            return;
        }
        if dop == OpAnyCharNotNL {
            if self.__matchRune(src, rune('\n')) {
                self.nm(dst).Op = OpAnyChar;
            }
            return;
        }
        if dop == OpCharClass {
            let r = core::mem::take(&mut self.nm(dst).Rune);
            if self.n(src).Op == OpLiteral {
                let (s0, sf) = (self.n(src).Rune[0], self.n(src).Flags);
                self.nm(dst).Rune = appendLiteral(r, s0, sf);
            } else {
                let sr = self.n(src).Rune.clone();
                self.nm(dst).Rune = appendClass(r, &sr);
            }
            return;
        }
        if dop == OpLiteral {
            if self.n(src).Rune[0] == self.n(dst).Rune[0]
                && self.n(src).Flags == self.n(dst).Flags
            {
                return;
            }
            self.nm(dst).Op = OpCharClass;
            let (d0, df) = (self.n(dst).Rune[0], self.n(dst).Flags);
            let mut r = appendLiteral(Vec::new(), d0, df);
            let (s0, sf) = (self.n(src).Rune[0], self.n(src).Flags);
            r = appendLiteral(r, s0, sf);
            self.nm(dst).Rune = r;
        }
    }

    // go: none — goish idiom: `matchRune` over an arena reference.
    /// See [`matchRune`].
    fn __matchRune(&self, re: pref, r: rune) -> bool {
        use super::regexp::*;
        let op = self.n(re).Op;
        if op == OpLiteral {
            return self.n(re).Rune.len() == 1 && self.n(re).Rune[0] == r;
        }
        if op == OpCharClass {
            let mut i = 0usize;
            while i < self.n(re).Rune.len() {
                if self.n(re).Rune[i] <= r && r <= self.n(re).Rune[i + 1] {
                    return true;
                }
                i += 2;
            }
            return false;
        }
        if op == OpAnyCharNotNL {
            return r != rune('\n');
        }
        if op == OpAnyChar {
            return true;
        }
        return false;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:778-786 parser.leadingString
    /// The literal run `re` begins with, and whether it is folded.
    pub(crate) fn leadingString(&self, re: pref) -> (Vec<rune>, Flags) {
        use super::regexp::*;
        let mut re = re;
        if self.n(re).Op == OpConcat && !self.n(re).Sub.is_empty() {
            re = self.n(re).Sub[0];
        }
        if self.n(re).Op != OpLiteral {
            return (Vec::new(), Flags(0));
        }
        return (self.n(re).Rune.clone(), self.n(re).Flags & FoldCase);
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:788-822 parser.removeLeadingString
    /// Drop the first `n` runes, returning the replacement for `re`.
    ///
    /// The concat arm is where the simplification happens: once the
    /// leading literal is empty the concat loses a child, and a
    /// two-child concat becomes its survivor.
    pub(crate) fn removeLeadingString(&mut self, re: pref, n: crate::int) -> pref {
        use super::regexp::*;
        let mut re = re;
        if self.n(re).Op == OpConcat && !self.n(re).Sub.is_empty() {
            // Go: "Removing a leading string in a concatenation might
            // simplify the concatenation."
            let mut sub = self.n(re).Sub[0];
            sub = self.removeLeadingString(sub, n);
            self.nm(re).Sub[0] = sub;
            if self.n(sub).Op == OpEmptyMatch {
                self.reuse(sub);
                let l = self.n(re).Sub.len();
                if l <= 1 {
                    // Go: "Impossible but handle."
                    self.nm(re).Op = OpEmptyMatch;
                    self.nm(re).Sub = Vec::new();
                } else if l == 2 {
                    let old = re;
                    re = self.n(re).Sub[1];
                    self.reuse(old);
                } else {
                    self.nm(re).Sub.remove(0);
                }
            }
            return re;
        }

        if self.n(re).Op == OpLiteral {
            let n = n as usize;
            let keep: Vec<rune> = self.n(re).Rune[n..].to_vec();
            self.nm(re).Rune = keep;
            if self.n(re).Rune.is_empty() {
                self.nm(re).Op = OpEmptyMatch;
            }
        }
        return re;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:827-839 parser.leadingRegexp
    /// The node `re` begins with, or `pnil` when it begins with an
    /// empty match.
    pub(crate) fn leadingRegexp(&self, re: pref) -> pref {
        use super::regexp::*;
        if self.n(re).Op == OpEmptyMatch {
            return pnil;
        }
        if self.n(re).Op == OpConcat && !self.n(re).Sub.is_empty() {
            let sub = self.n(re).Sub[0];
            if self.n(sub).Op == OpEmptyMatch {
                return pnil;
            }
            return sub;
        }
        return re;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:844-865 parser.removeLeadingRegexp
    /// Drop the leading node, returning the replacement for `re`.
    ///
    /// `reuse` is false for the run's first element, because that one's
    /// leading node BECAME the shared prefix and is still live.
    pub(crate) fn removeLeadingRegexp(&mut self, re: pref, reuse: bool) -> pref {
        use super::regexp::*;
        let mut re = re;
        if self.n(re).Op == OpConcat && !self.n(re).Sub.is_empty() {
            if reuse {
                let s0 = self.n(re).Sub[0];
                self.reuse(s0);
            }
            self.nm(re).Sub.remove(0);
            let l = self.n(re).Sub.len();
            if l == 0 {
                self.nm(re).Op = OpEmptyMatch;
                self.nm(re).Sub = Vec::new();
            } else if l == 1 {
                let old = re;
                re = self.n(re).Sub[0];
                self.reuse(old);
            }
            return re;
        }
        if reuse {
            self.reuse(re);
        }
        return self.newRegexp(OpEmptyMatch);
    }
}

impl parser {
    // go: sdk 1.25.5 regexp/syntax/parse.go:1330-1343 parser.parseVerticalBar
    /// Go: "The concatenation we just parsed is on top of the stack.
    /// If it sits above an opVerticalBar, swap it below (things below
    /// an opVerticalBar become an alternation). Otherwise, push a new
    /// vertical bar."
    ///
    /// This is why `alternate` can say "There are no | above (": the
    /// marker is kept BELOW the alternatives, one marker for the whole
    /// group rather than one per `|`.
    pub(crate) fn parseVerticalBar(&mut self) -> limitErr {
        let (_, e) = self.concat();
        if e.is_some() {
            return e;
        }
        if !self.swapVerticalBar() {
            let (_, e) = self.op(opVerticalBar);
            return e;
        }
        return None;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:1375-1409 parser.swapVerticalBar
    /// Move the just-parsed alternative below the `|` marker, merging
    /// it into the previous one when both are single-rune matchers.
    ///
    /// The merge is where `a|b|c` becomes `[abc]` incrementally rather
    /// than waiting for `factor`'s round 3, and the `re1.Op > re3.Op`
    /// swap keeps the MORE COMPLEX node as the destination so a literal
    /// is merged into a class and not the other way round.
    ///
    /// The `cleanAlt` call is Go's "Now out of reach. Clean
    /// opportunistically." — the node two below can never be touched
    /// again, so this is the last chance to normalise it. That is what
    /// lets `alternate` clean only the top one.
    pub(crate) fn swapVerticalBar(&mut self) -> bool {
        let n = self.stack.len();
        if n >= 3
            && self.n(self.stack[n - 2]).Op == opVerticalBar
            && self.__isCharClass(self.stack[n - 1])
            && self.__isCharClass(self.stack[n - 3])
        {
            let mut re1 = self.stack[n - 1];
            let mut re3 = self.stack[n - 3];
            // Go: make re3 the more complex of the two.
            if self.n(re1).Op > self.n(re3).Op {
                core::mem::swap(&mut re1, &mut re3);
                self.stack[n - 3] = re3;
            }
            self.__mergeCharClass(re3, re1);
            self.reuse(re1);
            self.stack.truncate(n - 1);
            return true;
        }

        if n >= 2 {
            let re1 = self.stack[n - 1];
            let re2 = self.stack[n - 2];
            if self.n(re2).Op == opVerticalBar {
                if n >= 3 {
                    // Go: "Now out of reach. Clean opportunistically."
                    let r = self.stack[n - 3];
                    self.__cleanAlt(r);
                }
                self.stack[n - 2] = re1;
                self.stack[n - 1] = re2;
                return true;
            }
        }
        return false;
    }
}

// go: sdk 1.25.5 regexp/syntax/parse.go:77-80 opLeftParen
/// Go: "Pseudo-ops for parsing stack." They sit at and above
/// `opPseudo`, which is what `concat` and `alternate` scan down to and
/// what `repeat` refuses to quantify.
pub(crate) const opLeftParen: super::regexp::Op = super::regexp::Op(128);
// go: none — goish-only placement: parse.go line 79, same iota block.
/// The `|` marker.
pub(crate) const opVerticalBar: super::regexp::Op = super::regexp::Op(129);

// ─── the text sub-parsers (stage 2b-iv) ──────────────────────────────

// go: sdk 1.25.5 regexp/syntax/parse.go:2204-2210 nextRune
/// Decode one rune, or refuse the input as invalid UTF-8.
///
/// The error's `Expr` is the WHOLE remainder from the bad byte, which
/// is what makes `Parse("a\xffb")` quote `\xffb`.
fn nextRune(
    s: &crate::gostring::string,
) -> (rune, crate::gostring::string, crate::errors::error) {
    let (c, size) = crate::unicode::utf8::DecodeRune(s.as_bytes());
    if c == crate::unicode::utf8::RuneError && crate::int64(size) == 1 {
        return (
            0,
            crate::gostring::string::new(),
            crate::errors::Wrap(Error {
                Code: ErrInvalidUTF8,
                Expr: s.clone(),
            }),
        );
    }
    return (c, s.slice(crate::int::from(crate::int64(size)), s.Len()), crate::errors::nil);
}

// go: sdk 1.25.5 regexp/syntax/parse.go:2216-2227 unhex
/// A hex digit's value, or `-1`.
fn unhex(c: rune) -> rune {
    if rune('0') <= c && c <= rune('9') {
        return c - rune('0');
    }
    if rune('a') <= c && c <= rune('f') {
        return c - rune('a') + 10;
    }
    if rune('A') <= c && c <= rune('F') {
        return c - rune('A') + 10;
    }
    return -1;
}

// go: sdk 1.25.5 regexp/syntax/parse.go:1675-1709 canonicalName
/// Go: fold `_`, `-` and space away, upper-case the first letter and
/// lower-case the rest — so `\p{han}`, `\p{HAN}` and `\p{Han}` are one
/// name.
///
/// Go returns the input unchanged when nothing needed changing, to
/// avoid the allocation; the observable result is the same.
fn canonicalName(name: &crate::gostring::string) -> crate::gostring::string {
    let src = name.as_bytes();
    let mut b: Vec<u8> = Vec::with_capacity(src.len());
    let mut first = true;
    for i in 0..src.len() {
        let mut c = src[i];
        if c == b'_' || c == b'-' || c == b' ' {
            c = b' ';
        } else if first {
            if b'a' <= c && c <= b'z' {
                c -= b'a' - b'A';
            }
            first = false;
        } else if b'A' <= c && c <= b'Z' {
            c += b'a' - b'A';
        }
        if c == b' ' {
            continue;
        }
        b.push(c);
    }
    return crate::gostring::string::from_bytes(&b);
}

// go: sdk 1.25.5 regexp/syntax/parse.go:1715-1749 unicodeTable
/// Go: resolve a `\p{Name}` to its table, its fold twin, and a sign.
///
/// ─── A REAL GAP, not a shortcut ──────────────────────────────────────
///
/// Go answers this out of `unicode.Categories`, `unicode.Scripts`,
/// `unicode.CategoryAliases` and their Fold twins. goish's `unicode`
/// does not have those maps — see the GOISH021 waiver at the top of
/// src/unicode/letter.rs — and the tables behind them are not in the
/// tree either: `tables.rs` exports `Mn` and `Zs` and nothing else.
///
/// So `\p{Han}`, `\p{L}` and every other named group RESOLVE TO
/// NOTHING here, which Go's own caller turns into
/// `ErrInvalidCharRange`. `\p{Any}` and `\p{ASCII}` work, because
/// their tables are built in this file.
///
/// That is a refusal, not a wrong answer — `regexp.MustCompile(
/// "\\p{Han}")` fails to compile instead of silently matching the
/// wrong runes — and it is a `unicode` item that `regexp` inherits, not
/// a regexp one. Recorded in ROADMAP §2c.
fn unicodeTable(
    name: &crate::gostring::string,
) -> (
    Option<&'static crate::unicode::RangeTable>,
    Option<&'static crate::unicode::RangeTable>,
    crate::int,
) {
    let name = canonicalName(name);
    // Go: "Special cases: Any, Assigned, and ASCII. Also LC is the only
    // non-canonical Categories key, so handle it here."
    if name == "Any" {
        return (Some(&anyTable), Some(&anyTable), 1);
    }
    if name == "Ascii" {
        return (Some(&asciiTable), Some(&asciiFoldTable), 1);
    }
    // Go's "Assigned" (invert unicode.Cn) and "Lc", and then the
    // Categories, Scripts and CategoryAliases lookups, all need tables
    // goish's unicode does not carry. See the doc comment.
    return (None, None, 0);
}

impl parser {
    // go: sdk 1.25.5 regexp/syntax/parse.go:1273-1300 parser.parseInt
    /// A decimal count, refusing a leading zero and clamping overflow
    /// to `-1` rather than wrapping.
    fn parseInt(
        &self,
        s: &crate::gostring::string,
    ) -> (crate::int, crate::gostring::string, bool) {
        let b = s.as_bytes();
        if b.is_empty() || b[0] < b'0' || b'9' < b[0] {
            return (0, crate::gostring::string::new(), false);
        }
        // Go: disallow leading zeros.
        if b.len() >= 2 && b[0] == b'0' && b'0' <= b[1] && b[1] <= b'9' {
            return (0, crate::gostring::string::new(), false);
        }
        let mut i = 0usize;
        while i < b.len() && b'0' <= b[i] && b[i] <= b'9' {
            i += 1;
        }
        let rest = s.slice(crate::int::from(crate::int64(i)), s.Len());
        let mut n: crate::int = 0;
        for j in 0..i {
            // Go: avoid overflow.
            if n >= 100000000 {
                n = -1;
                break;
            }
            n = n * 10 + crate::int::from(crate::int64(b[j])) - crate::int::from(48);
        }
        return (n, rest, true);
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:1102-1139 parser.parseRepeat
    /// Go: "parses {min} (max=min) or {min,} (max=-1) or {min,max}. If s
    /// is not of that form, it returns ok == false. If s has the right
    /// form but the values are too big, it returns min == -1, ok ==
    /// true."
    ///
    /// The `ok == false` case is why `a{` is a literal brace and not an
    /// error.
    fn parseRepeat(
        &self,
        s: &crate::gostring::string,
    ) -> (crate::int, crate::int, crate::gostring::string, bool) {
        let none = (
            crate::int::from(0),
            crate::int::from(0),
            crate::gostring::string::new(),
            false,
        );
        if s.Len() == 0 || s.as_bytes()[0] != b'{' {
            return none;
        }
        let mut s = s.slice(1, s.Len());
        let (min, rest, ok1) = self.parseInt(&s);
        if !ok1 {
            return (min, crate::int::from(0), crate::gostring::string::new(), false);
        }
        s = rest;
        let mut min = min;
        let mut max: crate::int;
        if s.Len() == 0 {
            return (min, crate::int::from(0), crate::gostring::string::new(), false);
        }
        if s.as_bytes()[0] != b',' {
            max = min;
        } else {
            s = s.slice(1, s.Len());
            if s.Len() == 0 {
                return (min, crate::int::from(0), crate::gostring::string::new(), false);
            }
            if s.as_bytes()[0] == b'}' {
                max = -1;
            } else {
                let (m, rest, ok1) = self.parseInt(&s);
                max = m;
                if !ok1 {
                    return (min, max, crate::gostring::string::new(), false);
                }
                s = rest;
                if max < 0 {
                    // Go: parseInt found too big a number.
                    min = -1;
                }
            }
        }
        if s.Len() == 0 || s.as_bytes()[0] != b'}' {
            return (min, max, crate::gostring::string::new(), false);
        }
        return (min, max, s.slice(1, s.Len()), true);
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:1445-1556 parser.parseEscape
    /// One backslash escape. Go's comment on the missing `\b` is worth
    /// keeping: "There is no case 'b', to avoid misparsing the Perl
    /// word-boundary \b as the C backspace \b when in POSIX mode. In
    /// Perl, /\b/ means word-boundary but /[\b]/ means backspace. We
    /// don't support that."
    fn parseEscape(
        &self,
        s: &crate::gostring::string,
    ) -> (rune, crate::gostring::string, crate::errors::error) {
        let bad = |t: &crate::gostring::string| -> (rune, crate::gostring::string, crate::errors::error) {
            (
                0,
                crate::gostring::string::new(),
                crate::errors::Wrap(Error {
                    Code: ErrInvalidEscape,
                    Expr: s.slice(0, s.Len() - t.Len()),
                }),
            )
        };
        let t0 = s.slice(1, s.Len());
        if t0.Len() == 0 {
            return (
                0,
                crate::gostring::string::new(),
                crate::errors::Wrap(Error {
                    Code: ErrTrailingBackslash,
                    Expr: crate::gostring::string::new(),
                }),
            );
        }
        let (c, mut t, err) = nextRune(&t0);
        if !err.IsNil() {
            return (0, crate::gostring::string::new(), err);
        }

        // Go: octal escapes. A single non-zero digit is a backreference,
        // which is not supported, so it falls through to the error.
        let octal_start = c == rune('0')
            || (rune('1') <= c
                && c <= rune('7')
                && t.Len() > 0
                && t.as_bytes()[0] >= b'0'
                && t.as_bytes()[0] <= b'7');
        if octal_start {
            // Go: consume up to three octal digits; already have one.
            let mut r = c - rune('0');
            let mut i = 1;
            while i < 3 {
                if t.Len() == 0 || t.as_bytes()[0] < b'0' || t.as_bytes()[0] > b'7' {
                    break;
                }
                r = r * 8 + crate::int32(crate::uint32(crate::int64(t.as_bytes()[0]))) - rune('0');
                t = t.slice(1, t.Len());
                i += 1;
            }
            return (r, t, crate::errors::nil);
        }

        if c == rune('x') {
            if t.Len() == 0 {
                return bad(&t);
            }
            let (c2, t2, err) = nextRune(&t);
            if !err.IsNil() {
                return (0, crate::gostring::string::new(), err);
            }
            t = t2;
            if c2 == rune('{') {
                // Go: "Any number of digits in braces. Perl accepts any
                // text at all; it ignores all text after the first
                // non-hex digit. We require only hex digits, and at
                // least one."
                let mut nhex = 0;
                let mut r: rune = 0;
                loop {
                    if t.Len() == 0 {
                        return bad(&t);
                    }
                    let (c3, t3, err) = nextRune(&t);
                    if !err.IsNil() {
                        return (0, crate::gostring::string::new(), err);
                    }
                    t = t3;
                    if c3 == rune('}') {
                        break;
                    }
                    let v = unhex(c3);
                    if v < 0 {
                        return bad(&t);
                    }
                    r = r * 16 + v;
                    if r > crate::unicode::MaxRune {
                        return bad(&t);
                    }
                    nhex += 1;
                }
                if nhex == 0 {
                    return bad(&t);
                }
                return (r, t, crate::errors::nil);
            }

            // Go: easy case: two hex digits.
            let x = unhex(c2);
            let (c3, t3, err) = nextRune(&t);
            if !err.IsNil() {
                return (0, crate::gostring::string::new(), err);
            }
            t = t3;
            let y = unhex(c3);
            if x < 0 || y < 0 {
                return bad(&t);
            }
            return (x * 16 + y, t, crate::errors::nil);
        }

        // Go's C escapes.
        if c == rune('a') {
            return (7, t, crate::errors::nil);
        }
        if c == rune('f') {
            return (12, t, crate::errors::nil);
        }
        if c == rune('n') {
            return (rune('\n'), t, crate::errors::nil);
        }
        if c == rune('r') {
            return (rune('\r'), t, crate::errors::nil);
        }
        if c == rune('t') {
            return (rune('\t'), t, crate::errors::nil);
        }
        if c == rune('v') {
            return (11, t, crate::errors::nil);
        }

        // Go's default arm, which the octal and hex cases fall past.
        if c < crate::int32(crate::uint32(crate::int64(crate::unicode::utf8::RuneSelf)))
            && !isalnum(c)
        {
            // Go: "Escaped non-word characters are always themselves.
            // PCRE is not quite so rigorous: it accepts things like \q,
            // but we don't. We once rejected \_, but too many programs
            // and people insist on using it, so allow \_."
            return (c, t, crate::errors::nil);
        }
        return bad(&t);
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:1560-1573 parser.parseClassChar
    /// One character inside `[...]`, escape or not.
    fn parseClassChar(
        &self,
        s: &crate::gostring::string,
        wholeClass: &crate::gostring::string,
    ) -> (rune, crate::gostring::string, crate::errors::error) {
        if s.Len() == 0 {
            return (
                0,
                crate::gostring::string::new(),
                crate::errors::Wrap(Error {
                    Code: ErrMissingBracket,
                    Expr: wholeClass.clone(),
                }),
            );
        }
        // Go: "Allow regular escape sequences even though many need not
        // be escaped in this context."
        if s.as_bytes()[0] == b'\\' {
            return self.parseEscape(s);
        }
        return nextRune(s);
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:1617-1636 parser.appendGroup
    /// Append a named group's class, negated and/or folded per the
    /// group's sign and the parser's flags.
    fn appendGroup(&mut self, r: Vec<rune>, g: charGroup) -> Vec<rune> {
        if !self.flags.__has(FoldCase) {
            if g.sign < 0 {
                return appendNegatedClass(r, g.class);
            }
            return appendClass(r, g.class);
        }
        // Go folds into `p.tmpClass` and cleans it there, so the buffer
        // is reused across groups.
        let mut tmp = core::mem::take(&mut self.tmpClass);
        tmp.clear();
        tmp = appendFoldedClass(tmp, g.class);
        self.tmpClass = tmp;
        let mut t = core::mem::take(&mut self.tmpClass);
        let cleaned = cleanClass(&mut t);
        self.tmpClass = t;
        if g.sign < 0 {
            return appendNegatedClass(r, &cleaned);
        }
        return appendClass(r, &cleaned);
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:1585-1597 parser.parsePerlClassEscape
    /// `\d`, `\s`, `\w` and their negations. `None` means "not one of
    /// these", which the caller treats as "try the next thing".
    fn parsePerlClassEscape(
        &mut self,
        s: &crate::gostring::string,
        r: Vec<rune>,
    ) -> Option<(Vec<rune>, crate::gostring::string)> {
        if !self.flags.__has(PerlX) || s.Len() < 2 || s.as_bytes()[0] != b'\\' {
            return None;
        }
        let g = super::perl_groups::perlGroup(&s.slice(0, 2))?;
        return Some((self.appendGroup(r, g), s.slice(2, s.Len())));
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:1599-1615 parser.parseNamedClass
    /// `[:alpha:]` and friends, inside a class.
    ///
    /// Three outcomes, and Go distinguishes all three: not a named
    /// class at all (`Ok(None)`), a known one (`Ok(Some(..))`), and
    /// `[:` … `:]` with an unknown name, which is an ERROR rather than
    /// a fallthrough.
    fn parseNamedClass(
        &mut self,
        s: &crate::gostring::string,
        r: Vec<rune>,
    ) -> Result<Option<(Vec<rune>, crate::gostring::string)>, crate::errors::error> {
        if s.Len() < 2 || s.as_bytes()[0] != b'[' || s.as_bytes()[1] != b':' {
            return Ok(None);
        }
        let i = crate::strings::Index(
            s.slice(2, s.Len()),
            crate::gostring::string::from_static(":]"),
        );
        if i < 0 {
            return Ok(None);
        }
        let i = i + 2;
        let name = s.slice(0, i + 2);
        let rest = s.slice(i + 2, s.Len());
        let g = match super::perl_groups::posixGroup(&name) {
            Some(g) => g,
            None => {
                return Err(crate::errors::Wrap(Error {
                    Code: ErrInvalidCharRange,
                    Expr: name,
                }))
            }
        };
        return Ok(Some((self.appendGroup(r, g), rest)));
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:1751-1823 parser.parseUnicodeClass
    /// `\p{Name}` / `\pN` and their `\P` negations.
    ///
    /// `\p{^Han} == \P{Han}` and `\P{^Han} == \p{Han}`: the leading
    /// caret flips the sign a second time.
    ///
    /// See [`unicodeTable`] for why every name but `Any` and `ASCII`
    /// currently resolves to nothing here.
    fn parseUnicodeClass(
        &mut self,
        s: &crate::gostring::string,
        r: Vec<rune>,
    ) -> Result<Option<(Vec<rune>, crate::gostring::string)>, crate::errors::error> {
        let b = s.as_bytes();
        if !self.flags.__has(UnicodeGroups)
            || s.Len() < 2
            || b[0] != b'\\'
            || (b[1] != b'p' && b[1] != b'P')
        {
            return Ok(None);
        }

        // Go: committed to parse or return error.
        let mut sign: crate::int = 1;
        if b[1] == b'P' {
            sign = -1;
        }
        let t0 = s.slice(2, s.Len());
        let (c, mut t, err) = nextRune(&t0);
        if !err.IsNil() {
            return Err(err);
        }
        let seq: crate::gostring::string;
        let mut name: crate::gostring::string;
        if c != rune('{') {
            // Go: single-letter name.
            seq = s.slice(0, s.Len() - t.Len());
            name = seq.slice(2, seq.Len());
        } else {
            // Go: name is in braces.
            let end = crate::strings::IndexRune(s.clone(), rune('}'));
            if end < 0 {
                let e = checkUTF8(s);
                if !e.IsNil() {
                    return Err(e);
                }
                return Err(crate::errors::Wrap(Error {
                    Code: ErrInvalidCharRange,
                    Expr: s.clone(),
                }));
            }
            seq = s.slice(0, end + 1);
            t = s.slice(end + 1, s.Len());
            name = s.slice(3, end);
            let e = checkUTF8(&name);
            if !e.IsNil() {
                return Err(e);
            }
        }

        // Go: "Group can have leading negation too. \p{^Han} ==
        // \P{Han}, \P{^Han} == \p{Han}."
        if name.Len() != 0 && name.as_bytes()[0] == b'^' {
            sign = -sign;
            name = name.slice(1, name.Len());
        }

        let (tab, fold, tsign) = unicodeTable(&name);
        let tab = match tab {
            Some(t) => t,
            None => {
                return Err(crate::errors::Wrap(Error {
                    Code: ErrInvalidCharRange,
                    Expr: seq,
                }))
            }
        };
        if tsign < 0 {
            sign = -sign;
        }

        let mut r = r;
        if !self.flags.__has(FoldCase) || fold.is_none() {
            if sign > 0 {
                r = appendTable(r, tab);
            } else {
                r = appendNegatedTable(r, tab);
            }
        } else {
            // Go: "Merge and clean tab and fold in a temporary buffer.
            // This is necessary for the negative case and just tidy for
            // the positive case."
            let mut tmp = core::mem::take(&mut self.tmpClass);
            tmp.clear();
            tmp = appendTable(tmp, tab);
            tmp = appendTable(tmp, fold.unwrap());
            self.tmpClass = tmp;
            let mut t2 = core::mem::take(&mut self.tmpClass);
            let cleaned = cleanClass(&mut t2);
            self.tmpClass = t2;
            if sign > 0 {
                r = appendClass(r, &cleaned);
            } else {
                r = appendNegatedClass(r, &cleaned);
            }
        }
        return Ok(Some((r, t)));
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:1827-1919 parser.parseClass
    /// A whole `[...]`, pushed onto the stack.
    ///
    /// The `\n` inserted for a negated class under POSIX semantics is
    /// Go's, and its comment says why: "If character class does not
    /// match \n, add it here, so that negation later will do the right
    /// thing."
    fn parseClass(
        &mut self,
        s: &crate::gostring::string,
    ) -> Result<crate::gostring::string, crate::errors::error> {
        let mut t = s.slice(1, s.Len()); // Go: chop [
        let re = self.newRegexp(super::regexp::OpCharClass);
        self.nm(re).Flags = self.flags;
        let mut class: Vec<rune> = Vec::new();

        let mut sign: crate::int = 1;
        if t.Len() != 0 && t.as_bytes()[0] == b'^' {
            sign = -1;
            t = t.slice(1, t.Len());
            if !self.flags.__has(ClassNL) {
                class.push(rune('\n'));
                class.push(rune('\n'));
            }
        }

        // Go: ] and - are okay as first char in class.
        let mut first = true;
        while t.Len() == 0 || t.as_bytes()[0] != b']' || first {
            // Go: "POSIX: - is only okay unescaped as first or last in
            // class. Perl: - is okay anywhere."
            if t.Len() != 0
                && t.as_bytes()[0] == b'-'
                && !self.flags.__has(PerlX)
                && !first
                && (t.Len() == 1 || t.as_bytes()[1] != b']')
            {
                let (_, size) = crate::unicode::utf8::DecodeRune(t.slice(1, t.Len()).as_bytes());
                return Err(crate::errors::Wrap(Error {
                    Code: ErrInvalidCharRange,
                    Expr: t.slice(0, 1 + crate::int::from(crate::int64(size))),
                }));
            }
            first = false;

            // Go: look for POSIX [:alnum:] etc.
            if t.Len() > 2 && t.as_bytes()[0] == b'[' && t.as_bytes()[1] == b':' {
                match self.parseNamedClass(&t, class.clone())? {
                    Some((nclass, nt)) => {
                        class = nclass;
                        t = nt;
                        continue;
                    }
                    None => {}
                }
            }

            // Go: look for Unicode character group like \p{Han}.
            match self.parseUnicodeClass(&t, class.clone())? {
                Some((nclass, nt)) => {
                    class = nclass;
                    t = nt;
                    continue;
                }
                None => {}
            }

            // Go: look for Perl character class symbols (extension).
            if let Some((nclass, nt)) = self.parsePerlClassEscape(&t, class.clone()) {
                class = nclass;
                t = nt;
                continue;
            }

            // Go: single character or simple range.
            let rng = t.clone();
            let (lo, t2, err) = self.parseClassChar(&t, s);
            if !err.IsNil() {
                return Err(err);
            }
            t = t2;
            let mut hi = lo;
            // Go: [a-] means (a|-) so check for final ].
            if t.Len() >= 2 && t.as_bytes()[0] == b'-' && t.as_bytes()[1] != b']' {
                t = t.slice(1, t.Len());
                let (h, t3, err) = self.parseClassChar(&t, s);
                if !err.IsNil() {
                    return Err(err);
                }
                hi = h;
                t = t3;
                if hi < lo {
                    return Err(crate::errors::Wrap(Error {
                        Code: ErrInvalidCharRange,
                        Expr: rng.slice(0, rng.Len() - t.Len()),
                    }));
                }
            }
            if !self.flags.__has(FoldCase) {
                class = appendRange(class, lo, hi);
            } else {
                class = appendFoldedRange(class, lo, hi);
            }
        }
        t = t.slice(1, t.Len()); // Go: chop ]

        let mut class = cleanClass(&mut class);
        if sign < 0 {
            class = negateClass(class);
        }
        self.nm(re).Rune = class;
        let _ = self.push(re);
        return Ok(t);
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:1411-1443 parser.parseRightParen
    /// Close a group: the same three lines the end of `parse` runs,
    /// then pop the `(` and either discard it (a non-capturing group)
    /// or turn it into the `OpCapture`.
    fn parseRightParen(&mut self) -> crate::errors::error {
        let _ = self.concat();
        if self.swapVerticalBar() {
            // Go: pop vertical bar
            let n = self.stack.len();
            self.stack.truncate(n - 1);
        }
        let _ = self.alternate();

        let n = self.stack.len();
        if n < 2 {
            return crate::errors::Wrap(Error {
                Code: ErrUnexpectedParen,
                Expr: self.wholeRegexp.clone(),
            });
        }
        let re1 = self.stack[n - 1];
        let re2 = self.stack[n - 2];
        self.stack.truncate(n - 2);
        if self.n(re2).Op != opLeftParen {
            return crate::errors::Wrap(Error {
                Code: ErrUnexpectedParen,
                Expr: self.wholeRegexp.clone(),
            });
        }
        // Go: restore flags at time of paren.
        self.flags = self.n(re2).Flags;
        if self.n(re2).Cap == 0 {
            // Go: just for grouping.
            let _ = self.push(re1);
        } else {
            self.nm(re2).Op = super::regexp::OpCapture;
            self.nm(re2).Sub = alloc::vec![re1];
            let _ = self.push(re2);
        }
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 regexp/syntax/parse.go:1141-1258 parser.parsePerlFlags
    /// `(?i)`, `(?i:…)`, `(?:…)` and the three named-capture spellings.
    ///
    /// Go supports `(?P<name>…)` and `(?<name>…)` but NOT `(?'name'…)`,
    /// despite its own comment listing all three — the code only checks
    /// for `P<` and `<`.
    fn parsePerlFlags(
        &mut self,
        s: &crate::gostring::string,
    ) -> Result<crate::gostring::string, crate::errors::error> {
        let mut t = s.clone();
        let tb = t.as_bytes();

        let startsWithP = t.Len() > 4 && tb[2] == b'P' && tb[3] == b'<';
        let startsWithName = t.Len() > 3 && tb[2] == b'<';

        if startsWithP || startsWithName {
            // Go: position of expr start.
            let exprStartPos: crate::int = if startsWithName { 3 } else { 4 };

            // Go: pull out name.
            let end = crate::strings::IndexRune(t.clone(), rune('>'));
            if end < 0 {
                let e = checkUTF8(&t);
                if !e.IsNil() {
                    return Err(e);
                }
                return Err(crate::errors::Wrap(Error {
                    Code: ErrInvalidNamedCapture,
                    Expr: s.clone(),
                }));
            }

            // Go: "(?P<name>" or "(?<name>", then "name".
            let capture = t.slice(0, end + 1);
            let name = t.slice(exprStartPos, end);
            let e = checkUTF8(&name);
            if !e.IsNil() {
                return Err(e);
            }
            if !isValidCaptureName(&name) {
                return Err(crate::errors::Wrap(Error {
                    Code: ErrInvalidNamedCapture,
                    Expr: capture,
                }));
            }

            // Go: like ordinary capture, but named.
            self.numCap += 1;
            let (re, _) = self.op(opLeftParen);
            let cap = self.numCap;
            self.nm(re).Cap = cap;
            self.nm(re).Name = name;
            return Ok(t.slice(end + 1, t.Len()));
        }

        // Go: non-capturing group. Might also twiddle Perl flags.
        t = t.slice(2, t.Len()); // Go: skip (?
        let mut flags = self.flags;
        let mut sign: crate::int = 1;
        let mut sawFlag = false;
        while t.Len() != 0 {
            let (c, t2, err) = nextRune(&t);
            if !err.IsNil() {
                return Err(err);
            }
            t = t2;
            if c == rune('i') {
                flags |= FoldCase;
                sawFlag = true;
            } else if c == rune('m') {
                flags = Flags(flags.0 & !OneLine.0);
                sawFlag = true;
            } else if c == rune('s') {
                flags |= DotNL;
                sawFlag = true;
            } else if c == rune('U') {
                flags |= NonGreedy;
                sawFlag = true;
            } else if c == rune('-') {
                // Go: switch to negation.
                if sign < 0 {
                    break;
                }
                sign = -1;
                // Go: "Invert flags so that | above turn into &^ and
                // vice versa. We'll invert flags again before using it
                // below."
                flags = !flags;
                sawFlag = false;
            } else if c == rune(':') || c == rune(')') {
                // Go: end of flags, starting group or not.
                if sign < 0 {
                    if !sawFlag {
                        break;
                    }
                    flags = !flags;
                }
                if c == rune(':') {
                    // Go: open new group.
                    let _ = self.op(opLeftParen);
                }
                self.flags = flags;
                return Ok(t);
            } else {
                break;
            }
        }

        return Err(crate::errors::Wrap(Error {
            Code: ErrInvalidPerlOp,
            Expr: s.slice(0, s.Len() - t.Len()),
        }));
    }
}

// go: sdk 1.25.5 regexp/syntax/parse.go:887-889 Parse
/// Go: "Parse parses a regular expression string s, controlled by the
/// specified Flags, and returns a regular expression parse tree."
pub fn Parse<S: Into<crate::gostring::string>>(
    s: S,
    flags: Flags,
) -> (
    crate::gonilable::nilable<super::regexp::Regexp>,
    crate::errors::error,
) {
    return parse(&s.into(), flags);
}

// go: sdk 1.25.5 regexp/syntax/parse.go:891-1097 parse
/// The parser proper: one pass over the pattern, driving the stack
/// machinery.
///
/// Go opens with a `defer`/`recover` that turns `panic(ErrLarge)` and
/// `panic(ErrNestingDepth)` into errors. goish's limit checks RETURN
/// their code instead — `recover!()` does not resume — so those two
/// arrive through the same `?`-shaped propagation as every other error
/// and there is no recover here. The errors a caller sees are the same.
fn parse(
    s: &crate::gostring::string,
    flags: Flags,
) -> (
    crate::gonilable::nilable<super::regexp::Regexp>,
    crate::errors::error,
) {
    use super::regexp::*;
    let fail = |e: crate::errors::error| {
        (crate::nilval::nil.into(), e)
    };

    if flags.__has(Literal) {
        // Go: trivial parser for literal string.
        let e = checkUTF8(s);
        if !e.IsNil() {
            return fail(e);
        }
        return (
            crate::gonilable::nilable::new(literalRegexp(s, flags)),
            crate::errors::nil,
        );
    }

    // Go: otherwise, must do real work.
    let mut p = parser::__new(s.clone(), flags);
    let mut t = s.clone();
    let mut lastRepeat = crate::gostring::string::new();

    while t.Len() != 0 {
        let mut repeat = crate::gostring::string::new();
        let b0 = t.as_bytes()[0];

        if b0 == b'(' {
            if p.flags.__has(PerlX) && t.Len() >= 2 && t.as_bytes()[1] == b'?' {
                // Go: flag changes and non-capturing groups.
                match p.parsePerlFlags(&t) {
                    Ok(nt) => t = nt,
                    Err(e) => return fail(e),
                }
            } else {
                p.numCap += 1;
                let (re, le) = p.op(opLeftParen);
                if let Some(c) = le {
                    return fail(wrapLimit(c, s));
                }
                let cap = p.numCap;
                p.nm(re).Cap = cap;
                t = t.slice(1, t.Len());
            }
        } else if b0 == b'|' {
            if let Some(c) = p.parseVerticalBar() {
                return fail(wrapLimit(c, s));
            }
            t = t.slice(1, t.Len());
        } else if b0 == b')' {
            let e = p.parseRightParen();
            if !e.IsNil() {
                return fail(e);
            }
            t = t.slice(1, t.Len());
        } else if b0 == b'^' {
            let (_, le) = if p.flags.__has(OneLine) {
                p.op(OpBeginText)
            } else {
                p.op(OpBeginLine)
            };
            if let Some(c) = le {
                return fail(wrapLimit(c, s));
            }
            t = t.slice(1, t.Len());
        } else if b0 == b'$' {
            if p.flags.__has(OneLine) {
                let (re, le) = p.op(OpEndText);
                if let Some(c) = le {
                    return fail(wrapLimit(c, s));
                }
                let f = p.n(re).Flags | WasDollar;
                p.nm(re).Flags = f;
            } else {
                let (_, le) = p.op(OpEndLine);
                if let Some(c) = le {
                    return fail(wrapLimit(c, s));
                }
            }
            t = t.slice(1, t.Len());
        } else if b0 == b'.' {
            let (_, le) = if p.flags.__has(DotNL) {
                p.op(OpAnyChar)
            } else {
                p.op(OpAnyCharNotNL)
            };
            if let Some(c) = le {
                return fail(wrapLimit(c, s));
            }
            t = t.slice(1, t.Len());
        } else if b0 == b'[' {
            match p.parseClass(&t) {
                Ok(nt) => t = nt,
                Err(e) => return fail(e),
            }
        } else if b0 == b'*' || b0 == b'+' || b0 == b'?' {
            let before = t.clone();
            let op = if b0 == b'*' {
                OpStar
            } else if b0 == b'+' {
                OpPlus
            } else {
                OpQuest
            };
            let after = t.slice(1, t.Len());
            let (after, e) = p.repeat(op, 0, 0, &before, &after, &lastRepeat);
            if !e.IsNil() {
                return fail(e);
            }
            repeat = before;
            t = after;
        } else if b0 == b'{' {
            let before = t.clone();
            let (min, max, after, ok) = p.parseRepeat(&t);
            if !ok {
                // Go: "If the repeat cannot be parsed, { is a literal."
                if let Some(c) = p.literal(rune('{')) {
                    return fail(wrapLimit(c, s));
                }
                t = t.slice(1, t.Len());
            } else if min < 0 || min > 1000 || max > 1000 || max >= 0 && min > max {
                // Go: "Numbers were too big, or max is present and
                // min > max."
                return fail(crate::errors::Wrap(Error {
                    Code: ErrInvalidRepeatSize,
                    Expr: before.slice(0, before.Len() - after.Len()),
                }));
            } else {
                let (after, e) = p.repeat(OpRepeat, min, max, &before, &after, &lastRepeat);
                if !e.IsNil() {
                    return fail(e);
                }
                repeat = before;
                t = after;
            }
        } else if b0 == b'\\' {
            let mut handled = false;
            if p.flags.__has(PerlX) && t.Len() >= 2 {
                let b1 = t.as_bytes()[1];
                if b1 == b'A' {
                    let (_, le) = p.op(OpBeginText);
                    if let Some(c) = le {
                        return fail(wrapLimit(c, s));
                    }
                    t = t.slice(2, t.Len());
                    handled = true;
                } else if b1 == b'b' {
                    let (_, le) = p.op(OpWordBoundary);
                    if let Some(c) = le {
                        return fail(wrapLimit(c, s));
                    }
                    t = t.slice(2, t.Len());
                    handled = true;
                } else if b1 == b'B' {
                    let (_, le) = p.op(OpNoWordBoundary);
                    if let Some(c) = le {
                        return fail(wrapLimit(c, s));
                    }
                    t = t.slice(2, t.Len());
                    handled = true;
                } else if b1 == b'C' {
                    // Go: any byte; not supported.
                    return fail(crate::errors::Wrap(Error {
                        Code: ErrInvalidEscape,
                        Expr: t.slice(0, 2),
                    }));
                } else if b1 == b'Q' {
                    // Go: \Q ... \E: the ... is always literals.
                    let rest = t.slice(2, t.Len());
                    let idx = crate::strings::Index(
                        rest.clone(),
                        crate::gostring::string::from_static("\\E"),
                    );
                    let mut lit;
                    if idx < 0 {
                        lit = rest.clone();
                        t = crate::gostring::string::new();
                    } else {
                        lit = rest.slice(0, idx);
                        t = rest.slice(idx + 2, rest.Len());
                    }
                    while lit.Len() != 0 {
                        let (c, next, e) = nextRune(&lit);
                        if !e.IsNil() {
                            return fail(e);
                        }
                        if let Some(code) = p.literal(c) {
                            return fail(wrapLimit(code, s));
                        }
                        lit = next;
                    }
                    handled = true;
                } else if b1 == b'z' {
                    let (_, le) = p.op(OpEndText);
                    if let Some(c) = le {
                        return fail(wrapLimit(c, s));
                    }
                    t = t.slice(2, t.Len());
                    handled = true;
                }
            }

            if !handled {
                let re = p.newRegexp(OpCharClass);
                p.nm(re).Flags = p.flags;

                // Go: look for Unicode character group like \p{Han}.
                let mut pushed = false;
                if t.Len() >= 2 && (t.as_bytes()[1] == b'p' || t.as_bytes()[1] == b'P') {
                    match p.parseUnicodeClass(&t, Vec::new()) {
                        Err(e) => return fail(e),
                        Ok(Some((r, rest))) => {
                            p.nm(re).Rune = r;
                            t = rest;
                            let (_, le) = p.push(re);
                            if let Some(c) = le {
                                return fail(wrapLimit(c, s));
                            }
                            pushed = true;
                        }
                        Ok(None) => {}
                    }
                }

                if !pushed {
                    // Go: Perl character class escape.
                    match p.parsePerlClassEscape(&t, Vec::new()) {
                        Some((r, rest)) => {
                            p.nm(re).Rune = r;
                            t = rest;
                            let (_, le) = p.push(re);
                            if let Some(c) = le {
                                return fail(wrapLimit(c, s));
                            }
                            pushed = true;
                        }
                        None => {
                            p.reuse(re);
                        }
                    }
                }

                if !pushed {
                    // Go: ordinary single-character escape.
                    let (c, rest, e) = p.parseEscape(&t);
                    if !e.IsNil() {
                        return fail(e);
                    }
                    t = rest;
                    if let Some(code) = p.literal(c) {
                        return fail(wrapLimit(code, s));
                    }
                }
            }
        } else {
            let (c, rest, e) = nextRune(&t);
            if !e.IsNil() {
                return fail(e);
            }
            t = rest;
            if let Some(code) = p.literal(c) {
                return fail(wrapLimit(code, s));
            }
        }

        lastRepeat = repeat;
    }

    let _ = p.concat();
    if p.swapVerticalBar() {
        // Go: pop vertical bar
        let n = p.stack.len();
        p.stack.truncate(n - 1);
    }
    let _ = p.alternate();

    if p.stack.len() != 1 {
        return fail(crate::errors::Wrap(Error {
            Code: ErrMissingParen,
            Expr: s.clone(),
        }));
    }
    let root = p.stack[0];
    return (
        crate::gonilable::nilable::new(p.__materialise(root)),
        crate::errors::nil,
    );
}

// go: none — goish idiom: Go's limit checks `panic(ErrLarge)` and the
//     `recover` at the top of `parse` attaches the WHOLE pattern as the
//     Expr. goish returns the code instead, so the wrap happens where
//     the recover would have.
/// A limit code, as the error Go's `recover` builds.
fn wrapLimit(code: ErrorCode, s: &crate::gostring::string) -> crate::errors::error {
    return crate::errors::Wrap(Error {
        Code: code,
        Expr: s.clone(),
    });
}

impl parser {
    // go: none — goish idiom: Go's parser IS building `*Regexp`s, so it
    //     returns the root and is done. goish's works in an arena, so
    //     the public tree is built from it once, here.
    /// The arena subtree at `r`, as a public [`Regexp`].
    fn __materialise(&self, r: pref) -> super::regexp::Regexp {
        let n = self.n(r);
        let mut sub: Vec<alloc::sync::Arc<super::regexp::Regexp>> = Vec::new();
        for s in n.Sub.iter() {
            sub.push(alloc::sync::Arc::new(self.__materialise(*s)));
        }
        return super::regexp::Regexp {
            Op: n.Op,
            Flags: n.Flags,
            Sub: sub,
            Rune: n.Rune.clone(),
            Min: n.Min,
            Max: n.Max,
            Cap: n.Cap,
            Name: n.Name.clone(),
        };
    }
}

// ─── test hooks for the parser machinery ─────────────────────────────

// go: none — goish-only: Go's `parser` is unexported and its own tests
//     drive it from inside the package. goish's reference is an
//     EXAMPLE, so the machinery needs a handle. `regexp_parser_ref_smoke`
//     is the only caller.
/// An opaque handle to a [`parser`], for driving it from a reference.
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub struct __Parser(parser);

#[doc(hidden)]
impl __Parser {
    // go: none — goish-only: see `__Parser`.
    /// A parser over `whole`, with `flags`.
    pub fn __new(whole: crate::gostring::string, flags: Flags) -> __Parser {
        return __Parser(parser::__new(whole, flags));
    }
    // go: none — goish-only: see `__Parser`.
    /// `p.literal(r)`.
    pub fn __literal(&mut self, r: rune) {
        let _ = self.0.literal(r);
    }
    // go: none — goish-only: see `__Parser`.
    /// `p.op(op)`.
    pub fn __op(&mut self, op: super::regexp::Op) {
        let _ = self.0.op(op);
    }
    // go: none — goish-only: see `__Parser`.
    /// Build an `OpCharClass` over `rs` and push it — the shape the
    /// class parser hands to `push`.
    pub fn __class(&mut self, rs: &[rune]) {
        let re = self.0.newRegexp(super::regexp::OpCharClass);
        self.0.nm(re).Flags = self.0.flags;
        self.0.nm(re).Rune.extend_from_slice(rs);
        let _ = self.0.push(re);
    }
    // go: none — goish-only: see `__Parser`.
    /// `p.concat()`.
    pub fn __concat(&mut self) {
        let _ = self.0.concat();
    }
    // go: none — goish-only: see `__Parser`.
    /// `p.alternate()`.
    pub fn __alternate(&mut self) {
        let _ = self.0.alternate();
    }
    // go: none — goish-only: see `__Parser`.
    /// `p.parseVerticalBar()`.
    pub fn __verticalBar(&mut self) {
        let _ = self.0.parseVerticalBar();
    }
    // go: none — goish-only: see `__Parser`.
    /// The three lines `parse`'s end and `parseRightParen` both write
    /// out (parse.go lines 1085-1089 and 1412-1416): concat, pop the
    /// vertical bar if `swapVerticalBar` moved one, then alternate.
    /// Popping the marker is what leaves the alternatives adjacent for
    /// `alternate` to take — without it `a|b|c` collapses only `c`.
    pub fn __closeGroup(&mut self) {
        let _ = self.0.concat();
        if self.0.swapVerticalBar() {
            let n = self.0.stack.len();
            self.0.stack.truncate(n - 1);
        }
        let _ = self.0.alternate();
    }
    // go: none — goish-only: see `__Parser`.
    /// `p.repeat(op, min, max, "x{2}", "", "")`.
    pub fn __repeat(
        &mut self,
        op: super::regexp::Op,
        min: crate::int,
        max: crate::int,
    ) -> crate::errors::error {
        let (_, e) = self.0.repeat(
            op,
            min,
            max,
            &crate::gostring::string::from_static("x{2}"),
            &crate::gostring::string::new(),
            &crate::gostring::string::new(),
        );
        return e;
    }
    // go: none — goish-only: see `__Parser`.
    /// Set `p.flags`.
    pub fn __setflags(&mut self, f: Flags) {
        self.0.flags = f;
    }
    // go: none — goish-only: see `__Parser`.
    /// `p.numRegexp`.
    pub fn __numRegexp(&self) -> crate::int {
        return self.0.numRegexp;
    }
    // go: none — goish-only: see `__Parser`.
    /// `p.numRunes`.
    pub fn __numRunes(&self) -> crate::int {
        return self.0.numRunes;
    }
    // go: none — goish-only: see `__Parser`.
    /// The stack, as the reference's space-separated s-expressions.
    pub fn __dump(&self) -> crate::gostring::string {
        let mut b = crate::gostring::string::new();
        for (i, r) in self.0.stack.iter().enumerate() {
            if i > 0 {
                b = b + crate::gostring::string::from_static(" ");
            }
            b = b + self.__dump_node(*r);
        }
        return b;
    }
    // go: none — goish-only: the recursive half of `__dump`.
    /// One node as the reference's s-expression.
    fn __dump_node(&self, r: pref) -> crate::gostring::string {
        let n = self.0.n(r);
        let mut b = crate::gostring::string::from_static("(")
            + crate::strconv::Itoa(crate::int::from(crate::int64(n.Op.0)))
            + crate::gostring::string::from_static(" ")
            + crate::strconv::Itoa(crate::int::from(crate::int64(n.Flags.0)))
            + crate::gostring::string::from_static(" ")
            + crate::strconv::Itoa(n.Min)
            + crate::gostring::string::from_static(" ")
            + crate::strconv::Itoa(n.Max)
            + crate::gostring::string::from_static(" ")
            + crate::strconv::Itoa(n.Cap)
            + crate::gostring::string::from_static(" ")
            + crate::strconv::Quote(n.Name.clone())
            + crate::gostring::string::from_static(" [");
        for (i, v) in n.Rune.iter().enumerate() {
            if i > 0 {
                b = b + crate::gostring::string::from_static(" ");
            }
            b = b + crate::strconv::Itoa(crate::int::from(crate::int64(*v)));
        }
        b = b + crate::gostring::string::from_static("]");
        for s in n.Sub.iter() {
            b = b + crate::gostring::string::from_static(" ") + self.__dump_node(*s);
        }
        return b + crate::gostring::string::from_static(")");
    }
}

// go: none — goish-only: the two pseudo-ops, for the reference.
/// `(opLeftParen, opVerticalBar)`.
#[doc(hidden)]
pub fn __pseudoOps() -> (super::regexp::Op, super::regexp::Op) {
    return (opLeftParen, opVerticalBar);
}
