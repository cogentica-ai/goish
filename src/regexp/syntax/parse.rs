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
