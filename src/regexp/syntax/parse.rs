// Port of Go 1.25.5 regexp/syntax/parse.go.
//
// STAGE 1 OF §2c ports only the `Flags` bitset from the top of this
// file. `prog.rs` cannot be written without it: an `Inst.Arg` holds
// one, and `MatchRunePos`, `Prefix` and `dumpInst` all read `FoldCase`
// out of it.
//
// The parser proper — `Parse`, the `parser` state machine, the class
// and repeat machinery, ~2,200 lines — is stage 2. The two waivers
// below are the checklist for it, in the shape root_openat.rs
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
