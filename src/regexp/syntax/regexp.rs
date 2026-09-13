// Port of Go 1.25.5 regexp/syntax/regexp.go.
//
// The AST the parser produces and the compiler consumes: a `Regexp`
// node with an `Op`, its flags, and its subexpressions. Stage 2a of
// §2c — the parser that BUILDS these is stage 2b; nothing here is
// wired to the live matcher.
//
// Go's note to implementers, worth keeping: "In this package, re is
// always a *Regexp and r is always a rune."
//
// ─── the one structural divergence ───────────────────────────────────
//
// Go's `Sub []*Regexp` is a slice of pointers, and `String()` keys a
// `map[*Regexp]printFlags` on POINTER IDENTITY — two structurally
// identical subexpressions at different addresses get different
// entries. goish's `Sub` is `Vec<Arc<Regexp>>`, and the map is keyed on
// the Arc's address. That reproduces the semantics exactly, including
// the aliasing case: a node the parser reuses in two places is one
// pointer in Go and one Arc here, and collides identically in both.
//
// `Sub0` and `Rune0` are NOT ported. They are Go's inline storage for
// the common one-subexpression and two-rune cases — `re.Sub =
// re.Sub0[:0]` avoids an allocation — and they hold no information
// that `Sub` and `Rune` do not. A `Vec` cannot borrow from its own
// struct, so the optimisation does not translate; the fields would be
// dead weight that a reader would have to check for meaning.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::gomap::map;
use crate::gostring::string;
use crate::{int, rune};

use super::parse::{inCharClass, maxFold, minFold, Flags, FoldCase, NonGreedy, WasDollar};

// goishlint:ignore GOISH019 Sub0, Rune0 — Go's inline storage for the
// common one-subexpression and two-rune cases (`re.Sub = re.Sub0[:0]`),
// which saves an allocation and holds no information `Sub` and `Rune`
// do not. A Vec cannot borrow from its own struct, so the optimisation
// does not translate; carrying the fields would leave a reader
// checking two dead arrays for meaning. See the file header.
// go: sdk 1.25.5 regexp/syntax/regexp.go:17-27 Regexp
/// Go: "A Regexp is a node in a regular expression syntax tree."
#[derive(Clone, Default)]
pub struct Regexp {
    /// Operator.
    pub Op: Op,
    pub Flags: Flags,
    /// Subexpressions, if any.
    pub Sub: Vec<Arc<Regexp>>,
    /// Matched runes, for `OpLiteral`, `OpCharClass`.
    pub Rune: Vec<rune>,
    /// Min for `OpRepeat`.
    pub Min: int,
    /// Max for `OpRepeat` (`-1` is no limit).
    pub Max: int,
    /// Capturing index, for `OpCapture`.
    pub Cap: int,
    /// Capturing name, for `OpCapture`.
    pub Name: string,
}

// go: sdk 1.25.5 regexp/syntax/regexp.go:33-33 Op
/// Go: "An Op is a single regular expression operator."
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Op(pub u8);

// go: sdk 1.25.5 regexp/syntax/regexp.go:38-58 OpNoMatch
/// Go: "Operators are listed in precedence order, tightest binding to
/// weakest. Character class operators are listed simplest to most
/// complex (OpLiteral, OpCharClass, OpAnyCharNotNL, OpAnyChar)."
///
/// The order is load-bearing twice over: `Op.String` indexes a table
/// with it, and `writeRegexp` compares `sub.Op > OpCapture` to decide
/// whether a repeat operand needs `(?:)` around it.
pub const OpNoMatch: Op = Op(1);
// go: none — goish-only placement: Go declares all nineteen in one
//     `iota` block with `OpNoMatch` (regexp.go lines 38-58).
/// Matches empty string.
pub const OpEmptyMatch: Op = Op(2);
/// Matches `Rune`s sequence.
pub const OpLiteral: Op = Op(3);
/// Matches `Rune`s interpreted as range pair list.
pub const OpCharClass: Op = Op(4);
/// Matches any character except newline.
pub const OpAnyCharNotNL: Op = Op(5);
/// Matches any character.
pub const OpAnyChar: Op = Op(6);
/// Matches empty string at beginning of line.
pub const OpBeginLine: Op = Op(7);
/// Matches empty string at end of line.
pub const OpEndLine: Op = Op(8);
/// Matches empty string at beginning of text.
pub const OpBeginText: Op = Op(9);
/// Matches empty string at end of text.
pub const OpEndText: Op = Op(10);
/// Matches word boundary `\b`.
pub const OpWordBoundary: Op = Op(11);
/// Matches word non-boundary `\B`.
pub const OpNoWordBoundary: Op = Op(12);
/// Capturing subexpression with index `Cap`, optional name `Name`.
pub const OpCapture: Op = Op(13);
/// Matches `Sub[0]` zero or more times.
pub const OpStar: Op = Op(14);
/// Matches `Sub[0]` one or more times.
pub const OpPlus: Op = Op(15);
/// Matches `Sub[0]` zero or one times.
pub const OpQuest: Op = Op(16);
/// Matches `Sub[0]` at least `Min` times, at most `Max` (`Max == -1` is
/// no limit).
pub const OpRepeat: Op = Op(17);
/// Matches concatenation of `Sub`s.
pub const OpConcat: Op = Op(18);
/// Matches alternation of `Sub`s.
pub const OpAlternate: Op = Op(19);

// go: sdk 1.25.5 regexp/syntax/regexp.go:61-61 opPseudo
/// Go: "where pseudo-ops start". The parser's stack markers live above
/// it; nothing in a finished tree carries one.
pub const opPseudo: Op = Op(128);

impl Regexp {
    // go: none — goish idiom: Go writes `&Regexp{Op: op}` inline. A
    //     Rust struct literal would have to name all eight fields, so
    //     the shorthand is a constructor.
    /// A node with everything but `Op` at its zero value.
    pub fn __new(op: Op) -> Regexp {
        let mut re = Regexp::default();
        re.Op = op;
        return re;
    }

    // go: sdk 1.25.5 regexp/syntax/regexp.go:63-99 Regexp.Equal
    /// Go: "Equal reports whether x and y have identical structure."
    ///
    /// Note what it does NOT compare: `Flags` in general. Only three
    /// bits matter — `WasDollar` under `OpEndText`, because it is what
    /// separates `$` from `\z`, and `NonGreedy` under the repeats. Two
    /// nodes differing in `FoldCase` alone are Equal, because the
    /// parser folds case into the rune list rather than leaving it in
    /// the flag.
    pub fn Equal(&self, y: &Regexp) -> bool {
        // Go's `if x == nil || y == nil { return x == y }` has no
        // counterpart: a goish `&Regexp` is never nil, and a caller
        // holding an absent node holds `None`.
        if self.Op != y.Op {
            return false;
        }
        if self.Op == OpEndText {
            // Go: "The parse flags remember whether this is \z or \Z."
            if (self.Flags & WasDollar) != (y.Flags & WasDollar) {
                return false;
            }
            return true;
        }
        if self.Op == OpLiteral || self.Op == OpCharClass {
            return self.Rune == y.Rune;
        }
        if self.Op == OpAlternate || self.Op == OpConcat {
            if self.Sub.len() != y.Sub.len() {
                return false;
            }
            for i in 0..self.Sub.len() {
                if !self.Sub[i].Equal(&y.Sub[i]) {
                    return false;
                }
            }
            return true;
        }
        if self.Op == OpStar || self.Op == OpPlus || self.Op == OpQuest {
            if (self.Flags & NonGreedy) != (y.Flags & NonGreedy)
                || !self.Sub[0].Equal(&y.Sub[0])
            {
                return false;
            }
            return true;
        }
        if self.Op == OpRepeat {
            if (self.Flags & NonGreedy) != (y.Flags & NonGreedy)
                || self.Min != y.Min
                || self.Max != y.Max
                || !self.Sub[0].Equal(&y.Sub[0])
            {
                return false;
            }
            return true;
        }
        if self.Op == OpCapture {
            if self.Cap != y.Cap || self.Name != y.Name || !self.Sub[0].Equal(&y.Sub[0]) {
                return false;
            }
            return true;
        }
        return true;
    }

    // go: sdk 1.25.5 regexp/syntax/regexp.go:384-394 Regexp.String
    /// The Perl syntax for this tree — the round trip Go's parser tests
    /// check against.
    pub fn String(&self) -> string {
        let mut b = string::new();
        let mut flags: map<usize, printFlags> = map::new();
        let (mut must, cant) = calcFlags(self, &mut flags);
        // Go: must |= (cant &^ flagI) << negShift
        must |= printFlags((cant.0 & !flagI.0) << negShift);
        if must.0 != 0 {
            must |= flagOff;
        }
        writeRegexp(&mut b, self, must, &flags);
        return b;
    }

    // go: sdk 1.25.5 regexp/syntax/regexp.go:437-448 Regexp.MaxCap
    /// Go: "MaxCap walks the regexp to find the maximum capture index."
    pub fn MaxCap(&self) -> int {
        let mut m: int = int::from(0);
        if self.Op == OpCapture {
            m = self.Cap;
        }
        for sub in self.Sub.iter() {
            let n = sub.MaxCap();
            if m < n {
                m = n;
            }
        }
        return m;
    }

    // go: sdk 1.25.5 regexp/syntax/regexp.go:451-455 Regexp.CapNames
    /// Go: "CapNames walks the regexp to find the names of capturing
    /// groups." Index 0 is the whole match and is always empty.
    pub fn CapNames(&self) -> crate::goslice::slice<string> {
        let n = crate::int64(self.MaxCap()) as usize + 1;
        let mut names: Vec<string> = Vec::with_capacity(n);
        names.resize(n, string::new());
        self.capNames(&mut names);
        return crate::goslice::slice::__from_vec(names);
    }

    // go: sdk 1.25.5 regexp/syntax/regexp.go:457-464 Regexp.capNames
    /// The recursive half of [`Regexp::CapNames`].
    fn capNames(&self, names: &mut Vec<string>) {
        if self.Op == OpCapture {
            names[crate::int64(self.Cap) as usize] = self.Name.clone();
        }
        for sub in self.Sub.iter() {
            sub.capNames(names);
        }
    }

    // go: none — goish idiom: Go keys `map[*Regexp]printFlags` on the
    //     node's address. goish keys on the same address as an integer,
    //     which is what a `map<usize, _>` can hash.
    /// This node's identity, for the print-flags map.
    fn __id(&self) -> usize {
        return self as *const Regexp as usize;
    }
}

// go: sdk 1.25.5 regexp/syntax/regexp.go:103-103 printFlags
/// Go: "printFlags is a bit set indicating which flags (including
/// non-capturing parens) to print around a regexp."
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) struct printFlags(pub u8);

impl core::ops::BitOr for printFlags {
    type Output = printFlags;
    // go: none — goish idiom: Go's `printFlags` is a defined integer
    //     type and gets its operators free; a Rust newtype spells them
    //     out.
    fn bitor(self, o: printFlags) -> printFlags {
        return printFlags(self.0 | o.0);
    }
}

impl core::ops::BitAnd for printFlags {
    type Output = printFlags;
    // go: none — goish idiom: see the note on `BitOr`.
    fn bitand(self, o: printFlags) -> printFlags {
        return printFlags(self.0 & o.0);
    }
}

impl core::ops::BitOrAssign for printFlags {
    // go: none — goish idiom: see the note on `BitOr`.
    fn bitor_assign(&mut self, o: printFlags) {
        self.0 |= o.0;
    }
}

// go: sdk 1.25.5 regexp/syntax/regexp.go:104-110 flagI
/// `(?i:`
const flagI: printFlags = printFlags(1 << 0);
// go: none — goish-only placement: Go declares these in one `iota`
//     block with `flagI` (regexp.go lines 104-110).
/// `(?m:`
const flagM: printFlags = printFlags(1 << 1);
/// `(?s:`
const flagS: printFlags = printFlags(1 << 2);
/// `)`
const flagOff: printFlags = printFlags(1 << 3);
/// `(?: )`
const flagPrec: printFlags = printFlags(1 << 4);
/// `flagI << negShift` is `(?-i:`.
const negShift: u8 = 5;

// go: sdk 1.25.5 regexp/syntax/regexp.go:112-121 addSpan
/// Go: "addSpan enables the flags f around start..last, by setting
/// flags[start] = f and flags[last] = flagOff."
///
/// Go's comment "maybe start==last" is the whole subtlety: when the
/// span is one node, that node gets both `f` and `flagOff`.
fn addSpan(start: &Regexp, last: &Regexp, f: printFlags, flags: &mut map<usize, printFlags>) {
    flags.Set(start.__id(), f);
    let (prev, _) = flags.Get(last.__id());
    flags.Set(last.__id(), prev | flagOff);
}

// go: sdk 1.25.5 regexp/syntax/regexp.go:129-222 calcFlags
/// Go: "calcFlags calculates the flags to print around each
/// subexpression in re, storing that information in (*flags)[sub] for
/// each affected subexpression. calcFlags also calculates the flags
/// that must be active or can't be active around re and returns those
/// flags."
///
/// The `OpCharClass` arm is the expensive one and it is Go's: for every
/// rune in every range it walks the fold orbit looking for a member the
/// class does NOT contain, because that is what makes the class
/// fold-sensitive. Bounded by `minFold..maxFold`, but still a scan.
fn calcFlags(re: &Regexp, flags: &mut map<usize, printFlags>) -> (printFlags, printFlags) {
    if re.Op == OpLiteral {
        // Go: "If literal is fold-sensitive, return (flagI, 0) or
        // (0, flagI) according to whether (?i) is active."
        for r in re.Rune.iter() {
            if minFold <= *r && *r <= maxFold && crate::unicode::SimpleFold(*r) != *r {
                if re.Flags.__has(FoldCase) {
                    return (flagI, printFlags(0));
                }
                return (printFlags(0), flagI);
            }
        }
        return (printFlags(0), printFlags(0));
    }
    if re.Op == OpCharClass {
        // Go: "If literal is fold-sensitive, return 0, flagI — (?i) has
        // been compiled out."
        let mut i = 0usize;
        while i < re.Rune.len() {
            let lo = if minFold > re.Rune[i] {
                minFold
            } else {
                re.Rune[i]
            };
            let hi = if maxFold < re.Rune[i + 1] {
                maxFold
            } else {
                re.Rune[i + 1]
            };
            let mut r = lo;
            while r <= hi {
                let mut f = crate::unicode::SimpleFold(r);
                while f != r {
                    if !(lo <= f && f <= hi) && !inCharClass(f, &re.Rune) {
                        return (printFlags(0), flagI);
                    }
                    f = crate::unicode::SimpleFold(f);
                }
                r += 1;
            }
            i += 2;
        }
        return (printFlags(0), printFlags(0));
    }
    if re.Op == OpAnyCharNotNL {
        // Go: (?-s).
        return (printFlags(0), flagS);
    }
    if re.Op == OpAnyChar {
        // Go: (?s).
        return (flagS, printFlags(0));
    }
    if re.Op == OpBeginLine || re.Op == OpEndLine {
        // Go: (?m)^ (?m)$
        return (flagM, printFlags(0));
    }
    if re.Op == OpEndText {
        if re.Flags.__has(WasDollar) {
            // Go: (?-m)$
            return (printFlags(0), flagM);
        }
        return (printFlags(0), printFlags(0));
    }
    if re.Op == OpCapture
        || re.Op == OpStar
        || re.Op == OpPlus
        || re.Op == OpQuest
        || re.Op == OpRepeat
    {
        return calcFlags(&re.Sub[0], flags);
    }
    if re.Op == OpConcat || re.Op == OpAlternate {
        // Go: "Gather the must and cant for each subexpression. When we
        // find a conflicting subexpression, insert the necessary flags
        // around the previously identified span and start over."
        let mut must = printFlags(0);
        let mut cant = printFlags(0);
        let mut allCant = printFlags(0);
        let mut start = 0usize;
        let mut last = 0usize;
        let mut did = false;
        for i in 0..re.Sub.len() {
            let (subMust, subCant) = calcFlags(&re.Sub[i], flags);
            if (must & subCant).0 != 0 || (subMust & cant).0 != 0 {
                if must.0 != 0 {
                    addSpan(&re.Sub[start], &re.Sub[last], must, flags);
                }
                must = printFlags(0);
                cant = printFlags(0);
                start = i;
                did = true;
            }
            must |= subMust;
            cant |= subCant;
            allCant |= subCant;
            if subMust.0 != 0 {
                last = i;
            }
            if must.0 == 0 && start == i {
                start += 1;
            }
        }
        if !did {
            // Go: "No conflicts: pass the accumulated must and cant
            // upward."
            return (must, cant);
        }
        if must.0 != 0 {
            // Go: "Conflicts found; need to finish final span."
            addSpan(&re.Sub[start], &re.Sub[last], must, flags);
        }
        return (printFlags(0), allCant);
    }
    // Go's `default: return 0, 0`.
    return (printFlags(0), printFlags(0));
}

// go: sdk 1.25.5 regexp/syntax/regexp.go:220-381 writeRegexp
/// Go: "writeRegexp writes the Perl syntax for the regular expression
/// re to b."
///
/// Go uses two `defer b.WriteString(")")` to close the groups it opens.
/// Rust has no defer, so the two closers are booleans written at the
/// end — the order matters and is Go's: LIFO, so `flagPrec`'s paren
/// closes before `flagOff`'s.
fn writeRegexp(b: &mut string, re: &Regexp, f0: printFlags, flags: &map<usize, printFlags>) {
    let (entry, _) = flags.Get(re.__id());
    let mut f = f0 | entry;
    if (f & flagPrec).0 != 0
        && (f.0 & !(flagOff.0 | flagPrec.0)) != 0
        && (f & flagOff).0 != 0
    {
        // Go: "flagPrec is redundant with other flags being added and
        // terminated."
        f = printFlags(f.0 & !flagPrec.0);
    }
    if (f.0 & !(flagOff.0 | flagPrec.0)) != 0 {
        *b = b.clone() + string::from_static("(?");
        if (f & flagI).0 != 0 {
            *b = b.clone() + string::from_static("i");
        }
        if (f & flagM).0 != 0 {
            *b = b.clone() + string::from_static("m");
        }
        if (f & flagS).0 != 0 {
            *b = b.clone() + string::from_static("s");
        }
        if (f.0 & ((flagM.0 | flagS.0) << negShift)) != 0 {
            *b = b.clone() + string::from_static("-");
            if (f.0 & (flagM.0 << negShift)) != 0 {
                *b = b.clone() + string::from_static("m");
            }
            if (f.0 & (flagS.0 << negShift)) != 0 {
                *b = b.clone() + string::from_static("s");
            }
        }
        *b = b.clone() + string::from_static(":");
    }
    // Go: defer b.WriteString(`)`) — see the note on this function.
    let close_off = (f & flagOff).0 != 0;
    let close_prec = (f & flagPrec).0 != 0;
    if close_prec {
        *b = b.clone() + string::from_static("(?:");
    }

    __writeBody(b, re, flags);

    // Go's two defers unwind LIFO: flagPrec's `)` was deferred second,
    // so it is written first.
    if close_prec {
        *b = b.clone() + string::from_static(")");
    }
    if close_off {
        *b = b.clone() + string::from_static(")");
    }
}

// go: none — goish idiom: the body of Go's `writeRegexp` switch, split
//     out because Go's two `defer`s have to run after it and Rust has
//     no defer. Splitting keeps the deferred writes in one place
//     instead of duplicating them down every `return`.
/// The per-operator rendering.
fn __writeBody(b: &mut string, re: &Regexp, flags: &map<usize, printFlags>) {
    if re.Op == OpNoMatch {
        *b = b.clone() + string::from_static("[^\\x00-\\x{10FFFF}]");
        return;
    }
    if re.Op == OpEmptyMatch {
        *b = b.clone() + string::from_static("(?:)");
        return;
    }
    if re.Op == OpLiteral {
        for r in re.Rune.iter() {
            escape(b, *r, false);
        }
        return;
    }
    if re.Op == OpCharClass {
        if re.Rune.len() % 2 != 0 {
            *b = b.clone() + string::from_static("[invalid char class]");
            return;
        }
        *b = b.clone() + string::from_static("[");
        if re.Rune.is_empty() {
            *b = b.clone() + string::from_static("^\\x00-\\x{10FFFF}");
        } else if re.Rune[0] == 0
            && re.Rune[re.Rune.len() - 1] == crate::unicode::MaxRune
            && re.Rune.len() > 2
        {
            // Go: "Contains 0 and MaxRune. Probably a negated class.
            // Print the gaps."
            *b = b.clone() + string::from_static("^");
            let mut i = 1usize;
            while i < re.Rune.len() - 1 {
                let lo = re.Rune[i] + 1;
                let hi = re.Rune[i + 1] - 1;
                escape(b, lo, lo == rune('-'));
                if lo != hi {
                    if hi != lo + 1 {
                        *b = b.clone() + string::from_static("-");
                    }
                    escape(b, hi, hi == rune('-'));
                }
                i += 2;
            }
        } else {
            let mut i = 0usize;
            while i < re.Rune.len() {
                let lo = re.Rune[i];
                let hi = re.Rune[i + 1];
                escape(b, lo, lo == rune('-'));
                if lo != hi {
                    if hi != lo + 1 {
                        *b = b.clone() + string::from_static("-");
                    }
                    escape(b, hi, hi == rune('-'));
                }
                i += 2;
            }
        }
        *b = b.clone() + string::from_static("]");
        return;
    }
    if re.Op == OpAnyCharNotNL || re.Op == OpAnyChar {
        *b = b.clone() + string::from_static(".");
        return;
    }
    if re.Op == OpBeginLine {
        *b = b.clone() + string::from_static("^");
        return;
    }
    if re.Op == OpEndLine {
        *b = b.clone() + string::from_static("$");
        return;
    }
    if re.Op == OpBeginText {
        *b = b.clone() + string::from_static("\\A");
        return;
    }
    if re.Op == OpEndText {
        if re.Flags.__has(WasDollar) {
            *b = b.clone() + string::from_static("$");
        } else {
            *b = b.clone() + string::from_static("\\z");
        }
        return;
    }
    if re.Op == OpWordBoundary {
        *b = b.clone() + string::from_static("\\b");
        return;
    }
    if re.Op == OpNoWordBoundary {
        *b = b.clone() + string::from_static("\\B");
        return;
    }
    if re.Op == OpCapture {
        if re.Name.Len() != 0 {
            *b = b.clone() + string::from_static("(?P<") + re.Name.clone() + string::from_static(">");
        } else {
            *b = b.clone() + string::from_static("(");
        }
        if re.Sub[0].Op != OpEmptyMatch {
            let (sf, _) = flags.Get(re.Sub[0].__id());
            writeRegexp(b, &re.Sub[0], sf, flags);
        }
        *b = b.clone() + string::from_static(")");
        return;
    }
    if re.Op == OpStar || re.Op == OpPlus || re.Op == OpQuest || re.Op == OpRepeat {
        let mut p = printFlags(0);
        let sub = &re.Sub[0];
        // The `>` is why the Op order is load-bearing: everything above
        // OpCapture is a repeat, a concat or an alternation, and each
        // needs `(?:)` around it before a quantifier binds.
        if sub.Op > OpCapture || (sub.Op == OpLiteral && sub.Rune.len() > 1) {
            p = flagPrec;
        }
        writeRegexp(b, sub, p, flags);

        if re.Op == OpStar {
            *b = b.clone() + string::from_static("*");
        } else if re.Op == OpPlus {
            *b = b.clone() + string::from_static("+");
        } else if re.Op == OpQuest {
            *b = b.clone() + string::from_static("?");
        } else if re.Op == OpRepeat {
            *b = b.clone() + string::from_static("{") + crate::strconv::Itoa(re.Min);
            if re.Max != re.Min {
                *b = b.clone() + string::from_static(",");
                if crate::int64(re.Max) >= 0 {
                    *b = b.clone() + crate::strconv::Itoa(re.Max);
                }
            }
            *b = b.clone() + string::from_static("}");
        }
        if re.Flags.__has(NonGreedy) {
            *b = b.clone() + string::from_static("?");
        }
        return;
    }
    if re.Op == OpConcat {
        for sub in re.Sub.iter() {
            let mut p = printFlags(0);
            if sub.Op == OpAlternate {
                p = flagPrec;
            }
            writeRegexp(b, sub, p, flags);
        }
        return;
    }
    if re.Op == OpAlternate {
        for i in 0..re.Sub.len() {
            if i > 0 {
                *b = b.clone() + string::from_static("|");
            }
            writeRegexp(b, &re.Sub[i], printFlags(0), flags);
        }
        return;
    }
    // Go's `default`.
    *b = b.clone()
        + string::from_static("<invalid op")
        + crate::strconv::Itoa(int::from(crate::int64(re.Op.0)))
        + string::from_static(">");
}

// go: sdk 1.25.5 regexp/syntax/regexp.go:396-396 meta
/// The characters `escape` backslashes when they are printable.
const meta: &str = "\\.+*?()|[]{}^$";

// go: none — goish idiom: Go writes `strings.ContainsRune(meta, r)`.
//     goish's `strings::ContainsRune` takes a `string`, and building
//     one per rune to search fourteen ASCII bytes is not what Go does
//     either — its `meta` is a constant and the search is a byte scan.
/// Whether `r` is one of the fourteen metacharacters.
fn __is_meta(r: rune) -> bool {
    if r >= 0x80 {
        return false;
    }
    return meta.as_bytes().contains(&crate::uint8(crate::uint32(crate::int64(r))));
}

// go: sdk 1.25.5 regexp/syntax/regexp.go:398-434 escape
/// Write `r`, backslashed if it is a metacharacter or `force` says so,
/// and as an escape sequence if it is not printable.
///
/// `force` exists for one case: a `-` inside a character class, where
/// the character is not a metacharacter outside brackets but would
/// start a range inside them.
fn escape(b: &mut string, r: rune, force: bool) {
    if crate::unicode::IsPrint(r) {
        if __is_meta(r) || force {
            *b = b.clone() + string::from_static("\\");
        }
        *b = b.clone() + crate::string(r);
        return;
    }

    if r == rune('\x07') {
        *b = b.clone() + string::from_static("\\a");
        return;
    }
    if r == rune('\x0c') {
        *b = b.clone() + string::from_static("\\f");
        return;
    }
    if r == rune('\n') {
        *b = b.clone() + string::from_static("\\n");
        return;
    }
    if r == rune('\r') {
        *b = b.clone() + string::from_static("\\r");
        return;
    }
    if r == rune('\t') {
        *b = b.clone() + string::from_static("\\t");
        return;
    }
    if r == rune('\x0b') {
        *b = b.clone() + string::from_static("\\v");
        return;
    }
    if r < 0x100 {
        *b = b.clone() + string::from_static("\\x");
        let s = crate::strconv::FormatInt(int::from(crate::int64(r)), 16);
        if s.Len() == 1 {
            *b = b.clone() + string::from_static("0");
        }
        *b = b.clone() + s;
        return;
    }
    *b = b.clone()
        + string::from_static("\\x{")
        + crate::strconv::FormatInt(int::from(crate::int64(r)), 16)
        + string::from_static("}");
}
