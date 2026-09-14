// Port of Go 1.25.5 regexp/syntax/prog.go.
//
// The compiled-program representation the RE2 construction runs on:
// an instruction array with explicit `Out`/`Arg` links, so a match is
// a walk over integers rather than a recursion over an AST.
//
// This is the foundation of §2c. goish's live matcher backtracks over
// the AST and is exponential on `(a+)+$` — 27 seconds at 22 characters
// where Go answers in under a millisecond — and the reason a step
// budget or a memo table cannot fix it is that its state is
// (node, pos, caps, CONTINUATION), which has no bounded key. Compiling
// to a program is what makes the key `(pc, pos)`, and the pc is what
// this file introduces. Nothing here is wired to the live matcher yet.

use alloc::vec::Vec;

use crate::gostring::string;
use crate::{int, rune};

use super::parse::{Flags, FoldCase};


// go: sdk 1.25.5 regexp/syntax/prog.go:18-22 Prog
/// Go: "A Prog is a compiled regular expression program."
#[derive(Clone, Default)]
pub struct Prog {
    pub Inst: Vec<Inst>,
    /// Index of start instruction.
    pub Start: int,
    /// Number of `InstCapture` insts in re.
    pub NumCap: int,
}

// go: sdk 1.25.5 regexp/syntax/prog.go:24-25 InstOp
/// Go: "An InstOp is an instruction opcode."
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct InstOp(pub u8);

// go: sdk 1.25.5 regexp/syntax/prog.go:27-39 InstAlt
/// The eleven opcodes, in Go's `iota` order — the order matters
/// because `InstOp::String` indexes a table with it.
pub const InstAlt: InstOp = InstOp(0);
// go: none — goish-only placement: Go declares all eleven in one
//     `iota` block with `InstAlt` (prog.go lines 27-39).
pub const InstAltMatch: InstOp = InstOp(1);
pub const InstCapture: InstOp = InstOp(2);
pub const InstEmptyWidth: InstOp = InstOp(3);
pub const InstMatch: InstOp = InstOp(4);
pub const InstFail: InstOp = InstOp(5);
pub const InstNop: InstOp = InstOp(6);
pub const InstRune: InstOp = InstOp(7);
pub const InstRune1: InstOp = InstOp(8);
pub const InstRuneAny: InstOp = InstOp(9);
pub const InstRuneAnyNotNL: InstOp = InstOp(10);

// go: sdk 1.25.5 regexp/syntax/prog.go:41-53 instOpNames
/// Go: `var instOpNames = []string{…}`.
static instOpNames: [&str; 11] = [
    "InstAlt",
    "InstAltMatch",
    "InstCapture",
    "InstEmptyWidth",
    "InstMatch",
    "InstFail",
    "InstNop",
    "InstRune",
    "InstRune1",
    "InstRuneAny",
    "InstRuneAnyNotNL",
];

impl InstOp {
    // go: sdk 1.25.5 regexp/syntax/prog.go:55-60 InstOp.String
    /// Go: an out-of-range opcode renders as the EMPTY string, not as
    /// a number and not a panic.
    pub fn String(&self) -> string {
        if (self.0 as usize) >= instOpNames.len() {
            return string::new();
        }
        return string::from_static(instOpNames[self.0 as usize]);
    }
}

// go: sdk 1.25.5 regexp/syntax/prog.go:62-63 EmptyOp
/// Go: "An EmptyOp specifies a kind or mixture of zero-width
/// assertions."
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct EmptyOp(pub u8);

// go: sdk 1.25.5 regexp/syntax/prog.go:65-72 EmptyBeginLine
/// The six zero-width assertions, in Go's `iota` order.
pub const EmptyBeginLine: EmptyOp = EmptyOp(1 << 0);
// go: none — goish-only placement: Go declares all six in one `iota`
//     block with `EmptyBeginLine` (prog.go lines 65-72).
pub const EmptyEndLine: EmptyOp = EmptyOp(1 << 1);
pub const EmptyBeginText: EmptyOp = EmptyOp(1 << 2);
pub const EmptyEndText: EmptyOp = EmptyOp(1 << 3);
pub const EmptyWordBoundary: EmptyOp = EmptyOp(1 << 4);
pub const EmptyNoWordBoundary: EmptyOp = EmptyOp(1 << 5);

impl core::ops::BitOr for EmptyOp {
    type Output = EmptyOp;
    // go: none — goish idiom: see the note above this impl.
    fn bitor(self, o: EmptyOp) -> EmptyOp {
        return EmptyOp(self.0 | o.0);
    }
}

impl core::ops::BitOrAssign for EmptyOp {
    // go: none — goish idiom: see the note above this impl.
    fn bitor_assign(&mut self, o: EmptyOp) {
        self.0 |= o.0;
    }
}

impl core::ops::BitXorAssign for EmptyOp {
    // go: none — goish idiom: see the note above this impl.
    fn bitxor_assign(&mut self, o: EmptyOp) {
        self.0 ^= o.0;
    }
}

impl core::ops::BitAnd for EmptyOp {
    type Output = EmptyOp;
    // go: none — goish idiom: see the note on `BitOr`.
    fn bitand(self, o: EmptyOp) -> EmptyOp {
        return EmptyOp(self.0 & o.0);
    }
}

impl core::ops::Not for EmptyOp {
    type Output = EmptyOp;
    // go: none — goish idiom: see the note above this impl.
    fn not(self) -> EmptyOp {
        return EmptyOp(!self.0);
    }
}

// go: sdk 1.25.5 regexp/syntax/prog.go:80-103 EmptyOpContext
/// Go: "EmptyOpContext returns the zero-width assertions satisfied at
/// the position between the runes r1 and r2. Passing r1 == -1
/// indicates that the position is at the beginning of the text.
/// Passing r2 == -1 indicates that the position is at the end of the
/// text."
///
/// The `boundary` byte is Go's trick for `IsWordChar(r1) !=
/// IsWordChar(r2)` without two calls: set on one side, XOR-ed on the
/// other, so it survives only when exactly one is a word character.
pub fn EmptyOpContext(r1: rune, r2: rune) -> EmptyOp {
    let mut op: EmptyOp = EmptyNoWordBoundary;
    let mut boundary: u8 = 0;
    if IsWordChar(r1) {
        boundary = 1;
    } else if r1 == (rune('\n')) {
        op |= EmptyBeginLine;
    } else if r1 < 0 {
        op |= EmptyBeginText | EmptyBeginLine;
    }
    if IsWordChar(r2) {
        boundary ^= 1;
    } else if r2 == (rune('\n')) {
        op |= EmptyEndLine;
    } else if r2 < 0 {
        op |= EmptyEndText | EmptyEndLine;
    }
    // Go: if boundary != 0 { // IsWordChar(r1) != IsWordChar(r2)
    if boundary != 0 {
        op ^= EmptyWordBoundary | EmptyNoWordBoundary;
    }
    return op;
}

// go: sdk 1.25.5 regexp/syntax/prog.go:108-112 IsWordChar
/// Go: "IsWordChar reports whether r is considered a 'word character'
/// during the evaluation of the \b and \B zero-width assertions. These
/// assertions are ASCII-only: the word characters are [A-Za-z0-9_]."
///
/// ASCII-only is the whole point and easy to 'improve' by mistake: `é`
/// is not a word character here, in Go or in RE2.
pub fn IsWordChar(r: rune) -> bool {
    // Go tests lowercase first, "as these occur more frequently than
    // uppercase letters in common cases".
    return (rune('a')) <= r && r <= (rune('z'))
        || (rune('A')) <= r && r <= (rune('Z'))
        || (rune('0')) <= r && r <= (rune('9'))
        || r == (rune('_'));
}

// go: sdk 1.25.5 regexp/syntax/prog.go:110-120 Inst
/// Go: "An Inst is a single instruction in a regular expression
/// program."
#[derive(Clone, Default)]
pub struct Inst {
    pub Op: InstOp,
    /// All but `InstMatch`, `InstFail`.
    pub Out: u32,
    /// `InstAlt`, `InstAltMatch`, `InstCapture`, `InstEmptyWidth`.
    pub Arg: u32,
    pub Rune: Vec<rune>,
}

impl Prog {
    // go: sdk 1.25.5 regexp/syntax/prog.go:122-126 Prog.String
    /// The `pc\tinstruction` dump Go's tests compare against.
    pub fn String(&self) -> string {
        let mut b = string::new();
        dumpProg(&mut b, self);
        return b;
    }

    // go: sdk 1.25.5 regexp/syntax/prog.go:128-135 Prog.skipNop
    /// Go: "skipNop follows any no-op or capturing instructions."
    ///
    /// Returns an INDEX where Go returns a pointer: a `&Inst` borrowed
    /// from `self.Inst` cannot be re-assigned inside the loop without
    /// fighting the borrow checker, and every caller wants to index
    /// again anyway.
    fn skipNop(&self, pc: u32) -> usize {
        let mut i = pc as usize;
        while self.Inst[i].Op == InstNop || self.Inst[i].Op == InstCapture {
            i = self.Inst[i].Out as usize;
        }
        return i;
    }

    // go: sdk 1.25.5 regexp/syntax/prog.go:146-164 Prog.Prefix
    /// Go: "Prefix returns a literal string that all matches for the
    /// regexp must start with. Complete is true if the prefix is the
    /// entire match."
    ///
    /// The three conditions on the gather loop are each load-bearing:
    /// a folded instruction matches more than its own rune, and
    /// `RuneError` is what a decode failure produces, so neither can
    /// go into a literal prefix.
    pub fn Prefix(&self) -> (string, bool) {
        let mut i = self.skipNop(crate::uint32(i64::from(self.Start)));

        // Go: "Avoid allocation of buffer if prefix is empty."
        if self.Inst[i].op() != InstRune || self.Inst[i].Rune.len() != 1 {
            return (string::new(), self.Inst[i].Op == InstMatch);
        }

        // Go: "Have prefix; gather characters."
        let mut buf: Vec<rune> = Vec::new();
        while self.Inst[i].op() == InstRune
            && self.Inst[i].Rune.len() == 1
            && !Flags::from(self.Inst[i].Arg).__has(FoldCase)
            && self.Inst[i].Rune[0] != crate::unicode::utf8::RuneError
        {
            buf.push(self.Inst[i].Rune[0]);
            i = self.skipNop(self.Inst[i].Out);
        }
        return (runes_to_string(&buf), self.Inst[i].Op == InstMatch);
    }

    // go: sdk 1.25.5 regexp/syntax/prog.go:169-189 Prog.StartCond
    /// Go: "StartCond returns the leading empty-width conditions that
    /// must be true in any match. It returns ^EmptyOp(0) if no matches
    /// are possible."
    pub fn StartCond(&self) -> EmptyOp {
        let mut flag: EmptyOp = EmptyOp(0);
        let mut pc = crate::uint32(i64::from(self.Start));
        loop {
            let i = &self.Inst[pc as usize];
            if i.Op == InstEmptyWidth {
                flag |= EmptyOp(crate::uint8(i.Arg));
            } else if i.Op == InstFail {
                return !EmptyOp(0);
            } else if i.Op == InstCapture || i.Op == InstNop {
                // skip
            } else {
                // Go: break Loop
                break;
            }
            pc = i.Out;
        }
        return flag;
    }
}

// go: sdk 1.25.5 regexp/syntax/prog.go:191-191 noMatch
/// Go: `const noMatch = -1`.
const noMatch: int = -1;

impl Inst {
    // go: sdk 1.25.5 regexp/syntax/prog.go:137-144 Inst.op
    /// Go: "op returns i.Op but merges all the Rune special cases into
    /// InstRune".
    fn op(&self) -> InstOp {
        let op = self.Op;
        if op == InstRune1 || op == InstRuneAny || op == InstRuneAnyNotNL {
            return InstRune;
        }
        return op;
    }

    // go: sdk 1.25.5 regexp/syntax/prog.go:195-197 Inst.MatchRune
    /// Go: "MatchRune reports whether the instruction matches (and
    /// consumes) r. It should only be called when i.Op == InstRune."
    pub fn MatchRune(&self, r: rune) -> bool {
        return self.MatchRunePos(r) != noMatch;
    }

    // go: sdk 1.25.5 regexp/syntax/prog.go:204-261 Inst.MatchRunePos
    /// Go: "MatchRunePos checks whether the instruction matches (and
    /// consumes) r. If so, MatchRunePos returns the index of the
    /// matching rune pair (or, when len(i.Rune) == 1, rune singleton).
    /// If not, MatchRunePos returns -1."
    ///
    /// Three strategies by size, which is Go's and not an
    /// optimisation invented here: a length-1 slice is a LITERAL and
    /// honours FoldCase, 2 is one range, 4/6/8 are linear because
    /// ASCII classes land there, and everything larger binary-searches.
    pub fn MatchRunePos(&self, r: rune) -> int {
        let rune_ = &self.Rune;

        match rune_.len() {
            0 => {
                return noMatch;
            }
            1 => {
                // Go: "Special case: single-rune slice is from literal
                // string, not char class."
                let r0 = rune_[0];
                if r == r0 {
                    return 0;
                }
                if Flags::from(self.Arg).__has(FoldCase) {
                    let mut r1 = crate::unicode::SimpleFold(r0);
                    while r1 != r0 {
                        if r == r1 {
                            return 0;
                        }
                        r1 = crate::unicode::SimpleFold(r1);
                    }
                }
                return noMatch;
            }
            2 => {
                if r >= rune_[0] && r <= rune_[1] {
                    return 0;
                }
                return noMatch;
            }
            4 | 6 | 8 => {
                // Go: "Linear search for a few pairs. Should handle
                // ASCII well."
                let mut j = 0usize;
                while j < rune_.len() {
                    if r < rune_[j] {
                        return noMatch;
                    }
                    if r <= rune_[j + 1] {
                        return int::from(crate::int64(j / 2));
                    }
                    j += 2;
                }
                return noMatch;
            }
            _ => {}
        }

        // Go: "Otherwise binary search."
        let mut lo = 0usize;
        let mut hi = rune_.len() / 2;
        while lo < hi {
            let m = (lo + hi) >> 1;
            let c = rune_[2 * m];
            if c <= r {
                if r <= rune_[2 * m + 1] {
                    return int::from(crate::int64(m));
                }
                lo = m + 1;
            } else {
                hi = m;
            }
        }
        return noMatch;
    }

    // go: sdk 1.25.5 regexp/syntax/prog.go:266-282 Inst.MatchEmptyWidth
    /// Go: "MatchEmptyWidth reports whether the instruction matches an
    /// empty string between the runes before and after. It should only
    /// be called when i.Op == InstEmptyWidth."
    ///
    /// Go's switch is on the WHOLE `EmptyOp(i.Arg)`, not on individual
    /// bits, and its default is `panic("unknown empty width arg")`. A
    /// mixture therefore reaches the panic, which is why the compiler
    /// only ever emits one bit here.
    pub fn MatchEmptyWidth(&self, before: rune, after: rune) -> bool {
        let a = EmptyOp(crate::uint8(self.Arg));
        if a == EmptyBeginLine {
            return before == (rune('\n')) || before == -1;
        }
        if a == EmptyEndLine {
            return after == (rune('\n')) || after == -1;
        }
        if a == EmptyBeginText {
            return before == -1;
        }
        if a == EmptyEndText {
            return after == -1;
        }
        if a == EmptyWordBoundary {
            return IsWordChar(before) != IsWordChar(after);
        }
        if a == EmptyNoWordBoundary {
            return IsWordChar(before) == IsWordChar(after);
        }
        panic!("unknown empty width arg");
    }

    // go: sdk 1.25.5 regexp/syntax/prog.go:284-288 Inst.String
    /// One line of `Prog.String`'s dump.
    pub fn String(&self) -> string {
        let mut b = string::new();
        dumpInst(&mut b, self);
        return b;
    }
}

// go: none — goish idiom: Go builds a `[]rune` into a string with
//     `string(runes)`. goish has no such conversion, so the encode is
//     explicit.
/// UTF-8 encode a rune slice.
fn runes_to_string(rs: &[rune]) -> string {
    let mut out: Vec<u8> = Vec::new();
    for r in rs.iter() {
        let mut buf = [0u8; 4];
        let n = crate::unicode::utf8::EncodeRune(&mut buf, *r);
        out.extend_from_slice(&buf[..i64::from(n) as usize]);
    }
    return string::from_bytes(&out);
}

// go: sdk 1.25.5 regexp/syntax/prog.go:296-310 dumpProg
/// Go pads the pc to three columns, marks the start instruction with
/// `*`, and separates with a tab.
fn dumpProg(b: &mut string, p: &Prog) {
    for j in 0..p.Inst.len() {
        let mut pc = crate::strconv::Itoa(int::from(crate::int64(j)));
        if pc.Len() < 3 {
            // Go: b.WriteString("   "[len(pc):]) — pad to width 3.
            let pad = 3 - i64::from(pc.Len()) as usize;
            bw(b, string::from_bytes(&b"   "[..pad]));
        }
        if int::from(crate::int64(j)) == p.Start {
            pc = pc + string::from_static("*");
        }
        bw(b, pc);
        bw(b, string::from_static("\t"));
        dumpInst(b, &p.Inst[j]);
        bw(b, string::from_static("\n"));
    }
}

// go: sdk 1.25.5 regexp/syntax/prog.go:290-294 bw
/// Go: `func bw(b *strings.Builder, args ...string)`. goish has no
/// variadic, so it appends one at a time; every Go call site that
/// passes a list is expanded into a run of these.
fn bw(b: &mut string, s: string) {
    *b = b.clone() + s;
}

// go: sdk 1.25.5 regexp/syntax/prog.go:312-314 u32
/// Go: `strconv.FormatUint(uint64(i), 10)`.
fn u32_(i: u32) -> string {
    return crate::strconv::FormatUint(crate::types::uint::from(crate::uint64(i)), 10);
}

// go: sdk 1.25.5 regexp/syntax/prog.go:316-349 dumpInst
/// The per-opcode rendering.
fn dumpInst(b: &mut string, i: &Inst) {
    if i.Op == InstAlt {
        bw(b, string::from_static("alt -> "));
        bw(b, u32_(i.Out));
        bw(b, string::from_static(", "));
        bw(b, u32_(i.Arg));
        return;
    }
    if i.Op == InstAltMatch {
        bw(b, string::from_static("altmatch -> "));
        bw(b, u32_(i.Out));
        bw(b, string::from_static(", "));
        bw(b, u32_(i.Arg));
        return;
    }
    if i.Op == InstCapture {
        bw(b, string::from_static("cap "));
        bw(b, u32_(i.Arg));
        bw(b, string::from_static(" -> "));
        bw(b, u32_(i.Out));
        return;
    }
    if i.Op == InstEmptyWidth {
        bw(b, string::from_static("empty "));
        bw(b, u32_(i.Arg));
        bw(b, string::from_static(" -> "));
        bw(b, u32_(i.Out));
        return;
    }
    if i.Op == InstMatch {
        bw(b, string::from_static("match"));
        return;
    }
    if i.Op == InstFail {
        bw(b, string::from_static("fail"));
        return;
    }
    if i.Op == InstNop {
        bw(b, string::from_static("nop -> "));
        bw(b, u32_(i.Out));
        return;
    }
    if i.Op == InstRune {
        if i.Rune.is_empty() {
            // Go: "shouldn't happen" — and it does NOT return here, so
            // the quoted form is written too. Reproduced rather than
            // tidied, because a dump is evidence.
            bw(b, string::from_static("rune <nil>"));
        }
        bw(b, string::from_static("rune "));
        bw(b, crate::strconv::QuoteToASCII(runes_to_string(&i.Rune)));
        if Flags::from(i.Arg).__has(FoldCase) {
            bw(b, string::from_static("/i"));
        }
        bw(b, string::from_static(" -> "));
        bw(b, u32_(i.Out));
        return;
    }
    if i.Op == InstRune1 {
        bw(b, string::from_static("rune1 "));
        bw(b, crate::strconv::QuoteToASCII(runes_to_string(&i.Rune)));
        bw(b, string::from_static(" -> "));
        bw(b, u32_(i.Out));
        return;
    }
    if i.Op == InstRuneAny {
        bw(b, string::from_static("any -> "));
        bw(b, u32_(i.Out));
        return;
    }
    if i.Op == InstRuneAnyNotNL {
        bw(b, string::from_static("anynotnl -> "));
        bw(b, u32_(i.Out));
        return;
    }
}
