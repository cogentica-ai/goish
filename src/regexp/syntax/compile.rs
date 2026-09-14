// Port of Go 1.25.5 regexp/syntax/compile.go.
//
// The AST becomes a `Prog`. This is the step that turns a recursive
// structure into an instruction array with explicit links, and it is
// what §2c is for: once a match is a walk over integer program
// counters, the memo key is `(pc, pos)` and the exponential blowup of a
// backtracker over an AST has nowhere to live.
//
// ─── the patch list ──────────────────────────────────────────────────
//
// The one piece of cleverness, and Go's comment explains it best: "A
// patchList is a list of instruction pointers that need to be filled in
// (patched). Because the pointers haven't been filled in yet, we can
// reuse their storage to hold the list. It's kind of sleazy, but works
// well in practice."
//
// A fragment is compiled before its successor exists, so its exit links
// are unknown. Rather than allocate a list of "places to fix up", the
// unfilled `Out`/`Arg` fields ARE the list: each holds the index of the
// next hole. `head` encodes both an instruction and which of its two
// fields: `p.Inst[head>>1].Out` when `head&1 == 0`, `.Arg` when it is 1.
// `head == 0` is the empty list, which is safe only because every
// program starts with a `fail` instruction at index 0 — nothing ever
// wants to point at ITS output.

use alloc::vec::Vec;

use super::parse::{FoldCase, Flags};
use super::prog::*;
use super::regexp::*;
use crate::rune;

// go: sdk 1.25.5 regexp/syntax/compile.go:19-21 patchList
/// A chain of unfilled instruction links, threaded through the links
/// themselves. See the file header.
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, Copy, Default)]
struct patchList {
    head: u32,
    tail: u32,
}

// go: sdk 1.25.5 regexp/syntax/compile.go:23-25 makePatchList
/// A one-element list.
fn makePatchList(n: u32) -> patchList {
    return patchList { head: n, tail: n };
}

impl patchList {
    // go: sdk 1.25.5 regexp/syntax/compile.go:27-38 patchList.patch
    /// Fill every hole in the chain with `val`, following the chain
    /// through the fields it is about to overwrite.
    fn patch(&self, p: &mut Prog, val: u32) {
        let mut head = self.head;
        while head != 0 {
            let i = (head >> 1) as usize;
            if head & 1 == 0 {
                head = p.Inst[i].Out;
                p.Inst[i].Out = val;
            } else {
                head = p.Inst[i].Arg;
                p.Inst[i].Arg = val;
            }
        }
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:41-56 patchList.append
    /// Splice `l2` onto the end of `self`, writing the join through
    /// `self`'s tail link.
    fn append(&self, p: &mut Prog, l2: patchList) -> patchList {
        if self.head == 0 {
            return l2;
        }
        if l2.head == 0 {
            return *self;
        }
        let i = (self.tail >> 1) as usize;
        if self.tail & 1 == 0 {
            p.Inst[i].Out = l2.head;
        } else {
            p.Inst[i].Arg = l2.head;
        }
        return patchList {
            head: self.head,
            tail: l2.tail,
        };
    }
}

// go: sdk 1.25.5 regexp/syntax/compile.go:59-63 frag
/// Go: "A frag represents a compiled program fragment."
///
/// `nullable` is not bookkeeping: `star` reads it to decide between
/// `loop` and `(f1+)?`, which is the fix for go.dev/issue/46123.
#[allow(non_camel_case_types)] // Go name
#[derive(Clone, Copy, Default)]
struct frag {
    /// Index of first instruction.
    i: u32,
    /// Where to record the end instruction.
    out: patchList,
    /// Whether the fragment can match the empty string.
    nullable: bool,
}

// go: sdk 1.25.5 regexp/syntax/compile.go:65-67 compiler
/// The program under construction.
#[allow(non_camel_case_types)] // Go name
struct compiler {
    p: Prog,
}

// go: sdk 1.25.5 regexp/syntax/compile.go:71-78 Compile
/// Go: "Compile compiles the regexp into a program to be executed. The
/// regexp should have been simplified already (returned from
/// re.Simplify)."
///
/// Go returns an error and never produces one; the signature is kept
/// so a caller written against Go's reads the same.
pub fn Compile(re: &Regexp) -> (Prog, crate::errors::error) {
    let mut c = compiler { p: Prog::default() };
    c.init();
    let f = c.compile(re);
    let m = c.inst(InstMatch).i;
    f.out.patch(&mut c.p, m);
    c.p.Start = crate::int::from(crate::int64(f.i));
    return (c.p, crate::errors::nil);
}

// go: sdk 1.25.5 regexp/syntax/compile.go:86-86 anyRuneNotNL
/// The class `.` compiles to without `(?s)`.
static anyRuneNotNL: [rune; 4] = [0, 10 - 1, 10 + 1, 0x10FFFF];
// go: none — goish-only placement: compile.go line 85, beside
//     `anyRuneNotNL`.
/// The class `(?s).` compiles to.
static anyRune: [rune; 2] = [0, 0x10FFFF];

impl compiler {
    // go: sdk 1.25.5 regexp/syntax/compile.go:80-84 compiler.init
    /// Go: `NumCap = 2` for "implicit ( and ) for whole match $0", and
    /// a `fail` at index 0 so the patch list can use 0 as its
    /// terminator.
    fn init(&mut self) {
        self.p = Prog::default();
        self.p.NumCap = 2;
        self.inst(InstFail);
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:161-166 compiler.inst
    /// Append one instruction and return a fragment naming it.
    ///
    /// Go's `nullable: true` default is deliberate: only `rune` clears
    /// it, because only a rune instruction must consume something.
    fn inst(&mut self, op: InstOp) -> frag {
        // Go: TODO: impose length limit
        let f = frag {
            i: crate::uint32(crate::int64(self.p.Inst.len())),
            out: patchList::default(),
            nullable: true,
        };
        let mut i = Inst::default();
        i.Op = op;
        self.p.Inst.push(i);
        return f;
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:168-172 compiler.nop
    fn nop(&mut self) -> frag {
        let mut f = self.inst(InstNop);
        f.out = makePatchList(f.i << 1);
        return f;
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:174-176 compiler.fail
    /// The empty fragment. `i == 0` is what `cat` and `alt` test, and
    /// it works because index 0 is the `fail` instruction.
    fn fail(&mut self) -> frag {
        return frag::default();
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:178-187 compiler.cap
    fn cap(&mut self, arg: u32) -> frag {
        let mut f = self.inst(InstCapture);
        f.out = makePatchList(f.i << 1);
        self.p.Inst[f.i as usize].Arg = arg;
        if crate::int64(self.p.NumCap) < crate::int64(arg) + 1 {
            self.p.NumCap = crate::int::from(crate::int64(arg) + 1);
        }
        return f;
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:189-198 compiler.cat
    /// Go: "concat of failure is failure".
    fn cat(&mut self, f1: frag, f2: frag) -> frag {
        if f1.i == 0 || f2.i == 0 {
            return frag::default();
        }
        // Go: TODO: elide nop
        f1.out.patch(&mut self.p, f2.i);
        return frag {
            i: f1.i,
            out: f2.out,
            nullable: f1.nullable && f2.nullable,
        };
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:200-216 compiler.alt
    /// Go: "alt of failure is other".
    fn alt(&mut self, f1: frag, f2: frag) -> frag {
        if f1.i == 0 {
            return f2;
        }
        if f2.i == 0 {
            return f1;
        }
        let mut f = self.inst(InstAlt);
        self.p.Inst[f.i as usize].Out = f1.i;
        self.p.Inst[f.i as usize].Arg = f2.i;
        f.out = f1.out.append(&mut self.p, f2.out);
        f.nullable = f1.nullable || f2.nullable;
        return f;
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:218-230 compiler.quest
    /// `f1?`. Greedy tries `f1` first by putting it in `Out`;
    /// non-greedy puts it in `Arg` and leaves `Out` as the hole, which
    /// is the whole of the priority difference.
    fn quest(&mut self, f1: frag, nongreedy: bool) -> frag {
        let mut f = self.inst(InstAlt);
        if nongreedy {
            self.p.Inst[f.i as usize].Arg = f1.i;
            f.out = makePatchList(f.i << 1);
        } else {
            self.p.Inst[f.i as usize].Out = f1.i;
            f.out = makePatchList(f.i << 1 | 1);
        }
        f.out = f.out.append(&mut self.p, f1.out);
        return f;
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:232-249 compiler.loop
    /// Go: "returns the fragment for the main loop of a plus or star.
    /// For plus, it can be used after changing the entry to f1.i. For
    /// star, it can be used directly when f1 can't match an empty
    /// string. (When f1 can match an empty string, f1* must be
    /// implemented as (f1+)? to get the priority match order correct.)"
    fn loop_(&mut self, f1: frag, nongreedy: bool) -> frag {
        let mut f = self.inst(InstAlt);
        if nongreedy {
            self.p.Inst[f.i as usize].Arg = f1.i;
            f.out = makePatchList(f.i << 1);
        } else {
            self.p.Inst[f.i as usize].Out = f1.i;
            f.out = makePatchList(f.i << 1 | 1);
        }
        f1.out.patch(&mut self.p, f.i);
        return f;
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:251-258 compiler.star
    /// `f1*`, with go.dev/issue/46123's fix: a nullable body compiles
    /// as `(f1+)?` so the priority order comes out right.
    fn star(&mut self, f1: frag, nongreedy: bool) -> frag {
        if f1.nullable {
            let p = self.plus(f1, nongreedy);
            return self.quest(p, nongreedy);
        }
        return self.loop_(f1, nongreedy);
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:260-262 compiler.plus
    /// `f1+` — the same loop, entered at the body instead of the alt.
    fn plus(&mut self, f1: frag, nongreedy: bool) -> frag {
        let l = self.loop_(f1, nongreedy);
        return frag {
            i: f1.i,
            out: l.out,
            nullable: f1.nullable,
        };
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:264-269 compiler.empty
    fn empty(&mut self, op: EmptyOp) -> frag {
        let mut f = self.inst(InstEmptyWidth);
        self.p.Inst[f.i as usize].Arg = crate::uint32(crate::int64(op.0));
        f.out = makePatchList(f.i << 1);
        return f;
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:272-296 compiler.rune
    /// One rune-matching instruction, then Go's three specialisations.
    ///
    /// The `FoldCase` clearing is not tidying: an instruction whose
    /// single rune has no fold orbit does not need the flag, and
    /// `InstRune1` — the fast path the machine takes for a literal —
    /// is only chosen once it is gone.
    fn rune_(&mut self, r: &[rune], flags: Flags) -> frag {
        let mut f = self.inst(InstRune);
        f.nullable = false;
        let mut v: Vec<rune> = Vec::new();
        v.extend_from_slice(r);
        // Go: only relevant flag is FoldCase.
        let mut flags = flags & FoldCase;
        if v.len() != 1 || crate::unicode::SimpleFold(v[0]) == v[0] {
            // Go: "and sometimes not even that"
            flags = Flags(flags.0 & !FoldCase.0);
        }
        self.p.Inst[f.i as usize].Arg = crate::uint32(crate::int64(flags.0));
        self.p.Inst[f.i as usize].Rune = v;
        f.out = makePatchList(f.i << 1);

        // Go: special cases for exec machine.
        let rr = &self.p.Inst[f.i as usize].Rune;
        if !flags.__has(FoldCase) && (rr.len() == 1 || rr.len() == 2 && rr[0] == rr[1]) {
            self.p.Inst[f.i as usize].Op = InstRune1;
        } else if rr.len() == 2 && rr[0] == 0 && rr[1] == crate::unicode::MaxRune {
            self.p.Inst[f.i as usize].Op = InstRuneAny;
        } else if rr.len() == 4
            && rr[0] == 0
            && rr[1] == rune('\n') - 1
            && rr[2] == rune('\n') + 1
            && rr[3] == crate::unicode::MaxRune
        {
            self.p.Inst[f.i as usize].Op = InstRuneAnyNotNL;
        }

        return f;
    }

    // go: sdk 1.25.5 regexp/syntax/compile.go:89-159 compiler.compile
    /// The recursive descent. Go's default arm is
    /// `panic("regexp: unhandled case in compile")`; a pseudo-op never
    /// survives the parser, so reaching it is a bug in the caller.
    fn compile(&mut self, re: &Regexp) -> frag {
        if re.Op == OpNoMatch {
            return self.fail();
        }
        if re.Op == OpEmptyMatch {
            return self.nop();
        }
        if re.Op == OpLiteral {
            if re.Rune.is_empty() {
                return self.nop();
            }
            let mut f = frag::default();
            for j in 0..re.Rune.len() {
                let f1 = self.rune_(&re.Rune[j..j + 1], re.Flags);
                if j == 0 {
                    f = f1;
                } else {
                    f = self.cat(f, f1);
                }
            }
            return f;
        }
        if re.Op == OpCharClass {
            let r = re.Rune.clone();
            return self.rune_(&r, re.Flags);
        }
        if re.Op == OpAnyCharNotNL {
            return self.rune_(&anyRuneNotNL, Flags(0));
        }
        if re.Op == OpAnyChar {
            return self.rune_(&anyRune, Flags(0));
        }
        if re.Op == OpBeginLine {
            return self.empty(EmptyBeginLine);
        }
        if re.Op == OpEndLine {
            return self.empty(EmptyEndLine);
        }
        if re.Op == OpBeginText {
            return self.empty(EmptyBeginText);
        }
        if re.Op == OpEndText {
            return self.empty(EmptyEndText);
        }
        if re.Op == OpWordBoundary {
            return self.empty(EmptyWordBoundary);
        }
        if re.Op == OpNoWordBoundary {
            return self.empty(EmptyNoWordBoundary);
        }
        if re.Op == OpCapture {
            let c = crate::int64(re.Cap);
            let bra = self.cap(crate::uint32(c << 1));
            let sub = self.compile(&re.Sub[0]);
            let ket = self.cap(crate::uint32(c << 1 | 1));
            let cs = self.cat(bra, sub);
            return self.cat(cs, ket);
        }
        if re.Op == OpStar {
            let s = self.compile(&re.Sub[0]);
            return self.star(s, re.Flags.__has(super::parse::NonGreedy));
        }
        if re.Op == OpPlus {
            let s = self.compile(&re.Sub[0]);
            return self.plus(s, re.Flags.__has(super::parse::NonGreedy));
        }
        if re.Op == OpQuest {
            let s = self.compile(&re.Sub[0]);
            return self.quest(s, re.Flags.__has(super::parse::NonGreedy));
        }
        if re.Op == OpConcat {
            if re.Sub.is_empty() {
                return self.nop();
            }
            let mut f = frag::default();
            for (i, sub) in re.Sub.iter().enumerate() {
                if i == 0 {
                    f = self.compile(sub);
                } else {
                    let g = self.compile(sub);
                    f = self.cat(f, g);
                }
            }
            return f;
        }
        if re.Op == OpAlternate {
            let mut f = frag::default();
            for sub in re.Sub.iter() {
                let g = self.compile(sub);
                f = self.alt(f, g);
            }
            return f;
        }
        panic!("regexp: unhandled case in compile");
    }
}
