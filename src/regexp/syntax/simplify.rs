// Port of Go 1.25.5 regexp/syntax/simplify.go.
//
// Counted repetition out, everything else left alone. `x{2,5}` becomes
// `xx(x(x(x)?)?)?` — Go's own nesting, chosen because "the machine will
// do less work if we nest the final m copies" — and `(?:a+)+` becomes
// `a+`.
//
// This is what makes the compiler's job finite: `Prog` has no counted
// repeat instruction, so every `{n,m}` has to be expanded before it
// gets there. The parser's `repeatIsValid` bound of 1000 copies is what
// keeps that expansion from being unbounded.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::parse::{Flags, NonGreedy};
use super::regexp::*;

impl Regexp {
    // go: sdk 1.25.5 regexp/syntax/simplify.go:14-117 Regexp.Simplify
    /// Go: "Simplify returns a regexp equivalent to re but without
    /// counted repetitions and with various other simplifications, such
    /// as rewriting /(?:a+)+/ to /a+/."
    ///
    /// Go's warning is worth keeping verbatim, because it is a real
    /// caveat and not a hedge: "The resulting regexp will execute
    /// correctly but its string representation will not produce the
    /// same parse tree, because capturing parentheses may have been
    /// duplicated or removed. For example, the simplified form for
    /// /(x){1,2}/ is /(x)(x)?/ but both parentheses capture as $1."
    ///
    /// Go returns the ORIGINAL pointer when nothing changed, and only
    /// copies a node when one of its children did. goish returns an
    /// owned tree either way; the sharing is an allocation choice, and
    /// the result is the same tree.
    pub fn Simplify(&self) -> Regexp {
        if self.Op == OpCapture || self.Op == OpConcat || self.Op == OpAlternate {
            // Go: "Simplify children, building new Regexp if children
            // change."
            let mut nre = self.clone();
            let mut sub: Vec<Arc<Regexp>> = Vec::with_capacity(self.Sub.len());
            for s in self.Sub.iter() {
                sub.push(Arc::new(s.Simplify()));
            }
            nre.Sub = sub;
            return nre;
        }

        if self.Op == OpStar || self.Op == OpPlus || self.Op == OpQuest {
            let sub = self.Sub[0].Simplify();
            return simplify1(self.Op, self.Flags, sub, Some(self));
        }

        if self.Op == OpRepeat {
            // Go: "Special special case: x{0} matches the empty string
            // and doesn't even need to consider x."
            if self.Min == 0 && self.Max == 0 {
                return Regexp::__new(OpEmptyMatch);
            }

            // Go: "The fun begins."
            let sub = self.Sub[0].Simplify();

            // Go: "x{n,} means at least n matches of x."
            if self.Max == -1 {
                // Go: special case: x{0,} is x*.
                if self.Min == 0 {
                    return simplify1(OpStar, self.Flags, sub, None);
                }
                // Go: special case: x{1,} is x+.
                if self.Min == 1 {
                    return simplify1(OpPlus, self.Flags, sub, None);
                }
                // Go: general case: x{4,} is xxxx+.
                let mut nre = Regexp::__new(OpConcat);
                let mut i: crate::int = 0;
                while i < self.Min - 1 {
                    nre.Sub.push(Arc::new(sub.clone()));
                    i += 1;
                }
                nre.Sub
                    .push(Arc::new(simplify1(OpPlus, self.Flags, sub, None)));
                return nre;
            }

            // Go: special case x{0} handled above.
            // Go: special case: x{1} is just x.
            if self.Min == 1 && self.Max == 1 {
                return sub;
            }

            // Go: "General case: x{n,m} means n copies of x and m
            // copies of x? The machine will do less work if we nest the
            // final m copies, so that x{2,5} = xx(x(x(x)?)?)?"

            // Go: build leading prefix: xx.
            let mut prefix: Option<Regexp> = None;
            if self.Min > 0 {
                let mut p = Regexp::__new(OpConcat);
                let mut i: crate::int = 0;
                while i < self.Min {
                    p.Sub.push(Arc::new(sub.clone()));
                    i += 1;
                }
                prefix = Some(p);
            }

            // Go: build and attach suffix: (x(x(x)?)?)?
            if self.Max > self.Min {
                let mut suffix = simplify1(OpQuest, self.Flags, sub.clone(), None);
                let mut i = self.Min + 1;
                while i < self.Max {
                    let mut nre2 = Regexp::__new(OpConcat);
                    nre2.Sub.push(Arc::new(sub.clone()));
                    nre2.Sub.push(Arc::new(suffix));
                    suffix = simplify1(OpQuest, self.Flags, nre2, None);
                    i += 1;
                }
                match prefix {
                    None => return suffix,
                    Some(mut p) => {
                        p.Sub.push(Arc::new(suffix));
                        return p;
                    }
                }
            }
            if let Some(p) = prefix {
                return p;
            }

            // Go: "Some degenerate case like min > max or min < max < 0.
            // Handle as impossible match."
            return Regexp::__new(OpNoMatch);
        }

        return self.clone();
    }
}

// go: sdk 1.25.5 regexp/syntax/simplify.go:134-151 simplify1
/// Go: "implements Simplify for the unary OpStar, OpPlus, and OpQuest
/// operators… under the assumption that sub is already simple, and
/// without first allocating that structure."
///
/// The two idempotence rules are why `(?:a+)+` collapses: `op ==
/// sub.Op` with matching greediness means the outer operator adds
/// nothing. The greediness check is not decoration — `(a+)+?` and
/// `(a+?)+` are different machines.
fn simplify1(op: Op, flags: Flags, sub: Regexp, re: Option<&Regexp>) -> Regexp {
    // Go: "Special case: repeat the empty string as much as you want,
    // but it's still the empty string."
    if sub.Op == OpEmptyMatch {
        return sub;
    }
    // Go: "The operators are idempotent if the flags match."
    if op == sub.Op && (flags & NonGreedy) == (sub.Flags & NonGreedy) {
        return sub;
    }
    if let Some(r) = re {
        if r.Op == op
            && (r.Flags & NonGreedy) == (flags & NonGreedy)
            && r.Sub[0].as_ref().Equal(&sub)
        {
            // Go compares POINTERS here (`sub == re.Sub[0]`), which is
            // an identity test on the node `Simplify` just returned —
            // it is the "nothing changed" case. goish's `Simplify`
            // returns an owned tree, so identity is gone and the
            // structural test stands in. It answers the same for the
            // case Go uses it for, where the child is literally
            // unchanged.
            return r.clone();
        }
    }

    let mut out = Regexp::__new(op);
    out.Flags = flags;
    out.Sub.push(Arc::new(sub));
    return out;
}
