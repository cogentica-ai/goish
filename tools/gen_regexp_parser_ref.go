package syntax

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// zzn writes a node as the s-expression both sides compare.
func zzn(b *strings.Builder, re *Regexp) {
	fmt.Fprintf(b, "(%d %d %d %d %d %s [", uint8(re.Op), uint16(re.Flags), re.Min, re.Max, re.Cap, strconv.Quote(re.Name))
	for i, r := range re.Rune {
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(b, "%d", r)
	}
	b.WriteString("]")
	for _, s := range re.Sub {
		b.WriteString(" ")
		zzn(b, s)
	}
	b.WriteString(")")
}

func zzstack(p *parser) string {
	var b strings.Builder
	for i, re := range p.stack {
		if i > 0 {
			b.WriteString(" ")
		}
		zzn(&b, re)
	}
	return b.String()
}

// A script is a list of operations both ports run in lockstep.
type opn struct {
	kind string
	a    int
	b    int
	c    int
	rs   []rune
}

func run(t *testing.T, name string, flags Flags, script []opn) {
	p := &parser{flags: flags, wholeRegexp: "zz"}
	for i, o := range script {
		var errs string
		switch o.kind {
		case "L":
			p.literal(rune(o.a))
		case "O":
			p.op(Op(o.a))
		case "C":
			re := p.newRegexp(OpCharClass)
			re.Flags = p.flags
			re.Rune = append(re.Rune[:0], o.rs...)
			p.push(re)
		case "X":
			p.concat()
		case "A":
			p.alternate()
		case "R":
			_, err := p.repeat(Op(o.a), o.b, o.c, "x{2}", "", "")
			if err != nil {
				errs = " err=" + strconv.Quote(err.Error())
			}
		case "V":
			p.parseVerticalBar()
		case "E":
			// The three lines parse's end and parseRightParen both
			// write out. Popping the bar is what leaves the
			// alternatives adjacent for alternate to take.
			p.concat()
			if p.swapVerticalBar() {
				p.stack = p.stack[:len(p.stack)-1]
			}
			p.alternate()
		case "F":
			p.flags = Flags(o.a)
		}
		fmt.Printf("%s %2d %-3s numRegexp=%d numRunes=%d | %s%s\n",
			name, i, o.kind, p.numRegexp, p.numRunes, zzstack(p), errs)
	}
}

func TestGoishRef(t *testing.T) {
	L := func(r rune) opn { return opn{kind: "L", a: int(r)} }
	O := func(op Op) opn { return opn{kind: "O", a: int(op)} }
	C := func(rs ...rune) opn { return opn{kind: "C", rs: rs} }
	X := opn{kind: "X"}
	A := opn{kind: "A"}
	R := func(op Op, min, max int) opn { return opn{kind: "R", a: int(op), b: min, c: max} }
	F := func(f Flags) opn { return opn{kind: "F", a: int(f)} }
	V := opn{kind: "V"}
	E := opn{kind: "E"}
	_, _, _ = V, E, A

	// Incremental concatenation: three literals become one node.
	run(t, "concat", Perl, []opn{L('a'), L('b'), L('c'), X})

	// A repeat stops the run: `ab*` is a then b*, not (ab)*.
	run(t, "abstar", Perl, []opn{L('a'), L('b'), R(OpStar, 0, -1), X})

	// A class of one rune collapses to a literal and then concatenates.
	run(t, "class1", Perl, []opn{L('a'), C('b', 'b'), X})

	// A fold pair collapses to a FOLDED literal.
	run(t, "foldpair", Perl, []opn{C('A', 'A', 'a', 'a'), X})
	run(t, "foldadj", Perl, []opn{C(0x394, 0x395), X})
	run(t, "foldK", Perl, []opn{C('K', 'K', 'k', 'k'), X})
	run(t, "notfold", Perl, []opn{C('a', 'a', 'z', 'z'), X})

	// Fold flag changes mid-run: the two literals must not merge.
	run(t, "flagsplit", Perl, []opn{L('a'), F(Perl | FoldCase), L('b'), X})

	// Alternation and the factoring rounds.
	run(t, "alt-simple", Perl, []opn{L('a'), V, L('b'), E})
	run(t, "alt-prefix", Perl, []opn{
		L('a'), L('b'), L('c'), V,
		L('a'), L('b'), L('d'), V,
		L('a'), L('e'), L('f'), E,
	})
	run(t, "alt-class", Perl, []opn{
		L('a'), V, L('b'), V, L('c'), E,
	})
	run(t, "alt-empty", Perl, []opn{E})
	run(t, "alt-one", Perl, []opn{L('a'), E})
	run(t, "alt-nested", Perl, []opn{
		L('a'), L('b'), L('c'), V,
		L('a'), L('b'), L('d'), V,
		L('b'), L('c'), L('x'), V,
		L('b'), L('c'), L('y'), E,
	})
	run(t, "alt-dupes", Perl, []opn{
		L('a'), V, L('a'), V, L('a'), E,
	})

	// Empty concat, and a concat of one.
	run(t, "empty", Perl, []opn{X})
	run(t, "one", Perl, []opn{L('a'), X})

	// Repeats, greedy and not, and the two refusals.
	run(t, "rep", Perl, []opn{L('a'), R(OpRepeat, 2, 5), X})
	run(t, "repinf", Perl, []opn{L('a'), R(OpRepeat, 2, -1), X})
	run(t, "repnone", Perl, []opn{R(OpStar, 0, -1)})
	run(t, "repbig", Perl, []opn{L('a'), R(OpRepeat, 2, 5), R(OpRepeat, 2, 5), R(OpRepeat, 2, 5), R(OpRepeat, 2, 5), X})
	run(t, "reppseudo", Perl, []opn{O(opLeftParen), R(OpStar, 0, -1)})

	// Round 2 factors a common leading REGEXP, but only when it is a
	// character class or a fixed repeat of one. These are both sides
	// of that restriction.
	run(t, "alt-repclass", Perl, []opn{
		C('a', 'z'), L('x'), V,
		C('a', 'z'), L('y'), E,
	})
	// a*x|a*y — the leading regexp is a STAR, so it must NOT factor:
	// "Complex subexpressions (e.g. involving quantifiers) are not
	// safe to factor because that collapses their distinct paths
	// through the automaton."
	run(t, "alt-starprefix", Perl, []opn{
		L('a'), R(OpStar, 0, -1), L('x'), V,
		L('a'), R(OpStar, 0, -1), L('y'), E,
	})
	run(t, "alt-plusprefix", Perl, []opn{
		L('a'), R(OpPlus, 1, -1), L('x'), V,
		L('a'), R(OpPlus, 1, -1), L('y'), E,
	})
	run(t, "alt-questprefix", Perl, []opn{
		L('a'), R(OpQuest, 0, 1), L('x'), V,
		L('a'), R(OpQuest, 0, 1), L('y'), E,
	})
	// [a-z]{2}x|[a-z]{2}y — a FIXED repeat of a class, which may.
	run(t, "alt-fixedrep", Perl, []opn{
		C('a', 'z'), R(OpRepeat, 2, 2), L('x'), V,
		C('a', 'z'), R(OpRepeat, 2, 2), L('y'), E,
	})
	// [a-z]{2,3}x|[a-z]{2,3}y — NOT fixed, so it must not.
	run(t, "alt-rangerep", Perl, []opn{
		C('a', 'z'), R(OpRepeat, 2, 3), L('x'), V,
		C('a', 'z'), R(OpRepeat, 2, 3), L('y'), E,
	})
	// A repeat of a non-class, fixed count: still refused.
	run(t, "alt-fixedrepgrp", Perl, []opn{
		L('a'), L('b'), X, R(OpRepeat, 2, 2), L('x'), V,
		L('a'), L('b'), X, R(OpRepeat, 2, 2), L('y'), E,
	})

	// The fold flag gates maybeConcat's merge. Exercise it in more
	// than one position, and inside an alternation.
	run(t, "fold-mid", Perl, []opn{
		L('a'), L('b'), F(Perl | FoldCase), L('c'), L('d'), F(Perl), L('e'), X,
	})
	run(t, "fold-all", Perl|FoldCase, []opn{L('a'), L('b'), L('c'), X})
	run(t, "fold-alt", Perl, []opn{
		L('a'), F(Perl | FoldCase), L('b'), V,
		F(Perl), L('a'), F(Perl | FoldCase), L('c'), E,
	})
	run(t, "fold-back", Perl|FoldCase, []opn{
		L('a'), F(Perl), L('b'), F(Perl | FoldCase), L('c'), X,
	})

	// swapVerticalBar merges two single-rune alternatives, and swaps so
	// the MORE COMPLEX one is the destination. Without the swap,
	// mergeCharClass's OpLiteral arm reads src.Rune[0] out of a CLASS,
	// where it is a range start and not a rune. Every ordering of the
	// four ranks — literal(3) < class(4) < anynotnl(5) < any(6).
	run(t, "swap-lit-class", Perl, []opn{L('a'), V, C('x', 'z'), E})
	run(t, "swap-class-lit", Perl, []opn{C('x', 'z'), V, L('a'), E})
	run(t, "swap-lit-any", Perl, []opn{L('a'), V, O(OpAnyChar), E})
	run(t, "swap-any-lit", Perl, []opn{O(OpAnyChar), V, L('a'), E})
	run(t, "swap-lit-notnl", Perl, []opn{L('a'), V, O(OpAnyCharNotNL), E})
	run(t, "swap-notnl-lit", Perl, []opn{O(OpAnyCharNotNL), V, L('a'), E})
	run(t, "swap-class-any", Perl, []opn{C('x', 'z'), V, O(OpAnyChar), E})
	run(t, "swap-any-class", Perl, []opn{O(OpAnyChar), V, C('x', 'z'), E})
	run(t, "swap-notnl-nl", Perl, []opn{O(OpAnyCharNotNL), V, L('\n'), E})
	run(t, "swap-three", Perl, []opn{L('a'), V, C('x', 'z'), V, O(OpAnyCharNotNL), E})
	run(t, "swap-classes", Perl, []opn{C('a', 'c'), V, C('x', 'z'), E})
	run(t, "swap-bigclass", Perl, []opn{C('a', 'c', 'e', 'g'), V, C('x', 'z'), E})
}
