package syntax

import (
	"fmt"
	"strconv"
	"testing"
)

func q(s string) string { return strconv.Quote(s) }

// prog builds a Prog literal for the dump/Prefix/StartCond rows.
func mk(start int, insts ...Inst) *Prog {
	return &Prog{Inst: insts, Start: start}
}

func TestGoishRef(t *testing.T) {
	// ── InstOp.String, including out of range ───────────────────────
	for i := 0; i <= 12; i++ {
		fmt.Printf("InstOp.String %2d %s\n", i, q(InstOp(i).String()))
	}

	// ── IsWordChar ──────────────────────────────────────────────────
	for _, r := range []rune{'a', 'z', 'A', 'Z', '0', '9', '_', '-', ' ', '\n', 'é', 0x4e00, -1, 0} {
		fmt.Printf("IsWordChar %6d %v\n", r, IsWordChar(r))
	}

	// ── EmptyOpContext ──────────────────────────────────────────────
	pairs := [][2]rune{
		{-1, -1}, {-1, 'a'}, {-1, '\n'}, {-1, ' '},
		{'a', -1}, {'a', 'b'}, {'a', ' '}, {'a', '\n'},
		{' ', 'a'}, {' ', ' '}, {'\n', 'a'}, {'\n', '\n'},
		{'\n', -1}, {'_', '9'}, {'9', '-'},
	}
	for _, p := range pairs {
		fmt.Printf("EmptyOpContext %4d %4d %d\n", p[0], p[1], uint8(EmptyOpContext(p[0], p[1])))
	}

	// ── MatchRunePos, one row per size class ────────────────────────
	cases := []struct {
		name string
		inst Inst
		rs   []rune
	}{
		{"len0", Inst{Op: InstRune, Rune: nil}, []rune{'a', 0}},
		{"len1", Inst{Op: InstRune, Rune: []rune{'k'}}, []rune{'k', 'K', 'j'}},
		{"len1fold", Inst{Op: InstRune, Arg: uint32(FoldCase), Rune: []rune{'k'}}, []rune{'k', 'K', 'j', 0x212A}},
		{"len1foldS", Inst{Op: InstRune, Arg: uint32(FoldCase), Rune: []rune{'s'}}, []rune{'s', 'S', 0x17F, 'x'}},
		{"len2", Inst{Op: InstRune, Rune: []rune{'a', 'f'}}, []rune{'a', 'c', 'f', 'g', '`'}},
		{"len4", Inst{Op: InstRune, Rune: []rune{'0', '9', 'a', 'f'}}, []rune{'/', '0', '5', '9', ':', '`', 'a', 'f', 'g'}},
		{"len6", Inst{Op: InstRune, Rune: []rune{'0', '9', 'A', 'Z', 'a', 'z'}}, []rune{'0', 'M', 'q', '_', '{'}},
		{"len8", Inst{Op: InstRune, Rune: []rune{1, 2, 10, 20, 100, 200, 1000, 2000}}, []rune{0, 1, 2, 3, 15, 150, 1500, 2001}},
		// Probe EVERY range start and end, plus one below and one
		// above each: `c <= r` vs `c < r` in the binary search only
		// differs at a start, so a table that misses the starts lets a
		// real search bug through.
		{"len12", Inst{Op: InstRune, Rune: []rune{1, 2, 10, 20, 100, 200, 1000, 2000, 5000, 6000, 9000, 9999}},
			[]rune{0, 1, 2, 3, 9, 10, 20, 21, 99, 100, 200, 201, 999, 1000, 2000, 2001,
				4999, 5000, 6000, 6001, 8999, 9000, 9999, 10000}},
		{"len16", Inst{Op: InstRune, Rune: []rune{'0', '9', 'A', 'F', 'a', 'f', 0x100, 0x10f, 0x300, 0x30f, 0x4e00, 0x4e0f, 0x1f600, 0x1f60f, 0x10000, 0x1000f}},
			[]rune{'/', '0', '9', ':', '@', 'A', 'F', 'G', '`', 'a', 'f', 'g',
				0xff, 0x100, 0x10f, 0x110, 0x2ff, 0x300, 0x30f, 0x310,
				0x4dff, 0x4e00, 0x4e0f, 0x4e10, 0x1f5ff, 0x1f600, 0x1f60f, 0x1f610,
				0xffff, 0x10000, 0x1000f, 0x10010}},
	}
	for _, c := range cases {
		for _, r := range c.rs {
			fmt.Printf("MatchRunePos %-9s %5d %3d %v\n", c.name, r, c.inst.MatchRunePos(r), c.inst.MatchRune(r))
		}
	}

	// ── MatchEmptyWidth ─────────────────────────────────────────────
	ops := []EmptyOp{EmptyBeginLine, EmptyEndLine, EmptyBeginText, EmptyEndText, EmptyWordBoundary, EmptyNoWordBoundary}
	for _, op := range ops {
		i := Inst{Op: InstEmptyWidth, Arg: uint32(op)}
		for _, p := range [][2]rune{{-1, 'a'}, {'a', -1}, {'\n', 'a'}, {'a', '\n'}, {'a', 'b'}, {'a', ' '}, {' ', 'a'}, {' ', ' '}} {
			fmt.Printf("MatchEmptyWidth %2d %4d %4d %v\n", uint8(op), p[0], p[1], i.MatchEmptyWidth(p[0], p[1]))
		}
	}

	// ── Inst.String, one per opcode ─────────────────────────────────
	insts := []Inst{
		{Op: InstAlt, Out: 3, Arg: 7},
		{Op: InstAltMatch, Out: 3, Arg: 7},
		{Op: InstCapture, Out: 4, Arg: 2},
		{Op: InstEmptyWidth, Out: 5, Arg: uint32(EmptyBeginText)},
		{Op: InstMatch},
		{Op: InstFail},
		{Op: InstNop, Out: 6},
		{Op: InstRune, Out: 7, Rune: []rune{'a', 'z'}},
		{Op: InstRune, Out: 7, Arg: uint32(FoldCase), Rune: []rune{'k'}},
		{Op: InstRune, Out: 7, Rune: []rune{'é', '\n', 0x4e00}},
		{Op: InstRune, Out: 7, Rune: nil},
		{Op: InstRune1, Out: 8, Rune: []rune{'x'}},
		{Op: InstRuneAny, Out: 9},
		{Op: InstRuneAnyNotNL, Out: 10},
	}
	for _, i := range insts {
		fmt.Printf("Inst.String %s\n", q(i.String()))
	}

	// ── Prog.String, Prefix, StartCond ──────────────────────────────
	progs := []*Prog{
		// "abc" then match
		mk(1,
			Inst{Op: InstFail},
			Inst{Op: InstRune1, Out: 2, Rune: []rune{'a'}},
			Inst{Op: InstRune1, Out: 3, Rune: []rune{'b'}},
			Inst{Op: InstRune1, Out: 4, Rune: []rune{'c'}},
			Inst{Op: InstMatch},
		),
		// nops and captures are skipped by Prefix
		mk(1,
			Inst{Op: InstFail},
			Inst{Op: InstCapture, Out: 2, Arg: 0},
			Inst{Op: InstNop, Out: 3},
			Inst{Op: InstRune1, Out: 4, Rune: []rune{'h'}},
			Inst{Op: InstMatch},
		),
		// a folded first rune is NOT a prefix
		mk(1,
			Inst{Op: InstFail},
			Inst{Op: InstRune, Out: 2, Arg: uint32(FoldCase), Rune: []rune{'a'}},
			Inst{Op: InstMatch},
		),
		// leading empty-width assertions
		mk(1,
			Inst{Op: InstFail},
			Inst{Op: InstEmptyWidth, Out: 2, Arg: uint32(EmptyBeginText)},
			Inst{Op: InstEmptyWidth, Out: 3, Arg: uint32(EmptyBeginLine)},
			Inst{Op: InstRune1, Out: 4, Rune: []rune{'z'}},
			Inst{Op: InstMatch},
		),
		// StartCond of an unmatchable program
		mk(1,
			Inst{Op: InstMatch},
			Inst{Op: InstFail},
		),
		// start instruction is a bare match: Prefix complete, empty
		mk(0, Inst{Op: InstMatch}),
		// a class first: no prefix, not complete
		mk(0,
			Inst{Op: InstRune, Out: 1, Rune: []rune{'a', 'z'}},
			Inst{Op: InstMatch},
		),
	}
	for n, p := range progs {
		pre, complete := p.Prefix()
		fmt.Printf("Prog %d Prefix %s complete=%v StartCond %d\n", n, q(pre), complete, uint8(p.StartCond()))
		fmt.Printf("Prog %d String %s\n", n, q(p.String()))
	}
}
