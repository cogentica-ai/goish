package syntax

import (
	"fmt"
	"testing"
	"unicode"
)

func rs(r []rune) string {
	s := "["
	for i, v := range r {
		if i > 0 {
			s += " "
		}
		s += fmt.Sprintf("%d", v)
	}
	return s + "]"
}

// Synthetic tables, so the rows do not depend on both sides carrying
// byte-identical Unicode data.
var t1 = &unicode.RangeTable{
	R16: []unicode.Range16{{Lo: 0x41, Hi: 0x5a, Stride: 1}},
}
var t2 = &unicode.RangeTable{
	R16: []unicode.Range16{{Lo: 0x100, Hi: 0x110, Stride: 2}},
}
var t3 = &unicode.RangeTable{
	R16: []unicode.Range16{{Lo: 0x30, Hi: 0x39, Stride: 1}, {Lo: 0x41, Hi: 0x5a, Stride: 3}},
	R32: []unicode.Range32{{Lo: 0x10000, Hi: 0x10010, Stride: 1}, {Lo: 0x20000, Hi: 0x2000a, Stride: 5}},
}
var t4 = &unicode.RangeTable{
	R16: []unicode.Range16{{Lo: 0, Hi: 0xffff, Stride: 1}},
	R32: []unicode.Range32{{Lo: 0x10000, Hi: 0x10ffff, Stride: 1}},
}

func TestGoishRef(t *testing.T) {
	// ── appendRange: the two-back coalescing ────────────────────────
	type ar struct {
		start  []rune
		lo, hi rune
	}
	ars := []ar{
		{nil, 'a', 'z'},
		{[]rune{'a', 'z'}, 'A', 'Z'},
		{[]rune{'a', 'z'}, '{', '~'},   // abuts above
		{[]rune{'a', 'z'}, 'W', '`'},   // abuts below
		{[]rune{'a', 'z'}, 'm', 'q'},   // inside
		{[]rune{'a', 'z'}, 'x', 0x100}, // overlaps above
		{[]rune{'a', 'z'}, 0x200, 0x300},
		{[]rune{'A', 'Z', 'a', 'z'}, '[', '`'},   // joins the two-back one
		{[]rune{'A', 'Z', 'a', 'z'}, 0x30, 0x40}, // abuts two back
		{[]rune{'A', 'Z', 'a', 'z'}, 1, 2},       // neither
		{[]rune{1, 2, 5, 6, 9, 10}, 3, 4},        // only the two-back window is checked
		{[]rune{1, 2, 5, 6, 9, 10}, 7, 8},
		{[]rune{0, 0}, 0, 0},
		{nil, 0, 0x10ffff},
	}
	for n, c := range ars {
		cp := append([]rune(nil), c.start...)
		fmt.Printf("appendRange %2d %s\n", n, rs(appendRange(cp, c.lo, c.hi)))
	}

	// ── appendFoldedRange: the three guards, then brute force ───────
	frs := [][2]rune{
		{0, 0x10ffff}, {0x41, 0x41}, {'k', 'k'}, {'K', 'K'}, {0x212a, 0x212a},
		{'s', 's'}, {0x17f, 0x17f}, {'a', 'z'}, {0, 0x40}, {0x1e944, 0x1e950},
		{0x20, 0x50}, {0x1e930, 0x1e950}, {0x130, 0x132}, {0x3a3, 0x3a3},
	}
	for n, c := range frs {
		fmt.Printf("appendFoldedRange %2d %s\n", n, rs(appendFoldedRange(nil, c[0], c[1])))
	}

	// ── appendClass / appendFoldedClass / appendNegatedClass ────────
	cls := [][]rune{
		{},
		{'a', 'z'},
		{'a', 'c', 'x', 'z'},
		{0, 0x10ffff},
		{'0', '9', 'A', 'Z', 'a', 'z'},
		{'k', 'k'},
		{1, 1},
	}
	for n, c := range cls {
		fmt.Printf("appendClass        %2d %s\n", n, rs(appendClass(nil, c)))
		fmt.Printf("appendFoldedClass  %2d %s\n", n, rs(appendFoldedClass(nil, c)))
		fmt.Printf("appendNegatedClass %2d %s\n", n, rs(appendNegatedClass(nil, c)))
		cp := append([]rune(nil), c...)
		fmt.Printf("negateClass        %2d %s\n", n, rs(negateClass(cp)))
	}

	// ── appendTable / appendNegatedTable ────────────────────────────
	tabs := []*unicode.RangeTable{t1, t2, t3, t4}
	for n, tb := range tabs {
		fmt.Printf("appendTable        %2d %s\n", n, rs(appendTable(nil, tb)))
		fmt.Printf("appendNegatedTable %2d %s\n", n, rs(appendNegatedTable(nil, tb)))
	}
	// And two real ones, which also checks the two sides carry the same
	// Unicode data.
	fmt.Printf("appendTable Zs %s\n", rs(appendTable(nil, unicode.Zs)))
	fmt.Printf("appendTable Mn.len %d\n", len(appendTable(nil, unicode.Mn)))
	fmt.Printf("appendNegatedTable Zs.len %d\n", len(appendNegatedTable(nil, unicode.Zs)))

	// ── cleanClass: the sort, the tie-break, the merge ──────────────
	dirty := [][]rune{
		{},
		{'a', 'z'},
		{'x', 'z', 'a', 'c'},
		{'a', 'c', 'b', 'd'},
		{'a', 'z', 'a', 'c'},   // tied lo, hi decreasing puts a-z first
		{'a', 'c', 'a', 'z'},   // same pair, other order
		{'a', 'b', 'c', 'd'},   // abutting
		{'a', 'b', 'd', 'e'},   // gap of one
		{5, 6, 1, 2, 3, 4},
		{9, 10, 1, 2, 5, 6},
		{0, 0x10ffff, 5, 6},
		{3, 4, 1, 9, 5, 6},
		{1, 1, 1, 1, 1, 1},
	}
	for n, c := range dirty {
		cp := append([]rune(nil), c...)
		fmt.Printf("cleanClass %2d %s\n", n, rs(cleanClass(&cp)))
	}

	// ── inCharClass ─────────────────────────────────────────────────
	cc := []rune{'0', '9', 'A', 'F', 'a', 'f', 0x100, 0x10f}
	for _, r := range []rune{'/', '0', '5', '9', ':', '@', 'A', 'F', 'G', '`', 'a', 'f', 'g', 0xff, 0x100, 0x10f, 0x110, -1} {
		fmt.Printf("inCharClass %6d %v\n", r, inCharClass(r, cc))
	}
	for _, r := range []rune{0, 1, 'a'} {
		fmt.Printf("inCharClass-empty %d %v\n", r, inCharClass(r, nil))
	}

	// ── minFoldRune ─────────────────────────────────────────────────
	for _, r := range []rune{'a', 'A', 'k', 'K', 0x212a, 's', 'S', 0x17f, '0', 0x40, 0x1e943, 0x1e944, 0x3c3, 0x3a3, 0x3c2, -1, 0x10ffff} {
		fmt.Printf("minFoldRune %7d %7d\n", r, minFoldRune(r))
	}
}
