package syntax

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

func zzrs(r []rune) string {
	s := "["
	for i, v := range r {
		if i > 0 {
			s += " "
		}
		s += fmt.Sprintf("%d", v)
	}
	return s + "]"
}

// zzdump2 writes a node as the s-expression the generator reads back.
func zzdump2(b *strings.Builder, re *Regexp) {
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
		zzdump2(b, s)
	}
	b.WriteString(")")
}

func zzre(re *Regexp) string {
	return fmt.Sprintf("op=%d flags=%d rune=%s", uint8(re.Op), uint16(re.Flags), zzrs(re.Rune))
}

func TestGoishRef(t *testing.T) {
	// ── the error type ──────────────────────────────────────────────
	codes := []ErrorCode{
		ErrInternalError, ErrInvalidCharClass, ErrInvalidCharRange, ErrInvalidEscape,
		ErrInvalidNamedCapture, ErrInvalidPerlOp, ErrInvalidRepeatOp, ErrInvalidRepeatSize,
		ErrInvalidUTF8, ErrMissingBracket, ErrMissingParen, ErrMissingRepeatArgument,
		ErrTrailingBackslash, ErrUnexpectedParen, ErrNestingDepth, ErrLarge,
	}
	for _, c := range codes {
		fmt.Printf("ErrorCode %s\n", strconv.Quote(c.String()))
		e := &Error{Code: c, Expr: "a**"}
		fmt.Printf("Error     %s\n", strconv.Quote(e.Error()))
	}
	fmt.Printf("Error-empty %s\n", strconv.Quote((&Error{Code: ErrLarge, Expr: ""}).Error()))

	// ── the limits ──────────────────────────────────────────────────
	fmt.Printf("maxHeight %d\n", maxHeight)
	fmt.Printf("maxSize   %d\n", maxSize)
	fmt.Printf("instSize  %d\n", instSize)
	fmt.Printf("maxRunes  %d\n", maxRunes)
	fmt.Printf("runeSize  %d\n", runeSize)

	// ── isValidCaptureName / isalnum ────────────────────────────────
	for _, n := range []string{"", "a", "A", "_", "0", "a1", "a_1", "a-b", "a b", "a.", "é", "abé", "1", "__", "a\x00b"} {
		fmt.Printf("isValidCaptureName %-8s %v\n", strconv.Quote(n), isValidCaptureName(n))
	}
	for _, c := range []rune{'0', '9', 'A', 'Z', 'a', 'z', '_', '-', '/', ':', '@', '[', '`', '{', 0xe9, -1} {
		fmt.Printf("isalnum %5d %v\n", c, isalnum(c))
	}

	// ── isCharClass / matchRune ─────────────────────────────────────
	nodes := []*Regexp{
		{Op: OpLiteral, Rune: []rune{'a'}},
		{Op: OpLiteral, Rune: []rune{'a', 'b'}},
		{Op: OpCharClass, Rune: []rune{'a', 'z'}},
		{Op: OpCharClass, Rune: []rune{'a', 'c', 'x', 'z'}},
		{Op: OpCharClass},
		{Op: OpAnyChar},
		{Op: OpAnyCharNotNL},
		{Op: OpEmptyMatch},
		{Op: OpConcat},
		{Op: OpStar},
	}
	for i, re := range nodes {
		fmt.Printf("isCharClass %2d %v\n", i, isCharClass(re))
		for _, r := range []rune{'a', 'b', 'y', 'z', '\n', 0x100} {
			fmt.Printf("matchRune   %2d %5d %v\n", i, r, matchRune(re, r))
		}
	}

	// ── appendLiteral ───────────────────────────────────────────────
	for _, c := range []struct {
		x  rune
		fl Flags
	}{{'a', 0}, {'a', FoldCase}, {'k', FoldCase}, {'K', FoldCase}, {0x212a, FoldCase}, {'0', FoldCase}, {'0', 0}} {
		fmt.Printf("appendLiteral %5d %d %s\n", c.x, uint16(c.fl), zzrs(appendLiteral(nil, c.x, c.fl)))
	}

	// ── cleanAlt: the two recognitions ──────────────────────────────
	alts := [][]rune{
		{0, unicode.MaxRune},
		{0, '\n' - 1, '\n' + 1, unicode.MaxRune},
		{'a', 'z'},
		{'a', 'c', 'a', 'z'},
		{0, unicode.MaxRune, 'a', 'z'},
		{0, 5, 3, unicode.MaxRune},
		{},
		{0, '\n' - 1, '\n' + 1, unicode.MaxRune - 1},
		// Each of the four positions in the AnyCharNotNL shape, moved
		// by one. Only the exact four runes may collapse.
		{1, '\n' - 1, '\n' + 1, unicode.MaxRune},
		{0, '\n', '\n' + 1, unicode.MaxRune},
		{0, '\n' - 1, '\n' + 2, unicode.MaxRune},
		{0, '\n' - 2, '\n' + 1, unicode.MaxRune},
		// And the AnyChar shape, likewise.
		{1, unicode.MaxRune},
		{0, unicode.MaxRune - 1},
		// Six runes cannot collapse however they are arranged.
		{0, '\n' - 1, '\n' + 1, 100, 102, unicode.MaxRune},
	}
	for i, c := range alts {
		re := &Regexp{Op: OpCharClass, Rune: append([]rune(nil), c...)}
		cleanAlt(re)
		fmt.Printf("cleanAlt %2d %s\n", i, zzre(re))
	}
	// A non-class is left alone.
	re := &Regexp{Op: OpLiteral, Rune: []rune{'z', 'a'}}
	cleanAlt(re)
	fmt.Printf("cleanAlt-nonclass %s\n", zzre(re))

	// ── mergeCharClass: all four dst arms ───────────────────────────
	type mc struct{ dst, src *Regexp }
	mcs := []mc{
		{&Regexp{Op: OpAnyChar}, &Regexp{Op: OpLiteral, Rune: []rune{'a'}}},
		{&Regexp{Op: OpAnyCharNotNL}, &Regexp{Op: OpLiteral, Rune: []rune{'a'}}},
		{&Regexp{Op: OpAnyCharNotNL}, &Regexp{Op: OpLiteral, Rune: []rune{'\n'}}},
		{&Regexp{Op: OpAnyCharNotNL}, &Regexp{Op: OpAnyChar}},
		{&Regexp{Op: OpCharClass, Rune: []rune{'a', 'c'}}, &Regexp{Op: OpLiteral, Rune: []rune{'x'}}},
		{&Regexp{Op: OpCharClass, Rune: []rune{'a', 'c'}}, &Regexp{Op: OpLiteral, Rune: []rune{'k'}, Flags: FoldCase}},
		{&Regexp{Op: OpCharClass, Rune: []rune{'a', 'c'}}, &Regexp{Op: OpCharClass, Rune: []rune{'x', 'z'}}},
		{&Regexp{Op: OpLiteral, Rune: []rune{'a'}}, &Regexp{Op: OpLiteral, Rune: []rune{'a'}}},
		{&Regexp{Op: OpLiteral, Rune: []rune{'a'}}, &Regexp{Op: OpLiteral, Rune: []rune{'b'}}},
		{&Regexp{Op: OpLiteral, Rune: []rune{'a'}}, &Regexp{Op: OpLiteral, Rune: []rune{'a'}, Flags: FoldCase}},
		{&Regexp{Op: OpLiteral, Rune: []rune{'k'}, Flags: FoldCase}, &Regexp{Op: OpLiteral, Rune: []rune{'s'}, Flags: FoldCase}},
		// The literal-vs-literal arm turns on TWO things — same rune
		// AND same flags — so both halves need a row that fails only
		// on that half.
		{&Regexp{Op: OpLiteral, Rune: []rune{'a'}, Flags: FoldCase}, &Regexp{Op: OpLiteral, Rune: []rune{'a'}, Flags: FoldCase}},
		{&Regexp{Op: OpLiteral, Rune: []rune{'a'}, Flags: FoldCase}, &Regexp{Op: OpLiteral, Rune: []rune{'a'}}},
		{&Regexp{Op: OpLiteral, Rune: []rune{'k'}}, &Regexp{Op: OpLiteral, Rune: []rune{'k'}, Flags: FoldCase}},
		{&Regexp{Op: OpLiteral, Rune: []rune{'k'}, Flags: FoldCase}, &Regexp{Op: OpLiteral, Rune: []rune{'k'}}},
		{&Regexp{Op: OpLiteral, Rune: []rune{'z'}, Flags: NonGreedy}, &Regexp{Op: OpLiteral, Rune: []rune{'z'}, Flags: NonGreedy}},
		{&Regexp{Op: OpLiteral, Rune: []rune{'z'}, Flags: NonGreedy}, &Regexp{Op: OpLiteral, Rune: []rune{'z'}, Flags: Simple}},
	}
	for i, c := range mcs {
		mergeCharClass(c.dst, c.src)
		fmt.Printf("mergeCharClass %2d %s\n", i, zzre(c.dst))
	}

	// ── literalRegexp ───────────────────────────────────────────────
	for _, s := range []string{"", "a", "abc", "héllo", "\U0001F600", strings.Repeat("x", 5)} {
		fmt.Printf("literalRegexp %-10s %s\n", strconv.Quote(s), zzre(literalRegexp(s, Perl)))
	}

	// ── repeatIsValid ───────────────────────────────────────────────
	type rv struct {
		pat string
		n   int
	}
	rvs := []rv{
		// `a{1001}` and `(a{100}){100}` are omitted: Go's parser
		// refuses them before repeatIsValid ever sees them, so a row
		// for either would test Parse, not this.
		{"a{2}", 1000}, {"a{1000}", 1000},
		{"(a{10}){10}", 1000}, {"(a{10}){10}", 99}, {"(a{10}){10}", 100},
		{"((a{5}){5}){5}", 1000}, {"((a{5}){5}){5}", 124},
		{"a{0}", 1}, {"a{0,}", 1000}, {"a{2,}", 1},
		{"abc", 1}, {"(a|b)*", 1},
	}
	for _, c := range rvs {
		re, err := Parse(c.pat, Perl)
		if err != nil {
			fmt.Printf("repeatIsValid %-14s parse-error\n", strconv.Quote(c.pat))
			continue
		}
		var bb strings.Builder
		zzdump2(&bb, re)
		fmt.Printf("RTREE %s\n", bb.String())
		fmt.Printf("repeatIsValid %-14s %4d %v\n", strconv.Quote(c.pat), c.n, repeatIsValid(re, c.n))
	}

	// ── checkUTF8 ───────────────────────────────────────────────────
	for _, s := range []string{"", "abc", "héllo", "\xff", "a\xffb", "\xe4\xb8", "\xe4\xb8\x80", "a\x00b"} {
		e := checkUTF8(s)
		if e == nil {
			fmt.Printf("checkUTF8 %-10s nil\n", strconv.Quote(s))
		} else {
			fmt.Printf("checkUTF8 %-10s %s\n", strconv.Quote(s), strconv.Quote(e.Error()))
		}
	}

	// ── the perl and posix groups ───────────────────────────────────
	for _, k := range []string{`\d`, `\D`, `\s`, `\S`, `\w`, `\W`, `\x`, `\`, `d`} {
		if g, ok := perlGroup[k]; ok {
			fmt.Printf("perlGroup %-4s %+d %s\n", strconv.Quote(k), g.sign, zzrs(g.class))
		} else {
			fmt.Printf("perlGroup %-4s absent\n", strconv.Quote(k))
		}
	}
	names := []string{"alnum", "alpha", "ascii", "blank", "cntrl", "digit", "graph", "lower", "print", "punct", "space", "upper", "word", "xdigit"}
	for _, n := range names {
		for _, k := range []string{"[:" + n + ":]", "[:^" + n + ":]"} {
			g := posixGroup[k]
			fmt.Printf("posixGroup %-13s %+d %s\n", k, g.sign, zzrs(g.class))
		}
	}
	for _, k := range []string{"[:nope:]", "[::]", "[:]", "alnum", "[:alnum]"} {
		if _, ok := posixGroup[k]; ok {
			fmt.Printf("posixGroup %-13s present\n", k)
		} else {
			fmt.Printf("posixGroup %-13s absent\n", k)
		}
	}

	// ── the three synthetic tables ──────────────────────────────────
	fmt.Printf("anyTable       %d %d\n", len(appendTable(nil, anyTable)), len(appendNegatedTable(nil, anyTable)))
	fmt.Printf("asciiTable     %s\n", zzrs(appendTable(nil, asciiTable)))
	fmt.Printf("asciiFoldTable %s\n", zzrs(appendTable(nil, asciiFoldTable)))
	fmt.Printf("anyTable.head  %s\n", zzrs(appendTable(nil, anyTable)))
}
