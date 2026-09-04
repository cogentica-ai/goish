package scanner_test

import (
	"fmt"
	"strings"
	"testing"
	"text/scanner"
)

// text/scanner tokenizes Go-like source, and a tokenizer's bugs are all
// at the boundaries: the last character of a token, the first of the
// next, and what happens when a token runs off the end of the input.
// Every one of those is invisible in ordinary input and obvious in a
// reference.
//
// The rules worth pinning:
//
//   * The Mode is a set of bits saying which token KINDS to recognise.
//     With ScanInts off, "123" is not an Int — it comes back as the
//     individual characters '1', '2', '3', because an unrecognised
//     token degrades to a rune rather than an error.
//   * Position is 1-based for Line and Column and counts RUNES, not
//     bytes, so a token after a CJK character reports the column a
//     human would count.
//   * A malformed token reports through the Error hook and still
//     returns something, so the scan continues — an unterminated string
//     does not swallow the rest of the file.
//   * Comments are skipped by default (SkipComments is in GoTokens) and
//     returned as tokens when ScanComments is set without it.
//   * Peek does not consume, and Next is the raw rune reader that
//     bypasses tokenisation entirely.
func TestGoishRef(t *testing.T) {
	type cfg struct {
		name string
		mode uint
	}
	configs := []cfg{
		{"gotokens", scanner.GoTokens},
		{"no-ints", scanner.GoTokens &^ scanner.ScanInts},
		{"comments", scanner.GoTokens&^scanner.SkipComments | scanner.ScanComments},
		{"idents-only", scanner.ScanIdents},
		{"zero", 0},
	}
	inputs := []struct {
		name string
		src  string
	}{
		{"idents", "abc _x9 Δx"},
		{"ints", "0 42 0x1f 0b101 0o17 1_000"},
		{"floats", "1.5 1e10 .5 1. 0x1p4"},
		{"strings", `"a" "b\nc" "é"`},
		{"rawstring", "`raw\nstring`"},
		{"chars", `'a' '\n' 'é'`},
		{"comments", "a // line\nb /* block */ c"},
		{"operators", "a+b*c == d"},
		{"mixed", "x := 1 + 2.5 // sum"},
		{"empty", ""},
		{"whitespace", "   \t\n  "},
		{"cjk", "日本 x"},
		{"unterminated-str", `"abc`},
		{"unterminated-cmt", "/* abc"},
		{"bad-char", `'ab'`},
		{"lone-backslash", `"a\qb"`},
	}
	for _, c := range configs {
		for _, in := range inputs {
			var s scanner.Scanner
			var errs []string
			s.Init(strings.NewReader(in.src))
			s.Mode = c.mode
			s.Error = func(_ *scanner.Scanner, msg string) {
				errs = append(errs, msg)
			}
			var toks []string
			for i := 0; i < 30; i++ {
				tok := s.Scan()
				if tok == scanner.EOF {
					break
				}
				toks = append(toks, fmt.Sprintf("%s:%q@%d:%d",
					scanner.TokenString(tok), s.TokenText(),
					s.Pos().Line, s.Pos().Column))
			}
			fmt.Printf("scan %-12s %-18s -> %v errs=%v\n",
				c.name, in.name, toks, errs)
		}
	}

	// Peek and Next: the raw rune interface underneath the tokenizer.
	{
		var s scanner.Scanner
		s.Init(strings.NewReader("ab日"))
		fmt.Printf("peek1=%q next1=%q peek2=%q next2=%q next3=%q next4=%q\n",
			s.Peek(), s.Next(), s.Peek(), s.Next(), s.Next(), s.Next())
	}

	// Position after each token, including across a newline.
	{
		var s scanner.Scanner
		s.Init(strings.NewReader("a\nbb\n\nccc"))
		s.Mode = scanner.GoTokens
		for {
			tok := s.Scan()
			if tok == scanner.EOF {
				break
			}
			p := s.Pos()
			fmt.Printf("pos %-4q offset=%-3d line=%d col=%d\n",
				s.TokenText(), p.Offset, p.Line, p.Column)
		}
	}

	// IsValid and the token names.
	for _, tok := range []rune{scanner.EOF, scanner.Ident, scanner.Int,
		scanner.Float, scanner.Char, scanner.String, scanner.RawString,
		scanner.Comment, '+', 'x'} {
		fmt.Printf("tokname %-12s\n", scanner.TokenString(tok))
	}
	{
		var p scanner.Position
		q := scanner.Position{Line: 1}
		r := scanner.Position{Filename: "f", Line: 2, Column: 3}
		fmt.Printf("pos-valid zero=%v set=%v\n", p.IsValid(), q.IsValid())
		fmt.Printf("pos-string zero=%q\n", p.String())
		fmt.Printf("pos-string set=%q\n", r.String())
	}
}
