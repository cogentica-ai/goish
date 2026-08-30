package scanner

import (
	"fmt"
	"strings"
	"testing"
)

func TestGoishRef(t *testing.T) {
	run := func(name string, mode uint, src string) {
		var s Scanner
		s.Init(strings.NewReader(src))
		s.Mode = mode
		s.Error = func(_ *Scanner, msg string) {} // count only
		fmt.Printf("== %s\n", name)
		for i := 0; i < 60; i++ {
			tok := s.Scan()
			if tok == EOF {
				break
			}
			fmt.Printf("%s|%q|%d:%d|%d\n",
				TokenString(tok), s.TokenText(), s.Position.Line, s.Position.Column, s.ErrorCount)
		}
		fmt.Printf("errors=%d\n", s.ErrorCount)
	}
	run("gotokens", GoTokens,
		"package main\n// line comment\nfunc f(x int) { y := 0x1f_2a; z := 1.5e3; s := \"hi\\n\"; c := 'a'; r := `raw` }\n")
	run("idents-only", ScanIdents, "abc 123 \"str\" x_1")
	run("comments-kept", ScanIdents|ScanComments, "a /*b*/ c // d\ne")
	run("numbers", ScanInts|ScanFloats,
		"0 00 0x 0b101 0o17 1_000 1__0 08 1.5 .5 1e3 0x1p-2 1e 0b1.2")
	run("bad", GoTokens, "\"unterminated\n 'ab' `x")
	run("unicode", GoTokens, "π := \"héllo\" // ünïcode\nΣ")
}
