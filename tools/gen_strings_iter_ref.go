package strings_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode"
)

// Each Seq function yields exactly what its slice-building twin
// returns, so the reference prints both and the smoke checks the Seq
// against the slice as well as against these vectors. The cases that
// separate them are the empty ones: an empty separator splits into
// runes, an empty input yields one empty string from SplitSeq but
// nothing from FieldsSeq, and a trailing separator yields a final
// empty fragment that a naive loop drops.
func TestGoishRef(t *testing.T) {
	splitCases := [][2]string{
		{"", ","},
		{"a", ","},
		{"a,b,c", ","},
		{"a,b,,c", ","},
		{",a,", ","},
		{",,", ","},
		{"abc", ""},
		{"héllo", ""},
		{"日本語", ""},
		{"a,,b", ",,"},
		{"aXXbXXc", "XX"},
		{"abc", "abc"},
		{"abc", "abcd"},
		{"\xff\xfe", ""},
	}
	for _, c := range splitCases {
		s, sep := c[0], c[1]
		fmt.Printf("split %-10q %-6q seq=%q slice=%q\n",
			s, sep, slices.Collect(strings.SplitSeq(s, sep)), strings.Split(s, sep))
		fmt.Printf("after %-10q %-6q seq=%q slice=%q\n",
			s, sep, slices.Collect(strings.SplitAfterSeq(s, sep)), strings.SplitAfter(s, sep))
	}

	lineCases := []string{
		"", "a", "a\n", "a\nb", "a\nb\n", "\n", "\n\n",
		"a\r\nb\r\n", "no newline at end", "日本\n語",
	}
	for _, s := range lineCases {
		fmt.Printf("lines %-22q seq=%q\n", s, slices.Collect(strings.Lines(s)))
	}

	fieldCases := []string{
		"",
		"   ",
		"a",
		"a b c",
		"  a  b  ",
		"\t\n\v\f\r a \r\f\v\n\t",
		"a b",
		"a b",
		"a　b",
		"日本 語",
		"one",
		"\xff \xfe",
	}
	for _, s := range fieldCases {
		fmt.Printf("fields %-22q seq=%q slice=%q\n",
			s, slices.Collect(strings.FieldsSeq(s)), strings.Fields(s))
	}

	// FieldsFuncSeq with three different predicates.
	preds := []struct {
		name string
		f    func(rune) bool
	}{
		{"digit", unicode.IsDigit},
		{"comma", func(r rune) bool { return r == ',' }},
		{"never", func(r rune) bool { return false }},
	}
	funcCases := []string{"", "a1b2c", "1234", ",a,,b,", "abc", "日1本"}
	for _, p := range preds {
		for _, s := range funcCases {
			fmt.Printf("fieldsfunc %-6s %-10q seq=%q slice=%q\n",
				p.name, s, slices.Collect(strings.FieldsFuncSeq(s, p.f)),
				strings.FieldsFunc(s, p.f))
		}
	}

	// Early stop: a yield returning false must end the walk.
	{
		for _, s := range []string{"a,b,c,d", "a b c d"} {
			var got []string
			for v := range strings.SplitSeq(s, ",") {
				got = append(got, v)
				if len(got) == 2 {
					break
				}
			}
			var gotF []string
			for v := range strings.FieldsSeq(s) {
				gotF = append(gotF, v)
				if len(gotF) == 2 {
					break
				}
			}
			fmt.Printf("stop %-10q split=%q fields=%q\n", s, got, gotF)
		}
	}
}
