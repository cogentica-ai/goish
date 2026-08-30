package strings_test

import (
	"fmt"
	"strings"
	"testing"
)

// NewReplacer picks one of four algorithms from the shape of its
// arguments, and the four do not agree by construction — they agree
// because each implements the same rule: replacements happen in the
// order they appear in the target string, without overlapping, and the
// old strings are compared in argument order. The cases below are
// chosen to land in each of the four, and to disagree if the priority
// rule is implemented as "first pattern that matches here" instead.
func TestGoishRef(t *testing.T) {
	cases := []struct {
		name   string
		oldnew []string
		inputs []string
	}{
		// singleStringReplacer: one pattern, longer than a byte.
		{"single", []string{"ab", "X"},
			[]string{"", "a", "ab", "aab", "abab", "xaby", "aaab", "ababab", "ba"}},
		{"single-empty-new", []string{"abc", ""},
			[]string{"abcabc", "aabcb", "abc"}},
		{"single-longer-new", []string{"a", "aa"},
			[]string{"a", "aa", "banana"}},
		// byteReplacer: every old AND new exactly one byte.
		{"bytes", []string{"a", "1", "b", "2", "c", "3"},
			[]string{"", "abc", "cba", "xyz", "aaa"}},
		{"bytes-dup", []string{"a", "1", "a", "2"},
			[]string{"aaa", "bab"}},
		// byteStringReplacer: old one byte, new varies.
		{"bytestring", []string{"a", "AA", "b", "", "c", "C"},
			[]string{"", "abc", "aaa", "bbb", "abcabc"}},
		{"bytestring-dup", []string{"a", "XX", "a", "YY"},
			[]string{"aaa", "bab"}},
		// genericReplacer: the trie.
		{"generic-prefix", []string{"a", "1", "ab", "2"},
			[]string{"ab", "aab", "abab", "a", "b"}},
		{"generic-prefix-rev", []string{"ab", "2", "a", "1"},
			[]string{"ab", "aab", "abab", "a", "b"}},
		{"generic-overlap", []string{"aa", "X", "aaa", "Y"},
			[]string{"aa", "aaa", "aaaa", "aaaaa"}},
		{"generic-doc", []string{"ax", "1", "ay", "2", "bcbc", "3", "x", "4", "xy", "5"},
			[]string{"ax", "ay", "bcbc", "x", "xy", "axy", "bcbcbc", "zzz"}},
		{"generic-empty-old", []string{"", "X"},
			[]string{"", "a", "ab"}},
		{"generic-empty-and-more", []string{"", "X", "a", "1"},
			[]string{"", "a", "ab", "ba"}},
		{"generic-html", []string{"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;"},
			[]string{"", "a<b>&c", `"'`, "<<>>"}},
		{"generic-multibyte", []string{"é", "e", "日本", "JP"},
			[]string{"café", "日本語", "é日本é"}},
		{"generic-same-first-byte", []string{"abc", "1", "abd", "2", "ab", "3"},
			[]string{"abc", "abd", "abe", "ab", "abcabd"}},
	}

	for _, c := range cases {
		r := strings.NewReplacer(c.oldnew...)
		for _, in := range c.inputs {
			out := r.Replace(in)
			var sb strings.Builder
			n, err := r.WriteString(&sb, in)
			fmt.Printf("%-24s %-12q -> %-16q ws=%-16q n=%-3d err=%v\n",
				c.name, in, out, sb.String(), n, err)
		}
	}

	// A Replacer is reusable, and WriteString must agree with Replace
	// over repeated use.
	{
		r := strings.NewReplacer("a", "b", "b", "a")
		for i := 0; i < 3; i++ {
			fmt.Printf("reuse %d %q\n", i, r.Replace("abab"))
		}
	}
}
