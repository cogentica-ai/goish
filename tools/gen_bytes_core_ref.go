package bytes_test

import (
	"bytes"
	"fmt"
	"testing"
	"unicode"
)

// The free functions in bytes.go were "covered" by a name match long
// before anything checked what they returned. The vectors below are
// picked for the places a byte-wise port and a rune-wise one disagree:
// an empty separator, a separator longer than the input, a lone
// continuation byte, an overlapping needle, a negative or zero count,
// and the boundary between "found at 0" and "not found".
func TestGoishRef(t *testing.T) {
	pairs := [][2]string{
		{"", ""},
		{"", "a"},
		{"a", ""},
		{"abc", "b"},
		{"abc", "abc"},
		{"abc", "abcd"},
		{"aaa", "aa"},
		{"banana", "ana"},
		{"héllo", "é"},
		{"héllo", "\xc3"},
		{"日本語", "本"},
		{"\xff\xfe", "\xfe"},
		{"abcabc", "c"},
	}
	for _, p := range pairs {
		s, sep := []byte(p[0]), []byte(p[1])
		fmt.Printf("idx %-8q %-6q Index=%-3d Last=%-3d Count=%-3d Contains=%-5v HasP=%-5v HasS=%v\n",
			p[0], p[1], bytes.Index(s, sep), bytes.LastIndex(s, sep), bytes.Count(s, sep),
			bytes.Contains(s, sep), bytes.HasPrefix(s, sep), bytes.HasSuffix(s, sep))
		before, after, found := bytes.Cut(s, sep)
		fmt.Printf("cut %-8q %-6q -> %q %q %v\n", p[0], p[1], before, after, found)
		cp, okp := bytes.CutPrefix(s, sep)
		cs, oks := bytes.CutSuffix(s, sep)
		fmt.Printf("cutfix %-8q %-6q pre=%q,%v suf=%q,%v\n", p[0], p[1], cp, okp, cs, oks)
		fmt.Printf("eq %-8q %-6q Equal=%-5v EqualFold=%-5v Compare=%d\n",
			p[0], p[1], bytes.Equal(s, sep), bytes.EqualFold(s, sep), bytes.Compare(s, sep))
	}

	// EqualFold is Unicode simple folding, not an ASCII tolower.
	foldPairs := [][2]string{
		{"Go", "GO"}, {"ß", "ss"}, {"K", "K"}, {"σ", "Σ"}, {"σ", "ς"},
		{"İ", "i"}, {"ı", "I"}, {"\xff", "\xff"}, {"a\xffb", "A\xffB"},
	}
	for _, p := range foldPairs {
		fmt.Printf("fold %-6q %-8q -> %v\n", p[0], p[1],
			bytes.EqualFold([]byte(p[0]), []byte(p[1])))
	}

	// IndexByte / IndexRune / LastIndexByte, including the invalid rune.
	for _, s := range []string{"", "abc", "héllo", "日本語", "\xff\xfe"} {
		for _, c := range []byte{'a', 'b', 0xff, 0xc3} {
			fmt.Printf("byte %-8q %#02x -> %d %d\n", s, c,
				bytes.IndexByte([]byte(s), c), bytes.LastIndexByte([]byte(s), c))
		}
		for _, r := range []rune{'a', 'é', '本', 0xFFFD, -1, 0x110000} {
			fmt.Printf("rune %-8q %-9d -> %d\n", s, r, bytes.IndexRune([]byte(s), r))
		}
	}

	// The Any/Func family: chars is a rune set, and an invalid byte in
	// the haystack must decode to RuneError, which is in the set only
	// if the caller put it there.
	for _, s := range []string{"", "abc", "héllo", "日本語", "\xff\xfe", "a\xffb"} {
		for _, chars := range []string{"", "a", "xyz", "é", "本語", "�", "\xff"} {
			fmt.Printf("any %-8q %-8q -> ContainsAny=%-5v Index=%-3d Last=%d\n",
				s, chars, bytes.ContainsAny([]byte(s), chars),
				bytes.IndexAny([]byte(s), chars), bytes.LastIndexAny([]byte(s), chars))
		}
		fmt.Printf("func %-8q digit=%-3d lastdigit=%-3d containsdigit=%-5v containsrune-é=%v\n",
			s, bytes.IndexFunc([]byte(s), unicode.IsDigit),
			bytes.LastIndexFunc([]byte(s), unicode.IsDigit),
			bytes.ContainsFunc([]byte(s), unicode.IsDigit),
			bytes.ContainsRune([]byte(s), 'é'))
	}

	// Split / SplitN / SplitAfter / SplitAfterN across the n arms.
	for _, p := range pairs {
		for _, n := range []int{-1, 0, 1, 2, 3, 100} {
			s, sep := []byte(p[0]), []byte(p[1])
			fmt.Printf("splitn %-8q %-6q n=%-4d -> %q | after %q\n",
				p[0], p[1], n, bytes.SplitN(s, sep, n), bytes.SplitAfterN(s, sep, n))
		}
		fmt.Printf("split %-8q %-6q -> %q | after %q\n",
			p[0], p[1], bytes.Split([]byte(p[0]), []byte(p[1])),
			bytes.SplitAfter([]byte(p[0]), []byte(p[1])))
	}

	// Join round-trips the split, including the empty-element cases.
	joins := [][]string{
		{}, {""}, {"a"}, {"a", "b"}, {"", "a", ""}, {"", ""}, {"日", "本"},
	}
	for _, parts := range joins {
		var b [][]byte
		for _, p := range parts {
			b = append(b, []byte(p))
		}
		for _, sep := range []string{"", ",", ", ", "日"} {
			fmt.Printf("join %-16q %-4q -> %q\n", parts, sep, bytes.Join(b, []byte(sep)))
		}
	}

	// Fields and FieldsFunc: the space set is unicode.IsSpace, so the
	// ideographic space U+3000 separates and NBSP U+00A0 does not.
	fieldCases := []string{
		"", "   ", "a", "a b c", "  a  b  ", "\t\n\v\f\r a \r\f\v\n\t",
		"a b", "a　b", "日本 語", "\xff \xfe", "a\xffb c",
	}
	for _, s := range fieldCases {
		fmt.Printf("fields %-16q -> %q\n", s, bytes.Fields([]byte(s)))
		fmt.Printf("fieldsfunc %-16q digit -> %q\n", s,
			bytes.FieldsFunc([]byte(s), unicode.IsDigit))
	}

	// Replace / ReplaceAll / Repeat across the n arms and the empty-old
	// case, which inserts between every rune (not every byte).
	repCases := [][3]string{
		{"", "", "x"}, {"abc", "", "-"}, {"abc", "b", "XY"}, {"abc", "b", ""},
		{"aaa", "a", "aa"}, {"banana", "ana", "X"}, {"héllo", "", "."},
		{"日本", "", "."}, {"abc", "d", "X"}, {"\xff\xfe", "", "."},
	}
	for _, c := range repCases {
		s, old, nw := []byte(c[0]), []byte(c[1]), []byte(c[2])
		for _, n := range []int{-1, 0, 1, 2, 100} {
			fmt.Printf("replace %-8q %-4q %-4q n=%-4d -> %q\n",
				c[0], c[1], c[2], n, bytes.Replace(s, old, nw, n))
		}
		fmt.Printf("replaceall %-8q %-4q %-4q -> %q\n", c[0], c[1], c[2],
			bytes.ReplaceAll(s, old, nw))
	}
	for _, s := range []string{"", "a", "ab", "日"} {
		for _, n := range []int{0, 1, 3} {
			fmt.Printf("repeat %-4q %d -> %q\n", s, n, bytes.Repeat([]byte(s), n))
		}
	}

	// Map drops a rune when f returns negative, and a mapped invalid
	// byte becomes RuneError.
	maps := []struct {
		name string
		f    func(rune) rune
	}{
		{"upper", unicode.ToUpper},
		{"drop-vowel", func(r rune) rune {
			if bytes.ContainsRune([]byte("aeiou"), r) {
				return -1
			}
			return r
		}},
		{"ident", func(r rune) rune { return r }},
		{"neg", func(r rune) rune { return -1 }},
	}
	mapCases := []string{"", "hello", "héllo", "日本語", "\xff\xfe", "a\xffb"}
	for _, m := range maps {
		for _, s := range mapCases {
			fmt.Printf("map %-10s %-8q -> %q\n", m.name, s, bytes.Map(m.f, []byte(s)))
		}
	}

	// Runes, ToValidUTF8, Title, Clone.
	for _, s := range mapCases {
		fmt.Printf("runes %-8q -> %q valid=%q clone=%q\n",
			s, bytes.Runes([]byte(s)), bytes.ToValidUTF8([]byte(s), []byte("?")),
			bytes.Clone([]byte(s)))
	}
	fmt.Printf("clone-nil %v %v\n", bytes.Clone(nil) == nil, len(bytes.Clone([]byte{})))
	for _, s := range []string{"", "her royal highness", "brown fox", "a", "日本 語", "x'y", "1a"} {
		fmt.Printf("title %-20q -> %q\n", s, bytes.Title([]byte(s))) //lint:ignore SA1019 reference
	}
}
