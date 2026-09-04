package strings_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// strings is the package every Go program uses, and goish had 2847
// lines of it with no reference test at all. Its edge cases are not
// exotic — they are the empty string, the empty separator, and the
// negative count, and each one has a rule that is easy to get
// backwards while every ordinary input still works:
//
//   * Split(s, "") splits into UTF-8 RUNES, not bytes and not an empty
//     result. Split("", sep) is []string{""} — one empty string, not
//     an empty slice — but Split("", "") is empty.
//   * SplitN's n is a cap on the RESULT, and n == 0 returns nil while
//     n < 0 means unlimited. Confusing 0 with "unlimited" is silent.
//   * Index of an empty substring is 0, and LastIndex of one is len(s).
//   * Trim/TrimLeft/TrimRight take a CUTSET of runes, not a prefix;
//     TrimPrefix takes a prefix. Reaching for the wrong one still
//     works whenever the cutset happens to be one character.
//   * Title is deprecated and does NOT lowercase the rest; ToTitle
//     upcases everything. They are different functions.
//   * EqualFold is Unicode simple case folding, so "K" folds to the
//     Kelvin sign and "ß" does not fold to "ss".
func TestGoishRef(t *testing.T) {
	// 1. Split family over the empty string and the empty separator.
	for _, c := range []struct{ s, sep string }{
		{"a,b,c", ","}, {"a,b,c", ""}, {"", ","}, {"", ""}, {"abc", ""},
		{"a", ","}, {",", ","}, {",,", ","}, {"a,,b", ","},
		{"日本語", ""}, {"a→b", "→"}, {"banana", "an"}, {"banana", "na"},
		{"aaa", "aa"}, {"x", "xx"},
	} {
		fmt.Printf("split %-8q %-4q -> %q\n", c.s, c.sep, strings.Split(c.s, c.sep))
		fmt.Printf("splitafter %-8q %-4q -> %q\n", c.s, c.sep, strings.SplitAfter(c.s, c.sep))
	}
	for _, n := range []int{-1, 0, 1, 2, 3, 10} {
		fmt.Printf("splitn n=%-3d -> %q  after=%q\n", n,
			strings.SplitN("a,b,c,d", ",", n), strings.SplitAfterN("a,b,c,d", ",", n))
	}

	// 2. Index family, including the empty needle and the not-found -1.
	for _, c := range []struct{ s, sub string }{
		{"chicken", "ken"}, {"chicken", ""}, {"", ""}, {"", "a"},
		{"chicken", "xyz"}, {"go gopher", "go"}, {"aaa", "aa"},
		{"日本語", "本"}, {"日本語", "語"},
	} {
		fmt.Printf("index %-10q %-5q -> idx=%-3d last=%-3d count=%d contains=%v\n",
			c.s, c.sub, strings.Index(c.s, c.sub), strings.LastIndex(c.s, c.sub),
			strings.Count(c.s, c.sub), strings.Contains(c.s, c.sub))
	}
	for _, c := range []struct{ s, chars string }{
		{"chicken", "aeiouy"}, {"crwth", "aeiouy"}, {"", "abc"}, {"abc", ""},
		{"日本語", "本語"}, {"abc", "cba"},
	} {
		fmt.Printf("indexany %-8q %-8q -> any=%-3d lastany=%d\n",
			c.s, c.chars, strings.IndexAny(c.s, c.chars), strings.LastIndexAny(c.s, c.chars))
	}
	for _, c := range []struct {
		s string
		r rune
	}{{"chicken", 'k'}, {"chicken", 'z'}, {"日本語", '本'}, {"", 'a'},
		{"abc", 0x10FFFF + 1}, {"a\xffb", 0xFFFD}} {
		fmt.Printf("indexrune %-8q %-9q -> %d\n", c.s, c.r, strings.IndexRune(c.s, c.r))
	}
	for _, c := range []struct{ s string }{{"chicken"}, {""}, {"日本語"}, {"ABC"}} {
		fmt.Printf("indexfunc %-8q upper=%-3d lastupper=%d\n", c.s,
			strings.IndexFunc(c.s, unicode.IsUpper), strings.LastIndexFunc(c.s, unicode.IsUpper))
	}

	// 3. Trim: a CUTSET, not a prefix.
	for _, c := range []struct{ s, cut string }{
		{"¡¡¡Hello!!!", "!¡"}, {"xxhixx", "x"}, {"xxhixx", "xh"},
		{"", "abc"}, {"abc", ""}, {"aaa", "a"}, {"  hi  ", " "},
		{"\t\n hi \r\n", ""}, {"日本語", "日語"},
	} {
		fmt.Printf("trim %-14q %-5q -> t=%-12q l=%-12q r=%-12q space=%q\n",
			c.s, c.cut, strings.Trim(c.s, c.cut), strings.TrimLeft(c.s, c.cut),
			strings.TrimRight(c.s, c.cut), strings.TrimSpace(c.s))
	}
	for _, c := range []struct{ s, p string }{
		{"hello", "he"}, {"hello", "x"}, {"hello", ""}, {"hello", "hello"},
		{"hello", "hellox"}, {"hello", "lo"},
	} {
		fmt.Printf("trimfix %-8q %-8q -> prefix=%-8q suffix=%-8q cutp=(%q,%v) cuts=(%q,%v)\n",
			c.s, c.p, strings.TrimPrefix(c.s, c.p), strings.TrimSuffix(c.s, c.p),
			mustCut(strings.CutPrefix(c.s, c.p)), mustOk(strings.CutPrefix(c.s, c.p)),
			mustCut(strings.CutSuffix(c.s, c.p)), mustOk(strings.CutSuffix(c.s, c.p)))
	}

	// 4. Cut.
	for _, c := range []struct{ s, sep string }{
		{"a=b", "="}, {"a=b=c", "="}, {"abc", "="}, {"", "="}, {"a=b", ""},
		{"=b", "="}, {"a=", "="},
	} {
		before, after, found := strings.Cut(c.s, c.sep)
		fmt.Printf("cut %-8q %-3q -> before=%-6q after=%-6q found=%v\n",
			c.s, c.sep, before, after, found)
	}

	// 5. Fields and FieldsFunc.
	for _, s := range []string{"  foo bar  baz   ", "", "   ", "a", "a\tb\nc\vd\fe\rf",
		"日 本 語", " x", "x y"} {
		fmt.Printf("fields %-20q -> %q\n", s, strings.Fields(s))
	}
	fmt.Printf("fieldsfunc %q -> %q\n", "a1b2c3",
		strings.FieldsFunc("a1b2c3", unicode.IsDigit))

	// 6. Case conversion, including the Unicode special cases.
	for _, s := range []string{"hello", "HELLO", "HeLlO", "", "日本語",
		"ǅungla", "ß", "İ", "ﬁ", "ΣΣΣ", "kelvin K"} {
		fmt.Printf("case %-10q -> lower=%-12q upper=%-14q title=%-12q totitle=%q\n",
			s, strings.ToLower(s), strings.ToUpper(s), strings.Title(s), strings.ToTitle(s))
	}

	// 7. EqualFold — simple folding, so K folds and ß does not.
	for _, p := range [][2]string{{"Go", "go"}, {"\u212a", "k"}, {"K", "K"}, {"ß", "ss"},
		{"ß", "SS"}, {"ſ", "s"}, {"ſ", "S"}, {"", ""}, {"", "x"},
		{"日本", "日本"}, {"ǅ", "ǆ"}, {"ǅ", "Ǆ"}} {
		fmt.Printf("equalfold %-8q %-8q -> %v\n", p[0], p[1], strings.EqualFold(p[0], p[1]))
	}

	// 8. Repeat, Join, Replace.
	for _, c := range []struct {
		s string
		n int
	}{{"ab", 0}, {"ab", 1}, {"ab", 3}, {"", 5}, {"日", 2}} {
		fmt.Printf("repeat %-4q %-2d -> %q\n", c.s, c.n, strings.Repeat(c.s, c.n))
	}
	for _, c := range []struct {
		elems []string
		sep   string
	}{{nil, ","}, {[]string{}, ","}, {[]string{"a"}, ","},
		{[]string{"a", "b"}, ","}, {[]string{"a", "b"}, ""},
		{[]string{"", ""}, "-"}} {
		fmt.Printf("join %q %-3q -> %q\n", c.elems, c.sep, strings.Join(c.elems, c.sep))
	}
	for _, c := range []struct {
		s, old, new string
		n           int
	}{
		{"oink oink oink", "k", "ky", 2}, {"oink oink oink", "oink", "moo", -1},
		{"banana", "a", "o", 0}, {"banana", "a", "o", 1}, {"banana", "a", "o", -1},
		{"abc", "", "-", -1}, {"abc", "", "-", 2}, {"", "", "-", -1},
		{"aaa", "aa", "b", -1},
	} {
		fmt.Printf("replace %-16q %-5q %-4q n=%-3d -> %q\n",
			c.s, c.old, c.new, c.n, strings.Replace(c.s, c.old, c.new, c.n))
	}

	// 9. Map and ToValidUTF8 over invalid input.
	fmt.Printf("map drop-vowels %q\n", strings.Map(func(r rune) rune {
		if strings.ContainsRune("aeiou", r) {
			return -1
		}
		return r
	}, "hello world"))
	for _, c := range []struct{ s, repl string }{
		{"abc", "?"}, {"a\xffb", "?"}, {"a\xffb", ""}, {"\xff\xfe", "!"},
		{"", "?"}, {"日本\xff語", "�"},
	} {
		fmt.Printf("tovalid %-10q %-8q -> %q\n", c.s, c.repl,
			strings.ToValidUTF8(c.s, c.repl))
	}

	// 10. HasPrefix / HasSuffix / Compare, including the empty cases.
	for _, p := range [][2]string{{"Gopher", "Go"}, {"Gopher", "C"},
		{"Gopher", ""}, {"", ""}, {"", "x"}, {"Gopher", "her"}, {"a", "ab"}} {
		fmt.Printf("prefix %-8q %-4q -> has=%-5v suffix=%-5v cmp=%d\n",
			p[0], p[1], strings.HasPrefix(p[0], p[1]),
			strings.HasSuffix(p[0], p[1]), strings.Compare(p[0], p[1]))
	}

	// 11. Builder and Replacer.
	{
		var b strings.Builder
		for i := 0; i < 3; i++ {
			fmt.Fprintf(&b, "%d-", i)
		}
		b.WriteString("end")
		b.WriteByte('!')
		b.WriteRune('日')
		fmt.Printf("builder %q len=%d\n", b.String(), b.Len())
		b.Reset()
		fmt.Printf("builder-reset %q len=%d\n", b.String(), b.Len())
	}
	{
		r := strings.NewReplacer("<", "&lt;", ">", "&gt;", "", "X")
		fmt.Printf("replacer %q\n", r.Replace("<b>hi</b>"))
		r2 := strings.NewReplacer("a", "b", "b", "a")
		fmt.Printf("replacer-swap %q\n", r2.Replace("abab"))
	}

	// 12. Lines / SplitSeq — the iterator forms added in Go 1.24.
	{
		var out []string
		for line := range strings.Lines("a\nb\n\nc") {
			out = append(out, line)
		}
		fmt.Printf("lines %q\n", out)
		out = nil
		for line := range strings.Lines("") {
			out = append(out, line)
		}
		fmt.Printf("lines-empty %q\n", out)
		out = nil
		for part := range strings.SplitSeq("a,b,c", ",") {
			out = append(out, part)
		}
		fmt.Printf("splitseq %q\n", out)
	}
}

func mustCut(s string, _ bool) string { return s }
func mustOk(_ string, ok bool) bool   { return ok }
