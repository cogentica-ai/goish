package strings_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// Trim, TrimLeft and TrimRight all dispatch three ways on the shape of
// the cutset — one ASCII byte, all-ASCII, or containing a non-ASCII
// rune — and the three paths have to agree. The cutsets below are
// chosen to land in each, and the inputs to straddle the boundaries:
// a cutset byte that is also a UTF-8 continuation byte, a cutset rune
// that is multi-byte, and an input that is entirely cutset.
func TestGoishRef(t *testing.T) {
	cutsets := []string{
		"",
		"a",
		" ",
		"ab",
		"abc",
		"0123456789",
		" \t\n",
		"\x80",
		"é",
		"aé",
		"日本",
		"\xff",
	}
	inputs := []string{
		"",
		"a",
		"abc",
		"aabbcc",
		"xyz",
		"aaa",
		"  hello  ",
		"\t\n x \n\t",
		"éaé",
		"ééé",
		"日本語日本",
		"caf\xc3\xa9",
		"\xff\xfe\xff",
		"abcxyzcba",
	}
	for _, c := range cutsets {
		for _, in := range inputs {
			fmt.Printf("trim %-12q %-16q -> %-16q L=%-16q R=%q\n",
				c, in, strings.Trim(in, c), strings.TrimLeft(in, c), strings.TrimRight(in, c))
		}
	}

	// TrimSpace, TrimPrefix, TrimSuffix on the same inputs.
	for _, in := range inputs {
		fmt.Printf("space %-16q -> %q\n", in, strings.TrimSpace(in))
	}
	for _, p := range []string{"", "a", "abc", "é", "xyz"} {
		for _, in := range inputs {
			fmt.Printf("fix %-6q %-16q pre=%-16q suf=%q\n",
				p, in, strings.TrimPrefix(in, p), strings.TrimSuffix(in, p))
		}
	}

	// The three SpecialCase mappings, on the runes Turkish moves.
	for _, in := range []string{"", "I", "i", "İ", "ı", "Istanbul", "istanbul", "aAıİ"} {
		fmt.Printf("special %-12q up=%-14q low=%-14q title=%-14q | plain-up=%-14q plain-low=%q\n",
			in,
			strings.ToUpperSpecial(unicode.TurkishCase, in),
			strings.ToLowerSpecial(unicode.TurkishCase, in),
			strings.ToTitleSpecial(unicode.TurkishCase, in),
			strings.ToUpper(in), strings.ToLower(in))
	}

	// ToUpper / ToLower / ToTitle over non-ASCII, which the package
	// header used to say were ASCII-only.
	for _, in := range []string{"café", "STRASSE", "Ǆǅǆ", "ß", "İ", "日本語"} {
		fmt.Printf("case %-12q up=%-12q low=%-12q title=%q\n",
			in, strings.ToUpper(in), strings.ToLower(in), strings.ToTitle(in))
	}

	// EqualFold across the fold orbits.
	pairs := [][2]string{
		{"", ""}, {"a", "A"}, {"abc", "ABC"}, {"Go", "GO"},
		{"K", "k"}, {"K", "K"}, {"ß", "ẞ"},
		{"ς", "σ"}, {"ς", "Σ"}, {"a", "b"}, {"a", "aa"},
	}
	for _, p := range pairs {
		fmt.Printf("fold %-8q %-8q -> %v\n", p[0], p[1], strings.EqualFold(p[0], p[1]))
	}
}
