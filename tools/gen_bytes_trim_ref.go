package bytes_test

import (
	"bytes"
	"fmt"
	"testing"
	"unicode"
)

// The cutset is a STRING and is decoded as runes: Trim(s, "é") strips
// the two-byte é, not the bytes 0xC3 and 0xA9 wherever they turn up.
// The cutsets below land in each of the three dispatch paths — one
// ASCII byte, all ASCII, and one holding a non-ASCII rune — and the
// inputs include a lone continuation byte, so a byte-wise
// implementation and a rune-wise one disagree.
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
		"\xc3abc",
		"abc\xc3",
		"\xa9\xa9",
		"\xff\xfe\xff",
		"abcxyzcba",
	}
	for _, c := range cutsets {
		for _, in := range inputs {
			s := []byte(in)
			fmt.Printf("trim %-12q %-16q -> %-16q L=%-16q R=%q\n",
				c, in, bytes.Trim(s, c), bytes.TrimLeft(s, c), bytes.TrimRight(s, c))
		}
	}

	for _, in := range inputs {
		fmt.Printf("space %-16q -> %q\n", in, bytes.TrimSpace([]byte(in)))
	}
	for _, p := range []string{"", "a", "abc", "é", "xyz"} {
		for _, in := range inputs {
			s, pb := []byte(in), []byte(p)
			fmt.Printf("fix %-6q %-16q pre=%-16q suf=%q\n",
				p, in, bytes.TrimPrefix(s, pb), bytes.TrimSuffix(s, pb))
		}
	}

	for _, in := range []string{"", "I", "i", "İ", "ı", "Istanbul", "istanbul", "aAıİ"} {
		s := []byte(in)
		fmt.Printf("special %-12q up=%-14q low=%-14q title=%-14q | plain-up=%-14q plain-low=%q\n",
			in,
			bytes.ToUpperSpecial(unicode.TurkishCase, s),
			bytes.ToLowerSpecial(unicode.TurkishCase, s),
			bytes.ToTitleSpecial(unicode.TurkishCase, s),
			bytes.ToUpper(s), bytes.ToLower(s))
	}
}
