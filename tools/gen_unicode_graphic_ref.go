package unicode_test

import (
	"fmt"
	"testing"
	"unicode"
)

// The Latin-1 block is where a hand-written approximation of these
// predicates goes wrong: '^' and '`' are Symbol, not Punct; U+00A1..
// U+00BF is a mix of the two; and U+00AA / U+00B5 / U+00BA are letters.
// Above Latin-1 the answer comes from a range table, so the checksums
// over the whole 0..0x10FFFF domain are what catch a table that is
// short a range.
func TestGoishRef(t *testing.T) {
	// Every Latin-1 code point, as one line per 16.
	for base := 0; base < 256; base += 16 {
		line := ""
		for i := base; i < base+16; i++ {
			r := rune(i)
			b := 0
			if unicode.IsControl(r) {
				b |= 1
			}
			if unicode.IsPunct(r) {
				b |= 2
			}
			if unicode.IsNumber(r) {
				b |= 4
			}
			if unicode.IsSymbol(r) {
				b |= 8
			}
			if unicode.IsSpace(r) {
				b |= 16
			}
			if unicode.IsUpper(r) {
				b |= 32
			}
			if unicode.IsLower(r) {
				b |= 64
			}
			if unicode.IsPrint(r) {
				b |= 128
			}
			if unicode.IsGraphic(r) {
				b |= 256
			}
			if unicode.IsLetter(r) {
				b |= 512
			}
			if unicode.IsDigit(r) {
				b |= 1024
			}
			if unicode.IsTitle(r) {
				b |= 2048
			}
			if unicode.IsMark(r) {
				b |= 4096
			}
			line += fmt.Sprintf("%04x,", b)
		}
		fmt.Printf("latin1 %02x %s\n", base, line)
	}

	// Counts over the whole rune domain: a missing or extra range in any
	// table moves exactly one of these.
	names := []struct {
		name string
		f    func(rune) bool
	}{
		{"IsControl", unicode.IsControl},
		{"IsPunct", unicode.IsPunct},
		{"IsNumber", unicode.IsNumber},
		{"IsSymbol", unicode.IsSymbol},
		{"IsSpace", unicode.IsSpace},
		{"IsUpper", unicode.IsUpper},
		{"IsLower", unicode.IsLower},
		{"IsTitle", unicode.IsTitle},
		{"IsPrint", unicode.IsPrint},
		{"IsGraphic", unicode.IsGraphic},
		{"IsLetter", unicode.IsLetter},
		{"IsMark", unicode.IsMark},
		{"IsDigit", unicode.IsDigit},
	}
	for _, n := range names {
		count := 0
		for r := rune(0); r <= 0x10FFFF; r++ {
			if n.f(r) {
				count++
			}
		}
		fmt.Printf("count %-10s %d\n", n.name, count)
	}

	// The same counts over a sample cheap enough for a debug-build
	// smoke to reproduce: every rune below U+10000, then every 17th
	// rune to U+10FFFF.
	for _, n := range names {
		count := 0
		for r := rune(0); r < 0x10000; r++ {
			if n.f(r) {
				count++
			}
		}
		for r := rune(0x10000); r <= 0x10FFFF; r += 17 {
			if n.f(r) {
				count++
			}
		}
		fmt.Printf("scount %-10s %d\n", n.name, count)
	}

	// A hand-picked set of the runes that separate a correct table from
	// an ASCII approximation.
	spot := []rune{
		'^', '`', '$', '+', '<', '=', '>', '|', '~',
		0xa1, 0xa2, 0xa6, 0xa7, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xb0,
		0xb1, 0xb5, 0xb6, 0xb7, 0xba, 0xbb, 0xbf, 0xd7, 0xf7,
		0x01c5, 0x01c8, 0x01cb, 0x01f2, 0x1f88, 0x1ffc,
		0x2000, 0x2028, 0x3000, 0x2070, 0x0660, 0x0966,
		0x2160, 0x0300, 0x1f600, 0x10ffff, -1,
	}
	for _, r := range spot {
		fmt.Printf("spot %-8d ctrl=%-5v punct=%-5v num=%-5v sym=%-5v space=%-5v up=%-5v low=%-5v title=%-5v print=%-5v graphic=%-5v letter=%-5v mark=%-5v digit=%v\n",
			r, unicode.IsControl(r), unicode.IsPunct(r), unicode.IsNumber(r),
			unicode.IsSymbol(r), unicode.IsSpace(r), unicode.IsUpper(r),
			unicode.IsLower(r), unicode.IsTitle(r), unicode.IsPrint(r),
			unicode.IsGraphic(r), unicode.IsLetter(r), unicode.IsMark(r),
			unicode.IsDigit(r))
	}

	fmt.Printf("consts MaxRune=%d ReplacementChar=%d MaxASCII=%d MaxLatin1=%d\n",
		unicode.MaxRune, unicode.ReplacementChar, unicode.MaxASCII, unicode.MaxLatin1)
}
