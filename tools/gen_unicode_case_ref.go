package unicode_test

import (
	"fmt"
	"testing"
	"unicode"
)

// CaseRanges is a range table with a delta triple per range, and the
// interesting entries are the ones whose delta is UpperLower: those are
// alternating Upper/Lower/Upper/Lower sequences where the mapping comes
// from the parity of the offset, not from a fixed shift. A flat
// rune-to-rune table gets those right by construction; a range table
// gets them right only if convertCase implements the parity rule.
func TestGoishRef(t *testing.T) {
	// Checksums over the whole domain: any single wrong mapping moves
	// one of these.
	var su, sl, st int64
	nu, nl, nt := 0, 0, 0
	for r := rune(0); r <= 0x10FFFF; r++ {
		u, l, ti := unicode.ToUpper(r), unicode.ToLower(r), unicode.ToTitle(r)
		su = su*31 + int64(u)
		sl = sl*31 + int64(l)
		st = st*31 + int64(ti)
		if u != r {
			nu++
		}
		if l != r {
			nl++
		}
		if ti != r {
			nt++
		}
	}
	fmt.Printf("checksum upper=%d lower=%d title=%d\n", su, sl, st)
	fmt.Printf("changed upper=%d lower=%d title=%d\n", nu, nl, nt)

	// The same over a sample a debug build can reproduce quickly: every
	// rune below U+10000, then every 17th to U+10FFFF.
	var su2, sl2, st2 int64
	sample := func(r rune) {
		su2 = su2*31 + int64(unicode.ToUpper(r))
		sl2 = sl2*31 + int64(unicode.ToLower(r))
		st2 = st2*31 + int64(unicode.ToTitle(r))
	}
	for r := rune(0); r < 0x10000; r++ {
		sample(r)
	}
	for r := rune(0x10000); r <= 0x10FFFF; r += 17 {
		sample(r)
	}
	fmt.Printf("schecksum upper=%d lower=%d title=%d\n", su2, sl2, st2)

	// Spot values, including every UpperLower sequence's first few runes
	// and the title-case letters.
	spot := []rune{
		'A', 'a', 'Z', 'z', '0', '@',
		0xb5,   // MICRO SIGN -> U+039C
		0xdf,   // LATIN SMALL LETTER SHARP S (no single-rune upper)
		0xff,   // y with diaeresis -> U+0178
		0x0100, 0x0101, 0x0130, 0x0131, 0x0132, 0x0133, 0x0134,
		0x01c4, 0x01c5, 0x01c6, // DZ with caron: an UpperLower triple
		0x01c7, 0x01c8, 0x01c9,
		0x0345, 0x03a3, 0x03c2, 0x03c3,
		0x1e9e, 0x1f88, 0x1fbc, 0x2126, 0x212a, 0x212b,
		0x2160, 0x2170, 0x24b6, 0x24d0,
		0x10400, 0x10428, 0x104b0, 0x104d8, 0x1e900, 0x1e922,
		-1, 0x110000,
	}
	for _, r := range spot {
		fmt.Printf("case %-8d upper=%-8d lower=%-8d title=%-8d fold=%d\n",
			r, unicode.ToUpper(r), unicode.ToLower(r), unicode.ToTitle(r),
			unicode.SimpleFold(r))
	}

	// To() with each case index, and with an out-of-range one.
	for _, c := range []int{unicode.UpperCase, unicode.LowerCase, unicode.TitleCase, -1, 3, 99} {
		fmt.Printf("to case=%-4d 'a'=%d 0x01c5=%d\n", c, unicode.To(c, 'a'), unicode.To(c, 0x01c5))
	}

	// The Turkish and Azeri dotted/dotless I.
	for _, r := range []rune{'I', 'i', 0x0130, 0x0131, 'A', 'a'} {
		fmt.Printf("turkish %-8d upper=%-8d lower=%-8d title=%d\n", r,
			unicode.TurkishCase.ToUpper(r), unicode.TurkishCase.ToLower(r),
			unicode.TurkishCase.ToTitle(r))
	}

	fmt.Printf("consts UpperCase=%d LowerCase=%d TitleCase=%d MaxCase=%d UpperLower=%d ranges=%d\n",
		unicode.UpperCase, unicode.LowerCase, unicode.TitleCase, unicode.MaxCase,
		unicode.UpperLower, len(unicode.CaseRanges))
}
