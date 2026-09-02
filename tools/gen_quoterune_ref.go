package strconv_test

import (
	"fmt"
	"strconv"
	"testing"
	"unicode"
)

// QuoteRune keeps a PRINTABLE rune literal, however wide it is; it is
// QuoteRuneToASCII that escapes non-ASCII. Confusing the two makes
// every quoted non-ASCII rune come out escaped.
func TestGoishRef(t *testing.T) {
	for _, r := range []rune{'a', '\n', 0xE9, 0x1F600, 0x7F, 0x200B} {
		fmt.Printf("rune U+%04X quote=%-12q toascii=%-14q printable=%v\n",
			r, strconv.QuoteRune(r), strconv.QuoteRuneToASCII(r), strconv.IsPrint(r))
	}
	for _, r := range []rune{'A', 'a', 0x01C5, 0x01C8, 0x1F88} {
		fmt.Printf("istitle U+%04X %v\n", r, unicode.IsTitle(r))
	}
}
