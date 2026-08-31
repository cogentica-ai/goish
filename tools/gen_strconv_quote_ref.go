package strconv_test

import (
	"fmt"
	"strconv"
	"testing"
)

// Quote, QuoteToASCII and QuoteToGraphic are three different functions.
// They share appendQuotedWith and differ only in the ASCIIonly and
// graphicOnly flags, which decide whether a rune is emitted as itself
// or escaped, and the question those flags ask is IsPrint's - a binary
// search over four generated range tables, not a rule about byte
// values. A port that keeps one appender and aliases the other two onto
// it agrees with Go for pure ASCII and disagrees for everything else,
// in both directions: printable runes get escaped, unassigned ones do
// not.
//
// Every value below is printed as HEX so the vectors survive the trip
// into a Rust source file without a single ambiguous byte.
func TestGoishRef(t *testing.T) {
	strs := []string{
		"", "hello", "a\tb\nc", "\"quoted\"", `back\slash`,
		"h\u00e9llo", "\u65e5\u672c\u8a9e", "emoji \U0001F600 here",
		"\u00fcn\u00efc\u00f6d\u00e9",
		"\x00\x01\x1f\x7f", "\u00ad", "\u200b", "\ufeff",
		"\u0378", "\u0870", "\u00a0", "\u00a1",
		"\U0001D11E", "\U000E0001", "\U0010FFFF",
		"\xff\xfe", "a\xffb", "\xe4\xb8",
		"\u00a0\u2003", "\u3000", "\u1680",
		"'single'", "mixed \"'` quotes",
	}
	for i, s := range strs {
		fmt.Printf("qcase %d in=%x q=%x qa=%x qg=%x\n", i, s,
			strconv.Quote(s), strconv.QuoteToASCII(s), strconv.QuoteToGraphic(s))
	}

	runes := []rune{
		0, '\a', '\b', '\f', '\n', '\r', '\t', '\v', ' ', '!', '\'', '"',
		'\\', '~', 0x7f, 0x80, 0x9f, 0xa0, 0xa1, 0xad, 0xff, 0x100,
		0x200b, 0x2028, 0x2029, 0x3000, 0x1680, 0xfeff, 0xfffd,
		0xffff, 0x10000, 0x1d11e, 0xe0001, 0x10ffff, -1, 0x110000,
		0xd800, 0x378, 0x870, 0x20000, 0x2fa1d, 0x2fa1e,
	}
	for _, r := range runes {
		fmt.Printf("rcase %d q=%x qa=%x qg=%x print=%v graphic=%v\n", r,
			strconv.QuoteRune(r), strconv.QuoteRuneToASCII(r),
			strconv.QuoteRuneToGraphic(r), strconv.IsPrint(r), strconv.IsGraphic(r))
	}

	// Walk the whole code space and summarise, so a table transcribed
	// one entry short shows up as a count rather than a lucky miss.
	np, ng := 0, 0
	for r := rune(0); r < 0x110000; r++ {
		if strconv.IsPrint(r) {
			np++
		}
		if strconv.IsGraphic(r) {
			ng++
		}
	}
	fmt.Printf("counts print=%d graphic=%d\n", np, ng)

	// The Append forms must extend dst, not replace it.
	fmt.Printf("append q=%x\n", strconv.AppendQuote([]byte("<"), "h\u00e9llo"))
	fmt.Printf("append qa=%x\n", strconv.AppendQuoteToASCII([]byte("<"), "h\u00e9llo"))
	fmt.Printf("append qg=%x\n", strconv.AppendQuoteToGraphic([]byte("<"), "\u00a0"))
	fmt.Printf("append r=%x\n", strconv.AppendQuoteRune([]byte("<"), 0xe9))
	fmt.Printf("append ra=%x\n", strconv.AppendQuoteRuneToASCII([]byte("<"), 0xe9))
	fmt.Printf("append rg=%x\n", strconv.AppendQuoteRuneToGraphic([]byte("<"), 0xa0))

	// NumError.Error renders Num with Quote, not with a pair of bare
	// double quotes: a Num holding a quote, a backslash, a newline or a
	// non-ASCII rune comes out escaped.
	for i, in := range []string{"12x", "a\"b", "a\\b", "a\nb", "h\u00e9llo", "\u65e5", "\xff"} {
		_, err := strconv.ParseInt(in, 10, 64)
		fmt.Printf("numerror %d %x\n", i, err.Error())
	}

	// Round trip: everything Quote produces must Unquote back.
	for i, s := range strs {
		u, err := strconv.Unquote(strconv.Quote(s))
		fmt.Printf("roundtrip %d ok=%v err=%v\n", i, u == s, err)
	}
}
