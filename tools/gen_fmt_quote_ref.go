package fmt_test

import (
	"errors"
	"fmt"
	"testing"
)

// fmt's %q is not a quoting rule of its own: format.go's fmtQ hands
// the value to strconv.AppendQuote (or AppendQuoteToASCII under the
// '+' flag), and fmtQc hands a rune to strconv.AppendQuoteRune. A fmt
// that quotes bytes itself gets three separate things wrong - non-ASCII
// runes, the escape short forms for runes, and the flags - and every
// one of them is silent.
//
// Values are printed as HEX so the vectors survive into a Rust source
// file unambiguously.
func TestGoishRef(t *testing.T) {
	strs := []string{
		"", "hello", "a\tb\nc", "he said \"hi\"", "back\\slash",
		"h\u00e9llo", "\u65e5\u672c\u8a9e", "emoji \U0001F600",
		"\x00\x01\x1f\x7f", "\u00ad", "\u200b", "\u00a0",
		"\xff\xfe", "a\xffb", "tab\there",
	}
	for i, s := range strs {
		fmt.Printf("q %d %x\n", i, fmt.Sprintf("%q", s))
		fmt.Printf("plusq %d %x\n", i, fmt.Sprintf("%+q", s))
		fmt.Printf("qb %d %x\n", i, fmt.Sprintf("%q", []byte(s)))
		fmt.Printf("qerr %d %x\n", i, fmt.Sprintf("%q", errors.New(s)))
		fmt.Printf("in %d %x\n", i, s)
	}

	runes := []rune{
		0, '\a', '\b', '\f', '\n', '\r', '\t', '\v', ' ', '!', '\'', '"',
		'\\', 'A', '~', 0x7f, 0x80, 0xa0, 0xa1, 0xad, 0xff, 0x100,
		0x200b, 0x3000, 0xfffd, 0xffff, 0x10000, 0x1d11e, 0x10ffff,
		-1, 0x110000, 0xd800,
	}
	for _, r := range runes {
		fmt.Printf("qrune %d %x %x\n", r, fmt.Sprintf("%q", r), fmt.Sprintf("%+q", r))
		fmt.Printf("crune %d %x\n", r, fmt.Sprintf("%c", r))
	}

	// Width and left-align still apply on top of the quoting.
	fmt.Printf("width %x\n", fmt.Sprintf("[%12q][%-12q]", "hi", "hi"))
	fmt.Printf("widthrune %x\n", fmt.Sprintf("[%8q][%-8q]", 'x', 'x'))
}
