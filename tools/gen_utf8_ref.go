package utf8_test

import (
	"fmt"
	"testing"
	"unicode/utf8"
)

// The interesting inputs are the invalid ones. Go's decoder rejects
// overlong encodings, surrogate halves and anything above U+10FFFF, and
// reports (RuneError, 1) for each — the size-1 part being what stops a
// caller looping forever. The encoders are the mirror image: a negative
// rune, a surrogate half or an out-of-range value all encode as
// RuneError's three bytes, and a naive "validate then encode" gets the
// same answer only by accident.
func TestGoishRef(t *testing.T) {
	inputs := [][]byte{
		{},
		[]byte("a"),
		[]byte("\x7f"),
		{0x80},                   // lone continuation byte
		{0xbf},                   // lone continuation byte
		{0xc0, 0x80},             // overlong NUL
		{0xc1, 0xbf},             // overlong
		{0xc2, 0x80},             // U+0080, shortest form
		[]byte("é"),         // 2 bytes
		[]byte("日"),         // 3 bytes
		[]byte("\U0001F600"),     // 4 bytes
		{0xe0, 0x80, 0x80},       // overlong
		{0xe0, 0x9f, 0xbf},       // overlong
		{0xe0, 0xa0, 0x80},       // U+0800, shortest form
		{0xed, 0xa0, 0x80},       // surrogate D800
		{0xed, 0xbf, 0xbf},       // surrogate DFFF
		{0xf0, 0x80, 0x80, 0x80}, // overlong
		{0xf0, 0x90, 0x80, 0x80}, // U+10000
		{0xf4, 0x8f, 0xbf, 0xbf}, // U+10FFFF
		{0xf4, 0x90, 0x80, 0x80}, // above U+10FFFF
		{0xf5, 0x80, 0x80, 0x80}, // above U+10FFFF
		{0xfe},
		{0xff},
		{0xc2},             // truncated 2-byte
		{0xe6, 0x97},       // truncated 3-byte
		{0xf0, 0x9f, 0x98}, // truncated 4-byte
		[]byte("a\xffb"),
	}
	for _, in := range inputs {
		r, size := utf8.DecodeRune(in)
		rs, sizes := utf8.DecodeRuneInString(string(in))
		lr, lsize := utf8.DecodeLastRune(in)
		lrs, lsizes := utf8.DecodeLastRuneInString(string(in))
		fmt.Printf("decode %-26x r=%-8d size=%d | instr r=%-8d size=%d | last r=%-8d size=%d | laststr r=%-8d size=%d\n",
			in, r, size, rs, sizes, lr, lsize, lrs, lsizes)
		fmt.Printf("props  %-26x full=%-5v fullstr=%-5v valid=%-5v validstr=%-5v count=%d countstr=%d\n",
			in, utf8.FullRune(in), utf8.FullRuneInString(string(in)),
			utf8.Valid(in), utf8.ValidString(string(in)),
			utf8.RuneCount(in), utf8.RuneCountInString(string(in)))
	}

	runes := []rune{
		-1, -2147483648, 0, 'a', 0x7f, 0x80, 0x7ff, 0x800,
		0xd7ff, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000,
		0xfffd, 0xffff, 0x10000, 0x10ffff, 0x110000, 0x7fffffff,
	}
	for _, r := range runes {
		var buf [4]byte
		n := utf8.EncodeRune(buf[:], r)
		app := utf8.AppendRune([]byte("Z"), r)
		fmt.Printf("encode r=%-12d len=%-3d encoded=%x append=%x valid=%v\n",
			r, utf8.RuneLen(r), buf[:n], app, utf8.ValidRune(r))
	}

	for _, b := range []byte{0x00, 0x41, 0x7f, 0x80, 0xbf, 0xc0, 0xff} {
		fmt.Printf("runestart %#02x = %v\n", b, utf8.RuneStart(b))
	}

	fmt.Printf("consts RuneError=%d RuneSelf=%d MaxRune=%d UTFMax=%d\n",
		utf8.RuneError, utf8.RuneSelf, utf8.MaxRune, utf8.UTFMax)
}
