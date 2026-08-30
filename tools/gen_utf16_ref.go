package utf16_test

import (
	"fmt"
	"testing"
	"unicode/utf16"
)

// Everything here is about the surrogate split: a code point above
// U+FFFF travels as a high half in U+D800..U+DBFF plus a low half in
// U+DC00..U+DFFF, and every function substitutes U+FFFD for a half that
// turns up alone or out of order.
func TestGoishRef(t *testing.T) {
	runes := []rune{
		-1, 0, 'a', 0x7f, 0xd7ff,
		0xd800, 0xdbff, 0xdc00, 0xdfff,
		0xe000, 0xfffd, 0xffff,
		0x10000, 0x1f600, 0x10ffff, 0x110000, 0x7fffffff,
	}
	for _, r := range runes {
		r1, r2 := utf16.EncodeRune(r)
		fmt.Printf("rune %-12d surrogate=%-5v runelen=%-3d encode=(%d,%d)\n",
			r, utf16.IsSurrogate(r), utf16.RuneLen(r), r1, r2)
	}

	pairs := [][2]rune{
		{0xd800, 0xdc00},
		{0xd83d, 0xde00},
		{0xdbff, 0xdfff},
		{0xd800, 0xd800}, // two high halves
		{0xdc00, 0xdc00}, // two low halves
		{0xdc00, 0xd800}, // reversed
		{'a', 'b'},
		{0xd800, 'a'},
		{'a', 0xdc00},
	}
	for _, p := range pairs {
		fmt.Printf("decoderune (%d,%d) -> %d\n", p[0], p[1], utf16.DecodeRune(p[0], p[1]))
	}

	inputs := [][]rune{
		{},
		{'a', 'b', 'c'},
		{0x10000},
		{'a', 0x1f600, 'b'},
		{0xd800},         // lone high half
		{0xdc00},         // lone low half
		{0xffff, 0x10000},
		{-1},
		{0x110000},
	}
	for _, in := range inputs {
		enc := utf16.Encode(in)
		back := utf16.Decode(enc)
		fmt.Printf("encode %v -> %v -> %v\n", in, enc, back)
	}

	// AppendRune keeps the prefix and appends one or two units.
	for _, r := range []rune{'a', 0x10000, 0xd800, 0x110000} {
		fmt.Printf("appendrune %-10d -> %v\n", r, utf16.AppendRune([]uint16{0x5a}, r))
	}

	// Decode over sequences the encoder would never emit.
	decInputs := [][]uint16{
		{},
		{0x61, 0x62},
		{0xd83d, 0xde00},
		{0xd83d},         // truncated pair
		{0xd83d, 0x61},   // high half then ASCII
		{0xde00},         // lone low half
		{0xde00, 0xd83d}, // reversed pair
		{0xd83d, 0xd83d, 0xde00},
	}
	for _, in := range decInputs {
		fmt.Printf("decode %v -> %v\n", in, utf16.Decode(in))
	}
}
