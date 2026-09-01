package fmt_test

import (
	"fmt"
	"testing"
)

// The '#' flag is "alternate format": 0b/0/0o/0x/0X prefixes on the
// integer bases, a backquoted string for %#q, the U+ form for %#U, and
// the Go-syntax rendering for %#v. A printf scanner that does not know
// '#' is a flag does not merely ignore it — it reads '#' as the VERB
// and leaves the real verb in the output as a literal.
func TestGoishRef(t *testing.T) {
	sf := fmt.Sprintf
	ints := []int64{0, 1, 7, 8, 255, 256, -1, -255}
	for _, n := range ints {
		fmt.Printf("int %-5d b=%q #b=%q o=%q #o=%q O=%q #O=%q x=%q #x=%q X=%q #X=%q d=%q\n",
			n, sf("%b", n), sf("%#b", n), sf("%o", n), sf("%#o", n),
			sf("%O", n), sf("%#O", n), sf("%x", n), sf("%#x", n),
			sf("%X", n), sf("%#X", n), sf("%d", n))
	}

	uints := []uint64{0, 1, 255, 4096}
	for _, n := range uints {
		fmt.Printf("uint %-5d #b=%q #o=%q #x=%q #X=%q\n",
			n, sf("%#b", n), sf("%#o", n), sf("%#x", n), sf("%#X", n))
	}

	// Strings and byte slices take %x/%#x too, and the prefix appears
	// ONCE, not per byte.
	for _, s := range []string{"", "a", "abc", "\xff\x00"} {
		fmt.Printf("str %-8q x=%q #x=%q X=%q #X=%q\n",
			s, sf("%x", s), sf("%#x", s), sf("%X", s), sf("%#X", s))
	}
	for _, b := range [][]byte{{}, {0x61}, {0xde, 0xad, 0xbe, 0xef}} {
		fmt.Printf("bytes %-14v x=%q #x=%q\n", b, sf("%x", b), sf("%#x", b))
	}

	// %#q backquotes when it can, and falls back to %q when it cannot.
	for _, s := range []string{"abc", "a\nb", "a`b", "a\"b", "héllo", "a\tb"} {
		fmt.Printf("q %-8q q=%q #q=%q\n", s, sf("%q", s), sf("%#q", s))
	}

	// %U and %#U.
	for _, r := range []rune{'x', 'é', '\n', 0x10FFFF, 0} {
		fmt.Printf("U %-8q U=%q #U=%q\n", string(r), sf("%U", r), sf("%#U", r))
	}

	// Width and zero-padding compose with '#': the prefix counts toward
	// the width, and '0' pads AFTER the prefix.
	fmt.Printf("pad a=%q b=%q c=%q d=%q e=%q f=%q\n",
		sf("%#8x", 255), sf("%#-8x|", 255), sf("%#08x", 255),
		sf("%08x", 255), sf("%#8o", 8), sf("%#08b", 5))

	// %#v — the Go-syntax form, for the handful of shapes goish can
	// build.
	fmt.Printf("sharpv int=%q str=%q bool=%q f=%q bytes=%q slice=%q\n",
		sf("%#v", 42), sf("%#v", "ab"), sf("%#v", true), sf("%#v", 1.5),
		sf("%#v", []byte{1, 2}), sf("%#v", []int{1, 2}))

	// '#' on a verb that does not use it is not an error in Go: it is
	// simply ignored.
	fmt.Printf("ignored s=%q d=%q f=%q v=%q c=%q\n",
		sf("%#s", "ab"), sf("%#d", 42), sf("%#f", 1.5), sf("%#v", 42), sf("%#c", 'x'))
}
