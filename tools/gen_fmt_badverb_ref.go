package fmt_test

import (
	"fmt"
	"testing"
)

// Go never silently prints a value under a verb its type does not take.
// It emits `%!verb(type=value)` — a marker that survives into logs and
// golden files and says exactly what went wrong. A printer without that
// machinery renders the value anyway, and the mistake is invisible.
func TestGoishRef(t *testing.T) {
	sf := fmt.Sprintf

	// Every verb against every scalar kind.
	verbs := []string{"v", "s", "q", "d", "b", "o", "O", "x", "X", "c", "U", "e", "f", "g", "t", "p", "T", "z"}
	vals := []any{
		"ab",
		[]byte("ab"),
		int(42),
		int64(-7),
		uint(9),
		byte(65),
		rune('x'),
		3.5,
		float32(1.5),
		true,
		error(nil),
		fmt.Errorf("boom"),
	}
	for _, v := range vals {
		line := fmt.Sprintf("bad %-12T", v)
		for _, verb := range verbs {
			line += fmt.Sprintf(" %s=%q", verb, sf("%"+verb, v))
		}
		fmt.Println(line)
	}

	// Composites take the marker per element.
	fmt.Printf("comp a=%q b=%q c=%q\n",
		sf("%d", []string{"a", "b"}), sf("%s", []int{1, 2}),
		sf("%d", map[string]int{"a": 1}))

	// Too many and too few arguments.
	fmt.Printf("extra a=%q b=%q c=%q d=%q\n",
		sf("%d", 1, 2), sf("x", 1), sf("%d %d", 1), sf("%d", 1, "s", 2.5))
	// A stray % at the end, and an unknown verb with a flag.
	fmt.Printf("noverb a=%q b=%q c=%q\n", sf("abc%"), sf("%!", 1), sf("%#z", 1))

	// The type name Go prints in the marker is the Go type name.
	fmt.Printf("tname a=%q b=%q c=%q d=%q e=%q\n",
		sf("%T", "x"), sf("%T", []byte("x")), sf("%T", 1), sf("%T", 1.5), sf("%T", []int{1}))
}
