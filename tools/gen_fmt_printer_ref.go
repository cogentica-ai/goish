package fmt_test

import (
	"fmt"
	"testing"
)

// The printer's edges: operand spacing, width and precision on
// strings, and what fmt writes when the call is WRONG - a bad verb,
// a missing argument, an extra one. Those three are not errors in
// Go; they are output, with an exact shape, and code that greps its
// own logs depends on it.
func TestGoishRef(t *testing.T) {
	p := func(tag string, s string) { fmt.Printf("%s %q\n", tag, s) }

	// Sprint inserts a space between operands when NEITHER is a string.
	p("sprint1", fmt.Sprint("a", "b"))
	p("sprint2", fmt.Sprint(1, 2))
	p("sprint3", fmt.Sprint("a", 1))
	p("sprint4", fmt.Sprint(1, "a"))
	p("sprint5", fmt.Sprint(1, 2, "a", "b", 3))
	p("sprint6", fmt.Sprint(true, false))
	p("sprint7", fmt.Sprint())
	p("sprint8", fmt.Sprint("x"))

	// Sprintln always separates and always terminates.
	p("sprintln1", fmt.Sprintln("a", "b"))
	p("sprintln2", fmt.Sprintln(1, 2))
	p("sprintln3", fmt.Sprintln())

	// Width and precision on strings.
	p("w1", fmt.Sprintf("[%5s]", "ab"))
	p("w2", fmt.Sprintf("[%-5s]", "ab"))
	p("w3", fmt.Sprintf("[%.1s]", "abc"))
	p("w4", fmt.Sprintf("[%5.1s]", "abc"))
	p("w5", fmt.Sprintf("[%.0s]", "abc"))
	p("w6", fmt.Sprintf("[%5d]", 42))
	p("w7", fmt.Sprintf("[%-5d]", 42))
	p("w8", fmt.Sprintf("[%05d]", 42))
	p("w9", fmt.Sprintf("[%05d]", -42))
	p("w10", fmt.Sprintf("[%+d]", 42))
	p("w11", fmt.Sprintf("[%+d]", -42))
	p("w12", fmt.Sprintf("[%5t]", true))
	p("w13", fmt.Sprintf("[%5q]", "ab"))
	p("w14", fmt.Sprintf("[%5x]", "ab"))

	// Wrong calls are output, not errors. Routed through a variable
	// so `go vet` does not reject the file.
	sf := fmt.Sprintf
	p("bad1", sf("%d"))
	p("bad2", sf("%d %d", 1))
	p("bad3", sf("%d", 1, 2))
	p("bad4", sf("%z", 1))
	p("bad5", sf("%s", 1))
	p("bad6", sf("%d", "x"))
	p("bad7", sf("abc"))
	p("bad8", sf("abc", 1))
	p("bad9", sf("%"))
	p("bad10", sf("%!"))
	p("bad11", sf("100%%"))

	// Precision on the string-ish verbs.
	p("pq1", sf("%.2q", "abc"))
	p("pq2", sf("%.2v", "abc"))
	p("pq3", sf("%.2x", "abc"))
	p("pq4", sf("%.2s", "ab"))
	p("pq5", sf("%.2d", 12345))
	p("pq6", sf("%.5d", 42))
	p("pq7", sf("%+05d", 42))
	p("pq8", sf("%+x", 255))
	p("pq9", sf("%+v", 42))
	p("pq10", sf("%+s", "a"))
	p("pq11", sf("%+q", "a"))
	p("pq12", sf("% d", 42))

	// %x / %X over strings and byte slices.
	p("x1", fmt.Sprintf("%x", "abc"))
	p("x2", fmt.Sprintf("%X", "abc"))
	p("x3", fmt.Sprintf("%x", []byte("abc")))
	p("x4", fmt.Sprintf("%x", 255))
	p("x5", fmt.Sprintf("%X", 255))
	p("x6", fmt.Sprintf("%o", 8))
	p("x7", fmt.Sprintf("%b", 5))
	p("x8", fmt.Sprintf("%x", -255))

	// %v over the basic kinds.
	p("v1", fmt.Sprintf("%v", 42))
	p("v2", fmt.Sprintf("%v", "s"))
	p("v3", fmt.Sprintf("%v", true))
	p("v4", fmt.Sprintf("%v", []int{1, 2, 3}))
	p("v5", fmt.Sprintf("%v", []string{"a", "b"}))
	p("v6", fmt.Sprintf("%v", map[string]int{"a": 1, "b": 2}))
	p("v7", fmt.Sprintf("%v", [0]int{}))
	p("v8", fmt.Sprintf("%v", []byte("hi")))
}
