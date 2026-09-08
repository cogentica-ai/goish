package flag_test

import (
	"flag"
	"fmt"
	"testing"
)

// Uint64 is the one integer width goish's flag set could not express,
// and Arg(i) is how a program reads positional arguments after
// parsing. Arg returns "" out of range rather than panicking, which is
// what lets flag.Arg(0) be read unguarded.
func TestGoishRef(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	n := fs.Uint64("n", 7, "a uint64")
	s := fs.String("s", "d", "a string")
	err := fs.Parse([]string{"-n", "18446744073709551615", "-s", "x", "one", "two"})
	fmt.Printf("parse err=%v n=%d s=%q\n", err, *n, *s)
	fmt.Printf("args nargs=%d a0=%q a1=%q a2=%q a-1=%q\n",
		fs.NArg(), fs.Arg(0), fs.Arg(1), fs.Arg(2), fs.Arg(-1))

	fs2 := flag.NewFlagSet("t2", flag.ContinueOnError)
	d := fs2.Uint64("d", 42, "a uint64")
	fs2.Parse([]string{})
	fmt.Printf("default n=%d\n", *d)

	fs3 := flag.NewFlagSet("t3", flag.ContinueOnError)
	fs3.SetOutput(discard{})
	fs3.Uint64("n", 1, "a uint64")
	e3 := fs3.Parse([]string{"-n", "-5"})
	fmt.Printf("negative err=%v\n", e3 != nil)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
