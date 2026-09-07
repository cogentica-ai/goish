package flag_test

import (
	"errors"
	"flag"
	"fmt"
	"testing"
)

// Func and BoolFunc define flags whose "value" is a callback. Each
// occurrence calls fn, so they accumulate rather than overwrite — the
// usual way to collect a repeatable flag. BoolFunc additionally
// reports IsBoolFlag, so `-v` stands alone and does NOT consume the
// next argument.
func TestGoishRef(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	var got []string
	fs.Func("tag", "add a tag", func(s string) error {
		got = append(got, s)
		return nil
	})
	err := fs.Parse([]string{"-tag", "a", "-tag", "b", "rest"})
	fmt.Printf("func err=%v got=%v nargs=%d a0=%q\n", err, got, fs.NArg(), fs.Arg(0))

	fs2 := flag.NewFlagSet("t2", flag.ContinueOnError)
	var seen []string
	fs2.BoolFunc("v", "verbose", func(s string) error {
		seen = append(seen, s)
		return nil
	})
	err2 := fs2.Parse([]string{"-v", "-v=false", "positional"})
	fmt.Printf("boolfunc err=%v seen=%v nargs=%d a0=%q\n", err2, seen, fs2.NArg(), fs2.Arg(0))

	fs3 := flag.NewFlagSet("t3", flag.ContinueOnError)
	fs3.SetOutput(discard{})
	fs3.Func("x", "fails", func(s string) error { return errors.New("boom") })
	err3 := fs3.Parse([]string{"-x", "v"})
	fmt.Printf("func-error err=%v\n", err3)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
