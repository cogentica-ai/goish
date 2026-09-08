package flag_test

import (
	"bytes"
	"flag"
	"fmt"
	"testing"
)

// defaultUsage (flag.go:684) prints a HEADER before the flag list:
// "Usage of <name>:" or, for an unnamed set, "Usage:". goish printed
// only the list, so -h output differed from Go's on its first line.
// goish's FlagSet carries no name, so it always takes the empty-name
// branch — the "prog" row is Go's other branch, recorded so the
// difference is visible rather than implied.
func TestGoishRef(t *testing.T) {
	for _, name := range []string{"", "prog"} {
		var b bytes.Buffer
		fs := flag.NewFlagSet(name, flag.ContinueOnError)
		fs.SetOutput(&b)
		fs.String("s", "def", "a string")
		err := fs.Parse([]string{"-h"})
		fmt.Printf("name=%q err=%v out=%q\n", name, err, b.String())
	}
}
