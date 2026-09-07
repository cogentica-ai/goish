package flag_test

import (
	"bytes"
	"flag"
	"fmt"
	"testing"
)

// failf (flag.go:1056) prints before it returns: sprintf writes the
// message to Output, then usage() writes the flag list. So a bad flag
// produces an EXPLANATION on the output, not just an error value —
// even under ContinueOnError, where the error is also returned.
func TestGoishRef(t *testing.T) {
	cases := [][]string{
		{"-nope"},
		{"-s"},
	}
	for _, args := range cases {
		var b bytes.Buffer
		fs := flag.NewFlagSet("", flag.ContinueOnError)
		fs.SetOutput(&b)
		fs.String("s", "def", "a string")
		err := fs.Parse(args)
		fmt.Printf("args=%v err=%v out=%q\n", args, err, b.String())
	}
}
