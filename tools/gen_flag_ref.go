package flag_test

import (
	"bytes"
	"flag"
	"fmt"
	"testing"
	"time"
)

// The flag package is mostly about what it ACCEPTS and what it says
// when it does not. Each row below defines the same five flags, then
// parses one argv and reports every observable: the error text, each
// flag value, and the residual arguments.
func TestGoishRef(t *testing.T) {
	argvs := [][]string{
		{},
		{"-s", "x"},
		{"--s", "x"},
		{"-s=x"},
		{"--s=x"},
		{"-n", "7"},
		{"-n=7"},
		{"-n", "-7"},
		{"-b"},
		{"--b"},
		{"-b=true"},
		{"-b=false"},
		{"-b", "true"},
		{"-b", "arg"},
		{"-b", "-n", "3"},
		{"-f", "1.5"},
		{"-d", "1s"},
		{"-d", "1h30m"},
		{"-d", "nope"},
		{"-n", "notanumber"},
		{"-n", "99999999999999999999"},
		{"-zzz"},
		{"-zzz", "1"},
		{"pos1", "pos2"},
		{"pos1", "-s", "x"},
		{"-s", "x", "pos1", "-n", "3"},
		{"--", "-s", "x"},
		{"-s", "x", "--", "-n", "3"},
		{"-"},
		{"-s"},
		{"-n"},
		{"---s", "x"},
		{"-h"},
		{"-help"},
		{"-s", ""},
		{"-s=", "y"},
		{"-b=1"},
		{"-b=0"},
		{"-b=yes"},
	}
	for i, argv := range argvs {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		var buf bytes.Buffer
		fs.SetOutput(&buf)
		s := fs.String("s", "def", "a string")
		n := fs.Int("n", 42, "an int")
		b := fs.Bool("b", false, "a bool")
		f := fs.Float64("f", 2.5, "a float")
		d := fs.Duration("d", time.Second, "a duration")
		err := fs.Parse(argv)
		es := ""
		if err != nil {
			es = err.Error()
		}
		fmt.Printf("row %d argv=%q err=%q s=%q n=%d b=%v f=%v d=%v args=%q parsed=%v\n",
			i, argv, es, *s, *n, *b, *f, *d, fs.Args(), fs.Parsed())
	}

	// PrintDefaults output, which is what a user sees on -h.
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	fs.String("s", "def", "a string")
	fs.Int("n", 42, "an int")
	fs.Bool("b", false, "a bool")
	fs.String("empty", "", "no default shown")
	fs.PrintDefaults()
	fmt.Printf("defaults %q\n", buf.String())

	// NFlag / Lookup / Set / Visit.
	fs2 := flag.NewFlagSet("t2", flag.ContinueOnError)
	fs2.SetOutput(&buf)
	fs2.String("a", "1", "u")
	fs2.Int("c", 2, "u")
	_ = fs2.Parse([]string{"-a", "z"})
	fmt.Printf("nflag %d\n", fs2.NFlag())
	fmt.Printf("lookup_a %q\n", fs2.Lookup("a").Value.String())
	fmt.Printf("lookup_missing_nil %v\n", fs2.Lookup("nope") == nil)
	fmt.Printf("set_err %v\n", fs2.Set("c", "9"))
	fmt.Printf("after_set %q\n", fs2.Lookup("c").Value.String())
	fmt.Printf("set_missing %v\n", fs2.Set("nope", "1") != nil)
	visited := []string{}
	fs2.Visit(func(fl *flag.Flag) { visited = append(visited, fl.Name) })
	fmt.Printf("visit %q\n", visited)
	all := []string{}
	fs2.VisitAll(func(fl *flag.Flag) { all = append(all, fl.Name) })
	fmt.Printf("visitall %q\n", all)
}
