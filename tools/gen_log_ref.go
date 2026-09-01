package log_test

import (
	"bytes"
	"fmt"
	"log"
	"testing"
)

// The log package is a header format. Every flag combination changes
// it, and the package-level Print family must go through the SAME
// standard logger the SetFlags/SetPrefix/SetOutput functions
// configure - a separate, simpler path would ignore all three.
//
// Digits are masked to 0 below so the vectors do not depend on the
// clock; everything else - separators, spacing, order, the newline
// rule - is compared exactly.
func TestGoishRef(t *testing.T) {
	flagsets := []struct {
		name string
		f    int
	}{
		{"zero", 0},
		{"date", log.Ldate},
		{"time", log.Ltime},
		{"std", log.LstdFlags},
		{"micro", log.Ltime | log.Lmicroseconds},
		{"datemicro", log.Ldate | log.Ltime | log.Lmicroseconds},
		{"utcstd", log.LstdFlags | log.LUTC},
		{"msgprefix", log.LstdFlags | log.Lmsgprefix},
		{"msgprefixzero", log.Lmsgprefix},
	}
	prefixes := []string{"", "P: "}
	for _, fsx := range flagsets {
		for pi, p := range prefixes {
			var buf bytes.Buffer
			lg := log.New(&buf, p, fsx.f)
			lg.Print("a", "b")
			lg.Println("a", "b")
			lg.Printf("x=%d", 7)
			lg.Printf("nl=%d\n", 8)
			_ = lg.Output(1, "raw")
			_ = lg.Output(1, "rawnl\n")
			fmt.Printf("logger %s %d %q\n", fsx.name, pi, buf.String())
		}
	}

	// Flags / Prefix round-trip.
	var b2 bytes.Buffer
	lg := log.New(&b2, "pfx ", log.LstdFlags)
	fmt.Printf("flags %d\n", lg.Flags())
	fmt.Printf("prefix %q\n", lg.Prefix())
	lg.SetFlags(log.Lshortfile)
	lg.SetPrefix("q ")
	fmt.Printf("flags2 %d\n", lg.Flags())
	fmt.Printf("prefix2 %q\n", lg.Prefix())

	// The PACKAGE-LEVEL functions must go through the standard logger,
	// so SetOutput / SetFlags / SetPrefix reach them.
	var b3 bytes.Buffer
	log.SetOutput(&b3)
	log.SetFlags(0)
	log.SetPrefix("std: ")
	log.Print("a", "b")
	log.Println("a", "b")
	log.Printf("x=%d", 7)
	fmt.Printf("pkg %q\n", b3.String())
	fmt.Printf("pkgflags %d\n", log.Flags())
	fmt.Printf("pkgprefix %q\n", log.Prefix())
	b3.Reset()
	log.SetPrefix("")
	log.SetFlags(log.Lmsgprefix)
	log.SetPrefix("M ")
	log.Println("hello")
	fmt.Printf("pkgmsgprefix %q\n", b3.String())
	fmt.Printf("default_is_std %v\n", log.Default().Flags() == log.Flags())
}
