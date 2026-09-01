package os_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CreateTemp and MkdirTemp take a caller-supplied PATTERN, and the
// one rule that keeps them safe is that a pattern may not contain a
// path separator: prefixAndSuffix rejects it, so the result can never
// escape the directory the caller named. The random part replaces the
// LAST "*", not the first, and is appended when there is none.
func TestGoishRef(t *testing.T) {
	dir := t.TempDir()
	patterns := []string{
		"", "x", "pre*", "*suf", "pre*suf", "a*b*c", "*", "**",
		"a/b", "/abs", "a/", "sub/x*", "../up*", "a\\b",
	}
	for i, p := range patterns {
		f, err := os.CreateTemp(dir, p)
		if err != nil {
			fmt.Printf("create %d %q ERR %q\n", i, p, err.Error())
		} else {
			base := filepath.Base(f.Name())
			indir := filepath.Dir(f.Name()) == dir
			// Mask the random run of digits so the vector is stable.
			masked := maskDigits(base)
			fmt.Printf("create %d %q OK %q indir=%v\n", i, p, masked, indir)
			f.Close()
			os.Remove(f.Name())
		}
	}
	for i, p := range patterns {
		name, err := os.MkdirTemp(dir, p)
		if err != nil {
			fmt.Printf("mkdir %d %q ERR %q\n", i, p, err.Error())
		} else {
			fmt.Printf("mkdir %d %q OK %q indir=%v\n", i, p,
				maskDigits(filepath.Base(name)), filepath.Dir(name) == dir)
			os.Remove(name)
		}
	}
	// Two calls never collide.
	a, _ := os.CreateTemp(dir, "c*")
	b, _ := os.CreateTemp(dir, "c*")
	fmt.Printf("distinct %v\n", a.Name() != b.Name())
	a.Close()
	b.Close()
	os.Remove(a.Name())
	os.Remove(b.Name())
}

// Collapse each RUN of digits to a single '#': the random part is a
// uint32 in decimal, so its LENGTH varies between calls.
func maskDigits(s string) string {
	var b strings.Builder
	prev := false
	for i := 0; i < len(s); i++ {
		d := s[i] >= '0' && s[i] <= '9'
		if d {
			if !prev {
				b.WriteByte('#')
			}
		} else {
			b.WriteByte(s[i])
		}
		prev = d
	}
	return b.String()
}
