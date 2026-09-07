package os_test

import (
	"fmt"
	"io"
	"os"
	"sort"
	"testing"
)

// File.ReadDir(n) reads the directory in BATCHES, resuming where the
// last call stopped, and reports io.EOF once drained — that is the
// whole point of the bounded form. n <= 0 reads everything and never
// returns io.EOF.
func TestGoishRef(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.txt", "b.txt", "c.txt"} {
		os.WriteFile(dir+"/"+n, []byte("x"), 0o644)
	}
	os.Mkdir(dir+"/sub", 0o755)

	f, _ := os.Open(dir)
	all, err := f.ReadDir(-1)
	names := []string{}
	for _, e := range all {
		names = append(names, fmt.Sprintf("%s:%v", e.Name(), e.IsDir()))
	}
	sort.Strings(names)
	fmt.Printf("all n=%d err=%v %v\n", len(all), err, names)
	f.Close()

	f2, _ := os.Open(dir)
	b1, e1 := f2.ReadDir(2)
	b2, e2 := f2.ReadDir(2)
	b3, e3 := f2.ReadDir(2)
	fmt.Printf("batch1 n=%d err=%v\n", len(b1), e1)
	fmt.Printf("batch2 n=%d err=%v\n", len(b2), e2)
	fmt.Printf("batch3 n=%d err=%v (io.EOF=%v)\n", len(b3), e3, e3 == io.EOF)
	f2.Close()
}
