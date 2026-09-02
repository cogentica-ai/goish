package os_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// SameFile answers about IDENTITY, not about paths or contents: two
// names for one inode are the same file, two identical copies are not,
// and a FileInfo that did not come from this package's Stat is never
// the same file as anything — including itself.
func TestGoishRef(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	link := filepath.Join(dir, "link")

	os.WriteFile(a, []byte("same"), 0o644)
	os.WriteFile(b, []byte("same"), 0o644)
	os.Link(a, link)

	fa, _ := os.Stat(a)
	fa2, _ := os.Stat(a)
	fb, _ := os.Stat(b)
	fl, _ := os.Stat(link)

	fmt.Printf("same-self        %v\n", os.SameFile(fa, fa))
	fmt.Printf("same-restat      %v\n", os.SameFile(fa, fa2))
	fmt.Printf("same-hardlink    %v\n", os.SameFile(fa, fl))
	fmt.Printf("diff-same-bytes  %v\n", os.SameFile(fa, fb))

	// A directory is the same file as itself.
	fd, _ := os.Stat(dir)
	fd2, _ := os.Stat(dir)
	fmt.Printf("same-dir         %v\n", os.SameFile(fd, fd2))
	fmt.Printf("dir-vs-file      %v\n", os.SameFile(fd, fa))

	// WriteString returns the BYTE count, not the rune count.
	f, _ := os.Create(filepath.Join(dir, "w"))
	n1, _ := f.WriteString("hello")
	n2, _ := f.WriteString("")
	n3, _ := f.WriteString("héllo")
	f.Close()
	fmt.Printf("writestring      %d %d %d\n", n1, n2, n3)
	got, _ := os.ReadFile(filepath.Join(dir, "w"))
	fmt.Printf("writestring-body %q len=%d\n", string(got), len(got))
}
