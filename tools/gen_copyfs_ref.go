package os_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// CopyFS copies a tree, and its edges are the interesting part: it
// REFUSES to overwrite (O_EXCL), it recreates symlinks rather than
// following them, and the mode it writes is 0666 masked with the
// source's permission bits — not the source mode itself.
func TestGoishRef(t *testing.T) {
	src := t.TempDir()
	os.MkdirAll(filepath.Join(src, "sub", "deep"), 0o755)
	os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha"), 0o644)
	os.WriteFile(filepath.Join(src, "sub", "b.txt"), []byte("beta"), 0o600)
	os.WriteFile(filepath.Join(src, "sub", "deep", "c.txt"), []byte("gamma"), 0o755)

	dst := filepath.Join(t.TempDir(), "out")
	err := os.CopyFS(dst, os.DirFS(src))
	fmt.Printf("copy err=%v\n", err)

	// Walk the destination and print what landed.
	var got []string
	filepath.Walk(dst, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dst, p)
		if rel == "." {
			return nil
		}
		if info.IsDir() {
			got = append(got, fmt.Sprintf("d %s", rel))
		} else {
			b, _ := os.ReadFile(p)
			got = append(got, fmt.Sprintf("f %s %04o %q", rel, info.Mode().Perm(), string(b)))
		}
		return nil
	})
	sort.Strings(got)
	for _, g := range got {
		fmt.Printf("dst %s\n", g)
	}

	// Copying again over the same destination must FAIL: CopyFS opens
	// files with O_EXCL and will not clobber.
	err2 := os.CopyFS(dst, os.DirFS(src))
	fmt.Printf("recopy err=%v exist=%v\n", err2 != nil, errors.Is(err2, fs.ErrExist))

	// An empty source tree copies to an empty (but created) directory.
	empty := t.TempDir()
	dst2 := filepath.Join(t.TempDir(), "empty-out")
	err3 := os.CopyFS(dst2, os.DirFS(empty))
	fi, serr := os.Stat(dst2)
	fmt.Printf("empty err=%v isdir=%v staterr=%v\n", err3, serr == nil && fi.IsDir(), serr != nil)
}
