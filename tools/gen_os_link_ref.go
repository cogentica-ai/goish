package os_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Every error-returning entry point in os names the operation and the
// path, and does it through one of two structured types: *PathError for
// the one-path calls and *LinkError for the two-path ones. A port that
// returns errors.New("rename failed") answers with a string that names
// neither file, cannot be inspected with errors.As, and — because the
// errno is gone — cannot be classified by os.IsNotExist either.
func TestGoishRef(t *testing.T) {
	root := t.TempDir()
	j := func(p string) string { return filepath.Join(root, p) }
	os.WriteFile(j("f"), []byte("x"), 0644)
	os.Mkdir(j("d"), 0755)
	os.Symlink(j("f"), j("l"))

	show := func(tag string, err error) {
		if err == nil {
			fmt.Printf("op %-18s err=<nil>\n", tag)
			return
		}
		var pe *fs.PathError
		var le *os.LinkError
		kind := "other"
		if errors.As(err, &pe) {
			kind = "PathError"
		} else if errors.As(err, &le) {
			kind = "LinkError"
		}
		fmt.Printf("op %-18s kind=%-9s notexist=%-5v exist=%-5v text=%q\n",
			tag, kind, os.IsNotExist(err), os.IsExist(err), err.Error())
	}

	show("chdir/missing", os.Chdir(j("nope")))
	show("chdir/file", os.Chdir(j("f")))
	show("chmod/missing", os.Chmod(j("nope"), 0644))
	show("chmod/ok", os.Chmod(j("f"), 0644))
	show("chown/missing", os.Chown(j("nope"), -1, -1))
	show("lchown/missing", os.Lchown(j("nope"), -1, -1))
	show("truncate/missing", os.Truncate(j("nope"), 0))
	show("truncate/ok", os.Truncate(j("f"), 1))
	show("readlink/notlink", func() error { _, e := os.Readlink(j("f")); return e }())
	show("readlink/missing", func() error { _, e := os.Readlink(j("nope")); return e }())
	show("chtimes/missing", os.Chtimes(j("nope"), time.Now(), time.Now()))
	show("symlink/exists", os.Symlink(j("f"), j("l")))
	show("symlink/badnew", os.Symlink(j("f"), j("nodir/x")))
	show("link/missing", os.Link(j("nope"), j("l2")))
	show("link/exists", os.Link(j("f"), j("f")))
	show("rename/missing", os.Rename(j("nope"), j("f2")))
	show("rename/dirover", os.Rename(j("f"), j("d")))
	show("rename/ok", os.Rename(j("f"), j("f2")))
	show("remove/missing", os.Remove(j("nope")))

	// A LinkError names both paths, in Op Old New order.
	le := &os.LinkError{Op: "rename", Old: "a", New: "b", Err: fs.ErrExist}
	fmt.Printf("linkerror text=%q unwrap=%q isexist=%v\n",
		le.Error(), errors.Unwrap(le).Error(), os.IsExist(le))

	// A closed file: every method answers ErrClosed through a
	// *PathError naming the file.
	f, _ := os.Open(j("f2"))
	f.Close()
	_, e1 := f.Seek(0, 0)
	_, e2 := f.Stat()
	b := make([]byte, 1)
	_, e3 := f.Read(b)
	for i, e := range []error{e1, e2, e3} {
		fmt.Printf("closed %d err=%v isclosed=%v\n", i, e, errors.Is(e, fs.ErrClosed))
	}
}
