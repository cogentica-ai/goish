package os_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// MkdirAll and RemoveAll are the two everyone calls without checking
// the docs. Their edges: MkdirAll over an existing FILE is ENOTDIR in
// a *PathError; RemoveAll of a missing path is nil, of "" is nil, and
// of anything whose last component is "." is EINVAL, because rmdir(2)
// will not take it. That last one is a SAFETY property: without it,
// RemoveAll walks the directory and empties it before failing.
func TestGoishRef(t *testing.T) {
	root := t.TempDir()
	j := func(p string) string { return filepath.Join(root, p) }
	show := func(tag string, err error) {
		if err == nil {
			fmt.Printf("%s nil\n", tag)
			return
		}
		msg := err.Error()
		out := ""
		for i := 0; i < len(msg); i++ {
			if i+len(root) <= len(msg) && msg[i:i+len(root)] == root {
				out += "<root>"
				i += len(root) - 1
				continue
			}
			out += string(msg[i])
		}
		fmt.Printf("%s %q\n", tag, out)
	}

	show("mk_fresh", os.MkdirAll(j("a"), 0755))
	show("mk_again", os.MkdirAll(j("a"), 0755))
	show("mk_nested", os.MkdirAll(j("b/c/d"), 0755))
	show("mk_nested_again", os.MkdirAll(j("b/c/d"), 0755))
	show("mk_trailing", os.MkdirAll(j("e/f/"), 0755))
	show("mk_dot", os.MkdirAll(j("g/."), 0755))
	show("mk_dotdot", os.MkdirAll(j("h/i/.."), 0755))
	show("mk_empty", os.MkdirAll("", 0755))

	os.WriteFile(j("afile"), []byte("x"), 0644)
	show("mk_over_file", os.MkdirAll(j("afile"), 0755))
	show("mk_under_file", os.MkdirAll(j("afile/sub"), 0755))

	show("rm_missing", os.RemoveAll(j("nope")))
	show("rm_empty", os.RemoveAll(""))
	show("rm_file", os.RemoveAll(j("afile")))
	show("rm_tree", os.RemoveAll(j("b")))
	fmt.Printf("tree_gone %v\n", func() bool { _, e := os.Stat(j("b")); return os.IsNotExist(e) }())

	// The dot guard, on a path INSIDE the scratch dir. Built by
	// concatenation, not filepath.Join, so the trailing "/." survives.
	os.MkdirAll(j("dotdir"), 0755)
	show("rm_dotpath", os.RemoveAll(root+"/dotdir/."))
	_, de := os.Stat(j("dotdir"))
	fmt.Printf("dotdir_survived %v\n", de == nil)

	show("rm_again", os.RemoveAll(j("b")))
	os.MkdirAll(j("k/l"), 0755)
	show("remove_nonempty", os.Remove(j("k")))
	show("remove_missing", os.Remove(j("zzz")))
}
