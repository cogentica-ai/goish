// gen_os_root5_ref — Root.MkdirAll, Root.RemoveAll and Root.Chtimes.
//
//	scripts/goref.sh os tools/gen_os_root5_ref.go
//
// RemoveAll inside a Root is where the os.RemoveAll defect would hurt
// most, so the rows are built to catch it: a symlink to a directory
// OUTSIDE the root, sitting inside the tree being removed. If the
// implementation follows it, the victim loses its contents — and the
// root's whole promise with it.
//
// MkdirAll is the one operation whose walk needs a custom
// openDirFunc: it CREATES missing intermediate directories rather than
// failing on them.
package os_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	base := t.TempDir()
	inside := filepath.Join(base, "inside")
	victim := filepath.Join(base, "victim")
	_ = os.MkdirAll(inside, 0o755)
	_ = os.MkdirAll(victim, 0o755)
	_ = os.WriteFile(filepath.Join(victim, "precious.txt"), []byte("precious"), 0o644)
	_ = os.WriteFile(filepath.Join(inside, "f.txt"), []byte("F"), 0o644)

	r, err := os.OpenRoot(inside)
	if err != nil {
		t.Fatal(err)
	}
	scrub := func(e error) string {
		if e == nil {
			return "<nil>"
		}
		s := e.Error()
		for _, p := range []struct{ old, new string }{
			{inside + "/", ""}, {inside, "."}, {base + "/", "OUT/"}, {base, "OUT"},
		} {
			for {
				i := idx(s, p.old)
				if i < 0 || p.old == "" {
					break
				}
				s = s[:i] + p.new + s[i+len(p.old):]
			}
		}
		return s
	}

	// MkdirAll: nested creation, idempotence, and the refusals.
	fmt.Printf("GOROW\tmkdirall:a/b/c\terr=%s\n", scrub(r.MkdirAll("a/b/c", 0o755)))
	fmt.Printf("GOROW\tmkdirall:again\terr=%s\n", scrub(r.MkdirAll("a/b/c", 0o755)))
	fmt.Printf("GOROW\tmkdirall:escape\terr=%s\n", scrub(r.MkdirAll("../evil/x", 0o755)))
	fmt.Printf("GOROW\tmkdirall:abs\terr=%s\n", scrub(r.MkdirAll("/tmp/evil/x", 0o755)))
	_, e := os.Stat(filepath.Join(base, "evil"))
	fmt.Printf("GOROW\tno_evil_dir\t%v\n", os.IsNotExist(e))

	// RemoveAll with a symlink to a directory outside the root.
	_ = os.MkdirAll(filepath.Join(inside, "tree", "sub"), 0o755)
	_ = os.WriteFile(filepath.Join(inside, "tree", "x.txt"), []byte("X"), 0o644)
	_ = os.Symlink(victim, filepath.Join(inside, "tree", "dirlink"))
	_ = os.Symlink("nowhere", filepath.Join(inside, "tree", "dangling"))
	fmt.Printf("GOROW\tremoveall:tree\terr=%s\n", scrub(r.RemoveAll("tree")))
	_, e = r.Stat("tree")
	fmt.Printf("GOROW\ttree_gone\t%v\n", os.IsNotExist(e))
	b, rerr := os.ReadFile(filepath.Join(victim, "precious.txt"))
	fmt.Printf("GOROW\tvictim_intact\tdata=%q err=%v\n", string(b), rerr)

	fmt.Printf("GOROW\tremoveall:missing\terr=%s\n", scrub(r.RemoveAll("gone")))
	fmt.Printf("GOROW\tremoveall:escape\terr=%s\n", scrub(r.RemoveAll("../victim")))
	_, e = os.Stat(victim)
	fmt.Printf("GOROW\tvictim_dir_alive\t%v\n", e == nil)

	// Chtimes.
	at := time.Unix(1700000000, 0)
	mt := time.Unix(1700000123, 0)
	fmt.Printf("GOROW\tchtimes:ok\terr=%s\n", scrub(r.Chtimes("f.txt", at, mt)))
	fi, _ := r.Stat("f.txt")
	fmt.Printf("GOROW\tchtimes:mtime\t%d\n", fi.ModTime().Unix())
	fmt.Printf("GOROW\tchtimes:escape\terr=%s\n", scrub(r.Chtimes("../victim", at, mt)))
}

func idx(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
