// gen_os_root2_ref — the operations that ride on Root's walk.
//
//	scripts/goref.sh os tools/gen_os_root2_ref.go
//
// The point of these rows is NOT that Stat and Mkdir work. It is that
// each one inherits the ESCAPE rules — a Root.Stat that resolved its
// own path would pass a "stat a file inside" row and be unprotected.
// So every operation gets the same three refusals: "..", an absolute
// path, and a symlink pointing outside.
package os_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestGoishRef(t *testing.T) {
	base := t.TempDir()
	inside := filepath.Join(base, "inside")
	_ = os.MkdirAll(filepath.Join(inside, "sub"), 0o755)
	_ = os.WriteFile(filepath.Join(inside, "ok.txt"), []byte("hello"), 0o644)
	_ = os.WriteFile(filepath.Join(base, "secret.txt"), []byte("secret"), 0o644)
	_ = os.Symlink(filepath.Join(base, "secret.txt"), filepath.Join(inside, "escape"))

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

	escapes := []string{"../secret.txt", "/etc/passwd", "escape"}

	// Stat: the allowed case, then the three refusals.
	fi, err := r.Stat("ok.txt")
	name, size := "", int64(-1)
	if err == nil {
		name, size = fi.Name(), fi.Size()
	}
	fmt.Printf("GOROW\tstat:ok.txt\tname=%q size=%d err=%s\n", name, size, scrub(err))
	for _, n := range escapes {
		_, err := r.Stat(n)
		fmt.Printf("GOROW\tstat:%s\terr=%s\n", n, scrub(err))
	}

	// Lstat sees the symlink itself rather than following it.
	li, err := r.Lstat("escape")
	isLink := err == nil && li.Mode()&os.ModeSymlink != 0
	fmt.Printf("GOROW\tlstat:escape\tis_symlink=%v err=%s\n", isLink, scrub(err))

	// Mkdir, then the refusals.
	fmt.Printf("GOROW\tmkdir:new\terr=%s\n", scrub(r.Mkdir("new", 0o755)))
	fmt.Printf("GOROW\tmkdir:again\terr=%s\n", scrub(r.Mkdir("new", 0o755)))
	for _, n := range escapes {
		fmt.Printf("GOROW\tmkdir:%s\terr=%s\n", n, scrub(r.Mkdir(n, 0o755)))
	}

	// Remove, and the refusals.
	fmt.Printf("GOROW\tremove:new\terr=%s\n", scrub(r.Remove("new")))
	fmt.Printf("GOROW\tremove:missing\terr=%s\n", scrub(r.Remove("gone")))
	for _, n := range escapes {
		fmt.Printf("GOROW\tremove:%s\terr=%s\n", n, scrub(r.Remove(n)))
	}
	// The file outside must still be there.
	_, serr := os.Stat(filepath.Join(base, "secret.txt"))
	fmt.Printf("GOROW\tsecret_survived\t%v\n", serr == nil)

	// OpenInRoot and Root.Create / Root.OpenRoot.
	f, err := os.OpenInRoot(inside, "ok.txt")
	if err == nil {
		f.Close()
	}
	fmt.Printf("GOROW\topeninroot:ok.txt\terr=%s\n", scrub(err))
	_, err = os.OpenInRoot(inside, "../secret.txt")
	fmt.Printf("GOROW\topeninroot:escape\terr=%s\n", scrub(err))
	cf, err := r.Create("made.txt")
	if err == nil {
		cf.Close()
	}
	fmt.Printf("GOROW\tcreate:made.txt\terr=%s\n", scrub(err))
	sub, err := r.OpenRoot("sub")
	if err == nil {
		sub.Close()
	}
	fmt.Printf("GOROW\trootinroot:sub\terr=%s\n", scrub(err))
	_, err = r.OpenRoot("..")
	fmt.Printf("GOROW\trootinroot:..\terr=%s\n", scrub(err))
}

func idx(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
