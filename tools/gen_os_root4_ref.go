// gen_os_root4_ref — Root's mutating half: Rename, Link, Symlink,
// Chmod, Chown, Lchown.
//
//	scripts/goref.sh os tools/gen_os_root4_ref.go
//
// Rename and Link take TWO names, so each has two ways to escape and
// both are pinned — an implementation that resolves the first through
// the walk and the second directly would pass every one-name test in
// the tree.
//
// Symlink is the odd one: the TARGET is not resolved at all (it is
// just bytes written into the link), so `Symlink("/etc/passwd", ok)`
// SUCCEEDS. What that creates is a link the root itself will then
// refuse to follow, which is the property worth pinning.
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
	_ = os.MkdirAll(inside, 0o755)
	_ = os.WriteFile(filepath.Join(inside, "a.txt"), []byte("A"), 0o644)
	_ = os.WriteFile(filepath.Join(inside, "b.txt"), []byte("B"), 0o644)
	_ = os.WriteFile(filepath.Join(base, "secret.txt"), []byte("secret"), 0o600)
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

	// Rename: allowed, then an escape in EACH position.
	fmt.Printf("GOROW\trename:ok\terr=%s\n", scrub(r.Rename("a.txt", "moved.txt")))
	fmt.Printf("GOROW\trename:from_escape\terr=%s\n", scrub(r.Rename("../secret.txt", "stolen.txt")))
	fmt.Printf("GOROW\trename:to_escape\terr=%s\n", scrub(r.Rename("b.txt", "../stolen.txt")))

	// Link: same, both positions.
	fmt.Printf("GOROW\tlink:ok\terr=%s\n", scrub(r.Link("b.txt", "b_link.txt")))
	fmt.Printf("GOROW\tlink:from_escape\terr=%s\n", scrub(r.Link("../secret.txt", "stolen2.txt")))
	fmt.Printf("GOROW\tlink:to_escape\terr=%s\n", scrub(r.Link("b.txt", "../stolen2.txt")))

	// Symlink: the target is NOT resolved, only the name is.
	fmt.Printf("GOROW\tsymlink:ok\terr=%s\n", scrub(r.Symlink("b.txt", "b_sym")))
	fmt.Printf("GOROW\tsymlink:abs_target\terr=%s\n", scrub(r.Symlink("/etc/passwd", "passwd_sym")))
	fmt.Printf("GOROW\tsymlink:name_escape\terr=%s\n", scrub(r.Symlink("b.txt", "../evil_sym")))
	// ...and the root refuses to FOLLOW what it just allowed to exist.
	_, e := r.Open("passwd_sym")
	fmt.Printf("GOROW\topen:passwd_sym\terr=%s\n", scrub(e))

	// Chmod / Chown / Lchown.
	fmt.Printf("GOROW\tchmod:ok\terr=%s\n", scrub(r.Chmod("b.txt", 0o600)))
	fi, _ := r.Stat("b.txt")
	fmt.Printf("GOROW\tchmod:perm\t%04o\n", fi.Mode().Perm())
	fmt.Printf("GOROW\tchmod:escape\terr=%s\n", scrub(r.Chmod("../secret.txt", 0o777)))
	fmt.Printf("GOROW\tchmod:symlink_escape\terr=%s\n", scrub(r.Chmod("escape", 0o777)))
	// The file outside keeps its mode.
	ofi, _ := os.Stat(filepath.Join(base, "secret.txt"))
	fmt.Printf("GOROW\tsecret_mode\t%04o\n", ofi.Mode().Perm())

	// Chown to our own ids is a no-op that still exercises the path.
	uid, gid := os.Getuid(), os.Getgid()
	fmt.Printf("GOROW\tchown:ok\terr=%s\n", scrub(r.Chown("b.txt", uid, gid)))
	fmt.Printf("GOROW\tchown:escape\terr=%s\n", scrub(r.Chown("../secret.txt", uid, gid)))
	fmt.Printf("GOROW\tlchown:link\terr=%s\n", scrub(r.Lchown("escape", uid, gid)))
	fmt.Printf("GOROW\tlchown:escape\terr=%s\n", scrub(r.Lchown("../secret.txt", uid, gid)))
}

func idx(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
