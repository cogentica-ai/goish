// gen_os_root_ref — os.Root's contract, especially what it REFUSES.
//
//	scripts/goref.sh os tools/gen_os_root_ref.go
//
// Root exists to make a path traversal impossible rather than merely
// discouraged: every component is resolved with openat(2) relative to
// the root's directory fd, with O_NOFOLLOW, so a "..", an absolute
// path, or a symlink pointing outside cannot escape even if an
// attacker controls the name. The rows below are the refusals — those
// are the security contract, and their exact errors are what a caller
// matches on.
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
	if err := os.MkdirAll(filepath.Join(inside, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inside, "ok.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the root pointing at the file outside it.
	_ = os.Symlink(filepath.Join(base, "secret.txt"), filepath.Join(inside, "escape"))
	_ = os.Symlink("../secret.txt", filepath.Join(inside, "rel_escape"))
	// Symlinks that stay INSIDE. Root follows these — it refuses an
	// escape, it does not refuse indirection — so an implementation
	// that simply rejects every symlink would pass the escape rows
	// above and still be wrong.
	_ = os.Symlink("ok.txt", filepath.Join(inside, "inside_link"))
	_ = os.Symlink("sub", filepath.Join(inside, "dir_link"))
	_ = os.Symlink("nowhere.txt", filepath.Join(inside, "dangling"))
	_ = os.WriteFile(filepath.Join(inside, "sub", "deep.txt"), []byte("deep"), 0o644)
	// A symlink that leaves and comes back: Root refuses it even
	// though the destination is inside, because a component escaped.
	_ = os.Symlink("../inside/ok.txt", filepath.Join(inside, "out_and_back"))

	r, err := os.OpenRoot(inside)
	if err != nil {
		t.Fatal(err)
	}
	// Name is the string handed to OpenRoot, and survives Close.
	fmt.Printf("GOROW\tname_is_arg\t%v\n", r.Name() == inside)

	// scrub the temp dir out of every message so the rows are stable
	scrub := func(e error) string {
		if e == nil {
			return "<nil>"
		}
		s := e.Error()
		s = replaceAll(s, inside+"/", "")
		s = replaceAll(s, inside, ".")
		s = replaceAll(s, base+"/", "OUT/")
		s = replaceAll(s, base, "OUT")
		return s
	}

	for _, name := range []string{
		"ok.txt",      // allowed
		"sub",         // allowed, a directory
		"../secret.txt",
		"..",
		"/etc/passwd",
		"sub/../ok.txt", // allowed: stays inside
		"escape",        // absolute symlink out
		"rel_escape",    // relative symlink out
		"nope.txt",      // simply missing
		"inside_link",   // symlink to a file inside: FOLLOWED
		"dir_link/deep.txt", // through a symlinked directory inside
		"dangling",      // symlink to nothing
		"out_and_back",  // leaves the root and returns
		"sub/../../secret.txt", // escapes via a deeper ..
		"./ok.txt",      // a no-op component
		"",              // the empty name
	} {
		f, err := r.Open(name)
		if err == nil {
			f.Close()
		}
		fmt.Printf("GOROW\topen:%s\terr=%s\n", name, scrub(err))
	}

	// OpenRoot on a non-directory, and on a missing name.
	_, err = os.OpenRoot(filepath.Join(inside, "ok.txt"))
	fmt.Printf("GOROW\troot_on_file\terr=%s\n", scrub(err))
	_, err = os.OpenRoot(filepath.Join(inside, "nope"))
	fmt.Printf("GOROW\troot_on_missing\terr=%s\n", scrub(err))

	// After Close, methods fail but Name still answers.
	r2, _ := os.OpenRoot(inside)
	nameBefore := r2.Name()
	_ = r2.Close()
	_, err = r2.Open("ok.txt")
	fmt.Printf("GOROW\tafter_close\tname_ok=%v err=%s\n", r2.Name() == nameBefore, scrub(err))
}

func replaceAll(s, old, new string) string {
	out := ""
	for {
		i := indexOf(s, old)
		if i < 0 || old == "" {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
