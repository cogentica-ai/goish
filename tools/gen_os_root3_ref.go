// gen_os_root3_ref — Root.Readlink, ReadFile and WriteFile.
//
//	scripts/goref.sh os tools/gen_os_root3_ref.go
//
// The three that need no syscalls the tree does not already have.
// Each gets the same three refusals as every other operation on the
// walk (ROADMAP §2q): "..", an absolute path, and a symlink pointing
// outside. Readlink is the interesting one — it acts on the LINK, so
// a link pointing outside is READ rather than refused, the same way
// Lstat describes it and Remove deletes it.
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
	_ = os.Symlink("ok.txt", filepath.Join(inside, "inside_link"))

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
	escapes := []string{"../secret.txt", "/etc/passwd"}

	// Readlink acts on the link itself.
	for _, n := range []string{"inside_link", "escape", "ok.txt"} {
		tgt, err := r.Readlink(n)
		fmt.Printf("GOROW\treadlink:%s\ttarget=%q err=%s\n", n, scrubStr(tgt, base, inside), scrub(err))
	}
	for _, n := range escapes {
		_, err := r.Readlink(n)
		fmt.Printf("GOROW\treadlink:%s\terr=%s\n", n, scrub(err))
	}

	// ReadFile: through a link that stays inside, and the refusals.
	for _, n := range []string{"ok.txt", "inside_link"} {
		b, err := r.ReadFile(n)
		fmt.Printf("GOROW\treadfile:%s\tdata=%q err=%s\n", n, string(b), scrub(err))
	}
	for _, n := range append(escapes, "escape") {
		_, err := r.ReadFile(n)
		fmt.Printf("GOROW\treadfile:%s\terr=%s\n", n, scrub(err))
	}

	// WriteFile, then read it back, then the refusals.
	err = r.WriteFile("written.txt", []byte("written"), 0o644)
	b, _ := r.ReadFile("written.txt")
	fmt.Printf("GOROW\twritefile:new\terr=%s readback=%q\n", scrub(err), string(b))
	for _, n := range append(escapes, "escape") {
		fmt.Printf("GOROW\twritefile:%s\terr=%s\n", n, scrub(r.WriteFile(n, []byte("x"), 0o644)))
	}
	// The file outside must be unchanged.
	out, _ := os.ReadFile(filepath.Join(base, "secret.txt"))
	fmt.Printf("GOROW\tsecret_intact\t%v\n", string(out) == "secret")
}

func scrubStr(s, base, inside string) string {
	for {
		i := idx(s, base+"/")
		if i < 0 {
			break
		}
		s = s[:i] + "OUT/" + s[i+len(base)+1:]
	}
	return s
}

func idx(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
