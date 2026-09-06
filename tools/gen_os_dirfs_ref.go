package os_test

// Reference bytes for examples/os_dirfs_ref_smoke.rs.
//
// os.DirFS is used as a sandbox boundary, so its join is where the
// boundary is enforced (os/file.go, dirFS.join):
//
//   * an EMPTY root is refused outright — "os: DirFS with empty root".
//     Without that check, joining yields "/" + name, which is an
//     absolute path from the filesystem root rather than a contained
//     one.
//   * the name goes through filepathlite.Localize, which is
//     fs.ValidPath AND a rejection of any embedded NUL byte. A name
//     carrying a NUL passes ValidPath but is truncated at the C string
//     boundary by the kernel, so the file opened is not the file
//     validated.

import (
	"fmt"
	"os"
	"testing"
)

func TestGoishRef(t *testing.T) {
	root := "/tmp/goish_os_dirfs_ref"
	os.RemoveAll(root)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+"/f", []byte("inside\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	show := func(name, dir, open string) {
		f, err := os.DirFS(dir).Open(open)
		if err != nil {
			fmt.Printf("GOREF %-18s err=%q\n", name, err.Error())
			return
		}
		defer f.Close()
		b := make([]byte, 32)
		n, _ := f.Read(b)
		fmt.Printf("GOREF %-18s ok %q\n", name, string(b[:n]))
	}

	show("ok", root, "f")
	show("trailing-slash", root+"/", "f")
	show("empty-root", "", "f")
	show("nul-in-name", root, "f\x00ignored")
	show("dotdot", root, "../etc/hostname")
	show("absolute", root, "/etc/hostname")

	os.RemoveAll(root)
}
