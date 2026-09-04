package os_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var tmpdir string

func show(tag string, err error) {
	var pe *os.PathError
	isPE := errors.As(err, &pe)
	op, path := "", ""
	if isPE {
		op, path = pe.Op, filepath.Base(pe.Path)
		if pe.Path == tmpdir {
			path = "DIRBASE"
		}
	}
	fmt.Printf("%-16s err=%-52q pathErr=%-5v op=%-6q base=%-12q notExist=%-5v perm=%v\n",
		tag, errString(err), isPE, op, path,
		errors.Is(err, fs.ErrNotExist), errors.Is(err, fs.ErrPermission))
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return strings.ReplaceAll(err.Error(), tmpdir, "DIR")
}

func TestGoishRef(t *testing.T) {
	dir := t.TempDir()
	tmpdir = dir

	// Missing file.
	_, err := os.Open(filepath.Join(dir, "nope.txt"))
	show("open-missing", err)

	// A directory opened for writing.
	_, err = os.OpenFile(dir, os.O_WRONLY, 0)
	show("openfile-dir", err)

	// Read a directory as a file.
	f, _ := os.Open(dir)
	buf := make([]byte, 4)
	_, err = f.Read(buf)
	show("read-dir", err)
	f.Close()

	// NOTE: no permission case here. Opening a 0000 file fails for an
	// ordinary user and SUCCEEDS for root, and CI containers are
	// commonly root — the line would differ by who ran it, which is
	// not a property of the port.
	secret := filepath.Join(dir, "secret")
	os.WriteFile(secret, []byte("x"), 0o644)

	// Remove something that is not there.
	err = os.Remove(filepath.Join(dir, "nope.txt"))
	show("remove-missing", err)

	// Mkdir over an existing name.
	err = os.Mkdir(secret, 0o755)
	show("mkdir-exists", err)

	// Stat a missing path.
	_, err = os.Stat(filepath.Join(dir, "nope.txt"))
	show("stat-missing", err)
}
