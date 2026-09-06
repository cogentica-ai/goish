package os_test

// Reference bytes for examples/os_readfile_ref_smoke.rs.
//
// os.ReadFile treats the stat size as a CAPACITY HINT and reads until
// EOF (os/file.go, readFileContents). Its own comment names the case
// this pins: "files in Linux's /proc claim size 0 but then do not work
// right if read in small pieces".
//
// /proc/sys/kernel/ostype is the stable probe — stat reports 0 bytes
// and the contents are "Linux\n" on every Linux, so the row is
// machine-independent and safe in CI.

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestGoishRef(t *testing.T) {
	dir := t.TempDir()

	reg := filepath.Join(dir, "regular")
	if err := os.WriteFile(reg, []byte("hello\nworld\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	show := func(name, path string) {
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Printf("GOREF %-14s err\n", name)
			return
		}
		fmt.Printf("GOREF %-14s len=%d %q\n", name, len(b), string(b))
	}

	show("regular", reg)
	show("empty", empty)
	// stat says 0; the contents are not 0.
	show("proc-ostype", "/proc/sys/kernel/ostype")
	show("missing", filepath.Join(dir, "nope"))

	// The stat size of the zero-size probe, to make the divergence
	// legible in the row itself rather than only in the comment.
	if fi, err := os.Stat("/proc/sys/kernel/ostype"); err == nil {
		fmt.Printf("GOREF %-14s statsize=%d\n", "proc-statsize", fi.Size())
	}
}
