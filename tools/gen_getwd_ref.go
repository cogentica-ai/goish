package os_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Go's Getwd prefers $PWD when it genuinely names the current
// directory — "clumsy but widespread kludge", os/getwd.go. The only
// way to see it is from inside a directory reached through a symlink,
// where the logical path ($PWD) and the physical one (getcwd) differ.
//
// Absolute paths are machine-specific, so report which of the two the
// answer equals rather than the path itself.
func TestGoishRef(t *testing.T) {
	base, err := os.MkdirTemp("", "goishwd")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)
	// The temp root itself may be a symlink (/tmp -> /private/tmp and
	// friends); resolve it so "real" really is the physical path.
	base, _ = filepath.EvalSymlinks(base)
	real := filepath.Join(base, "real")
	link := filepath.Join(base, "link")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(link); err != nil {
		t.Fatal(err)
	}

	report := func(name string) {
		d, err := os.Getwd()
		fmt.Printf("%-14s eq-link=%v eq-real=%v err=%v\n",
			name, d == link, d == real, err)
	}

	os.Setenv("PWD", link)
	report("pwd-symlink")

	os.Setenv("PWD", "/")
	report("pwd-elsewhere")

	os.Setenv("PWD", "relative/not/absolute")
	report("pwd-relative")

	os.Setenv("PWD", real)
	report("pwd-physical")

	os.Unsetenv("PWD")
	report("pwd-unset")
}
