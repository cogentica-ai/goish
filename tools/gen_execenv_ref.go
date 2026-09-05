package exec_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Cmd.Env: "If Env contains duplicate environment keys, only the last
// value in the slice for each duplicate key is used." That is what
// makes append(os.Environ(), "FOO=override") work.
func TestGoishRef(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"single", []string{"FOO=first"}},
		{"dup-two", []string{"FOO=first", "FOO=second"}},
		{"dup-three", []string{"FOO=a", "FOO=b", "FOO=c"}},
		{"override-shape", []string{"PATH=/bin:/usr/bin", "FOO=orig", "BAR=x", "FOO=override"}},
		{"empty-last", []string{"FOO=set", "FOO="}},
	} {
		// `env` prints the RAW environ, so duplicates are visible. A
		// shell would import them in order and mask the question.
		c := exec.Command("/bin/sh", "-c",
			"/usr/bin/env | grep -c '^FOO=' ; /usr/bin/env | grep '^FOO=' | tr '\n' ','")
		c.Env = tc.env
		out, err := c.Output()
		if err != nil {
			fmt.Printf("%-15s err=%v\n", tc.name, err)
			continue
		}
		fmt.Printf("%-15s FOO=%q\n", tc.name, string(out))
	}

	// Cmd.Dir: empty inherits the parent's cwd, set changes the
	// child's. goish's header claimed Dir was "not yet honored"; it is,
	// so the behaviour is pinned rather than the claim corrected.
	dir, _ := os.MkdirTemp("", "goishdir")
	defer os.RemoveAll(dir)
	real, _ := filepath.EvalSymlinks(dir)
	parent, _ := os.Getwd()
	for _, d := range []string{"", real} {
		c := exec.Command("/bin/sh", "-c", "pwd")
		c.Dir = d
		out, err := c.Output()
		if err != nil {
			fmt.Printf("dir-%-11s err=%v\n", label(d), err)
			continue
		}
		got := strings.TrimSpace(string(out))
		fmt.Printf("dir-%-11s matches=%v\n", label(d),
			(d == "" && got == parent) || (d != "" && got == real))
	}
}

func label(d string) string {
	if d == "" {
		return "inherit"
	}
	return "set"
}
