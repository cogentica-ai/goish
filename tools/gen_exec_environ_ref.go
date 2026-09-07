package exec_test

import (
	"fmt"
	"os/exec"
	"testing"
)

// Cmd.Environ reports the environment the child would get: Env when
// set, deduplicated LAST-WINS, with non-"key=value" entries kept and
// NUL-bearing ones dropped. PWD is added only when Env is nil, so an
// explicit Env is never silently overridden (go.dev/issue/50599).
func TestGoishRef(t *testing.T) {
	c := exec.Command("/bin/echo")
	c.Env = []string{"A=1", "B=2", "A=3", "novalue", "", "C=4"}
	fmt.Printf("dedup=%q\n", c.Environ())

	c2 := exec.Command("/bin/echo")
	c2.Env = []string{"A=1", "BAD=x\x00y", "A=2"}
	fmt.Printf("nul=%q\n", c2.Environ())

	c3 := exec.Command("/bin/echo")
	c3.Env = []string{"=weird=v", "K=1", "=weird=w"}
	fmt.Printf("leading-eq=%q\n", c3.Environ())

	c4 := exec.Command("/bin/echo")
	c4.Env = []string{"a=1", "A=2"}
	fmt.Printf("case=%q\n", c4.Environ())
}
