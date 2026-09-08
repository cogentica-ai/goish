package exec_test

import (
	"fmt"
	"os/exec"
	"testing"
)

// Output captures stdout and, when Stderr was not otherwise collected,
// attaches a bounded prefix of stderr to the ExitError.
// CombinedOutput points BOTH streams at one buffer. String is the
// debugging rendering: the resolved path plus the args after argv[0].
func TestGoishRef(t *testing.T) {
	out, err := exec.Command("/bin/echo", "hello", "world").Output()
	fmt.Printf("echo out=%q err=%v\n", string(out), err)

	c := exec.Command("/bin/sh", "-c", "echo out; echo err 1>&2; exit 3")
	out2, err2 := c.Output()
	code, stderr := 0, ""
	if ee, ok := err2.(*exec.ExitError); ok {
		code = ee.ExitCode()
		stderr = string(ee.Stderr)
	}
	fmt.Printf("fail out=%q code=%d stderr=%q\n", string(out2), code, stderr)

	comb, err3 := exec.Command("/bin/sh", "-c", "echo one; echo two 1>&2").CombinedOutput()
	fmt.Printf("combined out=%q err=%v\n", string(comb), err3)

	fmt.Printf("string=%q\n", exec.Command("/bin/echo", "a", "b").String())

	c2 := exec.Command("/bin/echo", "x")
	c2.Stdout = nil
	_, _ = c2.Output()
	_, e4 := c2.Output()
	_ = e4
	c3 := exec.Command("/bin/echo", "x")
	var sink myWriter
	c3.Stdout = &sink
	_, e5 := c3.Output()
	fmt.Printf("stdout-already-set err=%v\n", e5)
}

type myWriter struct{}

func (myWriter) Write(p []byte) (int, error) { return len(p), nil }
