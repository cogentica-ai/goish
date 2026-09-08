// gen_cmd_processstate_ref — what exec.Cmd.ProcessState reads back.
//
//	scripts/goref.sh os/exec tools/gen_cmd_processstate_ref.go
//
// Go documents the field as "Wait or Run will populate its
// ProcessState when the command completes" (exec.go:243). Pinned here:
// what it holds after a clean exit, a non-zero exit and a signal
// death, before Start, and after a SECOND Wait — plus that the rusage
// arrived, since Cmd.Wait reaping through Process.Wait rather than
// wait4 is the only reason UserTime has anything in it.
package exec_test

import (
	"fmt"
	"os/exec"
	"testing"
)

func has(c *exec.Cmd) string {
	if c.ProcessState == nil {
		return "<nil>"
	}
	return fmt.Sprintf("code=%d exited=%v success=%v str=%q",
		c.ProcessState.ExitCode(), c.ProcessState.Exited(),
		c.ProcessState.Success(), c.ProcessState.String())
}

func TestGoishRef(t *testing.T) {
	// Before Start.
	fresh := exec.Command("/bin/sh", "-c", "exit 0")
	fmt.Printf("GOROW\tbefore-start\tstate=%s\n", has(fresh))

	for _, c := range []struct{ name, sh string }{
		{"exit0", "exit 0"},
		{"exit7", "exit 7"},
		{"sigkill", "kill -9 $$"},
	} {
		cmd := exec.Command("/bin/sh", "-c", c.sh)
		err := cmd.Run()
		fmt.Printf("GOROW\t%s\terr=%v state=%s\n", c.name, err, has(cmd))

		// A second Wait is refused, and the state stays put.
		err2 := cmd.Wait()
		fmt.Printf("GOROW\t%s-again\terr=%v state=%s\n", c.name, err2, has(cmd))
	}

	// The rusage: a busy child must out-burn a sleeper, through Cmd.
	busy := exec.Command("/bin/sh", "-c", "i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done")
	_ = busy.Run()
	idle := exec.Command("/bin/sh", "-c", "sleep 0.3")
	_ = idle.Run()
	fmt.Printf("GOROW\trusage\tbusy>idle=%v idle_lt_100ms=%v\n",
		busy.ProcessState.UserTime() > idle.ProcessState.UserTime(),
		idle.ProcessState.UserTime() < 100000000)
}
