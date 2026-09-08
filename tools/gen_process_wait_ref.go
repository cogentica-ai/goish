// gen_process_wait_ref — os.Process.Wait's observable answers.
//
//	scripts/goref.sh os tools/gen_process_wait_ref.go
//
// CPU times cannot be pinned to a value — they are whatever the
// machine spent — so what is pinned is the shape Go guarantees around
// them: which state a Wait returns for an exit, for a signal death,
// and what the second Wait on the same process says. The times are
// asserted as ORDERING facts instead: a child that burns CPU reports
// more user time than one that sleeps, and a sleeper's user time is
// under its wall clock.
package os_test

import (
	"fmt"
	"os/exec"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	// exit codes and signal deaths, through the process the shell forks
	for _, c := range []struct {
		name string
		sh   string
	}{
		{"exit0", "exit 0"},
		{"exit3", "exit 3"},
		{"sigkill", "kill -9 $$"},
		{"sigterm", "kill -15 $$"},
	} {
		cmd := exec.Command("/bin/sh", "-c", c.sh)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		st, err := cmd.Process.Wait()
		fmt.Printf("GOROW\t%s\terr=%v exited=%v code=%d success=%v str=%q\n",
			c.name, err, st.Exited(), st.ExitCode(), st.Success(), st.String())

		// A second Wait on a reaped pid: ECHILD, wrapped by NewSyscallError.
		_, err2 := cmd.Process.Wait()
		fmt.Printf("GOROW\t%s-again\terr=%v\n", c.name, err2)
	}

	// CPU time: a busy child must report more user time than a sleeper,
	// and the sleeper's user time must be well under its wall clock.
	busy := exec.Command("/bin/sh", "-c", "i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done")
	_ = busy.Start()
	bst, _ := busy.Process.Wait()
	idle := exec.Command("/bin/sh", "-c", "sleep 0.3")
	start := time.Now()
	_ = idle.Start()
	ist, _ := idle.Process.Wait()
	wall := time.Since(start)
	fmt.Printf("GOROW\tcpu\tbusy>idle=%v idle_user<wall=%v idle_user_lt_100ms=%v\n",
		bst.UserTime() > ist.UserTime(),
		ist.UserTime() < wall,
		ist.UserTime() < 100*time.Millisecond)
}
