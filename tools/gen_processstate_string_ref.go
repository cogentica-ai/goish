// gen_processstate_string_ref — ground truth for os.ProcessState.String.
//
//	scripts/goref.sh os tools/gen_processstate_string_ref.go \
//	    tools/gen_processstate_string_export.go
//
// Every string below comes out of Go's own String(), not out of a
// re-implementation of it — the shim hands back a real ProcessState
// carrying the raw status.
//
// The two SIGTRAP rows are the point. A ptrace stop puts its event
// number in the byte above the signal, and Go appends " (trap N)" for
// it. goish had no such branch, so a traced child rendered as a plain
// SIGTRAP stop and the event was lost.
package os_test

import (
	"fmt"
	"os"
	"testing"
)

func TestGoishRef(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"exit0", 0x0000},
		{"exit3", 0x0300},
		{"exit255", 0xff00},
		{"sigkill", 0x0009},
		{"sigsegv_core", 0x008b},
		{"stop_sigstop", 0x137f},
		{"stop_sigtrap_nocause", 0x057f},
		{"stop_sigtrap_fork", 0x01057f},
		{"stop_sigtrap_exec", 0x04057f},
		{"continued", 0xffff},
	}
	for _, c := range cases {
		p := os.GoishRefProcessState(4242, c.status)
		fmt.Printf("GOROW\t%s\t0x%06x\t%q\n", c.name, c.status, p.String())
	}
}
