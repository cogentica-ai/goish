// gen_processstate_string_export — the export_test.go shim that lets
// the external ref test build an os.ProcessState with an arbitrary
// wait(2) status.
//
// ProcessState's fields are unexported and there is no constructor, so
// without this the only reachable states are the ones a real child can
// produce — which excludes every ptrace stop, and those are exactly
// the rows under test. `package os` with no import but syscall, the
// same shape as Go's own export_test.go, because os is a package that
// `testing` and `fmt` both sit on top of.
//
// Passed to scripts/goref.sh as an extra file; see
// tools/gen_processstate_string_ref.go.
package os

import "syscall"

func GoishRefProcessState(pid int, status int) *ProcessState {
	return &ProcessState{pid: pid, status: syscall.WaitStatus(status)}
}
