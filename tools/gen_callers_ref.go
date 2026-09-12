// gen_callers_ref — runtime.Callers' skip semantics (issue #9).
//
//	scripts/goref.sh runtime/pprof tools/gen_callers_ref.go
//
// A profile sample is a stack, so `Callers` is what runtime/pprof needs
// before any protobuf matters. Its `skip` parameter is the part worth
// pinning: the doc says 0 identifies "the frame for Callers itself" and
// 1 "the caller of Callers", and an off-by-one there produces a stack
// that looks plausible and attributes every sample one frame too deep.
package pprof_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func nameOf(pc uintptr) string {
	f := runtime.FuncForPC(pc)
	if f == nil {
		return "<nil>"
	}
	n := f.Name()
	if i := strings.LastIndex(n, "."); i >= 0 {
		n = n[i+1:]
	}
	return n
}

//go:noinline
func three(skip int, pcs []uintptr) int { return runtime.Callers(skip, pcs) }

//go:noinline
func two(skip int, pcs []uintptr) int { return three(skip, pcs) }

//go:noinline
func one(skip int, pcs []uintptr) int { return two(skip, pcs) }

func TestGoishRef(t *testing.T) {
	for _, skip := range []int{0, 1, 2, 3} {
		pcs := make([]uintptr, 16)
		n := one(skip, pcs)
		// Callers records RETURN addresses, so subtract one before
		// asking which function the frame is in.
		top := "<none>"
		if n > 0 {
			top = nameOf(pcs[0] - 1)
		}
		fmt.Printf("skip=%d top=%-10s\n", skip, top)
	}
	// Zero-length destination.
	fmt.Printf("empty_dst  %d\n", runtime.Callers(0, nil))
}
