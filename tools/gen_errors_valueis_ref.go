// gen_errors_valueis_ref — errors.Is on a COMPARABLE value-typed error.
//
//	scripts/goref.sh errors tools/gen_errors_valueis_ref.go
//
// Go's errors.Is compares two interface values with `==`. For a
// comparable dynamic type that is a type-AND-value comparison, so a
// named int32 error matches another of the same value without any hook.
// goish's `error` is an Arc handle and `==` on it is pointer identity,
// so the same value converted twice used to miss (issue #12).
//
// The `code7 vs code9` row is the one that matters: BOTH render as
// "code", so anything that compared Error() strings instead of values
// would report them equal — a false positive in exactly the routing
// decision this is used for (lsproto dispatches on ErrorCode).
package errors_test

import (
	"errors"
	"fmt"
	"testing"
)

type Code int32

func (c Code) Error() string { return "code" }

func TestGoishRef(t *testing.T) {
	var a error = Code(7)
	var b error = Code(7)
	var c error = Code(9)

	fmt.Printf("GOROW\tsame_handle\t%v\n", errors.Is(a, a))
	fmt.Printf("GOROW\tsame_value\t%v\n", errors.Is(a, b))
	fmt.Printf("GOROW\tdifferent_value\t%v\n", errors.Is(a, c))
	fmt.Printf("GOROW\tboth_render_same\t%v\n", a.Error() == c.Error())

	w := fmt.Errorf("ctx: %w", a)
	fmt.Printf("GOROW\tthrough_wrap\t%v\n", errors.Is(w, Code(7)))
	fmt.Printf("GOROW\twrap_wrong_value\t%v\n", errors.Is(w, Code(9)))

	// Multiple %w operands must each remain reachable (issue #11).
	left := errors.New("left")
	right := errors.New("right")
	m := fmt.Errorf("%w: %w", left, right)
	fmt.Printf("GOROW\tmulti_msg\t%q\n", m.Error())
	fmt.Printf("GOROW\tmulti_left\t%v\n", errors.Is(m, left))
	fmt.Printf("GOROW\tmulti_right\t%v\n", errors.Is(m, right))
}
