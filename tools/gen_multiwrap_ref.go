// gen_multiwrap_ref — several %w operands, beyond the headline (#11).
//
//	scripts/goref.sh errors tools/gen_multiwrap_ref.go
//
// `fmt.Errorf("%w: %w", a, b)` builds a multi-error whose `Unwrap()
// []error` both causes are reachable through. goish already gets that
// pair right. The rows here are the issue's remaining criteria, which
// a two-cause test does not reach: errors.As through a multi-wrap,
// repeated targets, a single wrapper NESTED inside a multi one and
// vice versa, three causes, a nil operand, and a non-error operand.
//
// Nil is the one worth measuring rather than guessing: `%w` with a nil
// operand is not a cause at all, and Go still formats something.
package errors_test

import (
	"errors"
	"fmt"
	"testing"
)

type myErr struct{ N int }

func (m *myErr) Error() string { return fmt.Sprintf("myErr(%d)", m.N) }

func TestGoishRef(t *testing.T) {
	row := func(name string, v any) { fmt.Printf("%-20s %v\n", name, v) }

	a := errors.New("a")
	b := errors.New("b")
	c := errors.New("c")

	two := fmt.Errorf("%w: %w", a, b)
	row("two_msg", two)
	row("two_is_a", errors.Is(two, a))
	row("two_is_b", errors.Is(two, b))
	row("two_is_c", errors.Is(two, c))

	three := fmt.Errorf("%w/%w/%w", a, b, c)
	row("three_msg", three)
	row("three_is_a", errors.Is(three, a))
	row("three_is_b", errors.Is(three, b))
	row("three_is_c", errors.Is(three, c))

	// Repeated target: the same error twice.
	dup := fmt.Errorf("%w and %w", a, a)
	row("dup_msg", dup)
	row("dup_is_a", errors.Is(dup, a))

	// A single wrapper nested inside a multi one.
	single := fmt.Errorf("wrapped: %w", c)
	nest := fmt.Errorf("%w | %w", a, single)
	row("nest_msg", nest)
	row("nest_is_a", errors.Is(nest, a))
	row("nest_is_c", errors.Is(nest, c))

	// A multi wrapper nested inside a single one.
	outer := fmt.Errorf("outer: %w", two)
	row("outer_msg", outer)
	row("outer_is_a", errors.Is(outer, a))
	row("outer_is_b", errors.Is(outer, b))

	// errors.As through a multi-wrap.
	target := &myErr{N: 7}
	withAs := fmt.Errorf("%w: %w", a, target)
	var got *myErr
	ok := errors.As(withAs, &got)
	row("as_ok", ok)
	if ok {
		row("as_n", got.N)
	}

	// Mixed %w and ordinary verbs.
	mixed := fmt.Errorf("code=%d %w tail=%s", 42, a, "x")
	row("mixed_msg", mixed)
	row("mixed_is_a", errors.Is(mixed, a))

	// A nil operand for %w, and a non-error operand.
	var nilErr error
	withNil := fmt.Errorf("%w: %w", a, nilErr)
	row("nil_msg", withNil)
	row("nil_is_a", errors.Is(withNil, a))
	// A non-error operand for %w is rejected by `go vet` outright, so
	// there is no Go row to pin: the case cannot be written in a
	// vet-clean program. goish should still not crash on it, which is
	// checked on the goish side only.
}
