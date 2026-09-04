package context_test

import (
	"context"
	"fmt"
	"testing"
)

// A Context's String is what shows up in a log line or a panic, and it
// is built by walking the PARENT CHAIN — each wrapper prepends its
// parent's name. So the string records how the context was
// constructed, not just what it is.
func TestGoishRef(t *testing.T) {
	bg := context.Background()
	todo := context.TODO()
	fmt.Printf("background %q\n", bg)
	fmt.Printf("todo       %q\n", todo)

	c1, cancel1 := context.WithCancel(bg)
	defer cancel1()
	fmt.Printf("cancel     %q\n", c1)

	c2, cancel2 := context.WithCancel(c1)
	defer cancel2()
	fmt.Printf("cancel2    %q\n", c2)

	v1 := context.WithValue(bg, "k", "v")
	fmt.Printf("value      %q\n", v1)

	v2 := context.WithValue(v1, "k2", 42)
	fmt.Printf("value2     %q\n", v2)

	// A value context over a cancel context keeps the whole chain.
	v3 := context.WithValue(c1, "x", "y")
	fmt.Printf("value-over-cancel %q\n", v3)

	c3, cancel3 := context.WithCancel(v1)
	defer cancel3()
	fmt.Printf("cancel-over-value %q\n", c3)

	// stringify's arms: a string prints bare, nil prints <nil>, and
	// anything else prints its TYPE rather than its value.
	fmt.Printf("value-int  %q\n", context.WithValue(bg, "n", 7))
	fmt.Printf("value-nil  %q\n", context.WithValue(bg, "z", nil))
	fmt.Printf("value-bool %q\n", context.WithValue(bg, "b", true))

	// A cause-carrying cancel is still ".WithCancel".
	c4, cancel4 := context.WithCancelCause(bg)
	defer cancel4(nil)
	fmt.Printf("cancelcause %q\n", c4)
}
