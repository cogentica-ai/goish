package ring

import (
	"fmt"
	"testing"
)

func goishDump(r *Ring) string {
	if r == nil {
		return "<nil>"
	}
	s := "["
	r.Do(func(v any) {
		if s != "[" {
			s += " "
		}
		s += fmt.Sprint(v)
	})
	return s + "]"
}

func TestGoishRef(t *testing.T) {
	fmt.Printf("New(0)=%v New(-1)=%v\n", New(0) == nil, New(-1) == nil)

	r := New(5)
	for i := 0; i < 5; i++ {
		r.Value = i
		r = r.Next()
	}
	fmt.Printf("r5 %s len=%d\n", goishDump(r), r.Len())
	fmt.Printf("Move(2) %s Move(-2) %s Move(0) %s\n",
		goishDump(r.Move(2)), goishDump(r.Move(-2)), goishDump(r.Move(0)))
	fmt.Printf("Move(7) %s Move(-7) %s\n", goishDump(r.Move(7)), goishDump(r.Move(-7)))

	// Link two distinct rings: s is inserted after r.
	a := New(3)
	for i, p := 0, a; i < 3; i, p = i+1, p.Next() {
		p.Value = i
	}
	b := New(2)
	for i, p := 0, b; i < 2; i, p = i+1, p.Next() {
		p.Value = 10 + i
	}
	n := a.Link(b)
	fmt.Printf("Link %s returned=%s len=%d\n", goishDump(a), goishDump(n), a.Len())

	// Unlink cuts a subring out of one ring.
	c := New(6)
	for i, p := 0, c; i < 6; i, p = i+1, p.Next() {
		p.Value = i
	}
	sub := c.Unlink(2)
	fmt.Printf("Unlink(2) ring=%s sub=%s lens=%d,%d\n", goishDump(c), goishDump(sub), c.Len(), sub.Len())
	fmt.Printf("Unlink(0)=%v\n", c.Unlink(0) == nil)

	// A zero Ring is a one-element ring; init() repairs it lazily.
	var z Ring
	fmt.Printf("zero len=%d next-is-self=%v prev-is-self=%v\n",
		z.Len(), z.Next() == &z, z.Prev() == &z)

	// Single-element ring.
	one := New(1)
	one.Value = 42
	fmt.Printf("one %s len=%d next=%v\n", goishDump(one), one.Len(), one.Next() == one)
}
