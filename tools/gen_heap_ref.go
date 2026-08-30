package heap

import (
	"fmt"
	"testing"
)

type goishInts []int

func (h goishInts) Len() int            { return len(h) }
func (h goishInts) Less(i, j int) bool  { return h[i] < h[j] }
func (h goishInts) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *goishInts) Push(x any)         { *h = append(*h, x.(int)) }
func (h *goishInts) Pop() any           { old := *h; n := len(old); x := old[n-1]; *h = old[:n-1]; return x }

func TestGoishRef(t *testing.T) {
	// Init on an unordered slice: the exact array afterwards, not just
	// the min — the sift order is what is being checked.
	h := &goishInts{5, 2, 9, 1, 7, 3, 8, 0, 4, 6}
	Init(h)
	fmt.Printf("Init %v\n", *h)

	Push(h, -1)
	fmt.Printf("Push(-1) %v\n", *h)
	Push(h, 10)
	fmt.Printf("Push(10) %v\n", *h)

	v := Pop(h)
	fmt.Printf("Pop=%v %v\n", v, *h)

	// Remove from the middle: down-then-up is the branch that matters.
	r := Remove(h, 3)
	fmt.Printf("Remove(3)=%v %v\n", r, *h)
	r = Remove(h, h.Len()-1)
	fmt.Printf("Remove(last)=%v %v\n", r, *h)

	// Fix after mutating an element in place, both directions.
	(*h)[2] = -5
	Fix(h, 2)
	fmt.Printf("Fix down->up %v\n", *h)
	(*h)[0] = 99
	Fix(h, 0)
	fmt.Printf("Fix up->down %v\n", *h)

	// Drain in order.
	var out []int
	for h.Len() > 0 {
		out = append(out, Pop(h).(int))
	}
	fmt.Printf("drain %v\n", out)
}
