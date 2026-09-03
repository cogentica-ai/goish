package heap_test

import (
	"container/heap"
	"container/list"
	"container/ring"
	"fmt"
	"strings"
	"testing"
)

// The container packages have no I/O and no hostile input, so what
// there is to get wrong is the INVARIANT. A heap that is not a heap
// still returns something from Pop; a list whose Remove leaves a stale
// pointer still iterates; a ring whose Unlink miscounts still walks. In
// every case the failure is a wrong answer rather than an error, which
// is why the interesting cases are the degenerate ones: empty, single
// element, removing while iterating, moving an element to its own
// position.
//
// heap in particular is defined by an interface the CALLER implements,
// so the package only guarantees the invariant given a correct Less. It
// is not a sorted container: Pop returns the minimum, but the backing
// slice is in heap order, and a caller that reads it directly sees an
// order the package never promised. Printing it after every operation
// is the point.
func TestGoishRef(t *testing.T) {
	// heap.
	{
		h := &intHeap{5, 2, 9, 1, 7}
		fmt.Printf("heap before-init=%v\n", *h)
		heap.Init(h)
		fmt.Printf("heap after-init=%v\n", *h)
		for _, v := range []int{0, 6, 3} {
			heap.Push(h, v)
			fmt.Printf("heap push %-2d -> %v\n", v, *h)
		}
		for len(*h) > 0 {
			min := heap.Pop(h)
			fmt.Printf("heap pop -> %-2v rest=%v\n", min, *h)
		}
		// Empty and single-element behaviour.
		e := &intHeap{}
		heap.Init(e)
		fmt.Printf("heap empty len=%d\n", e.Len())
		heap.Push(e, 42)
		// Sequenced explicitly. Written as one Printf with *e and
		// heap.Pop(e) as sibling arguments, the result depends on
		// whether the slice operand is evaluated before or after the
		// call — Go's spec orders function calls left to right but
		// leaves non-call operands unordered against them, and Go
		// printed the POST-pop slice. That is a coin toss, not a
		// behaviour to pin.
		single := fmt.Sprint(*e)
		popped := heap.Pop(e)
		fmt.Printf("heap single=%v pop=%v len=%d\n", single, popped, e.Len())
		// Fix after mutating in place, and Remove from the middle.
		f := &intHeap{1, 2, 3, 4, 5}
		heap.Init(f)
		(*f)[0] = 99
		fmt.Printf("heap corrupted=%v\n", *f)
		heap.Fix(f, 0)
		fmt.Printf("heap fixed=%v min=%v\n", *f, (*f)[0])
		g := &intHeap{1, 2, 3, 4, 5, 6}
		heap.Init(g)
		fmt.Printf("heap remove(2)=%v rest=%v\n", heap.Remove(g, 2), *g)
		// Duplicates.
		d := &intHeap{3, 3, 3, 1, 1}
		heap.Init(d)
		var got []int
		for d.Len() > 0 {
			got = append(got, heap.Pop(d).(int))
		}
		fmt.Printf("heap duplicates -> %v\n", got)
	}

	// list.
	{
		l := list.New()
		fmt.Printf("list empty len=%d front-nil=%v back-nil=%v\n",
			l.Len(), l.Front() == nil, l.Back() == nil)
		a := l.PushBack("a")
		b := l.PushBack("b")
		c := l.PushFront("c")
		fmt.Printf("list after-push -> %s len=%d\n", dumpList(l), l.Len())
		l.InsertBefore("x", b)
		l.InsertAfter("y", a)
		fmt.Printf("list after-insert -> %s\n", dumpList(l))
		l.MoveToFront(b)
		fmt.Printf("list move-to-front -> %s\n", dumpList(l))
		l.MoveToBack(c)
		fmt.Printf("list move-to-back -> %s\n", dumpList(l))
		// Moving an element to where it already is must be a no-op,
		// not a corruption.
		l.MoveToFront(l.Front())
		l.MoveToBack(l.Back())
		fmt.Printf("list move-noop -> %s\n", dumpList(l))
		fmt.Printf("list remove(a)=%v -> %s\n", l.Remove(a), dumpList(l))
		// Removing an element already removed returns its value and
		// leaves the list alone.
		fmt.Printf("list remove-twice=%v -> %s len=%d\n",
			l.Remove(a), dumpList(l), l.Len())
		// PushBackList / PushFrontList.
		l2 := list.New()
		l2.PushBack("p")
		l2.PushBack("q")
		l3 := list.New()
		l3.PushBack("1")
		l3.PushBackList(l2)
		l3.PushFrontList(l2)
		fmt.Printf("list concat -> %s len=%d\n", dumpList(l3), l3.Len())
		// The zero value is usable without New.
		var z list.List
		z.PushBack("z")
		fmt.Printf("list zero-value -> %s len=%d\n", dumpList(&z), z.Len())
	}

	// ring.
	{
		r := ring.New(5)
		for i := 0; i < r.Len(); i++ {
			r.Value = i
			r = r.Next()
		}
		fmt.Printf("ring len=%d -> %s\n", r.Len(), dumpRing(r))
		fmt.Printf("ring move(2) -> %v move(-2) -> %v\n",
			r.Move(2).Value, r.Move(-2).Value)
		fmt.Printf("ring prev=%v next=%v\n", r.Prev().Value, r.Next().Value)
		// Unlink and Link change the length of both rings.
		s := ring.New(3)
		for i := 0; i < s.Len(); i++ {
			s.Value = 100 + i
			s = s.Next()
		}
		joined := r.Link(s)
		fmt.Printf("ring after-link r-len=%d joined-len=%d r=%s\n",
			r.Len(), joined.Len(), dumpRing(r))
		cut := r.Unlink(3)
		fmt.Printf("ring after-unlink r-len=%d cut-len=%d cut=%s\n",
			r.Len(), cut.Len(), dumpRing(cut))
		// Degenerate sizes.
		one := ring.New(1)
		one.Value = "solo"
		fmt.Printf("ring one len=%d next-is-self=%v unlink0-nil=%v\n",
			one.Len(), one.Next() == one, one.Unlink(0) == nil)
		fmt.Printf("ring new(0)-nil=%v new(-1)-nil=%v\n",
			ring.New(0) == nil, ring.New(-1) == nil)
	}
}

type intHeap []int

func (h intHeap) Len() int            { return len(h) }
func (h intHeap) Less(i, j int) bool  { return h[i] < h[j] }
func (h intHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *intHeap) Push(x any)         { *h = append(*h, x.(int)) }
func (h *intHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func dumpList(l *list.List) string {
	var parts []string
	for e := l.Front(); e != nil; e = e.Next() {
		parts = append(parts, fmt.Sprint(e.Value))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func dumpRing(r *ring.Ring) string {
	var parts []string
	r.Do(func(v any) { parts = append(parts, fmt.Sprint(v)) })
	return "[" + strings.Join(parts, " ") + "]"
}
