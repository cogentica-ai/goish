package list

import (
	"fmt"
	"testing"
)

func dump(l *List) string {
	s := "["
	for e := l.Front(); e != nil; e = e.Next() {
		if s != "[" {
			s += " "
		}
		s += fmt.Sprint(e.Value)
	}
	return s + "]"
}

func TestGoishRef(t *testing.T) {
	// A zero List is usable: lazyInit repairs it on first Push.
	var z List
	z.PushBack(1)
	z.PushFront(0)
	fmt.Printf("zero-value %s len=%d\n", dump(&z), z.Len())

	l := New()
	e1 := l.PushBack(1)
	e2 := l.PushBack(2)
	e3 := l.PushBack(3)
	e4 := l.PushFront(0)
	fmt.Printf("built %s len=%d\n", dump(l), l.Len())

	l.MoveToFront(e3)
	fmt.Printf("MoveToFront(3) %s\n", dump(l))
	l.MoveToBack(e4)
	fmt.Printf("MoveToBack(0) %s\n", dump(l))
	l.MoveBefore(e1, e2)
	fmt.Printf("MoveBefore(1,2) %s\n", dump(l))
	l.MoveAfter(e1, e2)
	fmt.Printf("MoveAfter(1,2) %s\n", dump(l))

	// move is a no-op when e == at, and Move* is a no-op for a foreign element.
	other := New()
	oe := other.PushBack(99)
	l.MoveToFront(oe)
	fmt.Printf("foreign MoveToFront %s other=%s\n", dump(l), dump(other))
	l.MoveAfter(e1, e1)
	fmt.Printf("self MoveAfter %s\n", dump(l))

	// InsertBefore/After with a foreign mark returns nil, list unmodified.
	fmt.Printf("InsertBefore foreign nil=%v %s\n", l.InsertBefore(7, oe) == nil, dump(l))
	l.InsertBefore(10, e2)
	l.InsertAfter(20, e2)
	fmt.Printf("insert around 2 %s\n", dump(l))

	// Remove returns the value; removing a foreign element still returns it.
	fmt.Printf("Remove(e3)=%v %s len=%d\n", l.Remove(e3), dump(l), l.Len())
	fmt.Printf("Remove(foreign)=%v %s len=%d\n", l.Remove(oe), dump(l), l.Len())

	// PushBackList / PushFrontList, including the aliased self case.
	a := New()
	a.PushBack("x")
	a.PushBack("y")
	b := New()
	b.PushBack("1")
	b.PushBack("2")
	a.PushBackList(b)
	fmt.Printf("PushBackList %s\n", dump(a))
	a.PushFrontList(b)
	fmt.Printf("PushFrontList %s\n", dump(a))
	c := New()
	c.PushBack("p")
	c.PushBack("q")
	c.PushBackList(c)
	fmt.Printf("self PushBackList %s len=%d\n", dump(c), c.Len())
	d := New()
	d.PushBack("p")
	d.PushBack("q")
	d.PushFrontList(d)
	fmt.Printf("self PushFrontList %s len=%d\n", dump(d), d.Len())

	// Init clears.
	l.Init()
	fmt.Printf("Init %s len=%d front=%v\n", dump(l), l.Len(), l.Front() == nil)
}
