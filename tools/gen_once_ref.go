package sync_test

import (
	"fmt"
	"sync"
	"testing"
)

// Once and the OnceFunc family each guarantee "exactly once", and the
// interesting part is what they do on the calls AFTER the first: Do
// returns without calling f again, OnceValue hands back the CACHED
// value without recomputing, and OnceValues hands back both.
func TestGoishRef(t *testing.T) {
	// Once.Do runs f exactly once, however many times it is called.
	var o sync.Once
	n := 0
	for i := 0; i < 5; i++ {
		o.Do(func() { n++ })
	}
	fmt.Printf("once-do calls=%d\n", n)

	// A second Once is independent.
	var o2 sync.Once
	m := 0
	o2.Do(func() { m++ })
	fmt.Printf("once-independent calls=%d\n", m)

	// Do returns only after f has completed — the value f set is
	// visible to the caller of the FIRST Do and to every later one.
	var o3 sync.Once
	got := 0
	o3.Do(func() { got = 42 })
	before := got
	o3.Do(func() { got = 99 })
	fmt.Printf("once-visible first=%d after-second-do=%d\n", before, got)

	// OnceFunc: the wrapped function runs once.
	fn := 0
	wrapped := sync.OnceFunc(func() { fn++ })
	wrapped()
	wrapped()
	wrapped()
	fmt.Printf("oncefunc calls=%d\n", fn)

	// OnceValue: computed once, then the CACHED value is returned.
	comps := 0
	val := sync.OnceValue(func() int { comps++; return 7 })
	a, b, c := val(), val(), val()
	fmt.Printf("oncevalue computations=%d values=%d,%d,%d\n", comps, a, b, c)

	// A zero value is cached just as happily as a non-zero one — a
	// port that uses the zero value as its "not computed yet" marker
	// recomputes forever here.
	zcomps := 0
	zval := sync.OnceValue(func() int { zcomps++; return 0 })
	z1, z2 := zval(), zval()
	fmt.Printf("oncevalue-zero computations=%d values=%d,%d\n", zcomps, z1, z2)

	// OnceValues returns both, cached.
	vcomps := 0
	vals := sync.OnceValues(func() (int, string) { vcomps++; return 3, "x" })
	i1, s1 := vals()
	i2, s2 := vals()
	fmt.Printf("oncevalues computations=%d first=(%d,%q) second=(%d,%q)\n",
		vcomps, i1, s1, i2, s2)

	// Each OnceValue is independent of every other.
	c1 := sync.OnceValue(func() int { return 1 })
	c2 := sync.OnceValue(func() int { return 2 })
	fmt.Printf("independent %d %d %d %d\n", c1(), c2(), c1(), c2())
}
