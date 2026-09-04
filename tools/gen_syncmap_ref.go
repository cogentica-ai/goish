package sync_test

import (
	"fmt"
	"sync"
	"testing"
)

// sync.Map's methods each return a slightly different shape, and the
// differences are the whole API: LoadOrStore returns whether it LOADED
// (not whether it stored), Swap returns the PREVIOUS value and whether
// there was one, CompareAndSwap reports whether it swapped, and
// LoadAndDelete returns the value it removed. Getting any of those
// booleans inverted still compiles and still "works" for the common
// path.
func TestGoishRef(t *testing.T) {
	var m sync.Map

	p := func(tag string, vals ...any) { fmt.Printf("%-24s %v\n", tag, vals) }

	v, ok := m.Load("missing")
	p("load-missing", v, ok)

	m.Store("a", 1)
	v, ok = m.Load("a")
	p("load-present", v, ok)

	// LoadOrStore on a MISSING key stores and reports loaded=false.
	act, loaded := m.LoadOrStore("b", 2)
	p("loadorstore-new", act, loaded)
	// …and on a PRESENT key returns the existing value, loaded=true,
	// leaving the stored value alone.
	act, loaded = m.LoadOrStore("b", 99)
	p("loadorstore-existing", act, loaded)
	v, _ = m.Load("b")
	p("loadorstore-unchanged", v)

	// Swap returns the PREVIOUS value.
	prev, loaded := m.Swap("a", 10)
	p("swap-existing", prev, loaded)
	prev, loaded = m.Swap("new", 5)
	p("swap-missing", prev, loaded)

	// CompareAndSwap only swaps on an exact match.
	p("cas-match", m.CompareAndSwap("a", 10, 11))
	v, _ = m.Load("a")
	p("cas-after", v)
	p("cas-mismatch", m.CompareAndSwap("a", 999, 12))
	v, _ = m.Load("a")
	p("cas-after-mismatch", v)
	p("cas-missing-key", m.CompareAndSwap("nope", 1, 2))

	// CompareAndDelete likewise.
	p("cad-mismatch", m.CompareAndDelete("a", 999))
	p("cad-match", m.CompareAndDelete("a", 11))
	v, ok = m.Load("a")
	p("cad-after", v, ok)
	p("cad-missing-key", m.CompareAndDelete("gone", 1))

	// LoadAndDelete returns what it removed.
	m.Store("c", 3)
	v, loaded = m.LoadAndDelete("c")
	p("loadanddelete", v, loaded)
	v, loaded = m.LoadAndDelete("c")
	p("loadanddelete-again", v, loaded)

	// Delete of a missing key is a no-op, not a panic.
	m.Delete("never-there")
	p("delete-missing", "ok")

	// Range sees every live entry. Sort for a stable print.
	m.Store("x", 1)
	m.Store("y", 2)
	m.Store("z", 3)
	n := 0
	keys := []string{}
	m.Range(func(k, v any) bool {
		n++
		keys = append(keys, fmt.Sprintf("%v=%v", k, v))
		return true
	})
	p("range-count", n)
	// Range stops when f returns false.
	stopped := 0
	m.Range(func(k, v any) bool {
		stopped++
		return false
	})
	p("range-early-stop", stopped)

	// Clear empties it.
	m.Clear()
	n = 0
	m.Range(func(k, v any) bool { n++; return true })
	p("after-clear", n)

	// A zero Map is usable without construction.
	var z sync.Map
	z.Store("k", "v")
	v, ok = z.Load("k")
	p("zero-value-usable", v, ok)

	// Storing over an existing key replaces.
	z.Store("k", "v2")
	v, _ = z.Load("k")
	p("store-replaces", v)
}
