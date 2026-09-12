// gen_map_alias_ref — Go map VALUE semantics (issue #7).
//
//	scripts/goref.sh maps tools/gen_map_alias_ref.go
//
// A Go map value is a small header referencing backing state. Assigning
// it, passing it, or returning it copies the header — every copy keeps
// pointing at the same table. goish's `map<K, V>` owns its table and
// `Clone` copies every entry, so two handles diverge silently.
//
// The rows below separate the three things that are easy to conflate:
//
//   aliasing      a copied handle sees a later write through the other
//   maps.Clone    the ONE operation that does not alias
//   nil           a nil map reads, lens and ranges; writing panics
//
// The nil rows are measured rather than assumed because the panic is
// the only place Go's nil map behaves differently from an empty one for
// ordinary operations, and #14 showed that "obviously null" guesses
// about this family can be wrong.
package maps_test

import (
	"fmt"
	"maps"
	"testing"
)

func identity(m map[string]int) map[string]int { return m }

func mutate(m map[string]int) { m["viaArg"] = 9 }

func TestGoishRef(t *testing.T) {
	row := func(name string, v ...any) { fmt.Printf("%-24s %v\n", name, v) }

	// 1. assignment aliases.
	m := map[string]int{"a": 1}
	n := m
	n["b"] = 2
	row("assign_alias", m["b"], len(m), len(n))

	// 2. argument and return copies alias.
	r := identity(m)
	r["c"] = 3
	row("return_alias", m["c"], len(m))
	mutate(m)
	row("arg_alias", m["viaArg"], len(m))

	// 3. maps.Clone does NOT alias.
	c := maps.Clone(m)
	c["onlyInClone"] = 7
	_, inOrig := m["onlyInClone"]
	row("clone_no_alias", inOrig, len(m), len(c))

	// 4. delete and clear through one header are seen through another.
	delete(n, "b")
	_, stillB := m["b"]
	row("delete_visible", stillB)
	clear(n)
	row("clear_visible", len(m), len(n))

	// 5. nil versus allocated-empty.
	var nilMap map[string]int
	empty := map[string]int{}
	row("nil_is_nil", nilMap == nil)
	row("empty_is_nil", empty == nil)

	// 6. reads, len and range work on nil; write panics.
	row("nil_read", nilMap["missing"])
	v, ok := nilMap["missing"]
	row("nil_read_ok", v, ok)
	row("nil_len", len(nilMap))
	count := 0
	for range nilMap {
		count++
	}
	row("nil_range_iters", count)
	row("nil_delete_ok", func() bool {
		delete(nilMap, "x") // legal on nil, a no-op
		return true
	}())
	func() {
		defer func() {
			row("nil_write_panic", recover() != nil)
		}()
		nilMap["x"] = 1
	}()

	// 7. map VALUES stay ordinary value copies — sharing the map must
	// not deep-copy what it holds. A struct value read out is a copy;
	// mutating it does not touch the map.
	type S struct{ N int }
	sm := map[string]S{"k": {N: 1}}
	got := sm["k"]
	got.N = 99
	row("value_is_copy", sm["k"].N)

	// A map whose values are themselves maps: the inner map is a
	// header, so it DOES alias.
	inner := map[string]int{"i": 1}
	outer := map[string]map[string]int{"o": inner}
	outer["o"]["j"] = 2
	row("inner_map_aliases", inner["j"], len(inner))
}
