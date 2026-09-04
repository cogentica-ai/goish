package maps_test

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// maps is small enough that everything in it is a one-liner, which is
// exactly why it is worth measuring: a one-liner with the wrong
// emptiness rule or the wrong aliasing behaviour is invisible until a
// caller depends on it.
//
// Two properties carry the weight:
//
//   * Clone is SHALLOW and Copy MERGES rather than replacing. A caller
//     who expects Copy to leave the destination holding only the
//     source's entries gets the union instead, silently.
//   * Equal compares VALUES with ==, so it is not defined for maps
//     whose values are not comparable, and EqualFunc exists for that
//     case. Both answer true for two empty maps and — the case that
//     catches people — a nil map equals an empty one.
//
// Keys and Values return ITERATORS in Go 1.23+, not slices, and
// iteration order over a map is deliberately randomised, so everything
// here is sorted before printing. That is not a workaround: a port
// whose order happened to be stable would still be correct, and a
// reference that pinned an order would be pinning something Go does
// not promise.
func TestGoishRef(t *testing.T) {
	base := map[string]int{"b": 2, "a": 1, "c": 3}

	// Keys and Values, sorted so the comparison means something.
	{
		ks := slices.Sorted(maps.Keys(base))
		vs := slices.Sorted(maps.Values(base))
		fmt.Printf("keys=%v values=%v\n", ks, vs)
		empty := map[string]int{}
		fmt.Printf("keys-empty=%v values-empty=%v\n",
			slices.Sorted(maps.Keys(empty)), slices.Sorted(maps.Values(empty)))
		var nilm map[string]int
		fmt.Printf("keys-nil=%v values-nil=%v\n",
			slices.Sorted(maps.Keys(nilm)), slices.Sorted(maps.Values(nilm)))
	}

	// All / Collect / Insert round trip.
	{
		got := maps.Collect(maps.All(base))
		fmt.Printf("collect-roundtrip equal=%v len=%d\n", maps.Equal(got, base), len(got))
		dst := map[string]int{"z": 26}
		maps.Insert(dst, maps.All(base))
		fmt.Printf("insert -> %s\n", dump(dst))
		// Inserting over an existing key overwrites it.
		dst2 := map[string]int{"a": 99}
		maps.Insert(dst2, maps.All(base))
		fmt.Printf("insert-overwrite -> %s\n", dump(dst2))
	}

	// Clone: shallow, and nil in gives nil out.
	{
		c := maps.Clone(base)
		c["a"] = 100
		fmt.Printf("clone -> %s original -> %s independent=%v\n",
			dump(c), dump(base), base["a"] == 1)
		// Only LENGTHS are compared, not nil-ness. Go distinguishes a
		// nil map from an empty one — Clone(nil) is nil, Clone(empty)
		// is not — and goish's `map` is a value whose polymorphic-nil
		// comparison is true exactly when it is empty, so the two
		// states are one. That is a property of the value model, not
		// of maps.Clone, and pinning it would pin the deviation
		// rather than the function.
		var nilm map[string]int
		cn := maps.Clone(nilm)
		fmt.Printf("clone-nil len=%d\n", len(cn))
		ce := maps.Clone(map[string]int{})
		fmt.Printf("clone-empty len=%d\n", len(ce))
		// Go's Clone is SHALLOW, so a slice value is shared with the
		// clone and writing through one is visible in the other. Not
		// measured here: goish's slice OWNS its backing Vec and
		// subslicing copies, which goslice.rs records as a deliberate
		// v1 deviation — aliasing is spelled `&mut` there instead. The
		// line would measure the value model, not maps.Clone.
	}

	// Copy: MERGES into the destination.
	{
		dst := map[string]int{"x": 24, "a": 0}
		maps.Copy(dst, base)
		fmt.Printf("copy-merges -> %s\n", dump(dst))
		empty := map[string]int{}
		maps.Copy(empty, base)
		fmt.Printf("copy-into-empty -> %s\n", dump(empty))
		var src map[string]int
		d2 := map[string]int{"keep": 1}
		maps.Copy(d2, src)
		fmt.Printf("copy-nil-src -> %s\n", dump(d2))
	}

	// DeleteFunc, including deleting everything and nothing.
	{
		d := maps.Clone(base)
		maps.DeleteFunc(d, func(k string, v int) bool { return v%2 == 1 })
		fmt.Printf("delete-odd -> %s\n", dump(d))
		all := maps.Clone(base)
		maps.DeleteFunc(all, func(string, int) bool { return true })
		fmt.Printf("delete-all -> %s len=%d\n", dump(all), len(all))
		none := maps.Clone(base)
		maps.DeleteFunc(none, func(string, int) bool { return false })
		fmt.Printf("delete-none -> %s\n", dump(none))
		var nilm map[string]int
		maps.DeleteFunc(nilm, func(string, int) bool { return true })
		fmt.Printf("delete-nil ok len=%d\n", len(nilm))
	}

	// Equal and EqualFunc, including the nil-versus-empty question.
	{
		var nilm map[string]int
		empty := map[string]int{}
		same := map[string]int{"a": 1, "b": 2, "c": 3}
		diffVal := map[string]int{"a": 1, "b": 2, "c": 4}
		diffKey := map[string]int{"a": 1, "b": 2, "d": 3}
		shorter := map[string]int{"a": 1}
		for _, c := range []struct {
			name string
			x, y map[string]int
		}{
			{"same", base, same},
			{"self", base, base},
			{"diff-value", base, diffVal},
			{"diff-key", base, diffKey},
			{"shorter", base, shorter},
			{"nil-nil", nilm, nilm},
			{"nil-empty", nilm, empty},
			{"empty-empty", empty, map[string]int{}},
			{"nil-nonempty", nilm, base},
		} {
			fmt.Printf("equal %-14s -> %v\n", c.name, maps.Equal(c.x, c.y))
		}
		// EqualFunc with a comparison that ignores sign.
		abs := map[string]int{"a": -1, "b": -2, "c": -3}
		fmt.Printf("equalfunc abs=%v strict=%v\n",
			maps.EqualFunc(base, abs, func(a, b int) bool { return a == -b }),
			maps.Equal(base, abs))
	}
}

func dump(m map[string]int) string {
	ks := slices.Sorted(maps.Keys(m))
	var parts []string
	for _, k := range ks {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return "{" + strings.Join(parts, " ") + "}"
}
