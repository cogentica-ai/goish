package cmp_test

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"testing"
)

// cmp is three functions, and two of them exist because of NaN.
//
// A float comparison built from < and > alone gets NaN wrong in a way
// that does not announce itself: NaN < x, x < NaN and NaN == NaN are
// ALL false, so a comparator written the obvious way reports "equal"
// for every pair involving NaN. Feed that to a sort and the result is
// not merely unsorted — the algorithm can be driven off the end of the
// slice, because it relies on the comparator being a strict weak
// ordering and an inconsistent one violates the invariant the
// partitioning depends on.
//
// Go's answer is to define a TOTAL order in which NaN sorts BEFORE
// every other value and equals itself. That is not IEEE semantics and
// is not meant to be: it is the ordering that makes sorting terminate
// and be deterministic. cmp.Compare and cmp.Less implement it, and
// every line below that mentions NaN is pinning it.
//
// The other subtlety is signed zero: -0.0 and +0.0 compare EQUAL, so a
// sort will not reorder them and a caller cannot use cmp to tell them
// apart.
func TestGoishRef(t *testing.T) {
	nan := math.NaN()
	inf, ninf := math.Inf(1), math.Inf(-1)

	// Floats, where the interesting cases live.
	floats := []struct {
		name string
		v    float64
	}{
		{"nan", nan}, {"-inf", ninf}, {"-1", -1}, {"-0", math.Copysign(0, -1)},
		{"+0", 0}, {"1", 1}, {"+inf", inf}, {"max", math.MaxFloat64},
	}
	for _, a := range floats {
		for _, b := range floats {
			fmt.Printf("cmpf %-5s %-5s -> compare=%-2d less=%-5v less-rev=%v\n",
				a.name, b.name, cmp.Compare(a.v, b.v), cmp.Less(a.v, b.v), cmp.Less(b.v, a.v))
		}
	}

	// The properties a sort depends on, stated as invariants rather
	// than as individual answers.
	{
		vals := []float64{nan, ninf, -1, 0, 1, inf}
		total := true
		antisym := true
		for _, a := range vals {
			for _, b := range vals {
				c := cmp.Compare(a, b)
				if c != -cmp.Compare(b, a) {
					antisym = false
				}
				if (c < 0) != cmp.Less(a, b) {
					total = false
				}
			}
		}
		fmt.Printf("props antisymmetric=%v compare-agrees-less=%v nan-eq-nan=%v\n",
			antisym, total, cmp.Compare(nan, nan) == 0)
		// Sorting terminates and puts NaN first.
		s := []float64{3, nan, 1, inf, nan, -1, ninf}
		slices.SortFunc(s, cmp.Compare)
		fmt.Printf("sort -> %v sorted=%v\n", s, slices.IsSortedFunc(s, cmp.Compare))
	}

	// Integers and strings, where the answers are unremarkable and the
	// point is that they are the SAME shape: -1, 0, +1.
	for _, c := range []struct{ a, b int }{
		{-1, 1}, {1, -1}, {0, 0}, {math.MinInt64, math.MaxInt64},
		{math.MaxInt64, math.MinInt64}, {5, 5},
	} {
		fmt.Printf("cmpi %-21d %-21d -> compare=%-2d less=%v\n",
			c.a, c.b, cmp.Compare(c.a, c.b), cmp.Less(c.a, c.b))
	}
	for _, c := range []struct{ a, b string }{
		{"", ""}, {"", "a"}, {"a", ""}, {"a", "b"}, {"b", "a"},
		{"a", "a"}, {"A", "a"}, {"abc", "abd"}, {"ab", "abc"},
		{"\x00", ""}, {"é", "e"},
	} {
		fmt.Printf("cmps %-6q %-6q -> compare=%-2d less=%v\n",
			c.a, c.b, cmp.Compare(c.a, c.b), cmp.Less(c.a, c.b))
	}

	// Or returns the first non-zero argument, or the zero value.
	fmt.Printf("or-int %d %d %d %d\n",
		cmp.Or(0, 0, 3, 4), cmp.Or(1, 2), cmp.Or(0, 0), cmp.Or[int]())
	fmt.Printf("or-str %q %q %q %q\n",
		cmp.Or("", "", "c"), cmp.Or("a", "b"), cmp.Or("", ""), cmp.Or[string]())
	// Or's test is "is this the zero value", and NaN is not zero, so a
	// NaN first argument is returned rather than skipped — which means
	// Or can hand back a value that does not equal itself.
	orNaN := cmp.Or(nan, 1.0)
	fmt.Printf("or-float %g nan-passed-through=%v self-unequal=%v\n",
		cmp.Or(0.0, 2.5), math.IsNaN(orNaN), orNaN != orNaN)
}
