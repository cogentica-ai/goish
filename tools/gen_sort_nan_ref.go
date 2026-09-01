package sort_test

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"sort"
	"testing"
)

// Go's ordering of floats is not Rust's PartialOrd and not IEEE
// comparison: `cmp.Less` puts NaN BEFORE every non-NaN, `cmp.Compare`
// calls two NaNs equal, and -0.0 equals 0.0. Everything that sorts —
// slices.Sort, sort.Float64s, slices.BinarySearch — inherits that.
//
// A port that leaves NaN to `x < y` does not merely order NaNs oddly:
// `x < y` is FALSE in both directions for a NaN, so a comparison sort
// sees it as equal to everything and can leave the slice unsorted.
func TestGoishRef(t *testing.T) {
	nan := math.NaN()
	inf := math.Inf(1)
	ninf := math.Inf(-1)

	// cmp.Less and cmp.Compare over the awkward pairs.
	pairs := [][2]float64{
		{1, 2}, {2, 1}, {1, 1},
		{nan, 1}, {1, nan}, {nan, nan},
		{0, -0.0}, {-0.0, 0},
		{ninf, nan}, {nan, ninf}, {inf, nan},
		{ninf, inf},
	}
	for _, p := range pairs {
		fmt.Printf("cmp %-6v %-6v less=%-5v compare=%d\n",
			p[0], p[1], cmp.Less(p[0], p[1]), cmp.Compare(p[0], p[1]))
	}
	fmt.Printf("cmpint less=%v compare=%d %d %d\n",
		cmp.Less(1, 2), cmp.Compare(1, 2), cmp.Compare(2, 1), cmp.Compare(1, 1))
	fmt.Printf("cmpstr less=%v compare=%d\n", cmp.Less("a", "b"), cmp.Compare("b", "a"))

	// slices.Sort over floats with NaNs.
	f := []float64{3, nan, 1, inf, nan, ninf, 2, -0.0, 0}
	g := slices.Clone(f)
	slices.Sort(g)
	fmt.Printf("sortf %v sorted=%v\n", g, slices.IsSorted(g))
	h := slices.Clone(f)
	sort.Float64s(h)
	fmt.Printf("float64s %v sorted=%v\n", h, sort.Float64sAreSorted(h))

	// The plain cases.
	ii := []int{5, 2, 9, 2, -1}
	slices.Sort(ii)
	fmt.Printf("sorti %v\n", ii)
	ss := []string{"pear", "Apple", "apple", ""}
	slices.Sort(ss)
	fmt.Printf("sorts %q\n", ss)
	i2 := []int{5, 2, 9, 2, -1}
	sort.Ints(i2)
	s2 := []string{"pear", "Apple", "apple", ""}
	sort.Strings(s2)
	fmt.Printf("sortpkg %v %q\n", i2, s2)

	// SortFunc and SortStableFunc: the stable one keeps ties in input
	// order, which is the whole reason to reach for it.
	type kv struct {
		k string
		v int
	}
	in := []kv{{"a", 2}, {"b", 1}, {"c", 2}, {"d", 1}, {"e", 2}}
	a := slices.Clone(in)
	slices.SortStableFunc(a, func(x, y kv) int { return cmp.Compare(x.v, y.v) })
	fmt.Printf("stable %v\n", a)

	// Min / Max, including NaN propagation (they use the builtins).
	fmt.Printf("minmax i=%d,%d s=%q,%q\n",
		slices.Min(ii), slices.Max(ii), slices.Min(ss), slices.Max(ss))
	fm := []float64{2, 1, 3}
	fmt.Printf("minmaxf %v %v\n", slices.Min(fm), slices.Max(fm))
	fn := []float64{2, nan, 3}
	fmt.Printf("minmaxnan %v %v\n", slices.Min(fn), slices.Max(fn))

	// BinarySearch over a sorted float slice with NaN first.
	sorted := []float64{nan, ninf, 0, 1, 2, inf}
	for _, target := range []float64{nan, ninf, 0, 1.5, inf, 99} {
		i, found := slices.BinarySearch(sorted, target)
		fmt.Printf("bsearch %-6v i=%d found=%v\n", target, i, found)
	}
	si := []int{1, 3, 5, 7}
	for _, target := range []int{0, 1, 4, 7, 9} {
		i, found := slices.BinarySearch(si, target)
		fmt.Printf("bsearchi %d i=%d found=%v\n", target, i, found)
	}

	// sort.Search and sort.Find contracts.
	for _, target := range []int{0, 1, 4, 7, 9} {
		i := sort.SearchInts(si, target)
		fmt.Printf("searchints %d i=%d\n", target, i)
	}
	fmt.Printf("search empty=%d all=%d none=%d\n",
		sort.Search(0, func(int) bool { return true }),
		sort.Search(5, func(int) bool { return true }),
		sort.Search(5, func(int) bool { return false }))
	i, found := sort.Find(4, func(i int) int { return cmp.Compare(5, si[i]) })
	fmt.Printf("find 5 i=%d found=%v\n", i, found)
	i, found = sort.Find(4, func(i int) int { return cmp.Compare(4, si[i]) })
	fmt.Printf("find 4 i=%d found=%v\n", i, found)
}
