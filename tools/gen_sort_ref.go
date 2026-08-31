package sort_test

import (
	"fmt"
	"math"
	"sort"
	"testing"
)

// pairs is the shape that makes Stable's guarantee observable: two
// records that compare EQUAL under Less but are distinguishable by a
// second field. An unstable sort may leave them in either order; a
// stable one must not reorder them at all.
type pair struct {
	key int
	tag int
}

type byKey []pair

func (p byKey) Len() int           { return len(p) }
func (p byKey) Less(i, j int) bool { return p[i].key < p[j].key }
func (p byKey) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func tags(p []pair) []int {
	out := make([]int, len(p))
	for i, x := range p {
		out[i] = x.tag
	}
	return out
}

func keys(p []pair) []int {
	out := make([]int, len(p))
	for i, x := range p {
		out[i] = x.key
	}
	return out
}

func TestGoishRef(t *testing.T) {
	// Stable over inputs that are all ties, half ties, already sorted,
	// reversed, and long enough to cross the blockSize=20 boundary
	// where symMerge takes over from the insertion-sort blocks.
	cases := [][]pair{
		{},
		{{1, 0}},
		{{1, 0}, {1, 1}},
		{{2, 0}, {1, 1}},
		{{1, 0}, {1, 1}, {1, 2}},
		{{3, 0}, {1, 1}, {2, 2}, {1, 3}, {3, 4}, {2, 5}},
		{{1, 0}, {2, 1}, {3, 2}, {4, 3}},
		{{4, 0}, {3, 1}, {2, 2}, {1, 3}},
	}
	// A 45-element input: 3 distinct keys, so 15 ties each, crossing
	// blockSize twice.
	var big []pair
	for i := 0; i < 45; i++ {
		big = append(big, pair{key: i % 3, tag: i})
	}
	cases = append(cases, big)
	// And a 25-element already-reversed one.
	var rev []pair
	for i := 0; i < 25; i++ {
		rev = append(rev, pair{key: 25 - i, tag: i})
	}
	cases = append(cases, rev)

	for n, c := range cases {
		d := append([]pair(nil), c...)
		sort.Stable(byKey(d))
		fmt.Printf("stable %d keys=%v tags=%v sorted=%v\n", n, keys(d), tags(d), sort.IsSorted(byKey(d)))
	}

	// Sort is NOT stable, so only the keys are checked.
	for n, c := range cases {
		d := append([]pair(nil), c...)
		sort.Sort(byKey(d))
		fmt.Printf("sort %d keys=%v sorted=%v\n", n, keys(d), sort.IsSorted(byKey(d)))
	}

	// Reverse wraps an Interface and flips Less.
	for n, c := range cases[:8] {
		d := append([]pair(nil), c...)
		sort.Sort(sort.Reverse(byKey(d)))
		fmt.Printf("reverse %d keys=%v\n", n, keys(d))
	}

	// The three convenience types.
	ints := []int{5, 2, 9, 2, 7}
	sort.IntSlice(ints).Sort()
	fmt.Printf("intslice %v sorted=%v\n", ints, sort.IntsAreSorted(ints))
	strs := []string{"pear", "apple", "fig", "apple"}
	sort.StringSlice(strs).Sort()
	fmt.Printf("stringslice %v sorted=%v\n", strs, sort.StringsAreSorted(strs))
	f64 := []float64{3.5, math.NaN(), 1.5, math.Inf(-1), 2.5, math.NaN()}
	sort.Float64Slice(f64).Sort()
	fmt.Printf("float64slice nan-first=%v %v rest=%v sorted=%v\n",
		math.IsNaN(f64[0]) && math.IsNaN(f64[1]), f64[2], f64[3:], sort.Float64sAreSorted(f64))

	// Search and the three typed wrappers.
	a := []int{1, 3, 5, 7, 9}
	for _, x := range []int{0, 1, 2, 3, 8, 9, 10} {
		fmt.Printf("searchints %-3d -> %d\n", x, sort.SearchInts(a, x))
	}
	s := []string{"a", "c", "e"}
	for _, x := range []string{"", "a", "b", "e", "f"} {
		fmt.Printf("searchstrings %-3q -> %d\n", x, sort.SearchStrings(s, x))
	}
	fl := []float64{1.0, 2.5, 4.0}
	for _, x := range []float64{0, 1, 2, 4, 5} {
		fmt.Printf("searchfloat64s %-4v -> %d\n", x, sort.SearchFloat64s(fl, x))
	}
	for _, n := range []int{0, 1, 5} {
		fmt.Printf("search n=%d always-false=%d always-true=%d\n", n,
			sort.Search(n, func(int) bool { return false }),
			sort.Search(n, func(int) bool { return true }))
	}
	for _, target := range []int{0, 3, 4, 10} {
		i, found := sort.Find(len(a), func(i int) int { return target - a[i] })
		fmt.Printf("find %-3d -> (%d,%v)\n", target, i, found)
	}

	// Slice and SliceStable over the same tie-heavy input.
	d := append([]pair(nil), big...)
	sort.SliceStable(d, func(i, j int) bool { return d[i].key < d[j].key })
	fmt.Printf("slicestable keys=%v tags=%v\n", keys(d), tags(d))
	d2 := append([]pair(nil), big...)
	sort.Slice(d2, func(i, j int) bool { return d2[i].key < d2[j].key })
	fmt.Printf("slice keys=%v issorted=%v\n", keys(d2),
		sort.SliceIsSorted(d2, func(i, j int) bool { return d2[i].key < d2[j].key }))
}
