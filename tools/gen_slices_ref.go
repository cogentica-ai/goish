package slices_test

import (
	"fmt"
	"slices"
	"testing"
)

// slices is where an off-by-one is invisible: every function takes
// indices and returns a slice, and a wrong answer still looks like a
// slice. The vectors below are the boundaries — an empty input, an
// index at len, i == j, a needle that is not there, a count of zero or
// one, and BinarySearch on a value that falls before, between and
// after the elements.
func TestGoishRef(t *testing.T) {
	lists := [][]int{
		{},
		{1},
		{1, 2},
		{1, 2, 3},
		{1, 2, 2, 3},
		{2, 2, 2},
		{3, 1, 2},
		{1, 1, 2, 2, 3, 3},
	}
	for _, s := range lists {
		fmt.Printf("q %-16v sorted=%-5v min=%v max=%v\n",
			s, slices.IsSorted(s), minOf(s), maxOf(s))
	}

	// BinarySearch on a SORTED list: the index is where the value is,
	// or where it would be inserted.
	sorted := []int{1, 3, 5, 7, 9}
	for _, v := range []int{0, 1, 2, 3, 4, 5, 8, 9, 10} {
		i, ok := slices.BinarySearch(sorted, v)
		fmt.Printf("bsearch %-3d -> (%d,%v)\n", v, i, ok)
	}
	var empty []int
	i, ok := slices.BinarySearch(empty, 5)
	fmt.Printf("bsearch-empty -> (%d,%v)\n", i, ok)

	// Equal / Compare / Index / Contains across the pairs.
	for _, a := range lists {
		for _, b := range lists {
			fmt.Printf("cmp %-14v %-14v equal=%-5v compare=%d\n",
				a, b, slices.Equal(a, b), slices.Compare(a, b))
		}
	}
	for _, s := range lists {
		for _, v := range []int{0, 1, 2, 3} {
			fmt.Printf("find %-14v %d -> index=%-3d contains=%v\n",
				s, v, slices.Index(s, v), slices.Contains(s, v))
		}
	}

	// Compact collapses RUNS, not duplicates: {1,2,1} keeps both 1s.
	for _, s := range append(lists, []int{1, 2, 1}, []int{1, 1, 1, 2, 1}) {
		fmt.Printf("compact %-16v -> %v\n", s, slices.Compact(clone(s)))
	}

	// Delete, Insert, Replace at every boundary.
	base := []int{0, 1, 2, 3, 4}
	for _, ij := range [][2]int{{0, 0}, {0, 1}, {0, 5}, {2, 2}, {2, 4}, {5, 5}, {4, 5}} {
		fmt.Printf("delete [%d:%d] -> %v\n", ij[0], ij[1], slices.Delete(clone(base), ij[0], ij[1]))
	}
	for _, i := range []int{0, 1, 5} {
		fmt.Printf("insert @%d -> %v | empty %v\n",
			i, slices.Insert(clone(base), i, 8, 9), slices.Insert(clone(base), i))
	}
	for _, ij := range [][2]int{{0, 0}, {0, 2}, {2, 2}, {2, 5}, {5, 5}} {
		fmt.Printf("replace [%d:%d] -> %v | with-none %v\n",
			ij[0], ij[1], slices.Replace(clone(base), ij[0], ij[1], 8, 9),
			slices.Replace(clone(base), ij[0], ij[1]))
	}

	// Repeat, Concat, Reverse, Clone, Chunk.
	for _, n := range []int{0, 1, 2, 3} {
		fmt.Printf("repeat %d -> %v | empty %v\n", n,
			slices.Repeat([]int{1, 2}, n), slices.Repeat(empty, n))
	}
	fmt.Printf("concat %v\n", slices.Concat([]int{1}, []int{}, []int{2, 3}, nil))
	fmt.Printf("concat-none %v\n", slices.Concat[[]int]())
	for _, s := range lists {
		c := clone(s)
		slices.Reverse(c)
		fmt.Printf("reverse %-16v -> %v clone=%v\n", s, c, slices.Clone(s))
	}
	for _, n := range []int{1, 2, 3, 5, 10} {
		var chunks [][]int
		for c := range slices.Chunk([]int{1, 2, 3, 4, 5}, n) {
			chunks = append(chunks, c)
		}
		fmt.Printf("chunk %-3d -> %v\n", n, chunks)
	}

	// The iter bridge.
	for _, s := range lists {
		fmt.Printf("iter %-16v values=%v sorted=%v\n",
			s, slices.Collect(slices.Values(s)), slices.Sorted(slices.Values(s)))
	}
	fmt.Printf("appendseq %v\n", slices.AppendSeq([]int{9}, slices.Values([]int{1, 2})))
	var idx []int
	for i, v := range slices.All([]int{7, 8, 9}) {
		idx = append(idx, i, v)
	}
	fmt.Printf("all %v\n", idx)
	idx = nil
	for i, v := range slices.Backward([]int{7, 8, 9}) {
		idx = append(idx, i, v)
	}
	fmt.Printf("backward %v\n", idx)

	// Grow and Clip are capacity-only: the CONTENTS never change.
	g := slices.Grow([]int{1, 2}, 10)
	fmt.Printf("grow len=%d contents=%v capgrew=%v\n", len(g), g, cap(g) >= 12)
	c := slices.Clip(slices.Grow([]int{1, 2}, 10))
	fmt.Printf("clip len=%d cap=%d contents=%v\n", len(c), cap(c), c)
}

func clone(s []int) []int { return append([]int(nil), s...) }

func minOf(s []int) any {
	if len(s) == 0 {
		return "panic"
	}
	return slices.Min(s)
}

func maxOf(s []int) any {
	if len(s) == 0 {
		return "panic"
	}
	return slices.Max(s)
}
