// gen_slice_alias_ref — the Go contract for slice backing-array sharing
// (goish issue #26).
//
// Plain Go, no internal access:
//
//	mkdir /tmp/slicealias && cd /tmp/slicealias && go mod init slicealias
//	cp <goish>/tools/gen_slice_alias_ref.go main.go && go run main.go
//
// Covers every acceptance row the issue lists, plus the edges a
// representation with offset/len/cap has to get right and that the issue
// does not spell out: where cap comes from after a subslice, what a
// three-index subslice does to cap, whether a copy past capacity detaches
// only the appending header, and how `copy` interacts with overlap.
package main

import "fmt"

func row(name string, v ...any) { fmt.Printf("%-34s %v\n", name, v) }

//go:noinline
func appendOne(prefix []int, x int) []int { return append(prefix, x) }

func main() {
	// THE ORACLE FROM THE ISSUE. Two appends into the same spare slot:
	// the second write wins and is visible through the first result.
	{
		base := make([]int, 0, 3)
		base = append(base, 1, 2)
		first := append(base, 7)
		second := append(base, 9)
		row("two_appends_base", base, len(base), cap(base))
		row("two_appends_first", first)
		row("two_appends_second", second)
	}

	// The same through a function, which is how the downstream formatter
	// hits it (tokenRangeFromEx).
	{
		base := make([]int, 0, 3)
		base = append(base, 1, 2)
		a := appendOne(base, 7)
		b := appendOne(base, 9)
		row("via_func_a", a)
		row("via_func_b", b)
	}

	// Header copy aliases the backing array.
	{
		s := []int{1, 2, 3}
		t := s
		t[0] = 99
		row("header_copy_aliases", s[0])
	}

	// Two-index subslice: shares, and cap runs to the END of the backing
	// array from the subslice's start.
	{
		s := make([]int, 5, 8)
		for i := range s {
			s[i] = i
		}
		sub := s[1:3]
		row("sub_len_cap", len(sub), cap(sub))
		sub[0] = 77
		row("sub_write_visible", s[1])
		// Appending within the subslice's cap overwrites s[3].
		sub = append(sub, 88)
		row("sub_append_overwrites_parent", s[3], len(sub))
	}

	// Three-index subslice caps the capacity, so an append REALLOCATES
	// and stops aliasing.
	{
		s := make([]int, 5, 8)
		for i := range s {
			s[i] = i
		}
		sub := s[1:3:3]
		row("sub3_len_cap", len(sub), cap(sub))
		sub = append(sub, 88)
		row("sub3_append_detaches", s[3], sub[2])
	}

	// Append BEYOND capacity detaches only the appending header.
	{
		base := make([]int, 0, 2)
		base = append(base, 1, 2)
		grown := append(base, 3)
		grown[0] = 42
		row("beyond_cap_detaches", base[0], grown[0], cap(base), cap(grown) >= 3)
	}

	// Independent lengths off one array.
	{
		arr := make([]int, 4, 4)
		a := arr[0:2]
		b := arr[0:4]
		row("independent_lengths", len(a), len(b), cap(a), cap(b))
		b[3] = 9
		row("longer_write_invisible_to_shorter", len(a))
	}

	// copy() writes through to the shared array.
	{
		s := []int{1, 2, 3, 4}
		d := s[0:2]
		n := copy(d, []int{8, 9})
		row("copy_through_subslice", n, s)
	}

	// Overlapping copy, which a shared representation must handle like
	// memmove rather than a naive element loop.
	{
		s := []int{1, 2, 3, 4, 5}
		copy(s[1:], s[0:4])
		row("overlapping_copy_forward", s)
		t := []int{1, 2, 3, 4, 5}
		copy(t[0:4], t[1:])
		row("overlapping_copy_backward", t)
	}

	// A zero-length subslice at the very end still has the array behind
	// it, so an append there writes into it.
	{
		s := make([]int, 2, 4)
		tail := s[2:2]
		row("tail_len_cap", len(tail), cap(tail))
		tail = append(tail, 7)
		row("tail_append_into_parent_array", cap(s), len(s), tail[0])
	}

	// Appending to a nil slice allocates; the nil stays nil.
	{
		var z []int
		g := append(z, 1)
		row("append_nil_leaves_nil_nil", z == nil, len(z), g)
	}
}
