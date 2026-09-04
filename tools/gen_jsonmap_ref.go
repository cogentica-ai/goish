package json_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Go SORTS map keys when marshalling, so the output is deterministic
// for a given map. That is what makes a marshalled map usable as a
// cache key, a signature input or a golden test fixture.
func TestGoishRef(t *testing.T) {
	m := map[string]int{"zebra": 1, "apple": 2, "Mango": 3, "banana": 4, "": 5, "10": 6, "2": 7}
	for i := 0; i < 3; i++ {
		b, _ := json.Marshal(m)
		fmt.Printf("map-run%d %s\n", i, b)
	}

	nested := map[string]any{
		"b": map[string]int{"y": 1, "x": 2},
		"a": []int{3, 1, 2},
	}
	b, _ := json.Marshal(nested)
	fmt.Printf("nested %s\n", b)

	// Keys are compared as strings, so ordering is byte-wise: capitals
	// before lowercase, digits before both.
	keys := map[string]int{"B": 1, "a": 2, "A": 3, "b": 4, "_": 5, "0": 6}
	b2, _ := json.Marshal(keys)
	fmt.Printf("order %s\n", b2)

	// MarshalIndent over a map keeps the same order.
	b3, _ := json.MarshalIndent(map[string]int{"c": 1, "a": 2, "b": 3}, "", "  ")
	fmt.Printf("indent %s\n", b3)

	// An empty map is {} and a nil map is null.
	var nilm map[string]int
	b4, _ := json.Marshal(nilm)
	b5, _ := json.Marshal(map[string]int{})
	fmt.Printf("nilmap %s emptymap %s\n", b4, b5)

	// Same for slices.
	var nils []int
	b6, _ := json.Marshal(nils)
	b7, _ := json.Marshal([]int{})
	fmt.Printf("nilslice %s emptyslice %s\n", b6, b7)
}
