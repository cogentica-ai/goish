package fmt_test

import (
	"fmt"
	"testing"
)

// Go's printer walks a slice or a map and applies the verb to each
// ELEMENT, wrapping the result in brackets. A port whose Format trait
// is implemented per concrete type has to do the same or the call does
// not compile at all — which is the state goish was in for every slice
// but []byte.
//
// []byte is the exception in Go too, and in the opposite direction:
// %v prints the NUMBERS, %s the bytes as text.
func TestGoishRef(t *testing.T) {
	sf := fmt.Sprintf

	fmt.Printf("strs v=%q s=%q q=%q d=%q\n",
		sf("%v", []string{"a", "b c", ""}), sf("%s", []string{"a", "b c", ""}),
		sf("%q", []string{"a", "b c", ""}), sf("%d", []string{"a"}))
	fmt.Printf("empty v=%q nil=%q\n", sf("%v", []string{}), sf("%v", []string(nil)))

	ints := []int{1, 2, 30}
	fmt.Printf("ints v=%q d=%q x=%q X=%q b=%q q=%q 3d=%q\n",
		sf("%v", ints), sf("%d", ints), sf("%x", ints), sf("%X", ints),
		sf("%b", ints), sf("%q", ints), sf("%3d", ints))
	fmt.Printf("neg v=%q x=%q\n", sf("%v", []int{-1, -255}), sf("%x", []int{-1, -255}))

	fmt.Printf("nested v=%q\n", sf("%v", [][]int{{1, 2}, {3}, {}}))
	fmt.Printf("strsnested v=%q q=%q\n",
		sf("%v", [][]string{{"a"}, {"b", "c"}}), sf("%q", [][]string{{"a"}, {"b", "c"}}))

	b := []byte{1, 2, 255}
	fmt.Printf("bytes v=%q s=%q q=%q x=%q X=%q d=%q\n",
		sf("%v", b), sf("%s", b), sf("%q", b), sf("%x", b), sf("%X", b), sf("%d", b))
	ab := []byte("abc")
	fmt.Printf("abc v=%q s=%q q=%q x=%q\n",
		sf("%v", ab), sf("%s", ab), sf("%q", ab), sf("%x", ab))
	fmt.Printf("bempty v=%q s=%q x=%q nil=%q\n",
		sf("%v", []byte{}), sf("%s", []byte{}), sf("%x", []byte{}), sf("%v", []byte(nil)))

	fmt.Printf("floats v=%q f=%q .2f=%q\n",
		sf("%v", []float64{1, 1.5}), sf("%f", []float64{1, 1.5}), sf("%.2f", []float64{1, 1.5}))
	fmt.Printf("bools v=%q t=%q\n", sf("%v", []bool{true, false}), sf("%t", []bool{true, false}))

	// Maps sort by key.
	m := map[string]int{"b": 2, "a": 1, "c": 3}
	fmt.Printf("map v=%q d=%q q=%q\n", sf("%v", m), sf("%d", m), sf("%q", m))
	mi := map[int]string{3: "c", 1: "a", 2: "b"}
	fmt.Printf("mapi v=%q q=%q\n", sf("%v", mi), sf("%q", mi))
	fmt.Printf("mapempty v=%q nil=%q\n", sf("%v", map[string]int{}), sf("%v", map[string]int(nil)))

	// Println's spacing rules over a slice.
	fmt.Println([]string{"a", "b"}, []int{1}, []byte{65, 66})

	// Arrays render like slices.
	fmt.Printf("array v=%q\n", sf("%v", [3]int{1, 2, 3}))

	// A slice of errors, and a nil element.
	fmt.Printf("errs v=%q\n", sf("%v", []error{nil, fmt.Errorf("boom")}))

	// Width applies to the WHOLE rendering, not per element.
	fmt.Printf("width a=%q b=%q\n", sf("%12v|", []int{1, 2}), sf("%-12v|", []int{1, 2}))
}
