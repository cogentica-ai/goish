// gen_json_array_ref — a Go FIXED ARRAY under encoding/json/v2.
//
//	GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 tools/gen_json_array_ref.go
//
// A slice takes whatever length the document has; an array's length is
// part of its type, so `makeArrayArshaler` (arshal_default.go) has to
// decide what to do when the document disagrees. Both directions are
// rejections in v2 — underflow AND overflow — which is the opposite of
// v1, where a short array left the tail zeroed and a long one dropped
// the excess. A port that reused the slice codec would silently accept
// both.
//
// The rows that decide an implementation:
//
//   - what the destination looks like AFTER a rejection. A decoder
//     that fills as it goes leaves a half-written array behind; the
//     `pre` rows start from {7,8} so that is visible rather than
//     indistinguishable from a zero value.
//   - `null` into an array, which is not an error and not a no-op.
//   - N = 0, where `[]` is the only document that fits.
//   - a bad ELEMENT rather than a bad length.
package json_test

import (
	"encoding/json/v2"
	"fmt"
	"testing"
)

func show(name, in string, err error, got any) {
	fmt.Printf("%-14s %-12s err=%-5v got=%v\n", name, in, err != nil, got)
}

func TestGoishRef(t *testing.T) {
	// Round-trip: the shape the issue needs.
	out, err := json.Marshal([2]uint32{0, 4})
	fmt.Printf("%-14s %-12s err=%-5v got=%s\n", "marshal_2", "[0 4]", err != nil, out)

	empty, err := json.Marshal([0]uint32{})
	fmt.Printf("%-14s %-12s err=%-5v got=%s\n", "marshal_0", "[]", err != nil, empty)

	// Decode cases. Every destination starts populated so a partial
	// write is visible.
	for _, in := range []string{"[0,4]", "[1]", "[1,2,3]", "null", "[]", `"x"`, "{}", "[1,\"a\"]"} {
		got := [2]uint32{7, 8}
		err := json.Unmarshal([]byte(in), &got)
		show("dec_2", in, err, got)
	}

	for _, in := range []string{"[]", "[1]", "null"} {
		got := [0]uint32{}
		err := json.Unmarshal([]byte(in), &got)
		show("dec_0", in, err, got)
	}

	// Nested, and inside an Option-shaped pointer, which is how the
	// downstream union holds it.
	var p *[2]uint32
	err = json.Unmarshal([]byte("[9,10]"), &p)
	fmt.Printf("%-14s %-12s err=%-5v got=%v\n", "dec_ptr", "[9,10]", err != nil, *p)

	nested := [2][2]uint32{}
	err = json.Unmarshal([]byte("[[1,2],[3,4]]"), &nested)
	show("dec_nested", "[[1,2],[3,4]]", err, nested)

	// The error TEXT, since a caller routes on it.
	got := [2]uint32{7, 8}
	e1 := json.Unmarshal([]byte("[1]"), &got)
	fmt.Printf("%-14s %v\n", "err_under", e1)
	e2 := json.Unmarshal([]byte("[1,2,3]"), &got)
	fmt.Printf("%-14s %v\n", "err_over", e2)
}
