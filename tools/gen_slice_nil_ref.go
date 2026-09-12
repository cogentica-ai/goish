// gen_slice_nil_ref — nil versus allocated-empty slice (issue #14).
//
//	GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 tools/gen_slice_nil_ref.go
//
// goish represents both as an empty Vec and compares both equal to
// nil, so `if x == nil` cannot tell "not processed yet" from
// "processed, produced nothing" — and a zero-value record marshals as
// `[]` where Go writes `null`.
//
// The rows that matter are the ones where nilness SURVIVES or is LOST
// through an operation, because that is what a representation has to
// get right and what a len()==0 check cannot express:
//
//   append to nil      -> non-nil
//   nilSlice[:0]       -> STILL nil
//   empty[:0]          -> still non-nil
//   clone/copy of nil  -> nil
//
// JSON is the observable half: nil marshals as null, allocated-empty
// as [], and decoding has to put each back.
package json_test

import (
	v1 "encoding/json"
	"encoding/json/v2"
	"fmt"
	"testing"
)

func TestGoishRef(t *testing.T) {
	row := func(name string, v ...any) {
		fmt.Printf("%-20s %v\n", name, v)
	}
	jrow := func(name string, v any) {
		out, err := json.Marshal(v)
		fmt.Printf("%-20s err=%-5v got=%s\n", name, err != nil, out)
	}

	var nilSlice []int
	emptyLiteral := []int{}
	emptyMake := make([]int, 0)

	row("nil_is_nil", nilSlice == nil)
	row("literal_is_nil", emptyLiteral == nil)
	row("make_is_nil", emptyMake == nil)
	row("nil_len", len(nilSlice))
	row("literal_len", len(emptyLiteral))

	// Nilness through operations.
	row("append_nil_is_nil", append(nilSlice, 1) == nil)
	row("nil_slice0_is_nil", nilSlice[:0] == nil)
	row("empty_slice0_is_nil", emptyLiteral[:0] == nil)
	cp := nilSlice
	row("copy_nil_is_nil", cp == nil)

	// A non-empty slice truncated to zero keeps its backing array.
	three := []int{1, 2, 3}
	row("three_slice0_is_nil", three[:0] == nil)

	// JSON, both directions.
	jrow("marshal_nil", nilSlice)
	jrow("marshal_literal", emptyLiteral)
	jrow("marshal_make", emptyMake)

	type Rec struct {
		S []int `json:"s"`
	}
	jrow("marshal_zero_rec", Rec{})
	jrow("marshal_empty_rec", Rec{S: []int{}})

	type OmitEmpty struct {
		S []int `json:"s,omitempty"`
	}
	jrow("omitempty_nil", OmitEmpty{})
	jrow("omitempty_empty", OmitEmpty{S: []int{}})

	type OmitZero struct {
		S []int `json:"s,omitzero"`
	}
	jrow("omitzero_nil", OmitZero{})
	jrow("omitzero_empty", OmitZero{S: []int{}})

	// Decoding must put each back.
	var d1 []int
	_ = json.Unmarshal([]byte(`null`), &d1)
	row("dec_null_is_nil", d1 == nil)
	var d2 []int
	_ = json.Unmarshal([]byte(`[]`), &d2)
	row("dec_empty_is_nil", d2 == nil)
	d3 := []int{1, 2}
	_ = json.Unmarshal([]byte(`null`), &d3)
	row("dec_null_over_is_nil", d3 == nil)
	d4 := []int{1, 2}
	_ = json.Unmarshal([]byte(`[]`), &d4)
	row("dec_empty_over_is_nil", d4 == nil)

	// ── v1, because issue #14's acceptance criterion is v1's contract ──
	//
	// v2 marshals a nil slice as `[]`; v1 marshals it as `null`. Without
	// both versions here it is impossible to tell which behaviour a
	// report is describing, and a port built to the wrong one is a
	// divergence introduced on purpose.
	j1 := func(name string, v any) {
		out, err := v1.Marshal(v)
		fmt.Printf("%-20s err=%-5v got=%s\n", name, err != nil, out)
	}
	j1("v1_marshal_nil", nilSlice)
	j1("v1_marshal_literal", emptyLiteral)
	j1("v1_marshal_make", emptyMake)
	j1("v1_marshal_zero_rec", Rec{})
	j1("v1_marshal_empty_rec", Rec{S: []int{}})
	j1("v1_omitempty_nil", OmitEmpty{})
	j1("v1_omitempty_empty", OmitEmpty{S: []int{}})

	var e1 []int
	_ = v1.Unmarshal([]byte(`null`), &e1)
	row("v1_dec_null_is_nil", e1 == nil)
	var e2 []int
	_ = v1.Unmarshal([]byte(`[]`), &e2)
	row("v1_dec_empty_is_nil", e2 == nil)
	e3 := []int{1, 2}
	_ = v1.Unmarshal([]byte(`null`), &e3)
	row("v1_dec_null_over_is_nil", e3 == nil)
	e4 := []int{1, 2}
	_ = v1.Unmarshal([]byte(`[]`), &e4)
	row("v1_dec_empty_over_is_nil", e4 == nil, len(e4))
}
