// gen_json_any_ref — `any` (interface{}) under encoding/json/v2.
//
//	GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 tools/gen_json_any_ref.go
//
// goish has no v2 codec for `goish::Any` (issue #15), which makes an
// ordinary generated field like `Command.Arguments *[]any` unportable
// with its real shape.
//
// The `%T` column is the whole point of the decode rows: what Go picks
// as the DYNAMIC type. A number is float64 and never an int, so a
// decoder that stored an integer for `1` would round-trip `1` fine and
// diverge the moment anything looked at the type or did arithmetic.
//
// The `into_*` rows are the ones an implementation is most likely to
// get wrong: decoding into an interface that ALREADY holds something.
// Go v2 does not simply replace it with the default representation.
package json_test

import (
	"encoding/json/v2"
	"fmt"
	"testing"
)

// A dynamically held struct, and one with a custom marshaler — both
// reachable only through the interface, so a fixed downcast table
// cannot serve them.
type Point struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type Odd struct{ N int }

func (o Odd) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"odd-%d"`, o.N)), nil
}

func (o *Odd) UnmarshalJSON(b []byte) error {
	o.N = len(b)
	return nil
}

func TestGoishRef(t *testing.T) {
	mrow := func(name string, v any) {
		out, err := json.Marshal(v)
		fmt.Printf("%-20s err=%-5v got=%s\n", name, err != nil, out)
	}
	drow := func(name, in string, dst *any) {
		err := json.Unmarshal([]byte(in), dst)
		fmt.Printf("%-20s err=%-5v type=%-20T got=%v\n", name, err != nil, *dst, *dst)
	}

	// ── marshal: dispatch on the dynamic value ──────────────────────
	var nilAny any
	mrow("m_nil", nilAny)
	mrow("m_bool", any(true))
	mrow("m_string", any("hi"))
	mrow("m_float", any(1.5))
	mrow("m_int", any(7))
	mrow("m_slice", any([]any{1.0, "a", nil, true}))
	mrow("m_map", any(map[string]any{"k": 1.0}))
	mrow("m_nested", any([]any{[]any{1.0}, map[string]any{"m": []any{nil}}}))
	mrow("m_struct", any(Point{1, 2}))
	mrow("m_custom", any(Odd{3}))
	mrow("m_ptr_struct", any(&Point{1, 2}))

	// ── decode into an EMPTY interface: Go's default types ──────────
	for _, tc := range []struct{ name, in string }{
		{"d_null", `null`},
		{"d_true", `true`},
		{"d_string", `"hi"`},
		{"d_int_lit", `1`},
		{"d_float", `1.5`},
		{"d_big", `12345678901234567890`},
		{"d_array", `[1,"a",null,true]`},
		{"d_object", `{"k":1}`},
		{"d_nested", `[[1],{"m":[null]}]`},
	} {
		var dst any
		drow(tc.name, tc.in, &dst)
	}

	// ── decode into a POPULATED interface ───────────────────────────
	{
		dst := any(Point{9, 9})
		drow("into_struct_obj", `{"x":1,"y":2}`, &dst)
	}
	{
		dst := any(Point{9, 9})
		drow("into_struct_num", `5`, &dst)
	}
	{
		dst := any("old")
		drow("into_string_num", `5`, &dst)
	}
	{
		dst := any(map[string]any{"keep": 1.0})
		drow("into_map_obj", `{"x":1}`, &dst)
	}
	{
		dst := any([]any{1.0, 2.0, 3.0})
		drow("into_slice_arr", `[9]`, &dst)
	}
	{
		dst := any(Point{9, 9})
		drow("into_struct_null", `null`, &dst)
	}

	// ── malformed nested input: error AND partial state ─────────────
	{
		var dst any
		drow("bad_nested", `[1,{"a":}]`, &dst)
	}
	{
		var dst any
		drow("bad_trailing", `[1,2`, &dst)
	}

	// ── the shape the issue is blocked on: *[]any with omitzero ─────
	type Command struct {
		Arguments *[]any `json:"arguments,omitzero"`
	}
	mrow("cmd_absent", Command{})
	args := []any{1.0, "a", nil}
	mrow("cmd_present", Command{Arguments: &args})

	var back Command
	err := json.Unmarshal([]byte(`{"arguments":[1,"a",null]}`), &back)
	fmt.Printf("%-20s err=%-5v got=%v\n", "cmd_decode", err != nil, *back.Arguments)
}
