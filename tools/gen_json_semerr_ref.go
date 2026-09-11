// gen_json_semerr_ref — the TEXT of a v2 semantic decode error.
//
//	GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 tools/gen_json_semerr_ref.go
//
// goish's scalar codecs say `json: cannot unmarshal non-string into
// string`. Go names the rejected JSON KIND, the Go DESTINATION TYPE,
// and the JSON POINTER of the field that failed (issue #10):
//
//	json: cannot unmarshal JSON number into Go string within "/trigger"
//
// A caller routes on that. The pointer is the part a consumer cannot
// reconstruct itself, and the Go type is the part that tells a
// generated adapter which field of which message rejected the value.
//
// Rows cover each rejected kind into each destination, at the root and
// nested, plus the wrapping of a CUSTOM pointee error — where Go keeps
// the cause's own text and prefixes its own context rather than
// replacing it.
package json_test

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"testing"
)

type Custom struct{ N int }

var errCustom = errors.New("Custom: expected string or object, got number")

func (c *Custom) UnmarshalJSON(b []byte) error { return errCustom }

type Inner struct {
	S string `json:"s"`
}

type Outer struct {
	A  []int             `json:"a"`
	M  map[string]int    `json:"m"`
	In Inner             `json:"in"`
	C  *Custom           `json:"c"`
	Sl []Inner           `json:"sl"`
}

func TestGoishRef(t *testing.T) {
	row := func(name, doc string, dst any) {
		err := json.Unmarshal([]byte(doc), dst)
		if err == nil {
			fmt.Printf("%-18s <nil>\n", name)
			return
		}
		fmt.Printf("%-18s %v\n", name, err)
	}

	// Root-level: each rejected kind into each destination type.
	var s string
	row("root_num_str", `1`, &s)
	row("root_bool_str", `true`, &s)
	row("root_arr_str", `[]`, &s)
	row("root_obj_str", `{}`, &s)
	var b bool
	row("root_num_bool", `1`, &b)
	row("root_str_bool", `"x"`, &b)
	var i int
	row("root_str_int", `"x"`, &i)
	row("root_bool_int", `true`, &i)
	row("root_frac_int", `1.5`, &i)
	var u uint
	row("root_neg_uint", `-1`, &u)
	var f float64
	row("root_str_float", `"x"`, &f)
	var sl []int
	row("root_obj_slice", `{}`, &sl)
	var m map[string]int
	row("root_arr_map", `[]`, &m)

	// Nested: the pointer is what changes.
	var o Outer
	row("field_arr_elem", `{"a":[1,"x"]}`, &o)
	row("field_map_val", `{"m":{"k":"x"}}`, &o)
	row("field_nested_str", `{"in":{"s":1}}`, &o)
	row("field_slice_deep", `{"sl":[{"s":1}]}`, &o)
	row("field_custom", `{"c":5}`, &o)

	// errors.Is through the wrapping.
	o = Outer{}
	err := json.Unmarshal([]byte(`{"c":5}`), &o)
	fmt.Printf("%-18s %v\n", "custom_is", errors.Is(err, errCustom))

	// A member name needing RFC 6901 escaping, through a map.
	var mm map[string]int
	row("escaped_name", `{"a/b":"x"}`, &mm)
}
