// gen_json_null_ref — what a MALFORMED null does to the destination.
//
//	GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 tools/gen_json_null_ref.go
//
// `nul` and `nulx` both begin with 'n', so a decoder that dispatches on
// the first byte enters its null branch and only then discovers the
// token does not parse. The question this answers is what the
// destination looks like AFTERWARDS.
//
// Go's answer is that a rejected token leaves it alone. That matters
// because the caller still holds a populated struct: `Unmarshal` into
// an existing value is how a config or a source map gets updated, and
// a decoder that zeroes the fields before failing destroys data the
// caller never agreed to lose — silently, since the error says
// "syntax", not "and I also wiped your struct".
//
// A VALID null is the opposite and does zero the destination; the two
// cases share a branch and are pinned together so neither can be
// "fixed" into the other.
package json_test

import (
	"encoding/json/v2"
	"fmt"
	"testing"
)

type Probe struct {
	Value int    `json:"value"`
	Name  string `json:"name"`
}

func TestGoishRef(t *testing.T) {
	for _, in := range []string{"nul", "nulx", "null", "n", `{"value":3}`} {
		got := Probe{Value: 9, Name: "kept"}
		err := json.Unmarshal([]byte(in), &got)
		fmt.Printf("%-12q err=%-5v value=%d name=%q\n",
			in, err != nil, got.Value, got.Name)
	}
}
