// gen_json_mapkey_ref — a NAMED STRING type as a JSON object key.
//
//	GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 tools/gen_json_mapkey_ref.go
//
// Go lets any string-kinded type be a map key and encodes it as the
// member name, so `map[DocumentUri][]*TextEdit` is an ordinary field.
// goish's map codec is written for `map<string, V>` only (issue #17).
//
// Generalising it needs more than the key conversion. The rows below
// are the parts a `map<string, V>` implementation already had to
// decide and which must not change under a named key:
//
//   - member ORDER on marshal, which turns out to be unpinnable: v2
//     emits Go's randomised map iteration order, so only a one-key
//     map has a stable expectation.
//   - a nil map vs an empty one, in both directions.
//   - a DUPLICATE member name, which v2 treats differently from v1.
//   - what the destination holds after a value fails to decode —
//     the `pre` rows start from a populated map so a partial write
//     is visible.
package json_test

import (
	"encoding/json/v2"
	"fmt"
	"testing"
)

type DocumentUri string

func TestGoishRef(t *testing.T) {
	row := func(name string, err error, got any) {
		fmt.Printf("%-18s err=%-5v got=%v\n", name, err != nil, got)
	}

	// Marshal. NOT a multi-key map: v2 emits members in Go's map
	// iteration order, which is randomised — three runs here gave two
	// different orders — so a multi-key expectation cannot be pinned
	// at all. goish sorts instead (a documented divergence), and the
	// thing to check against Go is that the KEY is the bare string
	// with no conversion.
	m := map[DocumentUri]int{"file:///a.ts": 1}
	out, err := json.Marshal(m)
	row("marshal_1", err, string(out))

	var nilm map[DocumentUri]int
	out, err = json.Marshal(nilm)
	row("marshal_nil", err, string(out))

	out, err = json.Marshal(map[DocumentUri]int{})
	row("marshal_empty", err, string(out))

	// A key needing JSON string escaping.
	out, err = json.Marshal(map[DocumentUri]int{"a\"b\n": 1})
	row("marshal_escape", err, string(out))

	// Unmarshal into a nil map: does it allocate?
	var got map[DocumentUri]int
	err = json.Unmarshal([]byte(`{"x":1}`), &got)
	row("dec_into_nil", err, got)

	got = nil
	err = json.Unmarshal([]byte(`null`), &got)
	row("dec_null", err, got == nil)

	got = map[DocumentUri]int{"keep": 9}
	err = json.Unmarshal([]byte(`null`), &got)
	row("dec_null_over", err, got == nil)

	// Duplicate member name.
	got = map[DocumentUri]int{}
	err = json.Unmarshal([]byte(`{"d":1,"d":2}`), &got)
	row("dec_dup", err, got)

	// Merge into an existing map: untouched keys survive.
	got = map[DocumentUri]int{"keep": 9}
	err = json.Unmarshal([]byte(`{"x":1}`), &got)
	row("dec_merge", err, got)

	// A value that fails: what is in the map afterwards.
	got = map[DocumentUri]int{"keep": 9}
	err = json.Unmarshal([]byte(`{"x":"nope"}`), &got)
	row("dec_bad_value", err, got)

	// Wrong outer kind.
	got = map[DocumentUri]int{"keep": 9}
	err = json.Unmarshal([]byte(`[1]`), &got)
	row("dec_wrong_kind", err, got)

	// Round-trip the shape the issue names.
	type TextEdit struct {
		NewText string `json:"newText"`
	}
	ch := map[DocumentUri][]*TextEdit{"file:///a.ts": {{NewText: "hi"}}}
	out, err = json.Marshal(ch)
	row("marshal_edits", err, string(out))

	var back map[DocumentUri][]*TextEdit
	err = json.Unmarshal(out, &back)
	row("dec_edits", err, back["file:///a.ts"][0].NewText)
}
