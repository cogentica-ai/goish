// gen_jsondup_ref — reference generator for examples/jsondup_ref.txt.
//
// Runs a corpus of JSON documents through the REAL jsontext Decoder,
// once with duplicate names disallowed (the default) and once with
// AllowDuplicateNames(true), printing the token kinds read or the error.
// Driving the decoder rather than json.Unmarshal keeps the sweep on the
// layer that does the checking.
// examples/json_dup_diff.rs replays the same corpus against goish.
//
// Regenerate:  go run tools/gen_jsondup_ref.go > examples/jsondup_ref.txt
//
// Needs Go 1.25 with GOEXPERIMENT=jsonv2.
package main

import (
	"encoding/json/jsontext"
	"fmt"
	"io"
	"strings"
)

var corpus = []string{
	`{}`,
	`{"a":1}`,
	`{"a":1,"b":2}`,
	`{"a":1,"a":2}`,
	`{"a":1,"b":2,"a":3}`,
	`{"a":1,"A":2}`,
	// Escaped spellings of the same name: a duplicate only if the
	// tracker compares DECODED names, which is the point of the test.
	`{"\u0061":1,"a":2}`,
	`{"a":1,"\u0061":2}`,
	`{"a\u0062":1,"ab":2}`,
	`{"\u00e9":1,"\u00e9":2}`,
	// Nested: the inner object has its own namespace, so an inner "a"
	// beside an outer "a" is fine — a shared set would wrongly reject.
	`{"a":{"a":1}}`,
	`{"a":{"a":1},"b":{"a":2}}`,
	`{"a":{"b":1,"b":2}}`,
	`{"a":[{"x":1},{"x":2}]}`,
	// Frame popping: a name reused AFTER a sibling object closed is
	// still a duplicate at its own level.
	`{"a":{"z":1},"a":2}`,
	`{"a":{"z":1},"b":{"z":2},"a":3}`,
	// Arrays have no names at all.
	`[{"a":1},{"a":2}]`,
	`[1,1,1]`,
	// Deep nesting, duplicate at the bottom.
	`{"a":{"b":{"c":{"d":1,"d":2}}}}`,
	// Empty-string names.
	`{"":1}`,
	`{"":1,"":2}`,
	`{"":1,"a":2}`,
	// Pointer segments from ARRAY frames, and RFC 6901 escaping of a
	// name containing `/` or `~` so it cannot fake a path separator.
	`[{"a":1,"a":2}]`,
	`[0,{"a":1,"a":2}]`,
	`{"a/b":{"x":1,"x":2}}`,
	`{"a~b":{"x":1,"x":2}}`,
	`{"a":[[{"q":1,"q":2}]]}`,
	// String VALUES that repeat, or equal a name at the same level:
	// legal, and the only way to catch a check that records every
	// string it sees instead of only the member names.
	`{"a":"a","b":"a"}`,
	`{"x":"y","y":"z"}`,
	`{"a":"b","b":"a"}`,
}

func esc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x21 && c < 0x7f && c != '\\' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

func main() {
	for i, doc := range corpus {
		for _, allow := range []bool{false, true} {
			tag := "strict"
			if allow {
				tag = "allow"
			}
			// Driving the DECODER, not json.Unmarshal into `any`:
			// duplicate detection lives in jsontext, and unmarshalling
			// into `any` adds its own type errors that have nothing to
			// do with the check under test.
			dec := jsontext.NewDecoder(strings.NewReader(doc),
				jsontext.AllowDuplicateNames(allow))
			var kinds []string
			var failure string
			for {
				tok, err := dec.ReadToken()
				if err != nil {
					if err == io.EOF {
						break
					}
					failure = err.Error()
					break
				}
				kinds = append(kinds, tok.Kind().String())
			}
			if failure != "" {
				fmt.Printf("D %d %s %s err %s\n", i, tag, esc(doc), esc(failure))
			} else {
				fmt.Printf("D %d %s %s ok %s\n", i, tag, esc(doc), esc(strings.Join(kinds, "")))
			}
		}
	}
}
