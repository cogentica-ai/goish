// gen_jsonmap_ref — reference generator for examples/jsonmap_ref.txt.
//
// Sweeps map[string]string and map[string]int decoding through the REAL
// encoding/json/v2, including the PARTIAL STATE a failed decode leaves
// behind: Go stores each key with its zero value before decoding, so a
// bad value leaves that key present and empty and stops the walk.
// packagejson's Expected[T] keeps the partially decoded value, so this
// is observable rather than an internal detail.
//
// Regenerate:  GOEXPERIMENT=jsonv2 go run tools/gen_jsonmap_ref.go > examples/jsonmap_ref.txt
package main

import (
	"encoding/json/v2"
	"fmt"
	"sort"
	"strings"
)

var corpus = []string{
	`{}`,
	`{"a":"x"}`,
	`{"a":"x","b":"y"}`,
	`{"b":"y","a":"x"}`,
	// Failures at each position, so "stops at the first" is pinned.
	`{"a":1}`,
	`{"a":"x","b":1}`,
	`{"a":1,"b":"x"}`,
	`{"a":"x","b":1,"c":"z"}`,
	`{"a":[1]}`,
	`{"a":{}}`,
	`{"a":null}`,
	`{"a":true}`,
	// Non-objects.
	`null`,
	`[]`,
	`"x"`,
	`1`,
}

func esc(s string) string {
	if s == "" {
		return "-"
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x21 && c < 0x7f && c != '\\' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	return b.String()
}

func main() {
	for i, doc := range corpus {
		ms := map[string]string{}
		e1 := json.Unmarshal([]byte(doc), &ms)
		keys := make([]string, 0, len(ms))
		for k := range ms {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for j, k := range keys {
			parts[j] = esc(k) + "=" + esc(ms[k])
		}
		fmt.Printf("M %d %s err=%v {%s}\n", i, doc, e1 != nil, strings.Join(parts, " "))

		mi := map[string]int{}
		e2 := json.Unmarshal([]byte(doc), &mi)
		keys = keys[:0]
		for k := range mi {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts = make([]string, len(keys))
		for j, k := range keys {
			parts[j] = fmt.Sprintf("%s=%d", esc(k), mi[k])
		}
		fmt.Printf("I %d %s err=%v {%s}\n", i, doc, e2 != nil, strings.Join(parts, " "))
	}
}
