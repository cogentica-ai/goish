// Go 1.25.5 json/v2 map content and decoder-state oracle.
// GOEXPERIMENT=jsonv2 go run tools/gen_jsonmap_state_ref.go > examples/jsonmap_state_ref.txt
package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"
)

type record struct {
	A int
	B int
}

func row[V any](label, initial, input string, allow bool) {
	var value map[string]V
	if err := json.Unmarshal([]byte(initial), &value); err != nil {
		panic(err)
	}
	dec := jsontext.NewDecoder(strings.NewReader(input), jsontext.AllowDuplicateNames(allow))
	err := json.UnmarshalDecode(dec, &value)
	state, encodeErr := json.Marshal(value, json.Deterministic(true))
	if encodeErr != nil {
		panic(encodeErr)
	}
	fmt.Printf("%s|%s|%s|%t|%t|%s|%d\n", label, initial, input, allow, err == nil, state, dec.StackDepth())
}
func main() {
	common := []string{"", "null", "nul", "{}", "[]", "[1]", "true", "1", `"x"`, `{"x":null}`, `{"x":true}`, `{"x":1}`, `{"x":1,"x":2}`, `{"x":1,}`, `{"x":1`, `{"x":`, `{"y":1,"x":true}`, `{"x":1,"y":true}`, `{"x":1,"\u0078":2}`, `{"x":1} 0`}
	for _, initial := range []string{"null", "{}", `{"old":90,"x":91}`} {
		for _, input := range common {
			for _, allow := range []bool{false, true} {
				row[int]("I", initial, input, allow)
			}
		}
	}
	for _, initial := range []string{"{}", `{"old":[90],"x":[91,92]}`} {
		for _, input := range append(common, `{"x":[1,2]}`, `{"x":[1,true]}`, `{"y":[2],"x":[1,true]}`, `{"x":[1],"x":[2]}`, `{"x":[1,`, `{"x":[1],"y":[2,`) {
			for _, allow := range []bool{false, true} {
				row[[]int]("S", initial, input, allow)
			}
		}
	}
	for _, initial := range []string{"{}", `{"old":{"A":90,"B":89},"x":{"A":91,"B":92}}`} {
		for _, input := range append(common, `{"x":{"A":1}}`, `{"x":{"B":2}}`, `{"x":{"A":1,"B":true}}`, `{"x":{"A":1,"B":`, `{"y":{"A":1},"x":{"B":true}}`, `{"x":{"A":1},"x":{"B":2}}`) {
			for _, allow := range []bool{false, true} {
				row[record]("R", initial, input, allow)
				row[map[string]int]("M", initial, input, allow)
			}
		}
	}
}
