// Real Go 1.25.5 json/v2 slice decode status and partial-state oracle.
// Regenerate: GOEXPERIMENT=jsonv2 go run tools/gen_jsonslice_ref.go > examples/jsonslice_ref.txt
package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"
)

func row[T any](label, input string, value T) {
	decoder := jsontext.NewDecoder(strings.NewReader(input))
	err := json.UnmarshalDecode(decoder, &value)
	state, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		panic(marshalErr)
	}
	fmt.Printf("%s|%s|%t|%s|%d\n", label, input, err == nil, state, decoder.StackDepth())
}

func integers(input string) {
	row("empty", input, []int(nil))
	row("old", input, []int{91, 92, 93})
	row("p-nil", input, (*[]int)(nil))
	v := []int{91, 92, 93}
	row("p-old", input, &v)
}

func sweep(prefix []string, depth int) {
	integers("[" + strings.Join(prefix, ",") + "]")
	if depth == 0 {
		return
	}
	for _, atom := range []string{"0", "7", "null", "true", `"x"`, "{}", "[]"} {
		sweep(append(prefix, atom), depth-1)
	}
}

func main() {
	sweep(nil, 3)
	for _, input := range []string{"", "null", "nul", "false", "1", `"x"`, "{}", "[", "[1,", "[1,2,", "[1,2,3,", "[1,2,]", "[1 2]", "[1,2]x", "[1,2,3,4,5]", `[1,{"x":0,"x":1}]`, "[1.0,2]", "[1,1e2]", "[1,9223372036854775808]"} {
		integers(input)
	}
	for _, input := range []string{"null", "[]", "[[1,2],[3,4]]", "[[1],[3,4]]", "[[1,true],[3,4]]", "[null,[3,4]]", "[[1,2],null]", "[[1,2],[3,4],[]]", "[[1,2],[3,", "[[1,2],", "[[1,2],{}]"} {
		row("nested", input, [][]int{{91, 92}, {93, 94}})
	}
	for _, input := range []string{"null", "[]", `["a","b"]`, `["a"]`, `[null,"b"]`, `["a",1]`, `["a",`, `["a",null,3]`} {
		row("strings", input, []string{"old1", "old2"})
	}
	type record struct {
		Count int
		Other int
	}
	for _, input := range []string{"null", "nul", "{}", `{"Count":1}`, `{"Other":2}`, `{"Count":1,"Other":true}`, `{"Count":null}`, `{"Count":1,"Other":`, `{"Count":1,"unknown":0}`, "false", "[]", `{"Count":1,"Count":2}`} {
		row("record-nil", input, (*record)(nil))
		row("record-old", input, &record{91, 92})
		row("record-slice", "["+input+"]", []record{{91, 92}})
	}
}
