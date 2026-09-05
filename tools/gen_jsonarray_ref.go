// gen_jsonarray_ref — Go 1.25.5 json/v2 fixed-array differential oracle.
// Regenerate: GOEXPERIMENT=jsonv2 go run tools/gen_jsonarray_ref.go > examples/jsonarray_ref.txt
// Tests both status and final state, including partial state on errors.
package main

import (
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"strings"
)

func row[T any](label, input string, value T) {
	err := json.Unmarshal([]byte(input), &value)
	state, marshalErr := json.Marshal(value)
	if marshalErr != nil { panic(marshalErr) }
	fmt.Printf("%s|%s|%t|%s\n", label, input, err == nil, state)
}

func integers(input string) {
	row("i0", input, [0]int{})
	row("i1", input, [1]int{91})
	row("i2", input, [2]int{91, 92})
	row("i4", input, [4]int{91, 92, 93, 94})
}

func bytes(input string) {
	row("b0", input, [0]byte{})
	row("b1", input, [1]byte{91})
	row("b2", input, [2]byte{91, 92})
	row("b4", input, [4]byte{91, 92, 93, 94})
	row("b8", input, [8]byte{91, 92, 93, 94, 95, 96, 97, 98})
	row("b16", input, [16]byte{91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106})
}

func sweep(prefix []string, remaining int) {
	integers("[" + strings.Join(prefix, ",") + "]")
	if remaining == 0 { return }
	for _, atom := range []string{"0", "-1", "7", "null", "true", `"x"`, "{}", "[]"} {
		sweep(append(prefix, atom), remaining-1)
	}
}

func main() {
	sweep(nil, 3)
	for _, input := range []string{"null", "false", "1", `"x"`, "{}", "[", "[1,", "[1,2,", "[1,2,3,", "[1,2,3,4,", "[1,2,]", "[1 2]", "[1,2]x", "[1,2,3,4,5]", `[1,2,{"x":0,"x":1}]`, "[1.0,2]", "[1,1e2]"} {
		integers(input)
	}
	for _, input := range []string{"null", "false", "1", "[]", "[1,2]", "{}", `""`, `"!"`, `"AQ"`, `"AQ==!"`, `"AQ==\n"`, `"AQ\r\n=="`, `"AQID!!!!"`, `"AQIDBA!="`, `"AQIDBA==!"`} {
		bytes(input)
	}
	for n := 0; n <= 16; n++ {
		value := make([]byte, n)
		for i := range value { value[i] = byte(i*37 + 1) }
		encoded := base64.StdEncoding.EncodeToString(value)
		bytes(`"` + encoded + `"`)
		for i := range encoded {
			bytes(`"` + encoded[:i] + "!" + encoded[i+1:] + `"`)
		}
	}
	for _, input := range []string{"null", "[]", "[[1,2],[3,4]]", "[[1],[3,4]]", "[[1,2],[3]]", "[[1,true],[3,4]]", "[null,[3,4]]", "[[1,2],null]", "[[1,2],[3,4],[]]"} {
		row("nested", input, [2][2]int{{91,92},{93,94}})
	}
	for _, input := range []string{"null", "[]", `["a","b"]`, `["a"]`, `[null,"b"]`, `["a",1]`} {
		row("strings", input, [2]string{"old1", "old2"})
	}
	type namedByte byte
	for _, input := range []string{"null", "[]", "[1,2]", "[1]", "[1,256]", `"AQI="`} {
		row("namedByte", input, [2]namedByte{91,92})
	}
}
