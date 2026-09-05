// Real Go 1.25.5 jsontext raw-value duplicate-name oracle.
// GOEXPERIMENT=jsonv2 go run tools/gen_jsonrawdup_ref.go > examples/jsonrawdup_ref.txt
package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"
)

func main() {
	for _, input := range []string{`{}`, `{"a":1}`, `{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `{"a":{"x":1,"x":2}}`, `[{"x":1},{"x":2}]`, `{"x":[{"a":1,"a":2}]}`, `{"a/b~c":{"x":1,"x":2}}`, `{"a":{"x":1},"b":{"x":2}}`, `{"a":{"x":1},"a":2}`, `{"a":[1,2]}`, `[{"x":1,"x":2}]`, `{"x":"\u0061","y":"a"}`, `{"日本語":1,"日本語":2}`} {
		for _, allow := range []bool{false,true} {
			for _, mode := range []string{"read","skip","array","object"} {
				text := input
				if mode == "array" { text = "["+input+",0]" }
				if mode == "object" { text = `{"a/b~c":`+input+`,"next":0}` }
				dec := jsontext.NewDecoder(strings.NewReader(text), jsontext.AllowDuplicateNames(allow))
				if mode == "array" || mode == "object" { dec.ReadToken() }
				if mode == "object" { dec.ReadToken() }
				var err error
				if mode == "skip" { err = dec.SkipValue() } else { _, err = dec.ReadValue() }
				errText := ""
				if err != nil { errText = err.Error() }
				encodedError, _ := json.Marshal(errText)
				fmt.Printf("%s|%t|%s|%d|%s\n", mode, allow, input, dec.StackDepth(), encodedError)
			}
		}
	}
}
