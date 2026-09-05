// Real Go 1.25.5 jsontext delimiter oracle, including repeated PeekKind.
// GOEXPERIMENT=jsonv2 go run tools/gen_jsonseparator_ref.go > examples/jsonseparator_ref.txt
package main

import (
	"encoding/json/jsontext"
	"fmt"
	"io"
	"strings"
)

func main() {
	for _, input := range []string{"[]", "[1]", "[1,2]", "[1,]", "[1, ]", "[1,", "[1, ", "[1,,2]", "[1 2]", "{}", `{"a":1}`, `{"a":1,}`, `{"a":1, }`, `{"a":1,`, `{"a":1,,"b":2}`, `{"a":1 "b":2}`, `[[1,]]`, `[{"a":1,}]`, `{"a":[1,]}`, "[1,2] 3"} {
		for peeks := 0; peeks <= 2; peeks++ {
			dec := jsontext.NewDecoder(strings.NewReader(input))
			var result strings.Builder
			for {
				for i := 0; i < peeks; i++ { dec.PeekKind() }
				token, err := dec.ReadToken()
				if err == io.EOF { result.WriteString(" EOF"); break }
				if err != nil { result.WriteString(" ERROR"); break }
				result.WriteByte(byte(token.Kind()))
			}
			fmt.Printf("%d|%s|%s\n", peeks, input, result.String())
		}
	}
}
