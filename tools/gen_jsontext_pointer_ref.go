// gen_jsontext_pointer_ref — `Decoder.StackPointer()` through a
// document, token by token.
//
//	GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/jsontext tools/gen_jsontext_pointer_ref.go
//
// goish builds this pointer privately already (for duplicate-name
// errors) but does not expose it, so a struct adapter cannot say WHERE
// a field failed — issue #10, whose every other requirement sits on
// top of this one.
//
// The question a port has to get right is not the happy path but WHEN
// the pointer advances. After reading an object's member NAME, is the
// pointer already `/name`, or still the parent? After `]`, has the
// array frame popped? The transcript answers both by printing the
// pointer after every single token.
//
// RFC 6901 escaping (`~` -> `~0`, `/` -> `~1`) is included because a
// member name containing `/` would otherwise fake a path separator and
// point at a field that does not exist.
package jsontext_test

import (
	"encoding/json/jsontext"
	"fmt"
	"io"
	"strings"
	"testing"
)

func walk(label, doc string) {
	dec := jsontext.NewDecoder(strings.NewReader(doc))
	fmt.Printf("%-10s %s\n", label, doc)
	fmt.Printf("           start      ptr=%q depth=%d\n", dec.StackPointer(), dec.StackDepth())
	for {
		tok, err := dec.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("           err        %v\n", err)
			break
		}
		fmt.Printf("           %-10s ptr=%q depth=%d\n",
			tok.String(), dec.StackPointer(), dec.StackDepth())
	}
}

func TestGoishRef(t *testing.T) {
	walk("flat", `{"a":1,"b":2}`)
	walk("nested", `{"a":{"b":[10,20]}}`)
	walk("array", `[1,[2,3]]`)
	walk("escape", `{"a/b":1,"c~d":2}`)
	walk("root", `5`)
	walk("emptyobj", `{}`)
}
