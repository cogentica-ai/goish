// gen_json_marshalerr_ref — partial bytes and the error text when a
// marshaler fails mid-object (issue #13, and #10's encoder half).
//
//	GOEXPERIMENT=jsonv2 scripts/goref.sh encoding/json/v2 tools/gen_json_marshalerr_ref.go
//
// Two separate questions, and the issue is filed about the first:
//
//   1. What bytes come back. Go returns the prefix the encoder already
//      accepted, so a caller can see how far it got. goish already
//      does this.
//   2. What the error SAYS. Go names the Go type and the JSON pointer
//      of the value that failed, the same as on the decode side — and
//      that needs `Encoder.StackPointer`, which goish has not ported.
//
// The pointer rows below walk an encoder token by token for the same
// reason the decoder ones do: the timing is the part a port gets
// wrong.
package json_test

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"testing"
)

var errDeferred = errors.New("deferred params failure")

type Failing struct{}

func (Failing) MarshalJSONTo(enc *jsontext.Encoder) error { return errDeferred }

type Request struct {
	JSONRPC string  `json:"jsonrpc"`
	Method  string  `json:"method"`
	Params  Failing `json:"params"`
}

func TestGoishRef(t *testing.T) {
	// (1) partial bytes + (2) the message.
	out, err := json.Marshal(Request{JSONRPC: "2.0", Method: "test/deferred"})
	fmt.Printf("bytes  %s\n", out)
	fmt.Printf("err    %v\n", err)
	fmt.Printf("is     %v\n", errors.Is(err, errDeferred))

	// Nested one level deeper, to see the pointer grow.
	type Outer struct {
		A Request `json:"a"`
	}
	out, err = json.Marshal(Outer{})
	fmt.Printf("nested_bytes  %s\n", out)
	fmt.Printf("nested_err    %v\n", err)

	// Inside a slice.
	type WithSlice struct {
		S []Failing `json:"s"`
	}
	out, err = json.Marshal(WithSlice{S: []Failing{{}}})
	fmt.Printf("slice_bytes   %s\n", out)
	fmt.Printf("slice_err     %v\n", err)

	// Encoder.StackPointer, token by token.
	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	show := func(what string) {
		fmt.Printf("enc %-10s ptr=%q depth=%d\n", what, enc.StackPointer(), enc.StackDepth())
	}
	show("start")
	enc.WriteToken(jsontext.BeginObject)
	show("{")
	enc.WriteToken(jsontext.String("a"))
	show("a")
	enc.WriteToken(jsontext.Int(1))
	show("1")
	enc.WriteToken(jsontext.String("b"))
	show("b")
	enc.WriteToken(jsontext.BeginArray)
	show("[")
	enc.WriteToken(jsontext.Int(7))
	show("7")
	enc.WriteToken(jsontext.EndArray)
	show("]")
	enc.WriteToken(jsontext.EndObject)
	show("}")
}
