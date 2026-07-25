// gen_jsonint_ref — reference generator for examples/jsonint_ref.txt.
//
// Runs a corpus of JSON numbers (and non-numbers) through the REAL
// encoding/json/v2 into every integer width, printing the resulting
// value and whether it errored — and, when it did, WHICH of Go's two
// reasons applied. examples/json_int_diff.rs replays the same corpus.
//
// The message TEXT is not compared: Go names its own types ("int32")
// and goish cannot tell its `int` alias from `i64`, so the port names
// the Rust primitive. What is compared is the behaviour: accepted vs
// rejected, the reason, and the resulting value.
//
// Regenerate:  GOEXPERIMENT=jsonv2 go run tools/gen_jsonint_ref.go > examples/jsonint_ref.txt
package main

import (
	"encoding/json/v2"
	"fmt"
	"strings"
)

var corpus = []string{
	`0`, `1`, `-1`, `42`, `-42`,
	// Integer-VALUED but not integer-SPELLED: Go rejects all of these.
	`1.0`, `-1.0`, `1e2`, `1E2`, `1e+2`, `0.0`, `-0.0`,
	// Genuinely fractional.
	`1.5`, `-2.5`, `0.1`,
	// Width boundaries, so "value out of range" is hit per type.
	`127`, `128`, `-128`, `-129`,
	`255`, `256`,
	`32767`, `32768`, `-32768`, `-32769`,
	`65535`, `65536`,
	`2147483647`, `2147483648`, `-2147483648`, `-2147483649`,
	`4294967295`, `4294967296`,
	`9223372036854775807`, `9223372036854775808`,
	`-9223372036854775808`, `-9223372036854775809`,
	`1e30`,
	// Negative into unsigned.
	`-1`,
	// Leading zero is not valid JSON at all.
	`-0`,
	// Non-numbers.
	`null`, `true`, `false`, `"7"`, `[]`, `{}`,
}

func reason(err error) string {
	if err == nil {
		return "-"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "value out of range"):
		return "range"
	case strings.Contains(s, "invalid syntax"):
		return "syntax"
	default:
		return "type"
	}
}

func main() {
	for i, doc := range corpus {
		var i8v int8
		var i16v int16
		var i32v int32
		var i64v int64
		var u8v uint8
		var u16v uint16
		var u32v uint32

		e1 := json.Unmarshal([]byte(doc), &i8v)
		e2 := json.Unmarshal([]byte(doc), &i16v)
		e3 := json.Unmarshal([]byte(doc), &i32v)
		e4 := json.Unmarshal([]byte(doc), &i64v)
		e5 := json.Unmarshal([]byte(doc), &u8v)
		e6 := json.Unmarshal([]byte(doc), &u16v)
		e7 := json.Unmarshal([]byte(doc), &u32v)

		fmt.Printf("N %d %s i8=%d/%s i16=%d/%s i32=%d/%s i64=%d/%s u8=%d/%s u16=%d/%s u32=%d/%s\n",
			i, doc,
			i8v, reason(e1), i16v, reason(e2), i32v, reason(e3), i64v, reason(e4),
			u8v, reason(e5), u16v, reason(e6), u32v, reason(e7))
	}
}
