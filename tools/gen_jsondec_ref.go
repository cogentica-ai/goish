package json_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

// The encoder half of encoding/json was measured in 21b47cf and
// 4e25a97. This is the DECODER, which is the half that reads bytes
// somebody else wrote. Its refusals are the interesting part, because
// Go does not merely say "invalid": every syntax error names the
// offending character AND what the parser was looking for when it met
// it. A caller logging "invalid character '}' looking for beginning of
// object key string" can find the problem in a megabyte of input; a
// caller told "parse error" cannot.
//
// The rules that are easy to get wrong while every valid document
// still decodes:
//
//   * Valid() and Unmarshal must agree, and Go's answer is stricter
//     than most hand-written parsers: trailing commas, single quotes,
//     unquoted keys, NaN, Infinity, +1, 01, .1 and 1. are all refused.
//   * A truncated document is "unexpected end of JSON input", which is
//     a different error from meeting a wrong character.
//   * A lone surrogate in a \u escape is replaced with U+FFFD, not
//     refused — decoding is lenient exactly there, and the encoder half
//     had to be taught the same thing in ad06f55.
//   * A null into any target is a NO-OP that leaves the target alone,
//     which is not the same as writing a zero value.
//   * Duplicate keys: the LAST one wins, silently.
//   * Decoding into a slice REPLACES it, so a longer existing slice is
//     truncated rather than partly overwritten.
//
// The sections that depend on Go's struct tags and reflection
// (UnmarshalTypeError's field names, case-insensitive field matching,
// json.Number) are deliberately absent: goish's Unmarshal is generic
// over a FromValue trait rather than reflective, so comparing them
// line-for-line would be comparing two different APIs rather than two
// answers to one question.
func TestGoishRef(t *testing.T) {
	// 1. Valid() over the documents a strict parser must refuse.
	for _, s := range []string{
		`{"a":1}`, `[]`, `{}`, `null`, `true`, `1`, `"x"`, `1.5e10`,
		``, ` `, `{`, `}`, `[1,]`, `{"a":1,}`, `{'a':1}`, `{a:1}`,
		`[1 2]`, `01`, `+1`, `1.`, `.1`, `NaN`, `Infinity`, `"\x"`,
		`"unterminated`, `[[[[[[[[[[]]]]]]]]]]`, `{"a":}`, `{"a"}`,
		`tru`, `"\u00"`, `"\ud800"`, `1e`, `-`, `[,]`, `[1,2]`,
		`{"a":{"b":[1,{"c":null}]}}`,
	} {
		fmt.Printf("valid %-28q -> %v\n", s, json.Valid([]byte(s)))
	}

	// 2. Unmarshal into `any`, then re-Marshal: the round trip is what
	//    both sides can print identically, and the error text is the
	//    part that matters when it fails.
	for _, s := range []string{
		`{"a":1}`, `[1,2]`, `1`, `"x"`, `null`, `true`, `false`,
		`1.5`, `-0`, `1e3`, `{"a":{"b":[1,2]}}`, `[]`, `{}`,
		``, `{`, `[1,]`, `{"a":1,}`, `{a:1}`, `[1 2]`, `01`, `+1`,
		`{"a":}`, `tru`, `"\ud800"`, `1e`, `{"a":1}x`, `[1] [2]`,
		`"A"`, `"a\/b"`, `"\t"`,
	} {
		var v any
		err := json.Unmarshal([]byte(s), &v)
		if err != nil {
			fmt.Printf("roundtrip %-18q -> err=%q\n", s, err.Error())
			continue
		}
		out, merr := json.Marshal(v)
		fmt.Printf("roundtrip %-18q -> %s merr=%v\n", s, out, errText(merr))
	}

	// 3. Numbers into sized targets.
	for _, s := range []string{`0`, `1`, `-1`, `127`, `-128`,
		`9223372036854775807`, `-9223372036854775808`, `1.0`, `1.5`, `1e2`} {
		var i int
		ierr := json.Unmarshal([]byte(s), &i)
		var f float64
		ferr := json.Unmarshal([]byte(s), &f)
		fmt.Printf("num %-22s -> i=%-21d ierr=%-52v f64=%-12g ferr=%v\n",
			s, i, errText(ierr), f, errText(ferr))
	}

	// 4. null is a no-op on the target.
	{
		v := 42
		err := json.Unmarshal([]byte(`null`), &v)
		fmt.Printf("null-int v=%d err=%v\n", v, errText(err))
		sv := "keep"
		err = json.Unmarshal([]byte(`null`), &sv)
		fmt.Printf("null-string v=%q err=%v\n", sv, errText(err))
	}

	// 5. Duplicate keys: the last one wins.
	{
		var v map[string]int
		err := json.Unmarshal([]byte(`{"a":1,"a":2,"a":3}`), &v)
		fmt.Printf("dup-map a=%d err=%v\n", v["a"], errText(err))
	}

	// 6. Slices and maps: replacement, growth and merging.
	{
		v := []int{9, 9, 9, 9}
		err := json.Unmarshal([]byte(`[1,2]`), &v)
		fmt.Printf("slice-shrink v=%v len=%d err=%v\n", v, len(v), errText(err))
		v2 := []int{9}
		err = json.Unmarshal([]byte(`[1,2,3]`), &v2)
		fmt.Printf("slice-grow v=%v err=%v\n", v2, errText(err))
		v3 := []int{9, 9}
		err = json.Unmarshal([]byte(`[]`), &v3)
		fmt.Printf("slice-empty v=%v len=%d err=%v\n", v3, len(v3), errText(err))
		var nested [][]int
		err = json.Unmarshal([]byte(`[[1],[2,3],[]]`), &nested)
		fmt.Printf("slice-nested v=%v err=%v\n", nested, errText(err))
	}

	// 7. Strings: the escapes a decoder must accept, and the one it
	//    must replace rather than refuse.
	for _, s := range []string{
		`"plain"`, `"a\"b"`, `"a\\b"`, `"a\/b"`, `"a\bb"`, `"a\fb"`,
		`"a\nb"`, `"a\rb"`, `"a\tb"`, `"A"`, `"é"`,
		`"日"`, `"😀"`, `"\ud800"`, `"\udc00"`,
		`"\ud800x"`, `"\uZZZZ"`, `"a` + "\x7f" + `b"`,
	} {
		var v string
		err := json.Unmarshal([]byte(s), &v)
		if err != nil {
			fmt.Printf("str %-20q -> err=%q\n", s, err.Error())
			continue
		}
		fmt.Printf("str %-20q -> %q bytes=%x\n", s, v, []byte(v))
	}
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
