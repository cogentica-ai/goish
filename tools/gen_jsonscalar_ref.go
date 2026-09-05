// GOEXPERIMENT=jsonv2 go run tools/gen_jsonscalar_ref.go > examples/jsonscalar_ref.txt
package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"math"
	"strings"
)

func quote(v any) string {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return string(b)
}
func main() {
	for _, input := range []string{"", "null", "nul", `"x"`, `"\u0041\/"`, `"unfinished`, "true", "1", "[]", "[1]", "[1,", "[1,]", "{}", `{"x":1}`, `{"x":1,"x":2}`, `{"x":`, `"x" 0`} {
		value := "old"
		d := jsontext.NewDecoder(strings.NewReader(input))
		e := json.UnmarshalDecode(d, &value)
		fmt.Printf("S|%s|%t|%s|%d\n", input, e == nil, quote(value), d.StackDepth())
	}
	for _, bits := range []uint64{0, 0x8000000000000000, 0x3ff0000000000000, 0x7fefffffffffffff, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000000} {
		f := math.Float64frombits(bits)
		for _, mode := range []string{"value", "array", "map"} {
			var v any = f
			if mode == "array" {
				v = []float64{1, f}
			}
			if mode == "map" {
				v = map[string]float64{"a": 1, "b": f}
			}
			b, e := json.Marshal(v, json.Deterministic(true))
			fmt.Printf("F|%016x|%s|%t|%s\n", bits, mode, e == nil, quote(string(b)))
		}
	}
	for _, seed := range []string{"none", "dup0", "dup1", "utf0", "utf1", "det0", "det1", "indent", "prefix", "dec-none", "dec-dup0", "dec-dup1"} {
		var opts json.Options
		switch seed {
		case "dup0":
			opts = jsontext.AllowDuplicateNames(false)
		case "dup1":
			opts = jsontext.AllowDuplicateNames(true)
		case "utf0":
			opts = jsontext.AllowInvalidUTF8(false)
		case "utf1":
			opts = jsontext.AllowInvalidUTF8(true)
		case "det0":
			opts = json.Deterministic(false)
		case "det1":
			opts = json.Deterministic(true)
		case "indent":
			opts = jsontext.WithIndent("  ")
		case "prefix":
			opts = jsontext.WithIndentPrefix(" ")
		case "dec-none":
			opts = jsontext.NewDecoder(strings.NewReader("")).Options()
		case "dec-dup0":
			opts = jsontext.NewDecoder(strings.NewReader(""), jsontext.AllowDuplicateNames(false)).Options()
		case "dec-dup1":
			opts = jsontext.NewDecoder(strings.NewReader(""), jsontext.AllowDuplicateNames(true)).Options()
		}
		for _, kind := range []string{"dup", "utf", "det", "indent", "prefix"} {
			calls := 0
			zero := true
			var result any
			var present bool
			switch kind {
			case "dup", "utf", "det":
				result, present = json.GetOption(opts, func(v bool) json.Options {
					calls++
					zero = zero && !v
					if kind == "dup" {
						return jsontext.AllowDuplicateNames(v)
					}
					if kind == "utf" {
						return jsontext.AllowInvalidUTF8(v)
					}
					return json.Deterministic(v)
				})
			default:
				result, present = json.GetOption(opts, func(v string) json.Options {
					calls++
					zero = zero && v == ""
					if kind == "indent" {
						return jsontext.WithIndent(v)
					}
					return jsontext.WithIndentPrefix(v)
				})
			}
			fmt.Printf("O|%s|%s|%s|%t|%d|%t\n", seed, kind, quote(result), present, calls, zero)
		}
	}
}
