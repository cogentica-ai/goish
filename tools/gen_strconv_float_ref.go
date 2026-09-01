package strconv_test

import (
	"fmt"
	"math"
	"strconv"
	"testing"
)

// FormatFloat and ParseFloat sit under fmt, encoding/json and every
// numeric output path. A shortest-round-trip formatter that is one
// digit out still prints a number, and a parser that is one ULP out
// still returns a float — the two only disagree when the value crosses
// a boundary someone cares about.
func TestGoishRef(t *testing.T) {
	vals := []float64{
		0, math.Copysign(0, -1), 1, -1, 0.1, 0.2, 0.3, 1.0 / 3.0,
		1e-5, 1e-4, 1e20, 1e21, 1e22, 1e-300, 1e300,
		math.MaxFloat64, math.SmallestNonzeroFloat64,
		math.Inf(1), math.Inf(-1), math.NaN(),
		3.141592653589793, 2.718281828459045,
		1.7976931348623157e308, 4.9406564584124654e-324,
		123456789, 1234567890123456789, 0.000001, 100000000000000000000,
		1e-323, 5e-324, 2.2250738585072014e-308,
	}
	for _, v := range vals {
		fmt.Printf("f64 %-24v e=%-24q E=%-24q f=%-30q g=%-24q G=%-24q x=%-24q b=%q\n",
			v,
			strconv.FormatFloat(v, 'e', -1, 64), strconv.FormatFloat(v, 'E', -1, 64),
			strconv.FormatFloat(v, 'f', -1, 64), strconv.FormatFloat(v, 'g', -1, 64),
			strconv.FormatFloat(v, 'G', -1, 64), strconv.FormatFloat(v, 'x', -1, 64),
			strconv.FormatFloat(v, 'b', -1, 64))
	}
	for _, v := range vals {
		fmt.Printf("prec %-24v .0f=%-12q .2f=%-14q .17g=%-26q .3e=%q\n",
			v, strconv.FormatFloat(v, 'f', 0, 64), strconv.FormatFloat(v, 'f', 2, 64),
			strconv.FormatFloat(v, 'g', 17, 64), strconv.FormatFloat(v, 'e', 3, 64))
	}
	f32s := []float32{0, 1, 0.1, 1e-5, 1e20, float32(math.MaxFloat32),
		float32(math.SmallestNonzeroFloat32), 3.1415927}
	for _, v := range f32s {
		fmt.Printf("f32 %-16v g=%-16q e=%-16q f=%q\n",
			v, strconv.FormatFloat(float64(v), 'g', -1, 32),
			strconv.FormatFloat(float64(v), 'e', -1, 32),
			strconv.FormatFloat(float64(v), 'f', -1, 32))
	}

	inputs := []string{
		"0", "-0", "1", "-1", "0.1", ".1", "1.", "+1", "1e3", "1E3", "1e+3",
		"1e-3", "1_000", "0x1p-2", "0x1.fp4", "0X1P0", "inf", "Inf", "+Inf",
		"-inf", "infinity", "nan", "NaN", "-nan", "", " 1", "1 ", "abc",
		"1e", "e3", "1e999", "-1e999", "1e-999", "0.0000000000000000000001",
		"340282356779733661637539395458142568448", "1e310", "1e-310",
		"4.9406564584124654e-324", "2.2250738585072011e-308",
		"1.7976931348623159e308", "9007199254740993", "0b101", "0o17",
	}
	for _, in := range inputs {
		v, err := strconv.ParseFloat(in, 64)
		v32, err32 := strconv.ParseFloat(in, 32)
		fmt.Printf("parse %-42q 64=(%v,%v) 32=(%v,%v)\n", in, v, err, v32, err32)
	}

	// Round-trip: every shortest form must parse back to the same bits.
	bad := 0
	for _, v := range vals {
		s := strconv.FormatFloat(v, 'g', -1, 64)
		back, err := strconv.ParseFloat(s, 64)
		if err != nil || (math.Float64bits(back) != math.Float64bits(v) && !math.IsNaN(v)) {
			bad++
			fmt.Printf("roundtrip FAIL %v -> %q -> %v\n", v, s, back)
		}
	}
	fmt.Printf("roundtrip bad=%d of %d\n", bad, len(vals))
}
