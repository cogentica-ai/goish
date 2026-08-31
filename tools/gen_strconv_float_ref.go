package strconv_test

import (
	"fmt"
	"math"
	"strconv"
	"testing"
)

// atof.go and ftoa.go are the two halves of one contract: whatever
// FormatFloat writes with prec -1, ParseFloat must read back to the
// same 64 bits. goish carries the slow multiprecision path only (no
// Eisel-Lemire on the way in, no Ryu on the way out), which is supposed
// to be exactly as correct and merely slower - so every vector below is
// a place where "supposed to be" gets checked.
//
// Values are chosen where the two paths can disagree: the subnormal
// boundary, the largest and smallest normals, powers of ten near the
// exact-float64 cutoff, halfway cases that decide a rounding direction,
// and the hex forms that skip the decimal machinery entirely.
func TestGoishRef(t *testing.T) {
	bits := []uint64{
		0x0000000000000000, 0x8000000000000000,
		0x0000000000000001, 0x000fffffffffffff,
		0x0010000000000000, 0x7fefffffffffffff,
		0x3ff0000000000000, 0x3fe0000000000000,
		0x4024000000000000, 0x400921fb54442d18,
		0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000001,
		0x3fd5555555555555, 0x43abc16d674ec800,
	}
	for _, b := range bits {
		f := math.Float64frombits(b)
		for _, verb := range []byte{'b', 'e', 'E', 'f', 'g', 'G', 'x', 'X'} {
			for _, prec := range []int{-1, 0, 1, 5, 17} {
				fmt.Printf("f64 %016x %c %3d %q\n", b, verb, prec,
					strconv.FormatFloat(f, verb, prec, 64))
			}
		}
	}

	bits32 := []uint32{
		0x00000000, 0x80000000, 0x00000001, 0x007fffff,
		0x00800000, 0x7f7fffff, 0x3f800000, 0x40490fdb,
		0x7f800000, 0xff800000, 0x7fc00001,
	}
	for _, b := range bits32 {
		f := float64(math.Float32frombits(b))
		for _, verb := range []byte{'b', 'e', 'f', 'g', 'x'} {
			for _, prec := range []int{-1, 0, 3, 9} {
				fmt.Printf("f32 %08x %c %3d %q\n", b, verb, prec,
					strconv.FormatFloat(f, verb, prec, 32))
			}
		}
	}

	// ParseFloat: what comes back, as raw bits, plus the error.
	inputs := []string{
		"0", "-0", "1", "-1", "1.5", "3.14159265358979",
		"1e308", "1e309", "1e-308", "1e-323", "5e-324", "1e-324",
		"1.7976931348623157e308", "1.7976931348623159e308",
		"2.2250738585072011e-308", "4.9406564584124654e-324",
		"9007199254740993", "18446744073709551616",
		"1e", "e1", "", ".", "+", "-", "1.2.3", "0x", "1e1000x",
		"Inf", "-inf", "+INF", "infinity", "NaN", "nan", "NAN",
		"0x1p0", "0x1.8p1", "-0x1.fffffffffffffp1023", "0x1p-1074",
		"0x1p1024", "0x.1p4", "0x1p", "0x1.8", "0X1P-2",
		"1_000.5", "1_0e2", "_1", "1_", "1__0", "0b101", "0o17",
		"   1", "1   ", "1.0e+10", "1.0E-10", "00001", "0.0000",
	}
	for _, in := range inputs {
		f, err := strconv.ParseFloat(in, 64)
		f32, err32 := strconv.ParseFloat(in, 32)
		fmt.Printf("parse %-26q b64=%016x err=%q b32=%08x err32=%q\n",
			in, math.Float64bits(f), errstr(err),
			math.Float32bits(float32(f32)), errstr(err32))
	}

	// The round trip, over every shortest form above.
	for _, b := range bits {
		f := math.Float64frombits(b)
		s := strconv.FormatFloat(f, 'g', -1, 64)
		back, err := strconv.ParseFloat(s, 64)
		fmt.Printf("rt %016x %-24q back=%016x same=%v err=%v\n",
			b, s, math.Float64bits(back), math.Float64bits(back) == b, err)
	}
}

func errstr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
