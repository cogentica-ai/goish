package big

import (
	"fmt"
	"testing"
)

// big.Rat is an EXACT rational, which makes its rules different from
// both Int and Float in ways a port tends to smooth over:
//
//   * It is always kept in LOWEST TERMS with a positive denominator, so
//     NewRat(2, 4) and NewRat(-1, -2) are the same value and print the
//     same way. A port that stores what it was handed answers "2/4".
//   * String and RatString are NOT the same function. String always
//     shows a denominator ("2/1"); RatString omits it when the value is
//     an integer ("2"). Callers pick deliberately, and a port that
//     aliases them breaks one of the two.
//   * FloatString(n) rounds to n decimals, HALF AWAY FROM ZERO — not
//     the banker's rounding Float uses, and not truncation.
//   * SetFloat64 is exact: every finite float64 IS a rational, so
//     0.1 becomes 3602879701896397/36028797018963968 and not 1/10.
//     A port that goes via decimal text produces a different number.
//   * Float64 returns an `exact` bool that is false whenever the
//     rational cannot be represented, which is the normal case.
func TestGoishRef(t *testing.T) {
	// 1. Normalisation: lowest terms, positive denominator, and the
	//    two string forms.
	for _, c := range [][2]int64{{0, 1}, {1, 1}, {2, 1}, {1, 2}, {2, 4},
		{-1, 2}, {1, -2}, {-1, -2}, {-2, 4}, {6, 3}, {-6, 3}, {100, 10},
		{7, 7}, {0, 5}, {0, -5}, {3, 9}} {
		r := NewRat(c[0], c[1])
		fmt.Printf("norm %4d/%-4d -> str=%-10s rat=%-8s num=%-6s den=%-6s sign=%-2d isint=%v\n",
			c[0], c[1], r.String(), r.RatString(), r.Num(), r.Denom(),
			r.Sign(), r.IsInt())
	}

	// 2. Arithmetic stays exact and stays reduced.
	for _, c := range []struct {
		op                 string
		an, ad, bn, bd int64
	}{
		{"add", 1, 2, 1, 3}, {"add", 1, 2, 1, 2}, {"add", 1, 3, 2, 3},
		{"sub", 1, 2, 1, 3}, {"sub", 1, 2, 1, 2}, {"mul", 2, 3, 3, 2},
		{"mul", 1, 2, 1, 2}, {"quo", 1, 2, 1, 3}, {"quo", 1, 2, 2, 1},
		{"quo", -1, 2, 1, 3}, {"add", -1, 2, 1, 2}, {"mul", 0, 1, 5, 7},
	} {
		x, y := NewRat(c.an, c.ad), NewRat(c.bn, c.bd)
		z := new(Rat)
		switch c.op {
		case "add":
			z.Add(x, y)
		case "sub":
			z.Sub(x, y)
		case "mul":
			z.Mul(x, y)
		case "quo":
			z.Quo(x, y)
		}
		fmt.Printf("arith %-4s %3d/%-3d %3d/%-3d -> %-12s rat=%s\n",
			c.op, c.an, c.ad, c.bn, c.bd, z.String(), z.RatString())
	}

	// 3. Neg, Abs, Inv and the Inv of zero, which panics.
	for _, c := range [][2]int64{{1, 2}, {-1, 2}, {3, 1}, {-3, 1}} {
		r := NewRat(c[0], c[1])
		fmt.Printf("unary %3d/%-3d -> neg=%-8s abs=%-8s inv=%-8s\n",
			c[0], c[1], new(Rat).Neg(r), new(Rat).Abs(r), new(Rat).Inv(r))
	}
	func() {
		defer func() { fmt.Printf("inv zero -> panic=%v\n", recover()) }()
		new(Rat).Inv(new(Rat))
	}()

	// 4. FloatString rounds half AWAY FROM ZERO at every precision.
	for _, c := range [][2]int64{{1, 3}, {2, 3}, {1, 2}, {-1, 2}, {3, 2},
		{-3, 2}, {1, 8}, {5, 4}, {-5, 4}, {1, 1}, {0, 1}, {22, 7}} {
		r := NewRat(c[0], c[1])
		fmt.Printf("floatstr %4d/%-4d -> p0=%-8s p1=%-9s p2=%-10s p5=%-13s p20=%s\n",
			c[0], c[1], r.FloatString(0), r.FloatString(1), r.FloatString(2),
			r.FloatString(5), r.FloatString(20))
	}

	// 5. FloatPrec: the number of decimals needed for an EXACT decimal
	//    rendering, and whether one exists at all.
	for _, c := range [][2]int64{{0, 1}, {1, 1}, {1, 2}, {1, 3}, {1, 4},
		{1, 5}, {1, 8}, {1, 10}, {1, 6}, {1, 7}, {3, 8}, {1, 1000},
		{1, 1024}, {7, 20}} {
		r := NewRat(c[0], c[1])
		n, exact := r.FloatPrec()
		fmt.Printf("floatprec %4d/%-5d -> n=%-4d exact=%-5v str=%s\n",
			c[0], c[1], n, exact, r.FloatString(n))
	}

	// 6. SetFloat64 is EXACT — a float64 is already a rational.
	for _, f := range []float64{0, 1, -1, 0.5, 0.25, 0.1, 0.2, 1.0 / 3.0,
		3.141592653589793, 1e10, 1e-10, 12345.6789} {
		var r Rat
		if r.SetFloat64(f) == nil {
			fmt.Printf("setf64 %-22g -> not-finite\n", f)
			continue
		}
		g, exact := r.Float64()
		f32, e32 := r.Float32()
		fmt.Printf("setf64 %-22g -> %-46s back=%-22g exact=%-5v f32=%-14g e32=%v\n",
			f, r.RatString(), g, exact, f32, e32)
	}

	// 7. Float64 on rationals that are NOT representable: the exact bool
	//    is the whole answer.
	for _, c := range [][2]int64{{1, 3}, {1, 2}, {2, 1}, {1, 10}, {1, 7}} {
		r := NewRat(c[0], c[1])
		g, exact := r.Float64()
		fmt.Printf("tof64 %3d/%-3d -> %-24g exact=%v\n", c[0], c[1], g, exact)
	}

	// 8. SetString: fractions, decimals, exponents, the bases, and what
	//    is refused.
	for _, s := range []string{
		"0", "1", "-1", "2/4", "-2/4", "2/-4", "1/3", "1.5", "-1.5", ".5",
		"5.", "1e3", "1.5e-3", "1E3", "0x10", "0b101", "0o17", "1_000",
		"0x1p4", "", "x", "1/", "/2", "1/0", "1.2.3", "1/2/3", " 1", "1 ",
		"3/6", "10/5", "1e400", "0.000000000000000000001",
	} {
		r, ok := new(Rat).SetString(s)
		if !ok {
			fmt.Printf("setstring %-24q -> nil,false\n", s)
			continue
		}
		fmt.Printf("setstring %-24q -> %s,true\n", s, r.RatString())
	}

	// 9. SetFrac with a big and a negative denominator, and the zero
	//    denominator that panics.
	{
		a, _ := new(Int).SetString("123456789012345678901234567890", 10)
		b, _ := new(Int).SetString("987654321098765432109876543210", 10)
		fmt.Printf("setfrac big -> %s\n", new(Rat).SetFrac(a, b).RatString())
		fmt.Printf("setfrac negden -> %s\n",
			new(Rat).SetFrac(NewInt(1), NewInt(-2)).String())
		func() {
			defer func() { fmt.Printf("setfrac zeroden -> panic=%v\n", recover()) }()
			new(Rat).SetFrac(NewInt(1), NewInt(0))
		}()
	}

	// 10. Cmp across signs and magnitudes, where a port that compares
	//     numerators alone gets it wrong.
	pairs := [][2][2]int64{
		{{1, 2}, {1, 3}}, {{1, 3}, {1, 2}}, {{1, 2}, {2, 4}},
		{{-1, 2}, {1, 2}}, {{-1, 2}, {-1, 3}}, {{0, 1}, {0, 5}},
		{{1000000, 1}, {1, 1000000}}, {{1, 1000000}, {1000000, 1}},
	}
	for _, p := range pairs {
		x, y := NewRat(p[0][0], p[0][1]), NewRat(p[1][0], p[1][1])
		fmt.Printf("cmp %-10s %-10s -> %d\n", x.RatString(), y.RatString(), x.Cmp(y))
	}

	// 11. Text round trips through MarshalText.
	for _, c := range [][2]int64{{0, 1}, {1, 2}, {-3, 4}, {5, 1}} {
		r := NewRat(c[0], c[1])
		b, err := r.MarshalText()
		var back Rat
		uerr := back.UnmarshalText(b)
		fmt.Printf("text %4d/%-3d -> %q err=%v back=%s uerr=%v\n",
			c[0], c[1], b, err, back.RatString(), uerr)
	}
}
