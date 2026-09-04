package big

import (
	"fmt"
	"testing"
)

// big.Float is not a wider float64: it is a mantissa of ARBITRARY,
// CALLER-CHOSEN precision, and every operation reports how it had to
// round through an Accuracy. Four rules carry that, and a port that
// treats Float as "f64 with extra digits" gets all four wrong while
// still printing plausible numbers:
//
//   * The precision of a result comes from the RECEIVER, not the
//     operands. z.Add(x, y) with z.Prec() == 0 adopts the larger of the
//     two operand precisions; with z.Prec() set, it rounds to that.
//   * Accuracy is Below / Exact / Above relative to the true value, and
//     it is set by every operation. Exact is the interesting one: it
//     says the result needed no rounding at all.
//   * Rounding mode is a property of the receiver too, and ToZero /
//     AwayFromZero / ToNegativeInf / ToPositiveInf differ from
//     ToNearestEven in the last bit — which is the whole point.
//   * SetPrec on an existing value ROUNDS it, and reports the accuracy
//     of that rounding. Lowering precision is lossy and says so.
func TestGoishRef(t *testing.T) {
	modes := []RoundingMode{ToNearestEven, ToNearestAway, ToZero, AwayFromZero,
		ToNegativeInf, ToPositiveInf}

	// 1. The zero value, and what SetPrec/SetMode/SetInf report.
	{
		var z Float
		fmt.Printf("zero prec=%d mode=%v acc=%v sign=%d signbit=%v inf=%v s=%q\n",
			z.Prec(), z.Mode(), z.Acc(), z.Sign(), z.Signbit(), z.IsInf(), z.String())
		var p Float
		p.SetInf(false)
		var m Float
		m.SetInf(true)
		fmt.Printf("inf +=%q -=%q +sign=%d -sign=%d +isinf=%v -signbit=%v\n",
			p.String(), m.String(), p.Sign(), m.Sign(), p.IsInf(), m.Signbit())
	}

	// 2. SetFloat64 / Float64 round trip, and the accuracy at each prec.
	for _, f := range []float64{0, 1, -1, 0.5, 0.1, 1.0 / 3.0, 1e300, -1e-300,
		3.141592653589793, 12345.6789} {
		for _, prec := range []uint{0, 1, 2, 8, 24, 53, 100} {
			var z Float
			z.SetPrec(prec)
			z.SetFloat64(f)
			g, acc := z.Float64()
			fmt.Printf("setf64 %-22g prec=%-4d -> %-28s acc=%-5v back=%-22g backacc=%v\n",
				f, prec, z.Text('g', 20), z.Acc(), g, acc)
		}
	}

	// 3. Rounding mode changes the last bit. 1/3 at 10 bits, every mode,
	//    both signs.
	for _, mode := range modes {
		for _, sign := range []int64{1, -1} {
			var z Float
			z.SetPrec(10).SetMode(mode)
			z.Quo(NewFloat(float64(sign)), NewFloat(3))
			fmt.Printf("mode %-14v sign=%-2d -> %-24s acc=%v\n",
				mode, sign, z.Text('g', 12), z.Acc())
		}
	}
	// The classic tie: 0.5 ulp exactly, where the modes disagree.
	for _, mode := range modes {
		var z Float
		z.SetPrec(2).SetMode(mode)
		z.SetFloat64(3) // 11b needs 2 bits; 5 needs 3
		var w Float
		w.SetPrec(2).SetMode(mode)
		w.SetFloat64(5)
		var v Float
		v.SetPrec(2).SetMode(mode)
		v.SetFloat64(-5)
		fmt.Printf("tie %-14v 3->%-6s acc=%-5v 5->%-6s acc=%-5v -5->%-6s acc=%v\n",
			mode, z.Text('g', 8), z.Acc(), w.Text('g', 8), w.Acc(),
			v.Text('g', 8), v.Acc())
	}

	// 4. Precision comes from the receiver, not the operands.
	{
		x := new(Float).SetPrec(53).SetFloat64(1)
		y := new(Float).SetPrec(200).SetFloat64(3)
		var z0 Float // prec 0 -> adopts max(53, 200)
		z0.Quo(x, y)
		z10 := new(Float).SetPrec(10)
		z10.Quo(x, y)
		fmt.Printf("recvprec z0.prec=%d z10.prec=%d z0=%s z10=%s\n",
			z0.Prec(), z10.Prec(), z0.Text('g', 15), z10.Text('g', 15))
	}

	// 5. Arithmetic, with the accuracy each op reports.
	for _, c := range []struct {
		op   string
		a, b float64
		prec uint
	}{
		{"add", 1, 2, 53}, {"add", 0.1, 0.2, 53}, {"add", 1, 1e-30, 53},
		{"add", 1, 1e-30, 200}, {"sub", 1, 1, 53}, {"sub", 1, 3, 10},
		{"mul", 3, 7, 53}, {"mul", 0.1, 0.1, 10}, {"quo", 1, 3, 53},
		{"quo", 1, 3, 4}, {"quo", 10, 4, 53}, {"quo", 1, 0, 53},
		{"quo", -1, 0, 53},
	} {
		x, y := NewFloat(c.a), NewFloat(c.b)
		z := new(Float).SetPrec(c.prec)
		var panicked string
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = fmt.Sprint(r)
				}
			}()
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
		}()
		if panicked != "" {
			fmt.Printf("arith %-4s %-8g %-8g prec=%-4d -> panic=%q\n",
				c.op, c.a, c.b, c.prec, panicked)
			continue
		}
		fmt.Printf("arith %-4s %-8g %-8g prec=%-4d -> %-26s acc=%v\n",
			c.op, c.a, c.b, c.prec, z.Text('g', 18), z.Acc())
	}

	// 6. Sqrt, including the values that must panic.
	for _, c := range []struct {
		v    float64
		prec uint
	}{{4, 53}, {2, 53}, {2, 10}, {0, 53}, {1e300, 53}} {
		z := new(Float).SetPrec(c.prec)
		var panicked string
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = fmt.Sprint(r)
				}
			}()
			z.Sqrt(NewFloat(c.v))
		}()
		if panicked != "" {
			fmt.Printf("sqrt %-10g prec=%-4d -> panic=%q\n", c.v, c.prec, panicked)
			continue
		}
		fmt.Printf("sqrt %-10g prec=%-4d -> %-26s acc=%v\n",
			c.v, c.prec, z.Text('g', 18), z.Acc())
	}

	// 7. Text across every format verb and precision, where a port that
	//    routes through strconv on a float64 loses digits.
	third := new(Float).SetPrec(200).Quo(NewFloat(1), NewFloat(3))
	big1 := new(Float).SetPrec(200).SetFloat64(1e20)
	for _, format := range []byte{'e', 'E', 'f', 'g', 'G', 'x', 'p', 'b'} {
		for _, prec := range []int{-1, 0, 3, 10, 30} {
			fmt.Printf("text %c prec=%-4d third=%-46s big=%s\n",
				format, prec, third.Text(format, prec), big1.Text(format, prec))
		}
	}
	fmt.Printf("string third=%s\n", third.String())
	fmt.Printf("string big=%s\n", big1.String())

	// 8. Parse / SetString, including the bases and the refusals.
	for _, c := range []struct {
		s    string
		base int
	}{
		{"0", 10}, {"1", 10}, {"-1.5", 10}, {"+1.5", 10}, {"1e10", 10},
		{"1E10", 10}, {"1.5e-3", 10}, {".5", 10}, {"5.", 10}, {"", 10},
		{"x", 10}, {"1.2.3", 10}, {"0x1p4", 0}, {"0x1.8p1", 0},
		{"0b101", 0}, {"0o17", 0}, {"1_000", 0}, {"Inf", 10}, {"+Inf", 10},
		{"-Inf", 10}, {"inf", 10}, {"NaN", 10}, {"1p10", 2},
	} {
		z, base, err := new(Float).SetPrec(53).Parse(c.s, c.base)
		if err != nil {
			fmt.Printf("parse %-10q base=%-3d -> err=%q\n", c.s, c.base, err.Error())
			continue
		}
		fmt.Printf("parse %-10q base=%-3d -> %-24s base=%d acc=%v\n",
			c.s, c.base, z.Text('g', 18), base, z.Acc())
	}

	// 9. MantExp / SetMantExp — the decomposition Go guarantees is
	//    exact, with the mantissa in [0.5, 1).
	for _, f := range []float64{0, 1, -1, 0.5, 1024, 1e300, 0.1} {
		x := new(Float).SetPrec(53).SetFloat64(f)
		var mant Float
		exp := x.MantExp(&mant)
		var back Float
		back.SetPrec(53).SetMantExp(&mant, exp)
		fmt.Printf("mantexp %-10g -> mant=%-24s exp=%-6d back=%s\n",
			f, mant.Text('g', 18), exp, back.Text('g', 18))
	}

	// 10. Int / Rat / IsInt conversions and their accuracies.
	for _, c := range []struct {
		s    string
		prec uint
	}{{"0", 53}, {"1", 53}, {"-1", 53}, {"1.5", 53}, {"-1.5", 53},
		{"2.5", 53}, {"1e20", 53}, {"1e30", 53}, {"0.0001", 53}} {
		x, _, _ := new(Float).SetPrec(c.prec).Parse(c.s, 10)
		i, iacc := x.Int(nil)
		r, racc := x.Rat(nil)
		var rs string
		if r != nil {
			rs = r.RatString()
		} else {
			rs = "<nil>"
		}
		fmt.Printf("conv %-8s -> isint=%-5v int=%-22s iacc=%-5v rat=%-24s racc=%v\n",
			c.s, x.IsInt(), i.String(), iacc, rs, racc)
	}

	// 11. Int64 / Uint64 at and past the boundaries, with the accuracy
	//     that says the value was clamped.
	for _, s := range []string{"0", "1", "-1", "1.5", "-1.5",
		"9223372036854775807", "9223372036854775808", "-9223372036854775808",
		"-9223372036854775809", "18446744073709551615", "18446744073709551616",
		"1e40", "-1e40"} {
		x, _, _ := new(Float).SetPrec(200).Parse(s, 10)
		i, iacc := x.Int64()
		u, uacc := x.Uint64()
		f32, f32acc := x.Float32()
		fmt.Printf("bound %-21s -> i64=%-21d iacc=%-5v u64=%-21d uacc=%-5v f32=%-14g f32acc=%v\n",
			s, i, iacc, u, uacc, f32, f32acc)
	}

	// 12. SetPrec on an existing value rounds it and says so.
	{
		x := new(Float).SetPrec(200).Quo(NewFloat(1), NewFloat(3))
		for _, p := range []uint{200, 100, 53, 10, 2, 1, 0} {
			y := new(Float).Set(x)
			y.SetPrec(p)
			fmt.Printf("setprec %-4d -> %-24s acc=%v prec=%d\n",
				p, y.Text('g', 18), y.Acc(), y.Prec())
		}
	}

	// 13. Cmp, Sign and MinPrec over a spread including the infinities.
	vals := []string{"-Inf", "-1", "-0", "0", "1", "Inf"}
	for _, a := range vals {
		x, _, _ := new(Float).SetPrec(53).Parse(a, 10)
		fmt.Printf("props %-5s sign=%-2d signbit=%-5v isinf=%-5v isint=%-5v minprec=%d\n",
			a, x.Sign(), x.Signbit(), x.IsInf(), x.IsInt(), x.MinPrec())
		for _, b := range vals {
			y, _, _ := new(Float).SetPrec(53).Parse(b, 10)
			fmt.Printf("fcmp %-5s %-5s -> %d\n", a, b, x.Cmp(y))
		}
	}
}
