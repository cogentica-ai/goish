package math_test

import (
	"fmt"
	"math"
	"testing"
)

// src/math/mod.rs carries ZERO provenance anchors for 61 Go files: every
// one of these matches Go by NAME ONLY. A float function that returns a
// slightly wrong answer, or the wrong thing at an edge, is invisible
// until something downstream is wrong for a reason nobody can trace.
//
// The edges are where ports diverge: NaN, ±Inf, ±0, and the
// documented special cases each of these functions has.
func TestGoishRef(t *testing.T) {
	// %b prints the exact bit pattern's value, so a one-ulp difference
	// shows rather than being rounded away by %v.
	p1 := func(name string, f func(float64) float64, xs ...float64) {
		for _, x := range xs {
			fmt.Printf("1 %s %d %d\n", name, math.Float64bits(x), math.Float64bits(f(x)))
		}
	}
	p2 := func(name string, f func(float64, float64) float64, xs ...[2]float64) {
		for _, x := range xs {
			fmt.Printf("2 %s %d %d %d\n", name, math.Float64bits(x[0]), math.Float64bits(x[1]), math.Float64bits(f(x[0], x[1])))
		}
	}

	inf, ninf, nan := math.Inf(1), math.Inf(-1), math.NaN()
	zero, nzero := 0.0, math.Copysign(0, -1)

	p1("Sqrt", math.Sqrt, 0, 1, 2, 4, 1e300, 1e-300, -1, nan, inf, nzero)
	p1("Floor", math.Floor, 1.5, -1.5, 0.5, -0.5, 2, -2, nan, inf, ninf, nzero)
	p1("Ceil", math.Ceil, 1.5, -1.5, 0.5, -0.5, 2, -2, nan, inf, ninf, nzero)
	p1("Trunc", math.Trunc, 1.9, -1.9, 0.5, -0.5, nan, inf, nzero)
	p1("Round", math.Round, 0.5, -0.5, 1.5, -1.5, 2.5, -2.5, 0.49999999999999994, nan, inf)
	p1("Abs", math.Abs, -1, 1, nzero, nan, ninf)
	p1("Exp", math.Exp, 0, 1, -1, 709, 710, -746, nan, inf, ninf)
	p1("Exp2", math.Exp2, 0, 1, 10, -1, nan, inf)
	p1("Log", math.Log, 1, math.E, 0, -1, 1e300, nan, inf)
	p1("Log2", math.Log2, 1, 2, 8, 0.5, 0, -1, nan)
	p1("Log10", math.Log10, 1, 10, 100, 0.1, 0, -1, nan)
	p1("Log1p", math.Log1p, 0, 1, -1, -2, 1e-20, nan)
	p1("Sin", math.Sin, 0, math.Pi/2, math.Pi, 1, -1, nan, inf, nzero)
	p1("Cos", math.Cos, 0, math.Pi/2, math.Pi, 1, nan, inf)
	p1("Tan", math.Tan, 0, math.Pi/4, 1, nan, inf, nzero)
	p1("Asin", math.Asin, 0, 1, -1, 0.5, 2, nan, nzero)
	p1("Acos", math.Acos, 0, 1, -1, 0.5, 2, nan)
	p1("Atan", math.Atan, 0, 1, -1, inf, ninf, nan, nzero)
	p1("Sinh", math.Sinh, 0, 1, -1, 710, nan, inf, nzero)
	p1("Cosh", math.Cosh, 0, 1, -1, 710, nan, inf)
	p1("Tanh", math.Tanh, 0, 1, -1, 30, nan, inf, nzero)
	p1("Asinh", math.Asinh, 0, 1, -1, nan, inf, nzero)
	p1("Acosh", math.Acosh, 1, 2, 0.5, nan, inf)
	p1("Atanh", math.Atanh, 0, 0.5, 1, -1, 2, nan, nzero)

	p2("Pow", math.Pow, [2]float64{2, 10}, [2]float64{2, 0.5}, [2]float64{0, 0},
		[2]float64{-1, 0.5}, [2]float64{1, nan}, [2]float64{nan, 0},
		[2]float64{-1, inf}, [2]float64{2, -1}, [2]float64{nzero, -1},
		[2]float64{nzero, 3}, [2]float64{inf, 0})
	p2("Mod", math.Mod, [2]float64{5, 3}, [2]float64{-5, 3}, [2]float64{5, -3},
		[2]float64{5, 0}, [2]float64{inf, 3}, [2]float64{5, inf}, [2]float64{nan, 1})
	p2("Remainder", math.Remainder, [2]float64{5, 3}, [2]float64{-5, 3},
		[2]float64{5, 0}, [2]float64{inf, 3}, [2]float64{5, inf})
	p2("Atan2", math.Atan2, [2]float64{1, 1}, [2]float64{-1, 1}, [2]float64{1, -1},
		[2]float64{-1, -1}, [2]float64{0, 0}, [2]float64{nzero, nzero},
		[2]float64{0, -1}, [2]float64{inf, inf}, [2]float64{nan, 1})
	p2("Hypot", math.Hypot, [2]float64{3, 4}, [2]float64{0, 0}, [2]float64{inf, nan},
		[2]float64{nan, 1}, [2]float64{1e300, 1e300})
	p2("Dim", math.Dim, [2]float64{5, 3}, [2]float64{3, 5}, [2]float64{inf, inf},
		[2]float64{nan, 1})
	p2("Max", math.Max, [2]float64{1, 2}, [2]float64{nan, 1}, [2]float64{inf, 1},
		[2]float64{zero, nzero}, [2]float64{nzero, zero})
	p2("Min", math.Min, [2]float64{1, 2}, [2]float64{nan, 1}, [2]float64{ninf, 1},
		[2]float64{zero, nzero}, [2]float64{nzero, zero})
	p2("Copysign", math.Copysign, [2]float64{3, -1}, [2]float64{-3, 1},
		[2]float64{nan, -1}, [2]float64{inf, -1})

	// Frexp / Ldexp / Modf return pairs.
	for _, x := range []float64{1, 8, 0.5, 0, nzero, nan, inf, 1e-310} {
		fr, ex := math.Frexp(x)
		fmt.Printf("frexp %d %d %d\n", math.Float64bits(x), math.Float64bits(fr), ex)
	}
	for _, c := range [][2]float64{{1, 0}, {1, 10}, {1, -10}, {0, 5}, {math.NaN(), 3}} {
		fmt.Printf("ldexp %d %d %d\n", math.Float64bits(c[0]), int(c[1]), math.Float64bits(math.Ldexp(c[0], int(c[1]))))
	}
	for _, x := range []float64{1.5, -1.5, 0, nzero, nan, inf} {
		i, fr := math.Modf(x)
		fmt.Printf("modf %d %d %d\n", math.Float64bits(x), math.Float64bits(i), math.Float64bits(fr))
	}
	for _, n := range []int{0, 1, 5, 22, 23, 100, -1, 309, 310} {
		fmt.Printf("pow10 %d %d\n", n, math.Float64bits(math.Pow10(n)))
	}
	// Predicates and bit conversions.
	for _, x := range []float64{1, nan, inf, ninf, zero, nzero} {
		fmt.Printf("pred %d %v %v %v %v\n", math.Float64bits(x),
			math.IsNaN(x), math.IsInf(x, 1), math.IsInf(x, -1), math.Signbit(x))
	}
	for _, x := range []float32{1, 0.5, float32(math.Inf(1))} {
		fmt.Printf("f32 %d %d\n", math.Float32bits(x), math.Float32bits(math.Float32frombits(math.Float32bits(x))))
	}
}
