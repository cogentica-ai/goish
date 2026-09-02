package math_test

import (
	"fmt"
	"math"
	"testing"
)

// The math functions goish does not have. Bit patterns again, so a
// one-ulp difference shows.
func TestGoishRef(t *testing.T) {
	inf, ninf, nan := math.Inf(1), math.Inf(-1), math.NaN()
	nzero := math.Copysign(0, -1)

	p1 := func(name string, f func(float64) float64, xs ...float64) {
		for _, x := range xs {
			fmt.Printf("1 %s %d %d\n", name, math.Float64bits(x), math.Float64bits(f(x)))
		}
	}
	common := []float64{0, 1, -1, 0.5, 2, 8, -8, 1e-10, 1e10, nan, inf, ninf, nzero}

	p1("Cbrt", math.Cbrt, common...)
	p1("Expm1", math.Expm1, 0, 1, -1, 1e-10, -1e-10, 710, -746, nan, inf, ninf, nzero)
	p1("Log1p", math.Log1p, 0, 1, -1, -2, 1e-20, -0.5, nan, inf, nzero)
	p1("Erf", math.Erf, 0, 1, -1, 0.5, 10, -10, nan, inf, ninf, nzero)
	p1("Erfc", math.Erfc, 0, 1, -1, 0.5, 10, -10, nan, inf, ninf)
	p1("Gamma", math.Gamma, 1, 2, 5, 0.5, -0.5, 0, -1, 172, nan, inf, ninf, nzero)
	p1("Logb", math.Logb, 1, 2, 8, 0.5, 0, nan, inf, ninf, nzero)
	p1("RoundToEven", math.RoundToEven, 0.5, 1.5, 2.5, -0.5, -1.5, -2.5, 3.5, nan, inf, nzero)
	p1("J0", math.J0, 0, 1, 2, -1, 1e10, nan, inf, ninf)
	p1("J1", math.J1, 0, 1, 2, -1, nan, inf, ninf)
	p1("Y0", math.Y0, 1, 2, 0, -1, nan, inf, ninf)
	p1("Y1", math.Y1, 1, 2, 0, -1, nan, inf, ninf)

	for _, x := range []float64{1, 2, 8, 0.5, 0, nan, inf, nzero} {
		fmt.Printf("ilogb %d %d\n", math.Float64bits(x), math.Ilogb(x))
	}
	for _, x := range []float64{1, 2, 5, 0.5, -0.5, -1, 0, nan, inf} {
		l, sg := math.Lgamma(x)
		fmt.Printf("lgamma %d %d %d\n", math.Float64bits(x), math.Float64bits(l), sg)
	}
	for _, x := range []float64{0, 1, math.Pi / 2, -1, nan, inf} {
		sn, cs := math.Sincos(x)
		fmt.Printf("sincos %d %d %d\n", math.Float64bits(x), math.Float64bits(sn), math.Float64bits(cs))
	}
	for _, c := range [][2]float64{{1, 2}, {1, 0}, {1, 1}, {0, 1}, {0, -1}, {nan, 1}, {1, nan}, {math.MaxFloat64, inf}} {
		fmt.Printf("nextafter %d %d %d\n", math.Float64bits(c[0]), math.Float64bits(c[1]),
			math.Float64bits(math.Nextafter(c[0], c[1])))
	}
	for _, c := range [][2]float32{{1, 2}, {1, 0}, {1, 1}, {0, 1}} {
		fmt.Printf("nextafter32 %d %d %d\n", math.Float32bits(c[0]), math.Float32bits(c[1]),
			math.Float32bits(math.Nextafter32(c[0], c[1])))
	}
	for _, c := range [][3]float64{{2, 3, 4}, {1e300, 1e300, 1}, {0, inf, 1}, {nan, 1, 1}} {
		fmt.Printf("fma %d %d %d %d\n", math.Float64bits(c[0]), math.Float64bits(c[1]),
			math.Float64bits(c[2]), math.Float64bits(math.FMA(c[0], c[1], c[2])))
	}
	for _, n := range []int{0, 1, 2, 5, -1} {
		for _, x := range []float64{1, 2} {
			fmt.Printf("jn %d %d %d\n", n, math.Float64bits(x), math.Float64bits(math.Jn(n, x)))
			fmt.Printf("yn %d %d %d\n", n, math.Float64bits(x), math.Float64bits(math.Yn(n, x)))
		}
	}
}
