package math_test

import (
	"fmt"
	"math"
	"testing"
)

// Every function in Go's math package documents its special cases, and
// they are not always what the underlying libm or Rust's std does. The
// ones that bite: Max/Min propagate NaN and order -0 below +0; Dim
// returns NaN rather than 0 for +Inf-+Inf; Hypot is +Inf for an
// infinite argument EVEN IF the other is NaN.
func TestGoishRef(t *testing.T) {
	nan, inf, ninf := math.NaN(), math.Inf(1), math.Inf(-1)
	nz := math.Copysign(0, -1)
	sf := func(v float64) string { return fmt.Sprintf("%v", v) }
	// %v of a float loses the sign of zero, so say it explicitly.
	z := func(v float64) string {
		if v == 0 {
			if math.Signbit(v) {
				return "-0"
			}
			return "+0"
		}
		return sf(v)
	}

	pairs := [][2]float64{
		{1, 2}, {2, 1}, {1, 1},
		{0, nz}, {nz, 0}, {nz, nz},
		{nan, 1}, {1, nan}, {nan, nan},
		{inf, 1}, {1, inf}, {ninf, 1}, {1, ninf},
		{inf, inf}, {ninf, ninf}, {inf, ninf},
		{inf, nan}, {nan, inf},
	}
	for _, p := range pairs {
		fmt.Printf("mm %-6s %-6s max=%-6s min=%-6s dim=%-6s hypot=%-6s mod=%-8s rem=%s\n",
			z(p[0]), z(p[1]), z(math.Max(p[0], p[1])), z(math.Min(p[0], p[1])),
			z(math.Dim(p[0], p[1])), z(math.Hypot(p[0], p[1])),
			z(math.Mod(p[0], p[1])), z(math.Remainder(p[0], p[1])))
	}

	// Mod and Remainder over the ordinary cases too.
	for _, p := range [][2]float64{{5, 3}, {-5, 3}, {5, -3}, {-5, -3}, {5, 0}, {0, 5}, {5.5, 2}} {
		fmt.Printf("mod %-5s %-5s -> %-8s rem=%s\n",
			z(p[0]), z(p[1]), z(math.Mod(p[0], p[1])), z(math.Remainder(p[0], p[1])))
	}

	// Rounding, including the zeros and the halves.
	for _, v := range []float64{0, nz, 0.5, -0.5, 1.5, -1.5, 2.5, -2.5, 0.4, -0.4, inf, ninf, nan} {
		fmt.Printf("round %-6s floor=%-6s ceil=%-6s round=%-6s trunc=%-6s abs=%s\n",
			z(v), z(math.Floor(v)), z(math.Ceil(v)), z(math.Round(v)),
			z(math.Trunc(v)), z(math.Abs(v)))
	}

	// Pow's special cases — Go documents twenty of them.
	powcases := [][2]float64{
		{2, 3}, {2, 0.5}, {-2, 3}, {-2, 0.5},
		{1, nan}, {nan, 0}, {1, inf}, {-1, inf}, {-1, ninf},
		{0, 3}, {0, -3}, {nz, 3}, {nz, -3}, {nz, 2}, {nz, -2},
		{inf, 0}, {0, 0}, {nan, 1}, {2, inf}, {0.5, inf}, {2, ninf}, {0.5, ninf},
		{ninf, 3}, {ninf, -3}, {-2, 0.5},
	}
	for _, p := range powcases {
		fmt.Printf("pow %-6s %-6s -> %s\n", z(p[0]), z(p[1]), z(math.Pow(p[0], p[1])))
	}

	// Log, Sqrt, Exp at their boundaries.
	for _, v := range []float64{0, nz, -1, 1, inf, ninf, nan, math.E} {
		fmt.Printf("log %-6s log=%-6s log2=%-6s log10=%-6s sqrt=%-6s exp=%s\n",
			z(v), z(math.Log(v)), z(math.Log2(v)), z(math.Log10(v)),
			z(math.Sqrt(v)), z(math.Exp(v)))
	}

	// Atan2's special cases, which are a table in the docs.
	for _, p := range [][2]float64{
		{0, 0}, {0, nz}, {nz, 0}, {nz, nz}, {1, 0}, {-1, 0},
		{0, 1}, {0, -1}, {inf, inf}, {inf, ninf}, {ninf, inf},
		{1, inf}, {1, ninf}, {inf, 1}, {ninf, 1}, {nan, 1}, {1, nan},
	} {
		fmt.Printf("atan2 %-6s %-6s -> %s\n", z(p[0]), z(p[1]), z(math.Atan2(p[0], p[1])))
	}

	// Frexp / Ldexp / Modf at the boundaries.
	for _, v := range []float64{0, nz, 1, -1, 8, inf, ninf, nan} {
		fr, ex := math.Frexp(v)
		i, f := math.Modf(v)
		fmt.Printf("parts %-6s frexp=(%s,%d) modf=(%s,%s) ldexp=%s\n",
			z(v), z(fr), ex, z(i), z(f), z(math.Ldexp(v, 2)))
	}

	// Signbit, Copysign, IsInf, IsNaN, Inf.
	fmt.Printf("sign %v %v %v %v copysign=%s,%s inf0=%s isinf=%v,%v,%v\n",
		math.Signbit(0), math.Signbit(nz), math.Signbit(-1), math.Signbit(nan),
		z(math.Copysign(3, nz)), z(math.Copysign(nan, -1)), z(math.Inf(0)),
		math.IsInf(inf, 0), math.IsInf(ninf, 1), math.IsInf(ninf, -1))
}
