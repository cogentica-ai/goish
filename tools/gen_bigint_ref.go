package big

import (
	"fmt"
	"testing"
)

// math/big is the arithmetic under crypto/rsa, crypto/ecdsa and x509,
// so "close enough" is not a category it has. Three of its rules are
// the ones a plausible port gets wrong, and all three are silent when
// they are wrong — the answer is a number, just not Go's number:
//
//   * Div/Mod are EUCLIDEAN: the modulus is never negative, so
//     (-7).Div(2) is -4 and (-7).Mod(2) is 1, while Quo/Rem truncate
//     toward zero and give -3 and -1. Rust's own / and % truncate, so
//     a port that reaches for them gets Quo/Rem semantics under the
//     Div/Mod names.
//   * The bitwise operators treat a negative Int as an INFINITE two's
//     complement value. (-1) is all ones, so (-1) & x == x, and
//     (-1).Not() is 0. A sign-magnitude implementation that ors the
//     magnitudes and keeps a sign bit answers differently for every
//     negative operand.
//   * Bit(i) of a negative Int reads that same infinite two's
//     complement, so (-1).Bit(0) is 1 and so is Bit(1000).
func TestGoishRef(t *testing.T) {
	vals := []int64{0, 1, -1, 2, -2, 7, -7, 8, -8, 255, -255, 256, -256,
		1 << 20, -(1 << 20), 1<<62 - 1, -(1<<62 - 1)}

	// 1. Div/Mod (Euclidean) vs Quo/Rem (truncated), over every sign
	//    combination that matters.
	for _, a := range []int64{7, -7, 8, -8, 0, 1, -1, 100, -100} {
		for _, b := range []int64{2, -2, 3, -3, 7, -7, 1, -1} {
			x, y := NewInt(a), NewInt(b)
			d, m := new(Int).Div(x, y), new(Int).Mod(x, y)
			q, r := new(Int).Quo(x, y), new(Int).Rem(x, y)
			dm1, dm2 := new(Int).DivMod(x, y, new(Int))
			qr1, qr2 := new(Int).QuoRem(x, y, new(Int))
			fmt.Printf("divmod %5d %5d -> div=%-5s mod=%-4s quo=%-5s rem=%-5s divmod=(%s,%s) quorem=(%s,%s)\n",
				a, b, d, m, q, r, dm1, dm2, qr1, qr2)
		}
	}

	// 2. Bitwise over an infinite two's complement.
	for _, a := range []int64{0, 1, -1, 5, -5, 6, -6, 255, -255, -256, 1024, -1024} {
		for _, b := range []int64{0, 1, -1, 3, -3, 255, -255} {
			x, y := NewInt(a), NewInt(b)
			fmt.Printf("bitwise %5d %5d -> and=%-6s or=%-6s xor=%-6s andnot=%-6s\n",
				a, b, new(Int).And(x, y), new(Int).Or(x, y),
				new(Int).Xor(x, y), new(Int).AndNot(x, y))
		}
	}
	for _, a := range []int64{0, 1, -1, 5, -5, 255, -255, -256} {
		x := NewInt(a)
		fmt.Printf("not %5d -> %s\n", a, new(Int).Not(x))
	}

	// 3. Bit/SetBit/TrailingZeroBits/BitLen, including negatives.
	for _, a := range []int64{0, 1, -1, 5, -5, 8, -8, 255, -255, -256} {
		x := NewInt(a)
		fmt.Printf("bits %5d -> len=%-3d tz=%-4d b0=%d b1=%d b2=%d b7=%d b8=%d b100=%d\n",
			a, x.BitLen(), x.TrailingZeroBits(), x.Bit(0), x.Bit(1), x.Bit(2),
			x.Bit(7), x.Bit(8), x.Bit(100))
	}
	for _, a := range []int64{0, 1, -1, 5, -5, -256} {
		for _, i := range []int{0, 1, 7} {
			for _, v := range []uint{0, 1} {
				fmt.Printf("setbit %5d i=%d v=%d -> %s\n", a, i, v,
					new(Int).SetBit(NewInt(a), i, v))
			}
		}
	}

	// 4. Shifts. A right shift of a negative is an ARITHMETIC shift on
	//    the two's complement, so it floors rather than truncating.
	for _, a := range []int64{1, -1, 5, -5, 8, -8, 255, -255, -256} {
		for _, n := range []uint{0, 1, 3, 8, 64} {
			fmt.Printf("shift %5d n=%-3d -> lsh=%-24s rsh=%s\n", a, n,
				new(Int).Lsh(NewInt(a), n), new(Int).Rsh(NewInt(a), n))
		}
	}

	// 5. Text/String across bases, and the sign placement.
	for _, a := range []int64{0, 1, -1, 255, -255, 123456789, -123456789} {
		x := NewInt(a)
		fmt.Printf("text %11d -> b2=%-30s b8=%-12s b10=%-11s b16=%-9s b36=%s str=%s\n",
			a, x.Text(2), x.Text(8), x.Text(10), x.Text(16), x.Text(36), x.String())
	}

	// 6. SetString: the base-0 prefixes, underscores, and what is
	//    refused. The (value, ok) pair is what callers branch on.
	for _, c := range []struct {
		s    string
		base int
	}{
		{"0", 10}, {"-0", 10}, {"+42", 10}, {"42", 10}, {"  42", 10},
		{"42 ", 10}, {"", 10}, {"-", 10}, {"0x1f", 0}, {"0X1F", 0},
		{"0b101", 0}, {"0o17", 0}, {"017", 0}, {"0_1_7", 0}, {"1_000", 0},
		{"1_000", 10}, {"_100", 0}, {"100_", 0}, {"0x", 0}, {"ff", 16},
		{"FF", 16}, {"zz", 36}, {"zz", 35}, {"-0x10", 0}, {"1e3", 10},
		{"0x1f", 16}, {"0", 0}, {"00", 0}, {"08", 0},
	} {
		x, ok := new(Int).SetString(c.s, c.base)
		if !ok {
			fmt.Printf("setstring %-8q base=%-3d -> nil,false\n", c.s, c.base)
			continue
		}
		fmt.Printf("setstring %-8q base=%-3d -> %s,true\n", c.s, c.base, x)
	}

	// 7. Bytes/SetBytes/FillBytes — the big-endian magnitude, sign
	//    dropped. FillBytes panics if it does not fit, so the sizes
	//    here are the ones that do.
	for _, a := range []int64{0, 1, -1, 255, 256, 65535, -65535, 1 << 40} {
		x := NewInt(a)
		b := x.Bytes()
		buf := make([]byte, 8)
		fmt.Printf("bytes %12d -> %x fill8=%x back=%s\n",
			a, b, x.FillBytes(buf), new(Int).SetBytes(b))
	}

	// 8. Exp: the modular path, the nil-modulus path, and the negative
	//    exponent that Go defines as the modular inverse.
	for _, c := range [][3]int64{
		{2, 10, 0}, {2, 10, 1000}, {2, 0, 7}, {0, 0, 0}, {3, 100, 7},
		{-3, 3, 0}, {-3, 3, 7}, {-3, 2, 7}, {2, -1, 7}, {2, -1, 0},
		{5, -1, 7}, {7, -1, 7}, {2, 10, -1000},
	} {
		var m *Int
		if c[2] != 0 {
			m = NewInt(c[2])
		}
		r := new(Int).Exp(NewInt(c[0]), NewInt(c[1]), m)
		fmt.Printf("exp %3d^%-4d mod %-6d -> %v\n", c[0], c[1], c[2], r)
	}

	// 9. GCD, ModInverse, ModSqrt.
	for _, c := range [][2]int64{{12, 18}, {17, 5}, {0, 5}, {5, 0}, {0, 0},
		{-12, 18}, {12, -18}, {270, 192}} {
		x, y := NewInt(c[0]), NewInt(c[1])
		g := new(Int)
		var xx, yy Int
		if c[0] > 0 && c[1] > 0 {
			g.GCD(&xx, &yy, x, y)
			fmt.Printf("gcd %5d %5d -> g=%s x=%s y=%s\n", c[0], c[1], g, &xx, &yy)
		} else {
			fmt.Printf("gcd %5d %5d -> skipped (GCD requires a,b > 0)\n", c[0], c[1])
		}
	}
	for _, c := range [][2]int64{{3, 7}, {2, 7}, {6, 9}, {1, 7}, {-3, 7}, {3, 1}} {
		r := new(Int).ModInverse(NewInt(c[0]), NewInt(c[1]))
		fmt.Printf("modinv %5d mod %-4d -> %v\n", c[0], c[1], r)
	}
	for _, c := range [][2]int64{{4, 7}, {2, 7}, {2, 17}, {0, 7}, {9, 13}} {
		r := new(Int).ModSqrt(NewInt(c[0]), NewInt(c[1]))
		fmt.Printf("modsqrt %5d mod %-4d -> %v\n", c[0], c[1], r)
	}

	// 10. Sqrt, Abs, Neg, Sign, Cmp, CmpAbs over the value table.
	for _, a := range vals {
		x := NewInt(a)
		var sq string
		if a >= 0 {
			sq = new(Int).Sqrt(x).String()
		} else {
			sq = "n/a"
		}
		fmt.Printf("unary %21d -> abs=%-21s neg=%-22s sign=%-2d sqrt=%s\n",
			a, new(Int).Abs(x), new(Int).Neg(x), x.Sign(), sq)
	}
	for _, a := range []int64{-5, 0, 5} {
		for _, b := range []int64{-5, 0, 5} {
			fmt.Printf("cmp %3d %3d -> cmp=%-2d cmpabs=%d\n", a, b,
				NewInt(a).Cmp(NewInt(b)), NewInt(a).CmpAbs(NewInt(b)))
		}
	}

	// 11. Int64/Uint64/IsInt64/IsUint64 at the boundaries, where a
	//     port that goes through a float or a smaller word loses.
	for _, s := range []string{"0", "1", "-1", "9223372036854775807",
		"9223372036854775808", "-9223372036854775808", "-9223372036854775809",
		"18446744073709551615", "18446744073709551616"} {
		x, _ := new(Int).SetString(s, 10)
		fmt.Printf("range %-21s -> isi64=%-5v isu64=%-5v i64=%-21d u64=%d\n",
			s, x.IsInt64(), x.IsUint64(), x.Int64(), x.Uint64())
	}

	// 12. ProbablyPrime over a spread of small and Carmichael numbers.
	for _, s := range []string{"0", "1", "2", "3", "4", "561", "1105", "7919",
		"104729", "170141183460469231731687303715884105727"} {
		x, _ := new(Int).SetString(s, 10)
		fmt.Printf("prime %-40s -> n0=%-5v n20=%v\n", s, x.ProbablyPrime(0), x.ProbablyPrime(20))
	}

	// 13. Big values: multiplication, exponentiation and round trips
	//     past one word, where a limb-carry bug first shows.
	a, _ := new(Int).SetString("123456789012345678901234567890", 10)
	b, _ := new(Int).SetString("987654321098765432109876543210", 10)
	fmt.Printf("big add=%s\n", new(Int).Add(a, b))
	fmt.Printf("big sub=%s\n", new(Int).Sub(a, b))
	fmt.Printf("big mul=%s\n", new(Int).Mul(a, b))
	fmt.Printf("big quo=%s rem=%s\n", new(Int).Quo(b, a), new(Int).Rem(b, a))
	fmt.Printf("big div=%s mod=%s\n", new(Int).Div(new(Int).Neg(b), a),
		new(Int).Mod(new(Int).Neg(b), a))
	fmt.Printf("big exp=%s\n", new(Int).Exp(NewInt(2), NewInt(256), nil))
	fmt.Printf("big hex=%s\n", new(Int).Exp(NewInt(2), NewInt(256), nil).Text(16))
	fmt.Printf("big bytes=%x\n", new(Int).Exp(NewInt(2), NewInt(200), nil).Bytes())
	fmt.Printf("big bitlen=%d\n", new(Int).Exp(NewInt(2), NewInt(256), nil).BitLen())
}
