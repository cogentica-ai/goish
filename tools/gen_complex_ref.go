package strconv_test

import (
	"fmt"
	"strconv"
	"testing"
)

// FormatComplex always parenthesises and always signs the imaginary
// part, and ParseComplex accepts a good deal more than FormatComplex
// produces: bare reals, bare imaginaries, and the parenthesised form.
// The error messages name ParseComplex and quote the ORIGINAL string,
// not the fragment that failed.
func TestGoishRef(t *testing.T) {
	for _, c := range []struct {
		v    complex128
		f    byte
		prec int
		bits int
	}{
		{complex(1, 2), 'g', -1, 128},
		{complex(1, -2), 'g', -1, 128},
		{complex(0, 0), 'g', -1, 128},
		{complex(-1.5, 0), 'g', -1, 128},
		{complex(1, 2), 'f', 2, 128},
		{complex(1, 2), 'e', 3, 128},
		{complex(1.25, -0.5), 'g', -1, 64},
		{complex(0, 1), 'g', -1, 128},
	} {
		fmt.Printf("fmt  (%v,%v) f=%c prec=%d bits=%d -> %q\n",
			real(c.v), imag(c.v), c.f, c.prec, c.bits,
			strconv.FormatComplex(c.v, c.f, c.prec, c.bits))
	}

	for _, s := range []string{
		"1+2i", "(1+2i)", "1-2i", "1", "2i", "-2i", "+2i", "i",
		"(1+2i", "1+2i)", "1+2", "1++2i", "1+2j", "",
		"(0+0i)", "0", "1e10+1e-10i", "+1+2i", "-1-2i",
		"NaN", "Inf", "(Inf+Infi)", "1+NaNi", "(NaN+NaNi)",
		"1e400+1i", "1+1e400i",
		"(1+2i))", "((1+2i))", "1 + 2i",
	} {
		v, err := strconv.ParseComplex(s, 128)
		if err != nil {
			fmt.Printf("parse %-16q err=%v\n", s, err)
			continue
		}
		fmt.Printf("parse %-16q -> (%v,%v)\n", s, real(v), imag(v))
	}

	// bitSize 64 narrows both parts to float32 range.
	for _, s := range []string{"1+2i", "1e40+1i"} {
		v, err := strconv.ParseComplex(s, 64)
		if err != nil {
			fmt.Printf("p64   %-16q err=%v\n", s, err)
			continue
		}
		fmt.Printf("p64   %-16q -> (%v,%v)\n", s, real(v), imag(v))
	}
}
