package strconv_test

import (
	"fmt"
	"math"
	"strconv"
	"testing"
)

// itoa.go funnels every integer-formatting entry point through one
// `formatBits`, and that function has three separate digit loops — a
// base-10 one built on a two-digit lookup table, a shift-and-mask one
// for power-of-two bases, and a divide one for everything else. A port
// that keeps only the divide loop looks right for every value anyone
// prints casually and can still be wrong at a boundary, so the vectors
// below walk all three deliberately, including the one input whose
// negation overflows.
func TestGoishRef(t *testing.T) {
	values := []int64{
		0, 1, -1, 9, 10, 99, 100, 101, 999, 1000,
		1e9 - 1, 1e9, 1e9 + 1, 123456789012345,
		math.MaxInt64, math.MinInt64, -100, -99, -9,
	}
	for _, base := range []int{2, 8, 10, 16, 36, 3, 7, 32} {
		for _, v := range values {
			fmt.Printf("formatint base=%-3d v=%-21d %q\n", base, v, strconv.FormatInt(v, base))
		}
	}

	uvalues := []uint64{
		0, 1, 9, 10, 99, 100, 1e9 - 1, 1e9, 1e9 + 1,
		math.MaxUint64, math.MaxUint64 - 1, 1 << 63,
	}
	for _, base := range []int{2, 8, 10, 16, 36} {
		for _, v := range uvalues {
			fmt.Printf("formatuint base=%-3d v=%-21d %q\n", base, v, strconv.FormatUint(v, base))
		}
	}

	// Itoa and the two Append forms share the small-integer fast path,
	// which is only taken for base 10 and 0 <= i < 100.
	for _, v := range []int{0, 9, 10, 99, 100, -1, -99} {
		fmt.Printf("itoa %-6d %q\n", v, strconv.Itoa(v))
	}
	for _, v := range []int64{0, 42, 99, 100, -42, math.MinInt64} {
		fmt.Printf("appendint %-21d %q\n", v, string(strconv.AppendInt([]byte("<"), v, 10)))
		fmt.Printf("appendint16 %-21d %q\n", v, string(strconv.AppendInt([]byte("<"), v, 16)))
	}
	for _, v := range []uint64{0, 42, 99, 100, math.MaxUint64} {
		fmt.Printf("appenduint %-21d %q\n", v, string(strconv.AppendUint([]byte("<"), v, 10)))
	}

	// An illegal base panics, with this exact text.
	func() {
		defer func() { fmt.Printf("panic base=1 %v\n", recover()) }()
		_ = strconv.FormatInt(7, 1)
	}()
	func() {
		defer func() { fmt.Printf("panic base=37 %v\n", recover()) }()
		_ = strconv.FormatInt(7, 37)
	}()

	// baseError and bitSizeError render the offending number with Itoa,
	// so their message text is part of itoa.go's contract.
	for _, c := range []struct {
		base, bits int
	}{{1, 64}, {37, 64}, {-5, 64}, {10, 65}, {10, -1}} {
		_, err := strconv.ParseInt("12", c.base, c.bits)
		fmt.Printf("parseint base=%-4d bits=%-4d err=%q\n", c.base, c.bits, err)
		_, err = strconv.ParseUint("12", c.base, c.bits)
		fmt.Printf("parseuint base=%-4d bits=%-4d err=%q\n", c.base, c.bits, err)
	}

	// A sign is stripped before the delegation to ParseUint, but the
	// error the caller sees names the ORIGINAL string — including that
	// sign — and keeps the wrapped Err it came back with.
	for _, in := range []string{"-abc", "+abc", "abc", "-", "", "-99999999999999999999"} {
		_, err := strconv.ParseInt(in, 10, 64)
		fmt.Printf("reshape %-24q err=%q\n", in, err)
		v, err := strconv.ParseInt(in, 1, 64)
		fmt.Printf("reshape-base1 %-24q v=%d err=%q\n", in, v, err)
	}

	// IntSize is a declared constant, not a runtime probe.
	fmt.Printf("intsize %d\n", strconv.IntSize)

	// Round-tripping every base is the cheapest end-to-end check that
	// the three digit loops and the parser agree.
	for base := 2; base <= 36; base++ {
		v := int64(-1234567890123)
		s := strconv.FormatInt(v, base)
		back, err := strconv.ParseInt(s, base, 64)
		fmt.Printf("roundtrip base=%-3d %-46q back=%-15d err=%v\n", base, s, back, err)
	}
}
