package fmt_test

import (
	"fmt"
	"testing"
)

// Go's default precision is NOT "shortest" for every float verb. From
// the fmt doc: "For %v the default is the smallest number of digits
// necessary … %e, %E, %f, %F default to a precision of 6". A port that
// routes every float verb through strconv.FormatFloat(-1) prints
// "1.5" where Go prints "1.500000" — a difference that shows up in
// every column-aligned numeric report.
func TestGoishRef(t *testing.T) {
	sf := fmt.Sprintf
	for _, v := range []float64{0, 1, 1.5, -1.5, 3.14159265358979, 1e21, 1e-7, 100} {
		fmt.Printf("f %-20v v=%q f=%q F=%q e=%q E=%q g=%q G=%q\n",
			v, sf("%v", v), sf("%f", v), sf("%F", v), sf("%e", v),
			sf("%E", v), sf("%g", v), sf("%G", v))
	}
	// An explicit precision overrides the default in both directions.
	for _, v := range []float64{1.5, 3.14159265358979} {
		fmt.Printf("p %-18v .0f=%q .2f=%q .9f=%q .2e=%q .3g=%q\n",
			v, sf("%.0f", v), sf("%.2f", v), sf("%.9f", v),
			sf("%.2e", v), sf("%.3g", v))
	}
	// Width and zero padding over the default precision.
	fmt.Printf("w a=%q b=%q c=%q d=%q\n",
		sf("%10f", 1.5), sf("%-10f|", 1.5), sf("%010f", 1.5), sf("%+f", 1.5))
	// float32 takes the same defaults.
	var f32 float32 = 1.5
	fmt.Printf("f32 v=%q f=%q e=%q g=%q\n",
		sf("%v", f32), sf("%f", f32), sf("%e", f32), sf("%g", f32))
	// The special values.
	for _, s := range []string{"Inf", "-Inf", "NaN"} {
		var v float64
		fmt.Sscan(s, &v)
		fmt.Printf("s %-5s v=%q f=%q e=%q g=%q\n",
			s, sf("%v", v), sf("%f", v), sf("%e", v), sf("%g", v))
	}
}
