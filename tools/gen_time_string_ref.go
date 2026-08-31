package time_test

import (
	"fmt"
	"testing"
	"time"
)

// Time.String is what every fmt.Println(t) reaches. It is not a
// separate renderer: format.go:546 calls Format with one fixed
// layout and appends the monotonic reading when there is one.
func TestGoishRef(t *testing.T) {
	for _, c := range []struct{ sec, nsec int64 }{
		{0, 0}, {1, 0}, {-1, 0}, {1700000000, 123456789},
		{1700000000, 0}, {1700000000, 100000000}, {1700000000, 120000000},
		{1700000000, 1}, {1700000000, 999999999}, {1700000000, 1000},
		{-62135596800, 0}, {253402300799, 999999999},
	} {
		u := time.Unix(c.sec, c.nsec).UTC()
		fmt.Printf("str %d %d %q\n", c.sec, c.nsec, u.String())
		fmt.Printf("fmtv %d %d %q\n", c.sec, c.nsec, fmt.Sprintf("%v", u))
		fmt.Printf("fmts %d %d %q\n", c.sec, c.nsec, fmt.Sprintf("%s", u))
		fmt.Printf("lay %d %d %q\n", c.sec, c.nsec,
			u.Format("2006-01-02 15:04:05.999999999 -0700 MST"))
	}
	var z time.Time
	fmt.Printf("zero %q\n", z.String())
}
