package time_test

import (
	"fmt"
	"testing"
	"time"
)

// Go's zero Time is January 1 of YEAR 1, not the Unix epoch. That is
// not a detail: IsZero is what every "was this ever set?" check in the
// standard library asks, the binary encoding stores the internal count
// and not a Unix one, and a zero time formats as 0001-01-01. A port
// that anchors Time at the epoch answers all three differently while
// looking right for every timestamp anyone actually sets.
func TestGoishRef(t *testing.T) {
	var zero time.Time
	epoch := time.Unix(0, 0).UTC()

	fmt.Printf("zero iszero=%v unix=%d year=%d date=%v\n",
		zero.IsZero(), zero.Unix(), zero.Year(), zero.Format("2006-01-02 15:04:05"))
	fmt.Printf("epoch iszero=%v unix=%d year=%d date=%v\n",
		epoch.IsZero(), epoch.Unix(), epoch.Year(), epoch.Format("2006-01-02 15:04:05"))
	fmt.Printf("zero-before-epoch=%v epoch-after-zero=%v equal=%v\n",
		zero.Before(epoch), epoch.After(zero), zero.Equal(epoch))

	// Round-tripping a Unix timestamp must be exact in both directions.
	for _, sec := range []int64{0, 1, -1, 1700000000, -62135596800, 253402300799} {
		u := time.Unix(sec, 0).UTC()
		fmt.Printf("roundtrip %-14d unix=%-14d year=%-6d iszero=%v\n",
			sec, u.Unix(), u.Year(), u.IsZero())
	}

	// The binary encoding stores the INTERNAL second count.
	for _, c := range []struct {
		name string
		t    time.Time
	}{
		{"zero", zero},
		{"epoch", epoch},
		{"n99999", time.Unix(99999, 12345).UTC()},
	} {
		b, err := c.t.MarshalBinary()
		fmt.Printf("marshal %-8s err=%v len=%d bytes=%v\n", c.name, err, len(b), b)
		var back time.Time
		err = back.UnmarshalBinary(b)
		fmt.Printf("unmarshal %-8s err=%v unix=%d nano=%d iszero=%v\n",
			c.name, err, back.Unix(), back.UnixNano(), back.IsZero())
	}

	// A hand-built V2 buffer whose 8 second-bytes read 42: that is 42
	// INTERNAL seconds, which is year 1 plus 42 seconds — a long way
	// from Unix 42.
	buf := make([]byte, 16)
	buf[0] = 2
	buf[8] = 42
	var v2 time.Time
	err := v2.UnmarshalBinary(buf)
	fmt.Printf("v2 err=%v unix=%d year=%d\n", err, v2.Unix(), v2.Year())

	// Date and Clock at both epochs.
	for _, c := range []struct {
		name string
		t    time.Time
	}{{"zero", zero}, {"epoch", epoch}} {
		y, m, d := c.t.Date()
		hh, mm, ss := c.t.Clock()
		fmt.Printf("parts %-6s date=(%d,%v,%d) clock=(%d,%d,%d) weekday=%v yearday=%d\n",
			c.name, y, m, d, hh, mm, ss, c.t.Weekday(), c.t.YearDay())
	}

	// Sub saturates: the gap between the two epochs does not fit in a
	// Duration, which is an int64 of NANOSECONDS.
	fmt.Printf("sub epoch-zero=%v saturated=%v\n",
		epoch.Sub(zero), epoch.Sub(zero) == time.Duration(1<<63-1))
	// AddDate walks the calendar instead, so it can cross the gap.
	fmt.Printf("adddate zero+1969y unix=%d year=%d\n",
		zero.AddDate(1969, 0, 0).Unix(), zero.AddDate(1969, 0, 0).Year())
}
