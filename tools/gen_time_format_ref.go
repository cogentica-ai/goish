package time_test

import (
	"fmt"
	"testing"
	"time"
)

// Format is not a table of named layouts: nextStdChunk walks any
// layout and appendFormat emits one chunk at a time. A port that
// special-cases the constants answers correctly for them and
// wrongly - or not at all - for everything else, including layouts
// built by concatenation at run time.
func TestGoishRef(t *testing.T) {
	layouts := []string{
		time.Layout, time.ANSIC, time.UnixDate, time.RubyDate,
		time.RFC822, time.RFC822Z, time.RFC850, time.RFC1123,
		time.RFC1123Z, time.RFC3339, time.RFC3339Nano, time.Kitchen,
		time.Stamp, time.StampMilli, time.StampMicro, time.StampNano,
		time.DateTime, time.DateOnly, time.TimeOnly,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006", "06", "1", "01", "January", "Jan", "2", "02", "_2",
		"002", "__2", "15", "3", "03", "4", "04", "5", "05",
		"PM", "pm", "MST", "Z0700", "Z07:00", "Z07", "Z070000",
		"Z07:00:00", "-0700", "-07:00", "-07", "-070000", "-07:00:00",
		".0", ".00", ".000", ".000000000", ".9", ".99", ".999999999",
		",000", ",999", "15:04:05.000", "15:04:05,000",
		"Monday, January 2, 2006 at 3:04:05PM MST",
		"Mon Jan 2 15:04:05 MST 2006", "_2006", "2006-2-2",
		"Janxx", "Monxx", "January2006", "Mon2006",
		"", "literal text", "2006-01-02T15:04:05.999999999Z07:00",
		"20060102150405", "060102150405Z0700", "20060102150405Z0700",
		"20060102150405.999999999Z0700", "0601021504Z0700",
		"15:04:05.99", "3:4:5", "1/2/06", "Jan _2 15:04:05.000000",
	}
	times := []struct{ sec, nsec int64 }{
		{0, 0}, {1700000000, 123456789}, {1700000000, 0},
		{1700000000, 100000000}, {-62135596800, 0},
		{1136214245, 0}, {1704067199, 999999999}, {1709164800, 0},
		{951782400, 0}, {1735689600, 500000000},
	}
	for li, lay := range layouts {
		for ti, c := range times {
			u := time.Unix(c.sec, c.nsec).UTC()
			fmt.Printf("f %d %d %q\n", li, ti, u.Format(lay))
		}
	}
	for li, lay := range layouts {
		fmt.Printf("lay %d %q\n", li, lay)
	}
	for ti, c := range times {
		fmt.Printf("tim %d %d %d\n", ti, c.sec, c.nsec)
	}
	// AppendFormat extends dst.
	u := time.Unix(1700000000, 123456789).UTC()
	fmt.Printf("app %q\n", string(u.AppendFormat([]byte("<"), time.RFC3339Nano)))
}
