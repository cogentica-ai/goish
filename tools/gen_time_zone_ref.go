package time_test

import (
	"fmt"
	"testing"
	"time"
)

// A `Time` is an instant AND a location, and `Format` renders the wall
// clock of the second one. A port that keeps only the instant computes
// every arithmetic answer correctly and still hands back the wrong
// string: RFC 3339 in, RFC 3339 out, shifted by the offset it dropped.
// These vectors pin the location half — the parsed anonymous zone, the
// named FixedZone, `In`, `Date` in a zone, and the four zone layouts.
func TestGoishRef(t *testing.T) {
	for _, inp := range []string{
		"2024-01-02T03:04:05Z",
		"2024-01-02T03:04:05+02:00",
		"2024-01-02T03:04:05-05:30",
		"2024-01-02T03:04:05.123456789+02:00",
	} {
		tt, err := time.Parse(time.RFC3339Nano, inp)
		if err != nil {
			fmt.Printf("parse %-38q err=%v\n", inp, err)
			continue
		}
		name, off := tt.Zone()
		fmt.Printf("parse %-38q -> %q unix=%d zone=(%q,%d) hour=%d loc=%q\n",
			inp, tt.Format(time.RFC3339Nano), tt.Unix(), name, off, tt.Hour(),
			tt.Location().String())
	}

	z := time.FixedZone("CEST", 2*3600)
	base := time.Unix(1704164645, 0)
	inz := base.In(z)
	zn, zo := inz.Zone()
	fmt.Printf("fixed utc=%q in=%q zone=(%q,%d) hour=%d,%d date=%d,%d\n",
		base.UTC().Format(time.RFC3339), inz.Format(time.RFC3339), zn, zo,
		base.UTC().Hour(), inz.Hour(), base.UTC().Day(), inz.Day())

	neg := time.FixedZone("NST", -(3*3600 + 30*60))
	inn := base.In(neg)
	fmt.Printf("neg   in=%q hour=%d day=%d zonename=%q\n",
		inn.Format(time.RFC3339), inn.Hour(), inn.Day(), inn.Location().String())

	d := time.Date(2024, 1, 2, 3, 4, 5, 0, z)
	fmt.Printf("date  %q unix=%d utc=%q\n",
		d.Format(time.RFC3339), d.Unix(), d.UTC().Format(time.RFC3339))

	gmt := time.FixedZone("GMT", 0)
	fmt.Printf("gmt   %q rfc1123=%q\n",
		base.In(gmt).Format(time.RFC3339), base.In(gmt).Format(time.RFC1123))

	fmt.Printf("names utc=%q fixed=%q\n", time.UTC.String(), z.String())

	pl, _ := time.ParseInLocation("2006-01-02 15:04:05", "2024-01-02 03:04:05", z)
	fmt.Printf("pil   %q unix=%d\n", pl.Format(time.RFC3339), pl.Unix())

	for _, layout := range []string{"MST", "-0700", "-07:00", "Z0700", "Z07:00", "-07"} {
		fmt.Printf("layout %-8q utc=%q cest=%q\n",
			layout, base.UTC().Format(layout), inz.Format(layout))
	}
}
