package asn1

import (
	"fmt"
	"testing"
)

// The ASN.1 time parsers are `time.Parse` plus a re-`Format`-and-compare
// guard, so they inherit whatever the port's `time` does with a zone.
// A `Time` that cannot carry a location parses `910506234540-0700` to
// the right instant, formats it back as `...Z`, sees the mismatch, and
// returns an error — rejecting a string Go accepts. These vectors pin
// the accepting side, plus the forms that must still be rejected.
func TestGoishRef(t *testing.T) {
	for _, s := range []string{
		"910506234540Z",
		"910506234540-0700",
		"910506234540+0000",
		"9105062345Z",
		"9105062345-0700",
		"500506234540Z",
		"491231235959Z",
		"910506234540",
		"910506234540-07",
	} {
		tm, err := parseUTCTime([]byte(s))
		if err != nil {
			fmt.Printf("utc  %-20q err=%v\n", s, err)
			continue
		}
		zn, zo := tm.Zone()
		fmt.Printf("utc  %-20q unix=%-12d fmt=%q zone=(%q,%d) year=%d hour=%d\n",
			s, tm.Unix(), tm.Format("2006-01-02T15:04:05Z07:00"), zn, zo, tm.Year(), tm.Hour())
	}

	for _, s := range []string{
		"20100102030405Z",
		"20100102030405+0607",
		"20100102030405-0607",
		"20100102030405.123Z",
		"20100102030405.123+0607",
		"20100102030405",
		"20100102030405+06",
	} {
		tm, err := parseGeneralizedTime([]byte(s))
		if err != nil {
			fmt.Printf("gen  %-26q err=%v\n", s, err)
			continue
		}
		zn, zo := tm.Zone()
		fmt.Printf("gen  %-26q unix=%-12d nano=%-12d fmt=%q zone=(%q,%d) hour=%d\n",
			s, tm.Unix(), int64(tm.Nanosecond()), tm.Format("2006-01-02T15:04:05.999999999Z07:00"), zn, zo, tm.Hour())
	}
}
