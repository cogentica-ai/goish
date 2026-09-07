package time_test

import (
	"fmt"
	"math"
	"testing"
	"time"
)

// Duration.String is Duration.format, which Go writes backwards into a
// 32-byte array with its own fraction logic. The edges are where a
// reimplementation drifts: the smallest and largest values, the
// carry between units, and negative zero-ish values.
func TestGoishRef(t *testing.T) {
	ds := []time.Duration{
		0,
		1,
		999,
		1000,
		1001,
		999999,
		1000000,
		1500000,
		time.Second,
		time.Second + 500*time.Millisecond,
		59 * time.Second,
		time.Minute,
		time.Minute + time.Second,
		time.Hour,
		time.Hour + time.Minute + time.Second,
		25 * time.Hour,
		-1,
		-time.Second,
		-90 * time.Minute,
		time.Duration(math.MaxInt64),
		time.Duration(math.MinInt64),
	}
	for _, d := range ds {
		fmt.Printf("%d -> %q\n", int64(d), d.String())
	}
}
