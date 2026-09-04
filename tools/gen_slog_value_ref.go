package slog

import (
	"fmt"
	"testing"
	"time"
)

// Value.String is the renderer every handler leans on, and it is
// per-Kind rather than a single formatter: an Int64 is decimal, a
// Float64 is shortest-round-trip, a Duration is Go's duration syntax,
// a Time is RFC3339 with nanoseconds, and a Group is bracketed like a
// slice of Attrs. Attr.String is "key=value" over that.
func TestGoishRef(t *testing.T) {
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC)

	vals := []struct {
		tag string
		v   Value
	}{
		{"string", StringValue("hi")},
		{"string-empty", StringValue("")},
		{"string-space", StringValue("a b")},
		{"int64", Int64Value(-7)},
		{"int64-zero", Int64Value(0)},
		{"uint64", Uint64Value(18446744073709551615)},
		{"bool-true", BoolValue(true)},
		{"bool-false", BoolValue(false)},
		{"float-1.5", Float64Value(1.5)},
		{"float-int", Float64Value(2)},
		{"float-tiny", Float64Value(0.1)},
		{"float-neg", Float64Value(-0.25)},
		{"dur-1.5s", DurationValue(1500 * time.Millisecond)},
		{"dur-0", DurationValue(0)},
		{"dur-ns", DurationValue(1)},
		{"dur-neg", DurationValue(-2 * time.Hour)},
		{"time", TimeValue(fixed)},
		{"any-nil", AnyValue(nil)},
		{"any-err", AnyValue(fmt.Errorf("boom"))},
		{"any-int", AnyValue(42)},
		{"any-str", AnyValue("s")},
		{"group", GroupValue(String("a", "1"), Int("b", 2))},
		{"group-empty", GroupValue()},
		{"group-nested", GroupValue(Group("g", String("a", "1")))},
	}
	for _, c := range vals {
		fmt.Printf("val  %-14s kind=%-9s str=%q\n", c.tag, c.v.Kind(), c.v.String())
	}

	attrs := []struct {
		tag string
		a   Attr
	}{
		{"string", String("k", "v")},
		{"int", Int("n", 7)},
		{"bool", Bool("b", false)},
		{"float", Float64("f", 1.5)},
		{"dur", Duration("d", 90*time.Second)},
		{"time", Time("t", fixed)},
		{"any", Any("a", nil)},
		{"group", Group("g", String("a", "1"), Int("b", 2))},
		{"group-empty", Group("g")},
		{"empty-key", String("", "v")},
		{"empty-val", String("k", "")},
	}
	for _, c := range attrs {
		fmt.Printf("attr %-14s str=%-32q empty=%v\n", c.tag, c.a.String(), c.a.Equal(Attr{}))
	}

	// Record attr accumulation and iteration order.
	r := NewRecord(fixed, LevelInfo, "msg", 0)
	r.AddAttrs(String("a", "1"))
	r.AddAttrs(Int("b", 2), Bool("c", true))
	r.Add("d", "4")
	r.Add(Int("e", 5))
	fmt.Printf("rec  num=%d\n", r.NumAttrs())
	r.Attrs(func(a Attr) bool {
		fmt.Printf("rec  attr %q\n", a.String())
		return true
	})

	// A clone must not share the backing array.
	r2 := r.Clone()
	r2.AddAttrs(String("z", "9"))
	fmt.Printf("rec  after-clone orig=%d clone=%d\n", r.NumAttrs(), r2.NumAttrs())

}
