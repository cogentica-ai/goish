// gen_pprof_proto_ref — the exact profile.proto bytes Go's encoder
// writes for a known profile (issue #9).
//
//	scripts/goref.sh internal/profile tools/gen_pprof_proto_ref.go
//
// `go tool pprof` accepting goish's output proves it is VALID, not that
// it matches. Two encoders can both satisfy the tool and differ — Go
// omits proto3 zero values, packs a repeated varint only above two
// elements, and orders fields in a particular way. This prints the
// bytes so a port can be compared rather than merely parsed.
//
// internal/profile is not importable from outside the standard library,
// which is why this runs under goref inside a writable GOROOT.
package profile

import (
	"fmt"
	"testing"
)

func TestGoishRef(t *testing.T) {
	// String table, in the order goish interns them.
	st := []string{"", "samples", "count", "nanoseconds", "cpu",
		"main.main", "main.work", "/tmp/x.go"}
	idx := func(s string) int64 {
		for i, v := range st {
			if v == s {
				return int64(i)
			}
		}
		t.Fatalf("not interned: %s", s)
		return 0
	}

	work := &Function{ID: 1, Name: "main.work", SystemName: "main.work",
		Filename: "/tmp/x.go", StartLine: 10}
	main_ := &Function{ID: 2, Name: "main.main", SystemName: "main.main",
		Filename: "/tmp/x.go", StartLine: 20}
	l1 := &Location{ID: 1, Address: 0x1000, Line: []Line{{Function: work, Line: 12}}}
	l2 := &Location{ID: 2, Address: 0x2000, Line: []Line{{Function: main_, Line: 22}}}

	p := &Profile{
		SampleType: []*ValueType{
			{Type: "samples", Unit: "count"},
			{Type: "cpu", Unit: "nanoseconds"},
		},
		Sample: []*Sample{
			{Location: []*Location{l1, l2}, Value: []int64{7, 70000000}},
			{Location: []*Location{l2}, Value: []int64{3, 30000000}},
		},
		Location:      []*Location{l1, l2},
		Function:      []*Function{work, main_},
		PeriodType:    &ValueType{Type: "cpu", Unit: "nanoseconds"},
		Period:        10000000,
		TimeNanos:     1700000000000000000,
		DurationNanos: 1000000000,
	}

	// `Write` gzips; the raw protobuf is what a port can compare field
	// by field, so print that. `preEncode` builds the string table.
	p.preEncode()
	b := marshal(p)
	fmt.Printf("len %d\n", len(b))
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		fmt.Printf("%04x %x\n", i, b[i:end])
	}
	// The table Go built, to confirm the intern order matches.
	fmt.Printf("strings %q\n", p.stringTable)
	_ = idx
}
