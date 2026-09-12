// gen_heapprofile_ref — ground truth for the heap and allocs builtin
// profiles (goish issue #9, contract items 4-6).
//
//   scripts/goref.sh runtime/pprof tools/gen_heapprofile_ref.go
//
// Internal test (package pprof) so it can use internal/profile, the
// parser Go's own pprof tests use.
package pprof

import (
	"bytes"
	"fmt"
	"internal/profile"
	"runtime"
	"testing"
)

//go:noinline
func allocSite(n int) [][]byte {
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, make([]byte, 4096))
	}
	return out
}

func TestGoishRef(t *testing.T) {
	// The default rate samples one allocation per 512 KiB, which is
	// too coarse to make a deterministic assertion. Go's own tests set
	// it to 1 for exactly this reason.
	old := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	defer func() { runtime.MemProfileRate = old }()

	keep := allocSite(300)
	runtime.GC()

	for _, name := range []string{"heap", "allocs"} {
		p := Lookup(name)
		fmt.Printf("lookup_%s_nonnil %v\n", name, p != nil)
		if p == nil {
			continue
		}
		fmt.Printf("lookup_%s_name %s\n", name, p.Name())
		var buf bytes.Buffer
		err := p.WriteTo(&buf, 0)
		fmt.Printf("writeto_%s_err %v\n", name, err == nil)
		b := buf.Bytes()
		fmt.Printf("%s_gzip_magic %02x%02x\n", name, b[0], b[1])
		pr, perr := profile.Parse(bytes.NewReader(b))
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for i, st := range pr.SampleType {
			fmt.Printf("%s_sample_type[%d] %s/%s\n", name, i, st.Type, st.Unit)
		}
		fmt.Printf("%s_period_type %s/%s\n", name, pr.PeriodType.Type, pr.PeriodType.Unit)
		fmt.Printf("%s_period %d\n", name, pr.Period)
		fmt.Printf("%s_default_sample_type %q\n", name, pr.DefaultSampleType)
		fmt.Printf("%s_has_samples %v\n", name, len(pr.Sample) > 0)
		fmt.Printf("%s_values_per_sample %d\n", name, len(pr.Sample[0].Value))

		// The workload must actually show up, named.
		found := false
		var allocObjs, allocBytes int64
		for _, s := range pr.Sample {
			for _, loc := range s.Location {
				for _, ln := range loc.Line {
					if ln.Function != nil && ln.Function.Name == "runtime/pprof.allocSite" {
						found = true
						allocObjs += s.Value[0]
						allocBytes += s.Value[1]
					}
				}
			}
		}
		fmt.Printf("%s_workload_symbolized %v\n", name, found)
		fmt.Printf("%s_workload_objects_ge_300 %v\n", name, allocObjs >= 300)
		fmt.Printf("%s_workload_bytes_ge_1mb %v\n", name, allocBytes >= 300*4096)
	}
	runtime.KeepAlive(keep)

	// Names of every builtin profile, and their order.
	ps := Profiles()
	fmt.Printf("profiles_count %d\n", len(ps))
	for _, p := range ps {
		fmt.Printf("profile_name %s\n", p.Name())
	}
}

// Second pass: the facts the first one did not ask for — whether a heap
// profile carries timestamps, and how Go SCALES a sampled profile back
// up to an estimate of the whole heap.
func TestGoishRefScale(t *testing.T) {
	old := runtime.MemProfileRate
	defer func() { runtime.MemProfileRate = old }()

	// Timestamps.
	runtime.MemProfileRate = 1
	keep := allocSite(50)
	runtime.GC()
	var buf bytes.Buffer
	if err := Lookup("heap").WriteTo(&buf, 0); err != nil {
		t.Fatal(err)
	}
	pr, err := profile.Parse(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("heap_time_nanos_set %v\n", pr.TimeNanos > 0)
	fmt.Printf("heap_duration_set %v\n", pr.DurationNanos > 0)
	runtime.KeepAlive(keep)

	// Scaling. At rate 1 every allocation is recorded and the numbers
	// are exact. Above 1, Go scales each sample by
	// 1/(1-exp(-avgSize/rate)) so the profile estimates the whole heap
	// from the part it saw.
	for _, rate := range []int{1, 4096} {
		runtime.MemProfileRate = rate
		k2 := allocSite(2000)
		runtime.GC()
		var b2 bytes.Buffer
		if err := Lookup("allocs").WriteTo(&b2, 0); err != nil {
			t.Fatal(err)
		}
		p2, err := profile.Parse(bytes.NewReader(b2.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		var objs, space int64
		for _, s := range p2.Sample {
			for _, loc := range s.Location {
				for _, ln := range loc.Line {
					if ln.Function != nil && ln.Function.Name == "runtime/pprof.allocSite" {
						objs += s.Value[0]
						space += s.Value[1]
					}
				}
			}
		}
		// 2000 objects of 4096 bytes were allocated by this site in
		// this round; earlier rounds add to the cumulative total, so
		// the assertion is a lower bound and a sanity ceiling.
		fmt.Printf("rate%d_objects_at_least_2000 %v\n", rate, objs >= 2000)
		fmt.Printf("rate%d_space_per_object_near_4096 %v\n", rate, objs > 0 && space/objs >= 3000 && space/objs <= 6000)
		runtime.KeepAlive(k2)
	}
}
