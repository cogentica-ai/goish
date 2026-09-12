// gen_cpuprofile_ref — ground truth for runtime/pprof's StartCPUProfile /
// StopCPUProfile pair (goish issue #9).
//
// Run with:
//   scripts/goish/../goref.sh runtime/pprof tools/gen_cpuprofile_ref.go
//
// It is an INTERNAL test (package pprof) so it can import
// internal/profile, the parser Go's own pprof tests use to check what
// StopCPUProfile actually wrote. Parsing beats byte-comparing: the
// profile embeds timestamps and this machine's PCs, so no two runs
// agree byte for byte, but the SHAPE is a contract goish must match.
package pprof

import (
	"bytes"
	"errors"
	"fmt"
	"internal/profile"
	"testing"
	"time"
)

// A writer that refuses every Write, for the failing-writer case.
type failWriter struct{}

func (failWriter) Write(p []byte) (int, error) { return 0, errors.New("boom") }

func TestGoishRef(t *testing.T) {
	// 1. Stop without a start must be a silent no-op, not a panic.
	StopCPUProfile()
	fmt.Println("stop_without_start ok")

	// 2. Start twice: the second must fail, and the message is the
	//    contract net/http/pprof surfaces to a user.
	var buf bytes.Buffer
	if err := StartCPUProfile(&buf); err != nil {
		t.Fatalf("first StartCPUProfile: %v", err)
	}
	err := StartCPUProfile(&bytes.Buffer{})
	fmt.Printf("double_start_err %q\n", fmt.Sprint(err))

	// Burn CPU so the sampler has something to record.
	deadline := time.Now().Add(300 * time.Millisecond)
	x := 0
	for time.Now().Before(deadline) {
		for i := 0; i < 100000; i++ {
			x += i * i
		}
	}
	_ = x
	StopCPUProfile()

	// 3. After Stop the writer holds a gzipped profile.proto.
	b := buf.Bytes()
	fmt.Printf("gzip_magic %02x%02x\n", b[0], b[1])
	p, perr := profile.Parse(bytes.NewReader(b))
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	for i, st := range p.SampleType {
		fmt.Printf("sample_type[%d] %s/%s\n", i, st.Type, st.Unit)
	}
	fmt.Printf("period_type %s/%s\n", p.PeriodType.Type, p.PeriodType.Unit)
	fmt.Printf("period %d\n", p.Period)
	fmt.Printf("sample_values %d\n", len(p.Sample[0].Value))
	fmt.Printf("has_samples %v\n", len(p.Sample) > 0)
	fmt.Printf("has_locations %v\n", len(p.Location) > 0)
	fmt.Printf("time_nanos_set %v\n", p.TimeNanos > 0)
	fmt.Printf("duration_set %v\n", p.DurationNanos > 0)

	// 4. value[1] is value[0] scaled by the period — that is how a
	//    count of samples becomes nanoseconds of CPU.
	s := p.Sample[0]
	fmt.Printf("value1_is_value0_times_period %v\n", s.Value[1] == s.Value[0]*p.Period)

	// 5. Stopping twice is also a no-op.
	StopCPUProfile()
	fmt.Println("double_stop ok")

	// 5b. A writer that fails every Write. StopCPUProfile has nowhere
	//     to report an error, so the question is only whether it
	//     panics or hangs. Issue #9 lists this as a differential.
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("failing_writer_panicked true (%v)\n", r)
			} else {
				fmt.Println("failing_writer_panicked false")
			}
		}()
		if err := StartCPUProfile(failWriter{}); err != nil {
			t.Fatalf("start with failing writer: %v", err)
		}
		d := time.Now().Add(150 * time.Millisecond)
		x := 0
		for time.Now().Before(d) {
			for i := 0; i < 100000; i++ {
				x += i
			}
		}
		_ = x
		StopCPUProfile()
		fmt.Println("failing_writer_stop_returned true")
	}()

	// 6. And a profile can be started again after being stopped.
	var buf2 bytes.Buffer
	fmt.Printf("restart_err %v\n", StartCPUProfile(&buf2) == nil)
	StopCPUProfile()
}
