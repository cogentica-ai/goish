package os_test

// Reference bytes for examples/os_chtimes_ref_smoke.rs.
//
// os.Chtimes converts each time with syscall.NsecToTimespec, which
// CORRECTS a negative remainder:
//
//     sec := nsec / 1e9
//     nsec = nsec % 1e9
//     if nsec < 0 { nsec += 1e9; sec-- }
//
// Truncating division leaves tv_nsec negative for any pre-1970 time
// with a fractional part, and utimensat rejects a tv_nsec outside
// [0, 999999999] with EINVAL. So the rows that matter are the
// pre-epoch ones with a sub-second component.
//
// A zero time.Time means UTIME_OMIT — "leave this timestamp alone" —
// which is checked here too so the fix cannot regress it.

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	path := "/tmp/goish_os_chtimes_ref"

	show := func(name string, at, mt time.Time) {
		os.Remove(path)
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		// A known starting point, so an OMIT row is visible as "unchanged".
		base := time.Unix(1000000, 0).UTC()
		if err := os.Chtimes(path, base, base); err != nil {
			t.Fatal(err)
		}
		err := os.Chtimes(path, at, mt)
		if err != nil {
			fmt.Printf("GOREF %-22s err\n", name)
			return
		}
		fi, serr := os.Stat(path)
		if serr != nil {
			fmt.Printf("GOREF %-22s staterr\n", name)
			return
		}
		fmt.Printf("GOREF %-22s mtime=%s\n", name,
			fi.ModTime().UTC().Format(time.RFC3339Nano))
	}

	show("pre-epoch-frac", time.Unix(-1, 500000000), time.Unix(-1, 500000000))
	show("pre-epoch-whole", time.Unix(-2, 0), time.Unix(-2, 0))
	show("post-epoch-frac", time.Unix(1, 500000000), time.Unix(1, 500000000))
	show("epoch", time.Unix(0, 0), time.Unix(0, 0))
	show("omit-mtime", time.Unix(5, 0), time.Time{})

	os.Remove(path)
}
