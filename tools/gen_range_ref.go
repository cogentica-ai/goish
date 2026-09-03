package http

import (
	"fmt"
	"strings"
	"testing"
)

// A Range header is attacker-controlled input that decides how much of
// a file a server reads and sends. Its parser is therefore doing
// resource arithmetic on numbers a client chose, and the failure modes
// are not "wrong bytes" — they are "read past the end", "allocate
// something enormous", or "serve a byte range the caller never
// authorised".
//
// Go's parseRange is where every one of those is prevented, and the
// rules are specific:
//
//   * A range whose start is at or past the size is UNSATISFIABLE and
//     the whole header is rejected — not clamped, not ignored.
//   * A suffix range ("-500") counts back from the end, and one longer
//     than the file is clamped to the whole file rather than refused.
//   * An end past the last byte is clamped; a start past the end is
//     not.
//   * Overlapping and out-of-order ranges are ALLOWED, which is what
//     makes a bounded count necessary elsewhere: a client can ask for
//     the same bytes many times over.
//   * Anything malformed — a missing unit, a reversed pair, a negative
//     start, a non-number — is an error rather than a partial parse.
//
// A zero-size file is its own case: every range over it is
// unsatisfiable, including the suffix form.
func TestGoishRef(t *testing.T) {
	for _, size := range []int64{0, 1, 10, 1000} {
		for _, h := range []string{
			"", "bytes=0-0", "bytes=0-", "bytes=-1", "bytes=-5", "bytes=5-",
			"bytes=0-9", "bytes=0-100", "bytes=9-9", "bytes=10-", "bytes=10-20",
			"bytes=1000-", "bytes=-0", "bytes=-1000", "bytes=0-0,2-2",
			"bytes=0-1,1-2", "bytes=2-3,0-1", "bytes= 0-1", "bytes=0-1 ",
			"bytes=0-1, 2-3", "bytes=0-1,,2-3", "bytes=0-1,",
			"bytes=-", "bytes=1-0", "bytes=a-b", "bytes=0-b", "bytes=-a",
			"bytes=0--1", "bytes=+0-1", "items=0-1", "0-1", "bytes",
			"bytes=", "bytes=0-1-2", "bytes=999999999999999999999-",
			"bytes=0-999999999999999999999",
		} {
			rs, err := parseRange(h, size)
			if err != nil {
				fmt.Printf("range size=%-4d %-28q -> err=%q\n", size, h, err.Error())
				continue
			}
			var parts []string
			for _, r := range rs {
				parts = append(parts, fmt.Sprintf("%d+%d", r.start, r.length))
			}
			fmt.Printf("range size=%-4d %-28q -> n=%d [%s]\n",
				size, h, len(rs), strings.Join(parts, " "))
		}
	}
}
