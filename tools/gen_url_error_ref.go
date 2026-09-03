package url_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string { return "te" }
func (timeoutErr) Timeout() bool { return true }

type tempErr struct{}

func (tempErr) Error() string     { return "pe" }
func (tempErr) Temporary() bool   { return true }

type bothFalse struct{}

func (bothFalse) Error() string   { return "bf" }
func (bothFalse) Timeout() bool   { return false }
func (bothFalse) Temporary() bool { return false }

func TestGoishRef(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"plain", errors.New("boom")},
		{"nil-inner", nil},
		{"timeout-true", timeoutErr{}},
		{"temporary-true", tempErr{}},
		{"both-false", bothFalse{}},
		{"ctx-deadline", context.DeadlineExceeded},
		{"ctx-cancelled", context.Canceled},
		{"os-deadline", os.ErrDeadlineExceeded},
	}
	for _, c := range cases {
		e := &url.Error{Op: "Get", URL: "http://x/", Err: c.err}
		fmt.Printf("%-18s timeout=%-5v temporary=%-5v msg=%q\n",
			c.name, e.Timeout(), e.Temporary(), e.Error())
	}
}
