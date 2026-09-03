package http

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
)

func TestGoishRef(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"eof", io.EOF},
		{"nil-like", errors.New("boom")},
		{"deadline", os.ErrDeadlineExceeded},
		{"oper-read", &net.OpError{Op: "read", Err: errors.New("x")}},
		{"oper-write", &net.OpError{Op: "write", Err: errors.New("x")}},
		{"oper-dial", &net.OpError{Op: "dial", Err: errors.New("x")}},
		{"oper-read-timeout", &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}},
		// The text-matching trap: a plain error that merely READS like one.
		{"text-read-prefix", errors.New("read: malformed chunk size")},
		{"text-io-timeout", errors.New("json: i/o timeout in field")},
	}
	for _, c := range cases {
		fmt.Printf("%-18s %v\n", c.name, isCommonNetReadError(c.err))
	}
}
