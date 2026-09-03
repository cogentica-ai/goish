package net_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
)

func TestGoishRef(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"deadline-bare", os.ErrDeadlineExceeded},
		{"oper-deadline", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}},
		{"oper-plain", &net.OpError{Op: "read", Net: "tcp", Err: errors.New("boom")}},
	}
	for _, c := range cases {
		// The two ways a caller asks, both of which must agree.
		to, okT := c.err.(interface{ Timeout() bool })
		tm, okM := c.err.(interface{ Temporary() bool })
		ne, okN := c.err.(net.Error)
		fmt.Printf("%-14s iface-timeout=%-5v iface-temporary=%-5v net.Error=%-5v netTimeout=%-5v osIsTimeout=%v\n",
			c.name,
			okT && to.Timeout(),
			okM && tm.Temporary(),
			okN,
			okN && ne.Timeout(),
			os.IsTimeout(c.err))
	}
}
