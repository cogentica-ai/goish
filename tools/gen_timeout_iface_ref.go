package net_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"
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
	// A REAL socket read deadline, so the error is the one `net`
	// actually produces rather than one built by hand here.
	ln, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatal(lerr)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := ln.Accept()
		if e == nil {
			time.Sleep(300 * time.Millisecond)
			c.Close()
		}
	}()
	dc, derr := net.Dial("tcp", ln.Addr().String())
	if derr != nil {
		t.Fatal(derr)
	}
	dc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 16)
	_, realErr := dc.Read(buf)
	dc.Close()
	cases = append(cases, struct {
		name string
		err  error
	}{"real-read-timeout", realErr})

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
	<-done
}
