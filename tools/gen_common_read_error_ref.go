package http

import (
	"errors"
	"fmt"
	"io"
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

	// The case that matters most, and the one hand-built errors cannot
	// stand in for: a REAL socket read deadline, with the error built
	// by the net package the way production builds it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 16)
	_, rerr := c.Read(buf)
	fmt.Printf("%-18s %v\n", "real-read-timeout", isCommonNetReadError(rerr))
	<-done
}
