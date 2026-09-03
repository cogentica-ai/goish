package net_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	show := func(tag string, err error) {
		var oe *net.OpError
		isOp := errors.As(err, &oe)
		op, nw := "", ""
		if isOp {
			op, nw = oe.Op, oe.Net
		}
		var ne net.Error
		isNet := errors.As(err, &ne)
		msg := "<nil>"
		if err != nil {
			msg = err.Error()
		}
		fmt.Printf("%-14s opErr=%-5v op=%-8q net=%-5q netErr=%-5v timeout=%-5v msg=%q\n",
			tag, isOp, op, nw, isNet, isNet && ne.Timeout(),
			strings.ReplaceAll(msg, "127.0.0.1", "IP"))
	}

	// Connection refused: nothing listening on port 1.
	_, err := net.Dial("tcp", "127.0.0.1:1")
	show("dial-refused", err)

	// A read that hits its deadline.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
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
	c, _ := net.Dial("tcp", ln.Addr().String())
	c.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	buf := make([]byte, 4)
	_, rerr := c.Read(buf)
	show("read-timeout", rerr)
	c.Close()
	<-done

	// Write to a closed connection.
	c2, _ := net.Dial("tcp", "127.0.0.1:1")
	_ = c2
	_ = os.Getpid()
}
