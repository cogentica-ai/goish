package net_test

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	// Accept after Close: Go's ErrClosed path.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	_, aerr := ln.Accept()
	var oe *net.OpError
	isOp := errors.As(aerr, &oe)
	op, nw := "", ""
	if isOp {
		op, nw = oe.Op, oe.Net
	}
	var ne net.Error
	isNet := errors.As(aerr, &ne)
	msg := ""
	if aerr != nil {
		msg = strings.ReplaceAll(aerr.Error(), addr, "ADDR")
	}
	fmt.Printf("accept-closed  opErr=%-5v op=%-8q net=%-5q netErr=%-5v msg=%q\n",
		isOp, op, nw, isNet, msg)

	// Accept that hits a deadline.
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln2.Close()
	addr2 := ln2.Addr().String()
	tl := ln2.(*net.TCPListener)
	tl.SetDeadline(time.Now().Add(80 * time.Millisecond))
	_, aerr2 := tl.Accept()
	isOp2 := errors.As(aerr2, &oe)
	op2, nw2 := "", ""
	if isOp2 {
		op2, nw2 = oe.Op, oe.Net
	}
	isNet2 := errors.As(aerr2, &ne)
	to2 := isNet2 && ne.Timeout()
	msg2 := ""
	if aerr2 != nil {
		msg2 = strings.ReplaceAll(aerr2.Error(), addr2, "ADDR")
	}
	fmt.Printf("accept-timeout opErr=%-5v op=%-8q net=%-5q netErr=%-5v timeout=%-5v msg=%q\n",
		isOp2, op2, nw2, isNet2, to2, msg2)
}
