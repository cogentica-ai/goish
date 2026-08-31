package net_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
)

// timeoutErr is the shape OpError wraps: an error that answers
// Timeout() true. Go's assertion `err.(interface{ Timeout() bool })`
// reaches it through the error interface; a port whose assertion
// downcasts the handle instead of what it wraps answers false for
// every one of these.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

type tempErr struct{}

func (tempErr) Error() string   { return "temporary" }
func (tempErr) Timeout() bool   { return false }
func (tempErr) Temporary() bool { return true }

type plainErr struct{}

func (plainErr) Error() string { return "plain" }

func TestGoishRef(t *testing.T) {
	// OpError.Timeout and .Temporary forward to the wrapped error's,
	// and answer false when it has no such method.
	for _, c := range []struct {
		name string
		err  error
	}{
		{"timeout", timeoutErr{}},
		{"temporary", tempErr{}},
		{"plain", plainErr{}},
		{"deadline", context.DeadlineExceeded},
		{"canceled", context.Canceled},
	} {
		op := &net.OpError{Op: "read", Net: "tcp", Err: c.err}
		fmt.Printf("operror %-10s timeout=%-5v temporary=%-5v err=%q\n",
			c.name, op.Timeout(), op.Temporary(), op.Error())
	}

	// The accept special case: ECONNRESET/ECONNABORTED from accept are
	// temporary even though the wrapped error is not.
	for _, op := range []string{"read", "accept"} {
		e := &net.OpError{Op: op, Net: "tcp", Err: plainErr{}}
		fmt.Printf("accept-case op=%-7s temporary=%v\n", op, e.Temporary())
	}

	// net.Error assertions against each concrete type in the package.
	for _, c := range []struct {
		name string
		err  error
	}{
		{"OpError", &net.OpError{Op: "dial", Err: timeoutErr{}}},
		{"ParseError", &net.ParseError{Type: "IP address", Text: "x"}},
		{"AddrError", &net.AddrError{Err: "bad", Addr: "y"}},
		{"UnknownNetworkError", net.UnknownNetworkError("quux")},
		{"InvalidAddrError", net.InvalidAddrError("zap")},
		{"DNSError", &net.DNSError{Err: "no such host", Name: "h", IsTimeout: true}},
	} {
		var ne net.Error
		ok := errors.As(c.err, &ne)
		fmt.Printf("aserror %-20s ok=%-5v timeout=%-5v temporary=%-5v text=%q\n",
			c.name, ok, ok && ne.Timeout(), ok && ne.Temporary(), c.err.Error())
	}

	// A DNSError built around a timeout carries IsTimeout through.
	de := &net.DNSError{Err: "i/o timeout", Name: "h", Server: "s", IsTimeout: true}
	var ne net.Error
	ok := errors.As(de, &ne)
	fmt.Printf("dnserror as=%v timeout=%v text=%q\n", ok, ok && ne.Timeout(), de.Error())

	// os.ErrDeadlineExceeded is a net.Error too, and the standard
	// library relies on that.
	ok = errors.As(os.ErrDeadlineExceeded, &ne)
	fmt.Printf("osdeadline as=%v timeout=%v\n", ok, ok && ne.Timeout())
}
