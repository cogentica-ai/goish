package http_test

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	// A listener that accepts and never answers, so the client's own
	// timeout is what ends the request.
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
			time.Sleep(600 * time.Millisecond)
			c.Close()
		}
	}()

	client := &http.Client{Timeout: 150 * time.Millisecond}
	_, rerr := client.Get("http://" + ln.Addr().String() + "/x")

	var ue *url.Error
	isURLErr := errors.As(rerr, &ue)
	timeout, temporary := false, false
	if isURLErr {
		timeout, temporary = ue.Timeout(), ue.Temporary()
	}
	var ne net.Error
	isNetErr := errors.As(rerr, &ne)
	fmt.Printf("client-timeout urlErr=%-5v Timeout=%-5v Temporary=%-5v netErr=%-5v op=%q\n",
		isURLErr, timeout, temporary, isNetErr, opOf(ue, isURLErr))
	<-done
}

func opOf(ue *url.Error, ok bool) string {
	if !ok {
		return ""
	}
	return ue.Op
}
