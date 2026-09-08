package http_test

import (
	"errors"
	"fmt"
	"net"
	"io"
	"net/http"
	"net/http/httptest"
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

	// The OTHER half of Client.Timeout: it also covers reading the
	// BODY, and there the error is not a url.Error at all — the
	// response already came back fine. cancelTimerBody.Read
	// (client.go:972) wraps whatever the read returned, but only when
	// the client's timer is what fired, and marks it a timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.Write([]byte("0123456789"))
		w.(http.Flusher).Flush()
		time.Sleep(3 * time.Second)
	}))
	defer srv.Close()

	bc := &http.Client{Timeout: 400 * time.Millisecond}
	resp, berr := bc.Get(srv.URL)
	if berr != nil {
		fmt.Printf("body-timeout get failed: %v\n", berr)
		return
	}
	b, readErr := io.ReadAll(resp.Body)
	var bne net.Error
	isBodyNet := errors.As(readErr, &bne)
	fmt.Printf("body-timeout n=%d netErr=%-5v Timeout=%-5v err=%q\n",
		len(b), isBodyNet, isBodyNet && bne.Timeout(), errStr(readErr))
}

func errStr(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

func opOf(ue *url.Error, ok bool) string {
	if !ok {
		return ""
	}
	return ue.Op
}
