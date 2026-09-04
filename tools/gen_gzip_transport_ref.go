package http_test

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Go's Transport asks for gzip on the caller's behalf and unwraps the
// answer before the caller ever sees it — but ONLY when the caller did
// not ask for an encoding themselves. That condition is the whole
// design, and it is easy to get backwards.
//
// The rule, in the shape a port has to reproduce:
//
//   * If the caller set no Accept-Encoding, no Range, the method is not
//     HEAD, and DisableCompression is false, the transport adds
//     "Accept-Encoding: gzip" and REMEMBERS that it did. A gzipped
//     answer is then decoded transparently: the body reads as plain
//     bytes, Content-Encoding and Content-Length are REMOVED so nobody
//     downstream believes stale framing, ContentLength becomes -1, and
//     Uncompressed reports true.
//   * If the caller set Accept-Encoding themselves — even to exactly
//     "gzip" — the transport does none of that. The caller asked for
//     the encoded bytes and gets them, Content-Encoding intact. A
//     proxy relies on this: it must relay what the origin sent, not a
//     decoded copy with headers that no longer describe it.
//   * A "Content-Encoding: gzip" that arrives when gzip was NOT
//     requested is passed through untouched, whatever it contains.
//
// The header the SERVER sees is reported too, because "did the
// transport ask for gzip" is not observable from the client side at
// all — and a port that decodes without asking, or asks without
// decoding, is broken in a way the response alone cannot show.
func TestGoishRef(t *testing.T) {
	payload := strings.Repeat("gzip round trip ", 8)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(payload))
	zw.Close()
	gzBytes := gz.Bytes()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ae := r.Header.Get("Accept-Encoding")
		w.Header().Set("X-Saw-Accept-Encoding", fmt.Sprintf("%q", ae))
		switch r.URL.Path {
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", fmt.Sprint(len(gzBytes)))
			w.Write(gzBytes)
		case "/gzip-always":
			// Gzipped whether or not the client asked.
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(gzBytes)
		case "/gzip-corrupt":
			w.Header().Set("Content-Encoding", "gzip")
			w.Write([]byte("not actually gzip at all, not even close"))
		case "/gzip-truncated":
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(gzBytes[:len(gzBytes)/2])
		case "/gzip-empty":
			w.Header().Set("Content-Encoding", "gzip")
		case "/identity":
			w.Header().Set("Content-Encoding", "identity")
			w.Write([]byte(payload))
		case "/deflate":
			w.Header().Set("Content-Encoding", "deflate")
			w.Write([]byte(payload))
		default:
			w.Write([]byte(payload))
		}
	}))
	defer srv.Close()

	show := func(label string, resp *http.Response, err error) {
		if err != nil {
			fmt.Printf("%-34s -> err=%s\n", label, err.Error())
			return
		}
		body, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		re := "<nil>"
		if rerr != nil {
			re = rerr.Error()
		}
		out := string(body)
		same := out == payload
		if len(out) > 24 {
			out = out[:24] + "…"
		}
		fmt.Printf("%-34s -> code=%d saw-ae=%s ce=%q clen-hdr=%q ContentLength=%d "+
			"Uncompressed=%v n=%d same=%v err=%s out=%q\n",
			label, resp.StatusCode, resp.Header.Get("X-Saw-Accept-Encoding"),
			resp.Header.Get("Content-Encoding"), resp.Header.Get("Content-Length"),
			resp.ContentLength, resp.Uncompressed, len(body), same, re, out)
	}

	paths := []string{"/gzip", "/gzip-always", "/plain", "/identity", "/deflate",
		"/gzip-corrupt", "/gzip-truncated", "/gzip-empty"}

	// 1. Default transport: asks for gzip, decodes what comes back.
	for _, p := range paths {
		c := &http.Client{Transport: &http.Transport{}}
		resp, err := c.Get(srv.URL + p)
		show("default"+p, resp, err)
	}

	// 2. The caller set Accept-Encoding: hands-off, whatever the value.
	for _, ae := range []string{"gzip", "gzip, deflate", "identity", "*", ""} {
		req, _ := http.NewRequest("GET", srv.URL+"/gzip", nil)
		if ae != "" {
			req.Header.Set("Accept-Encoding", ae)
		} else {
			// An EXPLICIT empty value is not the same as absent: Go
			// treats the key's presence as the caller having decided.
			req.Header["Accept-Encoding"] = []string{""}
		}
		c := &http.Client{Transport: &http.Transport{}}
		resp, err := c.Do(req)
		show(fmt.Sprintf("caller-ae=%-14q", ae), resp, err)
	}

	// 3. DisableCompression: never ask, never decode.
	for _, p := range []string{"/gzip", "/plain"} {
		c := &http.Client{Transport: &http.Transport{DisableCompression: true}}
		resp, err := c.Get(srv.URL + p)
		show("disabled"+p, resp, err)
	}

	// 4. The suppressing conditions: a Range request and HEAD.
	{
		req, _ := http.NewRequest("GET", srv.URL+"/plain", nil)
		req.Header.Set("Range", "bytes=0-3")
		c := &http.Client{Transport: &http.Transport{}}
		resp, err := c.Do(req)
		show("range-request", resp, err)
	}
	{
		c := &http.Client{Transport: &http.Transport{}}
		resp, err := c.Head(srv.URL + "/plain")
		show("head-request", resp, err)
	}

	// 5. What a gzipped answer looks like when the caller asked for it
	//    and must decode it themselves.
	{
		req, _ := http.NewRequest("GET", srv.URL+"/gzip", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		c := &http.Client{Transport: &http.Transport{}}
		resp, err := c.Do(req)
		if err != nil {
			fmt.Printf("manual-decode -> err=%s\n", err.Error())
		} else {
			zr, zerr := gzip.NewReader(resp.Body)
			if zerr != nil {
				fmt.Printf("manual-decode -> newreader-err=%s\n", zerr.Error())
			} else {
				out, rerr := io.ReadAll(zr)
				re := "<nil>"
				if rerr != nil {
					re = rerr.Error()
				}
				fmt.Printf("manual-decode -> same=%v n=%d err=%s\n",
					string(out) == payload, len(out), re)
			}
			resp.Body.Close()
		}
	}
}
