package http_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "OK")
	})
	// reads the body
	mux.HandleFunc("/read", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "read=%d", len(b))
	})
	// deliberately ignores the body
	mux.HandleFunc("/noread", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "NOREAD")
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "http://")

	run := func(label, reqs string) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
		io.WriteString(c, reqs)
		b, _ := io.ReadAll(io.LimitReader(c, 16384))
		raw := string(b)
		n200 := strings.Count(raw, "HTTP/1.1 200")
		n400 := strings.Count(raw, "HTTP/1.1 400")
		bodies := []string{}
		for _, part := range strings.Split(raw, "\r\n\r\n")[1:] {
			// body runs to the start of the next response head
			if i := strings.Index(part, "HTTP/1.1 "); i >= 0 {
				part = part[:i]
			}
			bodies = append(bodies, part)
		}
		fmt.Printf("%-22s 200=%d 400=%d bodies=%v\n", label, n200, n400, bodies)
	}

	body := "12345"
	post := func(path string) string {
		return fmt.Sprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", path, len(body), body)
	}
	get := "GET /ok HTTP/1.1\r\nHost: x\r\n\r\n"
	last := "GET /ok HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"

	run("post-read+get", post("/read")+last)
	run("post-noread+get", post("/noread")+last)
	run("post-noread+2get", post("/noread")+get+last)
	run("2post-noread", post("/noread")+post("/noread")+last)
	run("chunked-read+get",
		"POST /read HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n"+last)
	run("chunked-noread+get",
		"POST /noread HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n"+last)
	// a body far bigger than the handler will read
	big := strings.Repeat("A", 70000)
	run("bigbody-noread+get",
		fmt.Sprintf("POST /noread HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n%s", len(big), big)+last)
	run("3get", get+get+last)
}
