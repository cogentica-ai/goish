// gen_trailerprefix_head_ref — the "Trailer:" magic prefix must not
// reach the wire as a header.
//
//	scripts/goref.sh net/http tools/gen_trailerprefix_head_ref.go
//
// A handler announces a trailer it cannot name up front by setting
// `w.Header().Set(http.TrailerPrefix+"X-Sum", …)`. Go's
// chunkWriter.writeHeader (server.go:1331-1340) collects every such
// key into excludeHeader, so the head carries NO "Trailer:X-Sum" line
// — the value is emitted after the last chunk instead, with the prefix
// stripped. Anything else puts a header on the wire whose name
// contains a colon.
//
// The response is read off a raw socket rather than through a client,
// because a client parses trailers away and the question here is
// exactly which bytes the server wrote.
package http_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
)
import "testing"

func TestGoishRef(t *testing.T) {
	cases := []struct {
		name    string
		declare bool // announce X-Sum up front via the Trailer header
	}{
		{"prefix_only", false},
		{"declared_and_prefix", true},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c.declare {
				w.Header().Set("Trailer", "X-Declared")
			}
			w.Header().Set(http.TrailerPrefix+"X-Sum", "abc")
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "hello")
			if c.declare {
				w.Header().Set("X-Declared", "yes")
			}
		}))
		conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		raw, _ := io.ReadAll(bufio.NewReader(conn))
		conn.Close()
		srv.Close()
		out := strings.ReplaceAll(string(raw), "\r\n", "\\n")
		// Date changes every run; blank it so the row is stable.
		for _, ln := range strings.Split(out, "\\n") {
			if strings.HasPrefix(ln, "Date: ") {
				out = strings.Replace(out, ln, "Date: <elided>", 1)
			}
		}
		fmt.Printf("GOROW\t%s\t%q\n", c.name, out)
	}
}
