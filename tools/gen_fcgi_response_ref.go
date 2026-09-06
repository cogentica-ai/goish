package fcgi

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestGoishRef(t *testing.T) {
	cases := []struct {
		label string
		h     http.HandlerFunc
	}{
		{"plain-200", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok"))
		}},
		{"304-strips", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "5")
			w.Header().Set("Transfer-Encoding", "chunked")
			w.Header().Set("ETag", `"x"`)
			w.WriteHeader(http.StatusNotModified)
		}},
		{"304-bare", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotModified)
		}},
		{"explicit-date", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Date", "Mon, 01 Jan 2024 00:00:00 GMT")
			w.Write([]byte("ok"))
		}},
		{"handler-ct", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{}"))
		}},
	}
	for _, tc := range cases {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		go Serve(ln, tc.h)
		time.Sleep(40 * time.Millisecond)
		c, _ := net.Dial("tcp", ln.Addr().String())
		params := map[string]string{
			"REQUEST_METHOD": "GET", "SERVER_PROTOCOL": "HTTP/1.1",
			"HTTP_HOST": "x", "REQUEST_URI": "/",
		}
		var buf []byte
		buf = append(buf, zzRecord(1, 1, zzBeginReq()...)...)
		buf = append(buf, zzRecord(4, 1, zzEncodePairs(params)...)...)
		buf = append(buf, zzRecord(4, 1)...)
		buf = append(buf, zzRecord(5, 1)...)
		c.Write(buf)
		c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		raw, _ := io.ReadAll(c)
		c.Close()
		ln.Close()

		// Reassemble FCGI_STDOUT (type 6) payloads.
		var out []byte
		for i := 0; i+8 <= len(raw); {
			typ := raw[i+1]
			clen := int(raw[i+4])<<8 | int(raw[i+5])
			plen := int(raw[i+6])
			body := raw[i+8 : min(i+8+clen, len(raw))]
			if typ == 6 {
				out = append(out, body...)
			}
			i += 8 + clen + plen
		}
		head, _, _ := strings.Cut(string(out), "\r\n\r\n")
		// Normalise only a SERVER-generated Date. The explicit-date
		// case sets a fixed one and the point of that row is that it
		// survives, so blanking every Date would make it vacuous —
		// it would pass whether the value was preserved or replaced.
		head = regexp.MustCompile(`Date: [^\r\n]+`).ReplaceAllStringFunc(head, func(m string) string {
			if m == "Date: Mon, 01 Jan 2024 00:00:00 GMT" {
				return m
			}
			return "Date: DATE"
		})
		fmt.Printf("%-14s %s\n", tc.label, strings.ReplaceAll(head, "\r\n", " | "))
	}
}
func zzClone(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func zzBeginReq() []byte {
	// role=1 (RESPONDER), flags=0, reserved
	return []byte{0, 1, 0, 0, 0, 0, 0, 0}
}

func zzRecord(typ byte, reqID uint16, content ...byte) []byte {
	out := []byte{1, typ, byte(reqID >> 8), byte(reqID)}
	out = append(out, byte(len(content)>>8), byte(len(content)), 0, 0)
	return append(out, content...)
}

func zzEncodePairs(m map[string]string) []byte {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []byte
	for _, k := range keys {
		out = append(out, zzEncodeLen(len(k))...)
		out = append(out, zzEncodeLen(len(m[k]))...)
		out = append(out, k...)
		out = append(out, m[k]...)
	}
	return out
}

func zzEncodeLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	return []byte{byte(n>>24) | 0x80, byte(n >> 16), byte(n >> 8), byte(n)}
}
