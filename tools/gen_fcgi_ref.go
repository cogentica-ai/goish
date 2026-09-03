package fcgi

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"
)

// FastCGI is a length-prefixed binary protocol read straight off a
// socket, which puts it in the class where a parser's handling of
// HOSTILE framing decides everything above it. A record announces its
// own content length in two bytes; a params stream announces each
// name's and value's length in one or four; and every one of those
// numbers comes from the peer.
//
// What is measured is what a HANDLER SEES after the parser is done —
// the method, the URL, the headers and the body — because that is the
// only thing the rest of the program acts on. Records are written by
// hand here rather than by a client library, so the inputs include
// shapes no cooperating client would send.
//
// The rules worth pinning:
//
//   * A parameter name or value under 128 bytes uses a ONE-byte
//     length; 128 or over sets the high bit and uses FOUR. A parser
//     that reads the wrong width walks off into the next field and
//     produces a request built from the wrong bytes.
//   * HTTP_ parameters become headers with underscores turned back
//     into dashes, and CONTENT_TYPE and CONTENT_LENGTH become headers
//     without the prefix. Both land in the SAME header: a peer sending
//     HTTP_CONTENT_TYPE gets a second Content-Type value beside the
//     real one rather than being ignored, which the `headers` line
//     below shows as "real/type|forged/type". Anything reading
//     Header.Get sees the first; anything reading Header.Values sees
//     both, and they disagree.
//   * An empty PARAMS record TERMINATES the stream; STDIN works the
//     same way, and a request with no terminator waits rather than
//     dispatching.
func TestGoishRef(t *testing.T) {
	run := func(label string, params map[string]string, stdin string, mangle func([]byte) []byte) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		seen := make(chan string, 1)
		go func() {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var keys []string
				for k := range r.Header {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				var hs []string
				for _, k := range keys {
					hs = append(hs, fmt.Sprintf("%s=%q", k, strings.Join(r.Header[k], "|")))
				}
				body, _ := io.ReadAll(r.Body)
				seen <- fmt.Sprintf("method=%s uri=%q host=%q len=%d hdr=[%s] body=%q",
					r.Method, r.RequestURI, r.Host, r.ContentLength,
					strings.Join(hs, " "), string(body))
				w.Write([]byte("ok"))
			})
			Serve(ln, h)
		}()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		var buf []byte
		buf = append(buf, zzRecord(1, 1, zzBeginReq()...)...) // BEGIN_REQUEST
		buf = append(buf, zzRecord(4, 1, zzEncodePairs(params)...)...)
		buf = append(buf, zzRecord(4, 1)...) // empty PARAMS ends the stream
		if stdin != "" {
			buf = append(buf, zzRecord(5, 1, []byte(stdin)...)...)
		}
		buf = append(buf, zzRecord(5, 1)...) // empty STDIN
		if mangle != nil {
			buf = mangle(buf)
		}
		c.Write(buf)
		// The server does not close the connection, so read with a
		// deadline rather than to EOF: what is being measured is the
		// request the handler saw, not the response framing.
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		io.ReadAll(c)
		c.Close()
		select {
		case s := <-seen:
			fmt.Printf("fcgi %-22s -> %s\n", label, s)
		case <-time.After(2 * time.Second):
			fmt.Printf("fcgi %-22s -> <no request dispatched>\n", label)
		}
	}

	base := map[string]string{
		"REQUEST_METHOD":  "GET",
		"REQUEST_URI":     "/path?q=1",
		"SERVER_PROTOCOL": "HTTP/1.1",
		"HTTP_HOST":       "example.test",
	}

	run("plain", base, "", nil)

	withHdrs := zzClone(base)
	withHdrs["HTTP_X_SIMPLE"] = "one"
	withHdrs["HTTP_X_TWO_WORDS"] = "two"
	withHdrs["HTTP_CONTENT_TYPE"] = "forged/type"
	withHdrs["CONTENT_TYPE"] = "real/type"
	run("headers", withHdrs, "", nil)

	post := zzClone(base)
	post["REQUEST_METHOD"] = "POST"
	post["CONTENT_TYPE"] = "application/x-www-form-urlencoded"
	post["CONTENT_LENGTH"] = "11"
	run("post", post, "field=value", nil)

	long := zzClone(base)
	long["HTTP_X_LONG"] = strings.Repeat("v", 300)
	long[strings.Repeat("HTTP_K", 30)] = "longname"
	run("long-values", long, "", nil)

	empty := zzClone(base)
	empty["HTTP_X_EMPTY"] = ""
	empty[""] = "empty-name"
	run("empty-name-and-value", empty, "", nil)

	// A params stream whose declared length exceeds the record — the
	// parser must not read past the record into the next one.
	run("truncated-pairs", base, "", func(b []byte) []byte {
		out := append([]byte(nil), b...)
		// Find the PARAMS record (type 4) and inflate the first name
		// length byte so it claims more than the record holds.
		for i := 0; i+8 < len(out); {
			typ := out[i+1]
			clen := int(binary.BigEndian.Uint16(out[i+4 : i+6]))
			plen := int(out[i+6])
			if typ == 4 && clen > 0 {
				out[i+8] = 0x7f // a 127-byte name inside a short record
				break
			}
			i += 8 + clen + plen
		}
		return out
	})

	// A record header claiming a content length far beyond what
	// follows.
	run("oversized-record", base, "", func(b []byte) []byte {
		out := append([]byte(nil), b...)
		for i := 0; i+8 < len(out); {
			typ := out[i+1]
			clen := int(binary.BigEndian.Uint16(out[i+4 : i+6]))
			plen := int(out[i+6])
			if typ == 4 && clen > 0 {
				binary.BigEndian.PutUint16(out[i+4:i+6], 0xffff)
				break
			}
			i += 8 + clen + plen
		}
		return out
	})

	// An unknown record type must be ignored, not fatal.
	run("unknown-record-type", base, "", func(b []byte) []byte {
		return append(zzRecord(99, 1, []byte("junk")...), b...)
	})
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
