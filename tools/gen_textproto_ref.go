package textproto_test

import (
	"bufio"
	"fmt"
	"net/textproto"
	"strings"
	"testing"
)

// textproto is what parses an HTTP header block. A header key that
// canonicalises differently, or a continuation line that is folded
// differently, changes which handler sees which value — and the
// difference is silent, because both sides produce a map.
func TestGoishRef(t *testing.T) {
	keys := []string{
		"", "a", "A", "accept", "ACCEPT", "Accept-Encoding", "accept-encoding",
		"ACCEPT-ENCODING", "aCcEpT-eNcOdInG", "x", "-", "a-", "-a", "a--b",
		"content-type", "www-authenticate", "etag", "ETag", "TE", "te",
		"user_agent", "user agent", "a b", "héllo", "x-1-2", "1-a",
	}
	for _, k := range keys {
		fmt.Printf("canon %-18q -> %q\n", k, textproto.CanonicalMIMEHeaderKey(k))
	}

	// MIMEHeader Get/Set/Add/Del/Values all canonicalise their key.
	h := textproto.MIMEHeader{}
	h.Set("content-type", "text/plain")
	h.Add("Set-Cookie", "a=1")
	h.Add("set-cookie", "b=2")
	fmt.Printf("hdr get=%q values=%q missing=%q missingv=%v\n",
		h.Get("Content-Type"), h.Values("SET-COOKIE"), h.Get("nope"), h.Values("nope"))
	h.Del("CONTENT-TYPE")
	fmt.Printf("hdr afterdel=%q len=%d\n", h.Get("content-type"), len(h))
	// Get on a nil header is "" and never panics.
	var nilh textproto.MIMEHeader
	fmt.Printf("nilhdr get=%q values=%v\n", nilh.Get("a"), nilh.Values("a"))

	// ReadMIMEHeader, including continuations, duplicates and the
	// malformed shapes.
	blocks := []string{
		"A: 1\r\nB: 2\r\n\r\n",
		"a: 1\r\na: 2\r\n\r\n",
		"A:1\r\n\r\n",
		"A:   spaced   \r\n\r\n",
		"A: one\r\n two\r\n\tthree\r\n\r\n",
		"A: \r\n\r\n",
		"A: 1\n B: 2\n\n",
		"\r\n",
		"A: 1\r\n",
		"A 1\r\n\r\n",
		" A: 1\r\n\r\n",
		"A: 1\r\nA: 2\r\nB: 3\r\n\r\n",
		"Empty:\r\n\r\n",
	}
	for _, b := range blocks {
		r := textproto.NewReader(bufio.NewReader(strings.NewReader(b)))
		m, err := r.ReadMIMEHeader()
		fmt.Printf("mime %-28q err=%v m=%v\n", b, err, m)
	}

	// ReadLine / ReadContinuedLine.
	for _, b := range []string{
		"one\r\ntwo\r\n", "one\ntwo\n", "one\r\n cont\r\nnext\r\n",
		"one\r\n\tcont\r\n", "\r\n", "no-newline",
	} {
		r := textproto.NewReader(bufio.NewReader(strings.NewReader(b)))
		l1, e1 := r.ReadLine()
		l2, e2 := r.ReadLine()
		fmt.Printf("line %-22q (%q,%v) (%q,%v)\n", b, l1, e1, l2, e2)
		r2 := textproto.NewReader(bufio.NewReader(strings.NewReader(b)))
		c1, ce1 := r2.ReadContinuedLine()
		c2, ce2 := r2.ReadContinuedLine()
		fmt.Printf("cont %-22q (%q,%v) (%q,%v)\n", b, c1, ce1, c2, ce2)
	}

	// TrimString / TrimBytes.
	for _, s := range []string{"", " ", " a ", "\ta\t", "\r\na\r\n", "a b", "  ",
		"\t \r\n x \r\n \t"} {
		fmt.Printf("trim %-14q -> %q bytes=%q\n", s, textproto.TrimString(s),
			textproto.TrimBytes([]byte(s)))
	}
}
