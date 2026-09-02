package multipart_test

import (
	"fmt"
	"io"
	"mime/multipart"
	"mime/quotedprintable"
	"strings"
	"testing"
)

// mime/multipart parses HTTP request bodies — file uploads, form
// submissions — so its input is attacker-shaped by default, and every
// rule about where a part begins and ends is a place two parsers can
// be made to disagree. Nothing in the tree had measured it.
//
// The rules that are easy to get wrong while every browser-generated
// upload still parses:
//
//   * A boundary only counts at the START OF A LINE. "--b" in the
//     middle of a body is data, not a delimiter, and a parser that
//     scans for the bare string truncates a file at whatever byte
//     happens to contain it.
//   * The CRLF BEFORE a delimiter belongs to the delimiter, not to the
//     part, so the part's content does not end with it. Off by that
//     two-byte sequence and every uploaded file gains a trailing
//     newline.
//   * Bare LF is accepted as well as CRLF, because real clients send
//     both.
//   * Trailing whitespace after a delimiter is allowed; other trailing
//     text is not, and makes the line ordinary data.
//   * The preamble before the first delimiter and the epilogue after
//     the closing one are ignored entirely.
//   * A part with a Content-Transfer-Encoding of quoted-printable is
//     decoded TRANSPARENTLY by NextPart, and that header is then
//     removed from the part.
//   * FormName is empty unless the disposition is exactly form-data;
//     FileName is taken from the filename parameter and is base-named,
//     which is what stops "../../etc/passwd" from being a path.
func TestGoishRef(t *testing.T) {
	// 1. The shapes a reader must accept, and where each part ends.
	type tc struct {
		name string
		body string
		bnd  string
	}
	for _, c := range []tc{
		{"simple", "--b\r\nA: 1\r\n\r\nbody\r\n--b--\r\n", "b"},
		{"two-parts", "--b\r\n\r\none\r\n--b\r\n\r\ntwo\r\n--b--\r\n", "b"},
		{"bare-lf", "--b\nA: 1\n\nbody\n--b--\n", "b"},
		{"preamble", "junk\r\nmore\r\n--b\r\n\r\nx\r\n--b--\r\n", "b"},
		{"epilogue", "--b\r\n\r\nx\r\n--b--\r\ntrailing junk\r\n", "b"},
		{"empty-part", "--b\r\n\r\n\r\n--b--\r\n", "b"},
		{"no-final-crlf", "--b\r\n\r\nx\r\n--b--", "b"},
		{"boundary-in-body", "--b\r\n\r\na--b-not\r\n--b--\r\n", "b"},
		{"trailing-space", "--b \r\n\r\nx\r\n--b--\r\n", "b"},
		{"no-closing", "--b\r\n\r\nx\r\n", "b"},
		{"missing-first", "nothing here\r\n", "b"},
		{"empty-body", "", "b"},
		{"headers", "--b\r\nX-A: 1\r\nX-B: 2\r\n\r\nz\r\n--b--\r\n", "b"},
		{"crlf-in-body", "--b\r\n\r\nline1\r\nline2\r\n--b--\r\n", "b"},
	} {
		r := multipart.NewReader(strings.NewReader(c.body), c.bnd)
		n := 0
		for {
			p, err := r.NextPart()
			if err == io.EOF {
				fmt.Printf("part %-17s #%d -> EOF\n", c.name, n)
				break
			}
			if err != nil {
				fmt.Printf("part %-17s #%d -> err=%q\n", c.name, n, err.Error())
				break
			}
			data, rerr := io.ReadAll(p)
			fmt.Printf("part %-17s #%d -> hdr=%s body=%q rerr=%v\n",
				c.name, n, hdrString(p.Header), data, errText(rerr))
			n++
			if n > 4 {
				break
			}
		}
	}

	// 2. FormName / FileName over the dispositions that matter,
	//    including the path-traversal attempt.
	for _, d := range []string{
		`form-data; name="field"`,
		`form-data; name="f"; filename="a.txt"`,
		`form-data; name="f"; filename="../../etc/passwd"`,
		`form-data; name="f"; filename="dir/sub/a.txt"`,
		`form-data; name="f"; filename="..\\..\\win.ini"`,
		`attachment; name="f"; filename="a.txt"`,
		`form-data`,
		`form-data; filename="a.txt"`,
		``,
	} {
		body := "--b\r\n"
		if d != "" {
			body += "Content-Disposition: " + d + "\r\n"
		}
		body += "\r\nx\r\n--b--\r\n"
		r := multipart.NewReader(strings.NewReader(body), "b")
		p, err := r.NextPart()
		if err != nil {
			fmt.Printf("disp %-38q -> err=%q\n", d, err.Error())
			continue
		}
		fmt.Printf("disp %-38q -> formname=%-8q filename=%q\n",
			d, p.FormName(), p.FileName())
	}

	// 3. quoted-printable is decoded transparently, and the header is
	//    removed from the part.
	{
		body := "--b\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
			"a=3Db=\r\nc\r\n--b--\r\n"
		r := multipart.NewReader(strings.NewReader(body), "b")
		p, _ := r.NextPart()
		data, _ := io.ReadAll(p)
		fmt.Printf("qp part body=%q cte=%q\n", data,
			p.Header.Get("Content-Transfer-Encoding"))
	}

	// 4. quotedprintable on its own, including what it refuses.
	for _, in := range []string{
		"plain", "a=3Db", "a=\r\nb", "a=\nb", "a=3", "a=ZZ", "a=",
		"line   \r\nnext", "=E2=98=BA", "a=3db", "tab\there",
	} {
		out, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(in)))
		fmt.Printf("qp %-14q -> %q err=%v\n", in, out, errText(err))
	}

	// 5. The writer, so the boundary it produces is pinned too.
	{
		var sb strings.Builder
		w := multipart.NewWriter(&sb)
		w.SetBoundary("fixedboundary")
		fw, _ := w.CreateFormField("a")
		fw.Write([]byte("1"))
		ff, _ := w.CreateFormFile("file", "up.txt")
		ff.Write([]byte("data"))
		w.WriteField("b", "2")
		w.Close()
		fmt.Printf("writer ct=%q\n", w.FormDataContentType())
		fmt.Printf("writer out=%q\n", sb.String())
		// Round trip it back.
		r := multipart.NewReader(strings.NewReader(sb.String()), "fixedboundary")
		for {
			p, err := r.NextPart()
			if err != nil {
				break
			}
			d, _ := io.ReadAll(p)
			fmt.Printf("writer-rt name=%-6q file=%-8q body=%q\n",
				p.FormName(), p.FileName(), d)
		}
	}

	// 6. SetBoundary's validation.
	{
		var sb strings.Builder
		w := multipart.NewWriter(&sb)
		for _, b := range []string{"ok", "", strings.Repeat("x", 70),
			strings.Repeat("x", 71), "has space", "has\ttab", "a:b"} {
			err := w.SetBoundary(b)
			fmt.Printf("setboundary len=%-3d -> err=%v\n", len(b), errText(err))
		}
	}
}

// hdrString renders a part's headers in a canonical, sorted form so
// the two sides are compared on content rather than on how each
// language happens to print a map.
func hdrString(h map[string][]string) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		for i, v := range h[k] {
			if i > 0 {
				sb.WriteString("|")
			}
			sb.WriteString(v)
		}
		sb.WriteString(";")
	}
	return sb.String()
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
