package mime

import (
	"fmt"
	"slices"
	"testing"
)

// ParseMediaType's hard part is RFC 2231: a parameter value may be
// split across name*0, name*1, … and any piece may be percent-encoded
// by a further '*' suffix, with the charset carried on the first piece
// only. The continuation table below is what a name-only port gets
// wrong, because none of it is reachable from a simple Content-Type.
func TestGoishRef(t *testing.T) {
	parseCases := []string{
		"form-data",
		"form-data; name=foo",
		`form-data; name="foo"`,
		`FORM-DATA; Name="foo"`,
		` form-data ; name=foo`,
		`form-data; key=value;  blah="value";name="foo" `,
		`form-data; name="foo"; filename="bar.txt"`,
		"text/html; charset=utf-8",
		"text/html; charset =utf-8",
		"text/html; charset= utf-8",
		"text/html;charset=utf-8;",
		"text/html;charset=utf-8; ",
		"text/html; charset=utf-8; charset=utf-8",
		"text/html; charset=utf-8; charset=iso-8859-1",
		"text/html; ; charset=utf-8",
		"text/html; charset",
		"text/html; charset=",
		`text/html; charset="utf-8`,
		`text/html; charset=";"`,
		`text/html; charset="\"quoted\""`,
		`application/x-stuff; title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A`,
		`application/x-stuff; title*0*=us-ascii'en'This%20is%20even%20; title*1=more%20; title*2*=%2A%2A%2Afun%2A%2A%2A%20; title*3="isn't it!"`,
		`attachment; filename*=UTF-8''foo-%c3%a4.html`,
		`attachment; filename*=utf-8''foo-%c3%a4.html`,
		`attachment; filename*=iso-8859-1''foo.html`,
		`attachment; filename*=''foo.html`,
		`attachment; filename*=UTF-8''foo-%`,
		`attachment; filename*0="foo"; filename*1="bar.html"`,
		`attachment; filename*0*=UTF-8''foo-%c3%a4; filename*1=".html"`,
		`x/y; z=""`,
		`x/y; z="\\"`,
		`x/y; z="C:\dev\go\foo.txt"`,
		"bogus",
		"bogus/",
		"bogus//",
		"bogus /x",
		"",
		";",
		"/",
		"a/b c",
	}
	for _, in := range parseCases {
		mt, params, err := ParseMediaType(in)
		keys := slices.Sorted(func(yield func(string) bool) {
			for k := range params {
				if !yield(k) {
					return
				}
			}
		})
		fmt.Printf("parse %-90q -> mt=%-32q params=[", in, mt)
		for i, k := range keys {
			if i > 0 {
				fmt.Printf(" ")
			}
			fmt.Printf("%s=%q", k, params[k])
		}
		fmt.Printf("] err=%v\n", err)
	}

	formatCases := []struct {
		typ    string
		param  map[string]string
		expect string
	}{
		{"noslash", map[string]string{"X": "Y"}, ""},
		{"foo bar/baz", nil, ""},
		{"foo/bar baz", nil, ""},
		{"foo/BAR", nil, ""},
		{"text/html", map[string]string{"charset": "utf-8"}, ""},
		{"text/html", map[string]string{"charset": "", "a": "b"}, ""},
		{"text/html", map[string]string{"charset": "utf-8", "boundary": "a b"}, ""},
		{"text/html", map[string]string{"charset": `"quoted"`}, ""},
		{"text/html", map[string]string{"charset": `back\slash`}, ""},
		{"text/html", map[string]string{"charset": "ä"}, ""},
		{"text/html", map[string]string{"charset": "a\tb"}, ""},
		{"text/html", map[string]string{"bad key": "x"}, ""},
		{"application/x-stuff", map[string]string{"title": "This is ***fun***"}, ""},
		{"form-data", map[string]string{"name": `we"ird\name`}, ""},
	}
	for _, fc := range formatCases {
		fmt.Printf("format %-22q %v -> %q\n", fc.typ, fc.param, FormatMediaType(fc.typ, fc.param))
	}

	// percentHexUnescape's error text and the well-formed path.
	for _, s := range []string{"a%20b", "a%2", "a%zz", "%", "%41%42", "plain"} {
		out, err := percentHexUnescape(s)
		fmt.Printf("unescape %-8q -> %q err=%v\n", s, out, err)
	}

	// The two character classes, as full 0..255 signatures.
	tsp, tok := 0, 0
	for c := 0; c < 256; c++ {
		if isTSpecial(byte(c)) {
			tsp++
		}
		if isTokenChar(byte(c)) {
			tok++
		}
	}
	fmt.Printf("classes tspecial=%d tokenchar=%d\n", tsp, tok)
	fmt.Printf("istoken empty=%v tok=%v sp=%v hi=%v\n",
		isToken(""), isToken("abc"), isToken("a b"), isToken("a\x80b"))
}
