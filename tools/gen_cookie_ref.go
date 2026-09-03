package http_test

import (
	"fmt"
	"net/http"
	"testing"
)

func TestGoishRef(t *testing.T) {
	// ── ParseSetCookie on hostile / edge input ──
	setLines := []string{
		"a=b",
		"a=b; Path=/x; Domain=example.com; Secure; HttpOnly",
		"a=b; SameSite=Strict",
		"a=b; SameSite=lax",
		"a=b; SameSite=None",
		"a=b; SameSite=bogus",
		"a=b; Max-Age=100",
		"a=b; Max-Age=0",
		"a=b; Max-Age=-1",
		"a=b; Max-Age=007",
		"a=b; Max-Age=abc",
		"a=b; Expires=Mon, 02 Jan 2006 15:04:05 GMT",
		"a=b; Expires=bogus",
		`a="quoted"`,
		`a="qu oted"`,
		"a=b; Partitioned",
		"a=b; Unknown=thing",
		"a=b; Path",
		"=b",
		"a=",
		"a=b; Domain=.example.com",
		"a=b; Domain=",
		"a\x00b=c",
		"a=b\x00c",
		"a=b; Path=/x\x00y",
		"a=b;;Secure",
		"  a  =  b  ",
		"__Host-a=b; Path=/; Secure",
		"a=b; Secure; Secure",
		"a=b, c=d",
	}
	for _, l := range setLines {
		c, err := http.ParseSetCookie(l)
		if err != nil {
			fmt.Printf("set %-42q err=%v\n", l, err)
			continue
		}
		fmt.Printf("set %-42q name=%q val=%q q=%v path=%q dom=%q ma=%d sec=%v ho=%v ss=%d part=%v raw_exp=%q unp=%q\n",
			l, c.Name, c.Value, c.Quoted, c.Path, c.Domain, c.MaxAge, c.Secure, c.HttpOnly, int(c.SameSite), c.Partitioned, c.RawExpires, c.Unparsed)
	}

	// ── Cookie.String() serialisation ──
	cookies := []*http.Cookie{
		{Name: "a", Value: "b"},
		{Name: "a", Value: "b", Path: "/x", Domain: "example.com", Secure: true, HttpOnly: true},
		{Name: "a", Value: "b", MaxAge: 100},
		{Name: "a", Value: "b", MaxAge: -1},
		{Name: "a", Value: "b", MaxAge: 0},
		{Name: "a", Value: "b", SameSite: http.SameSiteStrictMode},
		{Name: "a", Value: "b", SameSite: http.SameSiteNoneMode},
		{Name: "a", Value: "b", SameSite: http.SameSiteDefaultMode},
		{Name: "a", Value: "b", Partitioned: true},
		{Name: "a", Value: "b c"},
		{Name: "a", Value: `b"c`},
		{Name: "a", Value: "b", Quoted: true},
		{Name: "a", Value: "b\nc"},
		{Name: "a\nb", Value: "c"},
		{Name: "a", Value: "b", Path: "/x\ny"},
		{Name: "a", Value: "b", Domain: "exa\nmple.com"},
		{Name: "a", Value: "b", Domain: "-bad.com"},
		{Name: "", Value: "b"},
		{Name: "a", Value: "b", Path: "/x;y"},
	}
	for _, c := range cookies {
		fmt.Printf("str name=%-6q val=%-8q -> %q\n", c.Name, c.Value, c.String())
	}

	// ── Request.Cookies parsing ──
	reqLines := []string{
		"a=b",
		"a=b; c=d",
		"a=b;c=d",
		"a=b; ; c=d",
		"a=b; c",
		`a="b"`,
		"a=b\x00c; d=e",
		"a b=c; d=e",
		"a=b; a=c",
		"  a=b  ;  c=d  ",
	}
	for _, l := range reqLines {
		r := &http.Request{Header: http.Header{"Cookie": {l}}}
		got := []string{}
		for _, c := range r.Cookies() {
			got = append(got, c.Name+"="+c.Value)
		}
		fmt.Printf("req %-24q -> %q\n", l, got)
	}
}
