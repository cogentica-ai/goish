package url_test

import (
	"fmt"
	"net/url"
	"testing"
)

// net/url is where "compiles and returns something plausible" is at its
// most dangerous: a URL that parses into slightly the wrong fields
// still round-trips through String() often enough to look fine, and the
// difference only shows when it is used to route, to sign, or to
// compare against an allow-list.
func TestGoishRef(t *testing.T) {
	raws := []string{
		"http://example.com",
		"http://example.com/",
		"http://example.com/a/b?x=1&y=2#frag",
		"https://user:pass@host:8080/p?q#f",
		"https://user@host/p",
		"//host/path",
		"/just/a/path",
		"just/a/path",
		"mailto:me@example.com",
		"scheme:opaque?q=1#f",
		"http://[::1]:80/x",
		"http://[fe80::1%25eth0]/x",
		"http://host/a%2Fb/c",
		"http://host/a b",
		"http://host/?a=%20&b=+",
		"http://host?#",
		"http://host#",
		"",
		"http://example.com/././a/../b",
		"HTTP://Example.COM/Path",
		"http://user:pa%40ss@host/",
		"foo://host/path;params?q",
		"http://host/%zz",
		"http://host:port/",
		"?query-only",
		"#frag-only",
	}
	for _, raw := range raws {
		u, err := url.Parse(raw)
		if err != nil {
			fmt.Printf("parse %-34q err=%v\n", raw, err)
			continue
		}
		fmt.Printf("parse %-34q scheme=%q opaque=%q user=%q host=%q path=%q raw=%q force=%v query=%q frag=%q rawfrag=%q\n",
			raw, u.Scheme, u.Opaque, u.User.String(), u.Host, u.Path, u.RawPath,
			u.ForceQuery, u.RawQuery, u.Fragment, u.RawFragment)
		fmt.Printf("back  %-34q string=%q reqURI=%q abs=%v hostname=%q port=%q escpath=%q redacted=%q\n",
			raw, u.String(), u.RequestURI(), u.IsAbs(), u.Hostname(), u.Port(),
			u.EscapedPath(), u.Redacted())
	}

	// ParseRequestURI treats its input as an absolute URI or an
	// absolute path — never a relative reference.
	for _, raw := range []string{"http://h/p", "/p", "p", "//h/p", "http://h/p#f"} {
		u, err := url.ParseRequestURI(raw)
		if err != nil {
			fmt.Printf("reqURI %-12q err=%v\n", raw, err)
			continue
		}
		fmt.Printf("reqURI %-12q path=%q frag=%q string=%q\n", raw, u.Path, u.Fragment, u.String())
	}

	// Escaping. QueryEscape and PathEscape differ on space, +, / and ?.
	for _, s := range []string{"", "a", "a b", "a+b", "a/b", "a?b", "a#b", "a%b",
		"héllo", "\x00\x7f", "~-_.", "!*'()", ":@&=$,;"} {
		fmt.Printf("esc %-10q query=%q path=%q\n", s, url.QueryEscape(s), url.PathEscape(s))
	}
	for _, s := range []string{"", "a", "a+b", "a%20b", "a%2Fb", "%", "%2", "%zz",
		"%41", "a%00b", "+"} {
		q, qe := url.QueryUnescape(s)
		p, pe := url.PathUnescape(s)
		fmt.Printf("unesc %-8q query=(%q,%v) path=(%q,%v)\n", s, q, qe, p, pe)
	}

	// ResolveReference — the RFC 3986 merge, which is where a hand-
	// rolled join goes wrong.
	base, _ := url.Parse("http://a/b/c/d;p?q")
	for _, ref := range []string{"g", "./g", "g/", "/g", "//g", "?y", "g?y", "#s",
		"g#s", "", ".", "..", "../..", "../../g", "/./g", "/../g", "g.", ".g",
		"http://x/y", "mailto:m@e"} {
		r, err := url.Parse(ref)
		if err != nil {
			fmt.Printf("resolve %-10q err=%v\n", ref, err)
			continue
		}
		fmt.Printf("resolve %-10q -> %q\n", ref, base.ResolveReference(r).String())
	}

	// JoinPath.
	u, _ := url.Parse("http://h/a/b")
	for _, elems := range [][]string{{}, {"c"}, {"c", "d"}, {"../c"}, {"/c"}, {"c/"}, {"", "c"}} {
		j := u.JoinPath(elems...)
		fmt.Printf("join %-16v -> %q path=%q\n", elems, j.String(), j.Path)
	}

	// ParseQuery, including the malformed cases.
	for _, q := range []string{"", "a=1", "a=1&b=2", "a=1&a=2", "a", "a=", "=1",
		"a=1;b=2", "a=%zz", "a=%20&b=+", "&&a=1&&"} {
		v, err := url.ParseQuery(q)
		fmt.Printf("query %-12q err=%v v=%v encode=%q\n", q, err, v, v.Encode())
	}

	// Userinfo.
	fmt.Printf("user a=%q b=%q c=%q\n",
		url.User("u").String(), url.UserPassword("u", "p").String(),
		url.UserPassword("u:x", "p@y").String())
}
