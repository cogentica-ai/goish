package cookiejar_test

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
)

// A cookie jar decides which host each cookie is sent to. Getting that
// wrong is not a formatting bug: a cookie scoped too widely is sent to
// a site that should never see it, and one scoped too narrowly silently
// logs a user out. The rules are all in the Domain and Path matching,
// and they are asymmetric in ways that are easy to get backwards:
//
//   * A cookie with no Domain is HOST-ONLY: it goes back only to the
//     exact host that set it, not to its subdomains.
//   * A cookie WITH a Domain goes to that domain and all subdomains —
//     and a leading dot is stripped, so Domain=.a.com and Domain=a.com
//     mean the same thing. That asymmetry is the whole point: adding a
//     Domain WIDENS the scope.
//   * A host may not set a cookie for a domain it is not under, and may
//     not set one for a public suffix. Without a PublicSuffixList
//     configured, Go's jar cannot check the second, and its own docs
//     say so — the behaviour is still worth pinning, because it is what
//     a caller gets by default.
//   * Path matching is a PREFIX match on segment boundaries: /foo
//     matches /foo, /foo/, /foo/bar, but not /foobar.
//   * A Secure cookie is withheld from an http:// URL.
//   * Setting a cookie with MaxAge<0 (or a past Expires) DELETES it.
func TestGoishRef(t *testing.T) {
	type setStep struct {
		from    string
		cookies []string
	}
	cases := []struct {
		name  string
		steps []setStep
		reads []string
	}{
		{
			"host-only",
			[]setStep{{"http://a.example.com/", []string{"k=1"}}},
			[]string{"http://a.example.com/", "http://b.a.example.com/",
				"http://example.com/", "http://other.com/"},
		},
		{
			"with-domain",
			[]setStep{{"http://a.example.com/", []string{"k=1; Domain=example.com"}}},
			[]string{"http://a.example.com/", "http://b.example.com/",
				"http://example.com/", "http://notexample.com/"},
		},
		{
			"leading-dot",
			[]setStep{{"http://a.example.com/", []string{"k=1; Domain=.example.com"}}},
			[]string{"http://a.example.com/", "http://example.com/"},
		},
		{
			"foreign-domain",
			[]setStep{{"http://a.example.com/", []string{"k=1; Domain=other.com"}}},
			[]string{"http://a.example.com/", "http://other.com/"},
		},
		{
			"superdomain-of-self",
			[]setStep{{"http://a.b.example.com/", []string{"k=1; Domain=b.example.com"}}},
			[]string{"http://a.b.example.com/", "http://b.example.com/",
				"http://example.com/"},
		},
		{
			"paths",
			[]setStep{{"http://x.com/foo/bar", []string{"k=1; Path=/foo"}}},
			[]string{"http://x.com/foo", "http://x.com/foo/", "http://x.com/foo/bar",
				"http://x.com/foobar", "http://x.com/", "http://x.com/fo"},
		},
		{
			"default-path",
			[]setStep{{"http://x.com/a/b/c", []string{"k=1"}}},
			[]string{"http://x.com/a/b/c", "http://x.com/a/b/", "http://x.com/a/b",
				"http://x.com/a/", "http://x.com/"},
		},
		{
			"secure",
			[]setStep{{"https://x.com/", []string{"k=1; Secure"}}},
			[]string{"https://x.com/", "http://x.com/"},
		},
		{
			"delete-maxage",
			[]setStep{
				{"http://x.com/", []string{"k=1"}},
				{"http://x.com/", []string{"k=2; Max-Age=-1"}},
			},
			[]string{"http://x.com/"},
		},
		{
			"overwrite",
			[]setStep{
				{"http://x.com/", []string{"k=1"}},
				{"http://x.com/", []string{"k=2"}},
			},
			[]string{"http://x.com/"},
		},
		{
			"two-cookies",
			[]setStep{{"http://x.com/", []string{"a=1", "b=2"}}},
			[]string{"http://x.com/"},
		},
		{
			"same-name-diff-path",
			[]setStep{
				{"http://x.com/", []string{"k=root; Path=/"}},
				{"http://x.com/sub/", []string{"k=sub; Path=/sub"}},
			},
			[]string{"http://x.com/", "http://x.com/sub/"},
		},
		{
			"ip-host",
			[]setStep{{"http://127.0.0.1/", []string{"k=1"}}},
			[]string{"http://127.0.0.1/", "http://127.0.0.2/"},
		},
		{
			"ip-with-domain",
			[]setStep{{"http://127.0.0.1/", []string{"k=1; Domain=127.0.0.1"}}},
			[]string{"http://127.0.0.1/"},
		},
		{
			"port-ignored",
			[]setStep{{"http://x.com:8080/", []string{"k=1"}}},
			[]string{"http://x.com/", "http://x.com:9090/"},
		},
		{
			"case-host",
			[]setStep{{"http://X.CoM/", []string{"k=1"}}},
			[]string{"http://x.com/", "http://X.COM/"},
		},
		{
			"empty-name",
			[]setStep{{"http://x.com/", []string{"=v"}}},
			[]string{"http://x.com/"},
		},
		{
			"non-http-scheme",
			[]setStep{{"ftp://x.com/", []string{"k=1"}}},
			[]string{"ftp://x.com/", "http://x.com/"},
		},
	}
	for _, c := range cases {
		jar, _ := cookiejar.New(nil)
		for _, st := range c.steps {
			u, err := url.Parse(st.from)
			if err != nil {
				fmt.Printf("jar %-22s setup-err=%v\n", c.name, err)
				continue
			}
			var cs []*http.Cookie
			for _, line := range st.cookies {
				ck, err := http.ParseSetCookie(line)
				if err != nil {
					fmt.Printf("jar %-22s parse-err=%v\n", c.name, err)
					continue
				}
				cs = append(cs, ck)
			}
			jar.SetCookies(u, cs)
		}
		for _, r := range c.reads {
			u, _ := url.Parse(r)
			var parts string
			for i, ck := range jar.Cookies(u) {
				if i > 0 {
					parts += " "
				}
				parts += ck.Name + "=" + ck.Value
			}
			fmt.Printf("jar %-22s %-28s -> [%s]\n", c.name, r, parts)
		}
	}
}
