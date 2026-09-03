package cgi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// CGI hands attacker-controlled bytes to a child process as its
// ENVIRONMENT, which makes the mapping from request to environment a
// security boundary rather than a serialization detail. Two of its
// rules exist because getting them wrong was a vulnerability:
//
//   * The "Proxy" request header is DROPPED rather than exported as
//     HTTP_PROXY. Every HTTP client in every language reads HTTP_PROXY
//     from the environment, so exporting it would let any client
//     redirect the script's own outbound requests through a host of
//     their choosing. That is httpoxy, CVE-2016-5386, and the fix is
//     one `continue`.
//   * Header names are mapped through upperCaseAndUnderscore, so
//     anything that is not a letter or digit becomes "_". A header
//     called "X-Foo" and one called "X_Foo" therefore collide, and a
//     header named to look like a reserved variable — "Content-Type",
//     say — lands under HTTP_CONTENT_TYPE rather than overwriting
//     CONTENT_TYPE.
//
// The child here is a shell script that prints its environment, so
// what is measured is what CROSSED the boundary, not what the host
// meant to send.
func TestGoishRef(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "dump.sh")
	body := "#!/bin/sh\n" +
		"echo \"Content-Type: text/plain\"\n" +
		"echo \"X-From-Script: yes\"\n" +
		"echo\n" +
		"env | grep -E '^(HTTP_|CONTENT_|REQUEST_|SCRIPT_|PATH_|QUERY_|SERVER_|REMOTE_|GATEWAY_|AUTH_|HTTPS|EXTRA_)' | LC_ALL=C sort\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	run := func(label string, h *Handler, r *http.Request) {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var keys []string
		for k := range w.Header() {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var hs []string
		for _, k := range keys {
			hs = append(hs, fmt.Sprintf("%s=%q", k, strings.Join(w.Header()[k], "|")))
		}
		fmt.Printf("cgi %-22s -> code=%d hdr=[%s]\n", label, w.Code, strings.Join(hs, " "))
		for _, line := range strings.Split(strings.TrimRight(w.Body.String(), "\n"), "\n") {
			if line == "" {
				continue
			}
			// SCRIPT_FILENAME and PWD carry the temp dir.
			line = strings.ReplaceAll(line, dir, "<tmp>")
			fmt.Printf("env %-22s %s\n", label, line)
		}
	}

	base := func() *Handler {
		return &Handler{Path: script, Root: "/cgi"}
	}

	// 1. A plain GET, so the fixed variables are all visible.
	{
		r := httptest.NewRequest("GET", "http://example.test/cgi/script/extra/path?a=1&b=2", nil)
		r.RemoteAddr = "192.0.2.9:5555"
		run("plain", base(), r)
	}

	// 2. Header mapping, including the two rules above.
	{
		r := httptest.NewRequest("GET", "http://example.test/cgi/x", nil)
		r.RemoteAddr = "192.0.2.9:5555"
		r.Header.Set("X-Simple", "one")
		r.Header.Set("X-Two-Words", "two")
		r.Header.Set("X_Underscore", "collide")
		r.Header.Add("X-Multi", "a")
		r.Header.Add("X-Multi", "b")
		r.Header.Set("Cookie", "a=1")
		r.Header.Add("Cookie", "b=2")
		r.Header.Set("Proxy", "http://evil.test")
		r.Header.Set("X-Dot.Sep", "dotted")
		r.Header.Set("Authorization", "Bearer secret")
		run("headers", base(), r)
	}

	// 3. A POST with a body: CONTENT_LENGTH and CONTENT_TYPE are their
	//    own variables, NOT HTTP_-prefixed.
	{
		r := httptest.NewRequest("POST", "http://example.test/cgi/post",
			strings.NewReader("field=value"))
		r.RemoteAddr = "192.0.2.9:5555"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		run("post", base(), r)
	}

	// 4. Handler.Env and InheritEnv.
	{
		os.Setenv("GOISH_INHERITED", "from-host")
		os.Setenv("GOISH_NOT_INHERITED", "should-not-appear")
		h := base()
		h.Env = []string{"EXTRA_ONE=1", "EXTRA_TWO=two words"}
		h.InheritEnv = []string{"GOISH_INHERITED"}
		r := httptest.NewRequest("GET", "http://example.test/cgi/env", nil)
		r.RemoteAddr = "192.0.2.9:5555"
		run("env-opts", h, r)
	}

	// 5. Root prefix handling: what SCRIPT_NAME and PATH_INFO become.
	for _, c := range []struct{ name, root, target string }{
		{"root-empty", "", "/a/b"},
		{"root-slash", "/", "/a/b"},
		{"root-prefix", "/cgi", "/cgi/a/b"},
		{"root-exact", "/cgi", "/cgi"},
		{"root-trailing", "/cgi/", "/cgi/a"},
		{"root-mismatch", "/cgi", "/other/a"},
	} {
		h := &Handler{Path: script, Root: c.root}
		r := httptest.NewRequest("GET", "http://example.test"+c.target, nil)
		r.RemoteAddr = "192.0.2.9:5555"
		run(c.name, h, r)
	}
}
