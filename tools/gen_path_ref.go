package path_test

import (
	"fmt"
	"path"
	"testing"
)

// path is the slash-separated cousin of path/filepath, and it is not a
// convenience: it is what http.ServeMux's cleanPath, http.FileServer
// and io/fs are all built on. A Clean that disagrees with Go's is a
// routing decision that disagrees with Go's, which is why this is
// measured against a running Go rather than reasoned about.
//
// The rules that are easy to get subtly wrong, all of them exercised
// below:
//
//   * Clean is PURELY LEXICAL. It never consults a filesystem, so it
//     happily resolves "a/../b" to "b" even when "a" would have been a
//     symlink somewhere else. That is a documented property, not a
//     bug, and a port that "improves" on it diverges.
//   * ".." above the root is DROPPED for a rooted path ("/../a" is
//     "/a") but KEPT for a relative one ("../a" stays "../a"). The two
//     halves of that rule are what stops "/../../etc/passwd" escaping
//     and what makes relative traversal still expressible.
//   * Clean("") is ".", not "". An empty result would make a
//     concatenating caller build a path with a leading slash it did
//     not intend.
//   * Trailing slashes are removed, except at the root.
//   * Split, Dir, Base and Ext are defined in terms of the LAST slash,
//     with their own answers for the empty and all-slash cases.
//   * Join cleans the result, so a ".." in a later element eats an
//     earlier one — the exact shape of a traversal through a joined
//     user-supplied segment.
//   * Match is a glob, not a regexp: "*" does not cross a slash, and a
//     malformed pattern is an ERROR rather than a non-match.
func TestGoishRef(t *testing.T) {
	inputs := []string{
		"", ".", "..", "/", "//", "///", "a", "/a", "a/", "/a/",
		"a/b", "a//b", "a/./b", "a/../b", "../a", "/../a", "/../../a",
		"a/b/..", "a/b/../..", "a/b/../../..", "./a", "././a",
		"/a/b/./../c/", "a/b/c/../../d", "...", "a...", "..a", "a..b",
		"/.", "/..", "/./", "/../", "abc/../../def", "/a/../..",
		"x/y/../../../z", "//a//b//", "a/b/c/", ".../a", "/a/.",
	}
	for _, in := range inputs {
		fmt.Printf("clean %-16q -> %q\n", in, path.Clean(in))
	}
	for _, in := range inputs {
		d, f := path.Split(in)
		fmt.Printf("split %-16q -> dir=%-12q file=%q\n", in, d, f)
	}
	for _, in := range inputs {
		fmt.Printf("parts %-16q -> dir=%-12q base=%-8q ext=%q abs=%v\n",
			in, path.Dir(in), path.Base(in), path.Ext(in), path.IsAbs(in))
	}
	joins := [][]string{
		{}, {""}, {"a"}, {"a", "b"}, {"a", ""}, {"", "b"}, {"", ""},
		{"a", "..", "b"}, {"a", "../.."}, {"/", "a"}, {"/a", "/b"},
		{"a/", "/b"}, {"a", "b", "c"}, {"a", "../../b"},
		{"/var/www", "../../etc/passwd"}, {"/var/www", "..%2f..%2fetc"},
		{"base", "sub/../../escape"}, {"a", ".", "b"}, {"//", "a"},
		{"a", "b/"}, {".", "a"}, {"..", "a"},
	}
	for _, j := range joins {
		fmt.Printf("join  %-34q -> %q\n", j, path.Join(j...))
	}
	globs := []struct{ pat, name string }{
		{"*", "a"}, {"*", "a/b"}, {"*/*", "a/b"}, {"a/*", "a/b"},
		{"a/*", "a/b/c"}, {"**", "a/b"}, {"?", "a"}, {"?", "ab"},
		{"[abc]", "b"}, {"[a-c]", "b"}, {"[^a]", "b"}, {"[!a]", "b"},
		{"a[", "a["}, {"[", "["}, {"[]", "[]"}, {"\\*", "*"},
		{"*.go", "x.go"}, {"*.go", "a/x.go"}, {"/*", "/a"},
		{"", ""}, {"", "a"}, {"a", ""}, {"*", ""}, {"[-]", "-"},
	}
	for _, g := range globs {
		ok, err := path.Match(g.pat, g.name)
		e := "<nil>"
		if err != nil {
			e = err.Error()
		}
		fmt.Printf("match %-8q %-8q -> %-5v err=%s\n", g.pat, g.name, ok, e)
	}
}
