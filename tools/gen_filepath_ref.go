package filepath_test

import (
	"fmt"
	"path/filepath"
	"testing"
)

// Clean, Join, Match and Rel are the four with real edge cases, and all
// four are used to decide whether a path is inside a directory. A Clean
// that keeps one ".." too many, or a Match that treats '/' as ordinary,
// turns a containment check into a false answer.
func TestGoishRef(t *testing.T) {
	for _, p := range []string{
		"", ".", "..", "/", "//", "///", "a", "a/", "/a", "a/b", "a//b",
		"a/./b", "a/../b", "../a", "a/..", "a/../..", "/..", "/../a",
		"./a", "././a", "a/b/../../c", "/a/b/../../../c", "a/b/",
		"a/./", "/./", "abc/", "abc/def/..", "abc/../..", "/a/../..",
		".//a", "a/b/c/../../d", "..//..", "a/..//b",
	} {
		fmt.Printf("clean %-20q -> %-14q isabs=%-5v isLocal=%v\n",
			p, filepath.Clean(p), filepath.IsAbs(p), filepath.IsLocal(p))
	}

	for _, p := range []string{"", "/", "a", "a/b", "/a/b", "a/b/", "/a/",
		"a.txt", "/a/b.txt", "dir/.hidden", ".hidden", "a.b.c", "a/b.c/d"} {
		d, f := filepath.Split(p)
		fmt.Printf("split %-14q -> (%q,%q) base=%-8q dir=%-8q ext=%q\n",
			p, d, f, filepath.Base(p), filepath.Dir(p), filepath.Ext(p))
	}

	for _, e := range [][]string{
		{}, {""}, {"a"}, {"a", "b"}, {"a", "", "b"}, {"", "a"}, {"a/", "b"},
		{"/a", "b"}, {"a", "/b"}, {"a", "../b"}, {"a", ".."}, {"..", "a"},
		{"a", "b", "c"}, {"/", "a"}, {"a", "."}, {".", "a"},
	} {
		fmt.Printf("join %-26v -> %q\n", e, filepath.Join(e...))
	}

	type M struct{ pat, name string }
	for _, m := range []M{
		{"", ""}, {"", "a"}, {"a", "a"}, {"a", "b"}, {"*", "a"}, {"*", ""},
		{"*", "a/b"}, {"*/*", "a/b"}, {"a/*", "a/b"}, {"a/*", "a/b/c"},
		{"?", "a"}, {"?", "ab"}, {"a?c", "abc"}, {"[abc]", "b"},
		{"[a-c]", "b"}, {"[^a-c]", "d"}, {"[!a-c]", "d"}, {"[]a]", "a"},
		{"\\*", "*"}, {"\\*", "a"}, {"a[", "a["}, {"[", "a"}, {"[a-", "a"},
		{"*.go", "x.go"}, {"*.go", "x.g"}, {"**", "a/b"}, {"a/**", "a/b"},
		{"[-x]", "-"}, {"*[", "a["},
	} {
		ok, err := filepath.Match(m.pat, m.name)
		fmt.Printf("match %-10q %-8q -> %-5v err=%v\n", m.pat, m.name, ok, err)
	}

	type R struct{ base, targ string }
	for _, r := range []R{
		{"/a", "/a/b"}, {"/a", "/a"}, {"/a/b", "/a"}, {"/a", "/b"},
		{"a", "a/b"}, {"a/b", "a"}, {"a", "b"}, {"/", "/a"}, {"/a", "/"},
		{".", "a"}, {"a", "."}, {"/a", "b"}, {"a", "/b"}, {"a/b", "a/b"},
		{"a/./b", "a/b/c"}, {"/a/../b", "/b/c"},
	} {
		rel, err := filepath.Rel(r.base, r.targ)
		fmt.Printf("rel %-10q %-10q -> %-10q err=%v\n", r.base, r.targ, rel, err)
	}

	for _, p := range []string{"", ".", "..", "/", "a", "a/b", "../a", "a/../b",
		"a/..", "./a", "/a"} {
		l, err := filepath.Localize(p)
		fmt.Printf("localize %-10q -> %-10q err=%v\n", p, l, err)
	}

	for _, p := range []string{"", "a", "a:b", "/a:/b", ":", "::", "a:"} {
		fmt.Printf("splitlist %-10q -> %q\n", p, filepath.SplitList(p))
	}
	for _, p := range []string{"a/b", "a\\b", "/a/b"} {
		fmt.Printf("slash %-8q toslash=%q fromslash=%q\n",
			p, filepath.ToSlash(p), filepath.FromSlash(p))
	}
}
