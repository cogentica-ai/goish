package path_test

import (
	"fmt"
	"path"
	"testing"
)

// path is slash-only and purely lexical: it never touches a filesystem,
// so every answer is derivable from the string. That makes it easy to
// get almost right — Clean's ".." handling above the root, Join's
// treatment of empty elements, Ext's rule about the LAST dot, Base's
// answers for "" and "/", and Match's bracket expressions with a
// negation, a range and an escape.
func TestGoishRef(t *testing.T) {
	paths := []string{
		"", ".", "..", "/", "//", "///",
		"a", "a/b", "a/b/c",
		"a//b", "a/./b", "a/../b", "a/b/..", "a/b/../..", "a/b/../../..",
		"/a/b/../..", "/..", "/../a", "../a", "../../a",
		"./a", "././a", "a/", "a//", "/a/", "/a//",
		"abc/", "abc/def", "abc//def//ghi",
		"a/b/c/../../d", "a/b/c/./d",
		"/a/b/c/../../../../d",
		"x/y/../../../z",
		".hidden", "a/.hidden", "a.b.c", "a/b.c/d",
		"file.txt", "file.tar.gz", ".config", "dir.d/file",
		"/usr/local/go/src",
	}
	for _, p := range paths {
		dir, file := path.Split(p)
		fmt.Printf("path %-24q clean=%-18q split=(%q,%q) ext=%-8q base=%-10q isabs=%-5v dir=%q\n",
			p, path.Clean(p), dir, file, path.Ext(p), path.Base(p), path.IsAbs(p), path.Dir(p))
	}

	joins := [][]string{
		{},
		{""},
		{"a"},
		{"a", "b"},
		{"a", "", "b"},
		{"", "a", "b"},
		{"a", "b", ""},
		{"", ""},
		{"/", "a"},
		{"a", "/b"},
		{"a/", "/b"},
		{"a", "..", "b"},
		{"a", "../.."},
		{"/", ""},
		{"", "/"},
		{"a", "b/../c"},
		{"..", "a"},
	}
	for _, j := range joins {
		fmt.Printf("join %-22q -> %q\n", j, path.Join(j...))
	}

	// Match: the syntax is the interesting half. A bracket expression
	// can be negated, can hold a range, and can escape its own
	// metacharacters; an unterminated one is ErrBadPattern, and so is a
	// trailing backslash.
	cases := [][2]string{
		{"", ""}, {"", "a"}, {"*", ""}, {"*", "a"}, {"*", "a/b"},
		{"a", "a"}, {"a", "b"}, {"a*", "abc"}, {"a*", "ab/c"},
		{"*/*", "a/b"}, {"*/*", "a/b/c"}, {"**", "a/b"},
		{"?", "a"}, {"?", ""}, {"?", "ab"}, {"?", "/"},
		{"a?c", "abc"}, {"a?c", "a/c"},
		{"[abc]", "b"}, {"[abc]", "d"}, {"[a-c]", "b"}, {"[a-c]", "d"},
		{"[^abc]", "d"}, {"[^abc]", "b"}, {"[^a-c]", "d"},
		{"[]a]", "a"}, {"[-]", "-"}, {"[a-]", "-"},
		{"[\\]]", "]"}, {"[\\-]", "-"}, {"a\\*b", "a*b"}, {"a\\*b", "axb"},
		{"[", "a"}, {"[^", "a"}, {"[a-", "a"}, {"a\\", "a"},
		{"[z-a]", "b"},
		{"*x", "abcx"}, {"*x", "abcy"}, {"a*b*c", "abc"}, {"a*b*c", "axbyc"},
		{"a*b*c", "axbyd"}, {"*.txt", "a.txt"}, {"*.txt", "a/b.txt"},
		{"日*", "日本"}, {"?", "日"}, {"[日本]", "日"}, {"[日本]", "語"},
		{"\xff", "\xff"}, {"?", "\xff"},
	}
	for _, c := range cases {
		ok, err := path.Match(c[0], c[1])
		fmt.Printf("match %-10q %-8q -> %-5v err=%v\n", c[0], c[1], ok, err)
	}
	fmt.Printf("errbadpattern %q\n", path.ErrBadPattern.Error())
}
