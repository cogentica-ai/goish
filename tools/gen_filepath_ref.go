package filepath_test

import (
	"fmt"
	"path/filepath"
	"testing"
)

// Rel is the one to worry about: it is lexical, it has to agree with
// Clean on both arguments, it must count how many ".." get it from base
// to target, and it must REFUSE when that count cannot be known — a
// relative base and an absolute target, or a base that walks above what
// it can see. Every "can't make X relative to Y" below is a case where
// returning a plausible path would be worse than an error.
//
// IsLocal and Localize are the security-shaped pair: IsLocal answers
// whether a path stays inside the directory it is evaluated in, which
// is what an archive extractor asks before writing.
func TestGoishRef(t *testing.T) {
	rels := [][2]string{
		{"a/b", "a/b"},
		{"a/b/.", "a/b"},
		{"a/b", "a/b/c/d"},
		{"a/b", "a/b/../c"},
		{"a/b/c", "a/b"},
		{"a/b/c", "a"},
		{"a/b/c", "a/b/c/d/e"},
		{"a/b/c", "x/y/z"},
		{"a", "a"},
		{"a", "."},
		{".", "a"},
		{".", "."},
		{"..", "a"},
		{"../..", "a"},
		{"/a/b", "/a/b/c"},
		{"/a/b/c", "/a/b"},
		{"/a", "/a"},
		{"/", "/a/b"},
		{"/a/b", "/"},
		{"/a/b", "/c/d"},
		{"/", "/"},
		{"a/b", "/a/b"},
		{"/a/b", "a/b"},
		{"a/./b", "a/b/c"},
		{"a//b", "a/b/c"},
		{"a/b/", "a/b/c"},
		{"..", ".."},
		{"../a", "../b"},
		{"a/../..", "b"},
	}
	for _, r := range rels {
		got, err := filepath.Rel(r[0], r[1])
		fmt.Printf("rel %-10q %-12q -> %-14q err=%v\n", r[0], r[1], got, err)
	}

	locals := []string{
		"", ".", "..", "/", "a", "a/b", "a/b/c",
		"./a", "a/./b", "a/../b", "a/..", "a/../..",
		"/a", "../a", "a/../../b", ".hidden", "a//b",
		"a/", "/a/b", "..a", "a..", "a/..b",
	}
	for _, p := range locals {
		loc, err := filepath.Localize(p)
		fmt.Printf("local %-12q islocal=%-5v localize=(%q,%v)\n", p, filepath.IsLocal(p), loc, err)
	}
	// Localize also rejects a path holding the OS separator it would
	// have to invent — on Unix that is a backslash, which is a legal
	// filename character and so must NOT be split on.
	for _, p := range []string{"a\\b", "a\\", "\\", "a\x00b"} {
		loc, err := filepath.Localize(p)
		fmt.Printf("local-sep %-8q islocal=%-5v -> (%q,%v)\n", p, filepath.IsLocal(p), loc, err)
	}

	for _, p := range []string{"", ":", "a", "a:b", "a:b:c", "::", "a::b", ":a", "a:"} {
		fmt.Printf("splitlist %-8q -> %q (n=%d)\n", p, filepath.SplitList(p), len(filepath.SplitList(p)))
	}

	// On Unix these three are identities or empty, and Go says so.
	for _, p := range []string{"", "a/b", "a\\b", "C:\\x", "/a/b"} {
		fmt.Printf("slash %-8q toslash=%-8q fromslash=%-8q volume=%q\n",
			p, filepath.ToSlash(p), filepath.FromSlash(p), filepath.VolumeName(p))
	}

	fmt.Printf("sep %q listsep %q\n", filepath.Separator, filepath.ListSeparator)
}
