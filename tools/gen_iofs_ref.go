package fs_test

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// io/fs is the abstraction every file-serving thing in the tree sits
// on: http.FileServer, embed, os.DirFS, archive/zip. Its rules decide
// which paths a caller can reach, and the one that matters most is
// ValidPath — the single function standing between a caller-supplied
// name and an FS implementation that will happily open whatever it is
// given.
//
// ValidPath is deliberately strict in ways that are easy to relax by
// accident: no leading slash, no trailing slash, no "." or ".."
// element ANYWHERE, no empty element, no backslashes-as-separators.
// "." alone is the only special case, and it is valid. An FS that
// skipped the check would accept "../../etc/passwd" and a port that
// accepted one extra shape opens exactly that door.
//
// The rest is the plumbing every FS shares: ReadDir's sort order, Glob's
// pattern rules, WalkDir's traversal order and its SkipDir/SkipAll
// controls, Sub's path rewriting, and the String() forms that get
// printed into logs.
func TestGoishRef(t *testing.T) {
	// 1. ValidPath, the gate.
	for _, p := range []string{
		".", "", "/", "//", "a", "a/b", "a/b/c", "./a", "a/.", "a/./b",
		"..", "../a", "a/..", "a/../b", "a//b", "/a", "a/", "a/b/",
		"...", "a...", ".a", "a.", " ", "a b", "a\\b", "C:/a",
		"\x00", "a\x00b", "日本/語", "a/./", "././.",
	} {
		fmt.Printf("valid %-12q -> %v\n", p, fs.ValidPath(p))
	}

	// A tiny filesystem, fixed so both sides walk the same tree.
	mt := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	fsys := fstest.MapFS{
		"a.txt":         {Data: []byte("alpha"), Mode: 0644, ModTime: mt},
		"b.txt":         {Data: []byte("bravo!!"), Mode: 0600, ModTime: mt},
		"dir/c.txt":     {Data: []byte("charlie"), Mode: 0644, ModTime: mt},
		"dir/d.go":      {Data: []byte("delta"), Mode: 0644, ModTime: mt},
		"dir/sub/e.txt": {Data: []byte("echo"), Mode: 0644, ModTime: mt},
		"z.md":          {Data: []byte("zulu"), Mode: 0644, ModTime: mt},
	}

	// 2. ReadDir: sorted by filename, always.
	for _, dir := range []string{".", "dir", "dir/sub", "missing", "a.txt"} {
		ents, err := fs.ReadDir(fsys, dir)
		if err != nil {
			fmt.Printf("readdir %-10q -> err=%q\n", dir, err.Error())
			continue
		}
		var parts []string
		for _, e := range ents {
			parts = append(parts, fmt.Sprintf("%s(dir=%v,type=%s)", e.Name(), e.IsDir(), e.Type()))
		}
		fmt.Printf("readdir %-10q -> n=%d [%s]\n", dir, len(ents), strings.Join(parts, " "))
	}

	// 3. Stat and the String() forms, which is what lands in a log.
	for _, name := range []string{"a.txt", "dir", "dir/sub/e.txt", "missing", "."} {
		fi, err := fs.Stat(fsys, name)
		if err != nil {
			fmt.Printf("stat %-14q -> err=%q\n", name, err.Error())
			continue
		}
		fmt.Printf("stat %-14q -> name=%q size=%d dir=%v mode=%s modtime=%s\n",
			name, fi.Name(), fi.Size(), fi.IsDir(), fi.Mode(),
			fi.ModTime().UTC().Format(time.RFC3339))
		// FileInfoToDirEntry wraps a FileInfo; its String() is the
		// documented rendering and it is NOT the same as the
		// FileInfo's.
		de := fs.FileInfoToDirEntry(fi)
		fmt.Printf("entry %-14q -> name=%q dir=%v type=%s info-eq=%v\n",
			name, de.Name(), de.IsDir(), de.Type(), infoName(de) == fi.Name())
		fmt.Printf("strings %-12q -> fileinfo=%q direntry=%q\n",
			name, fmt.Sprintf("%v", fi), fmt.Sprintf("%v", de))
	}

	// 4. Glob: a pattern language, not a regexp, and a malformed
	//    pattern is an ERROR rather than a non-match.
	for _, pat := range []string{
		"*", "*.txt", "dir/*", "dir/*.txt", "dir/**", "*/*", "*/*/*",
		"a.txt", "missing", "[", "a[", "dir/[a-z].txt", "**",
		"", ".", "./*", "dir", "dir/", "*/", "?.txt", "[!a]*.txt",
	} {
		names, err := fs.Glob(fsys, pat)
		if err != nil {
			fmt.Printf("glob %-14q -> err=%q\n", pat, err.Error())
			continue
		}
		sort.Strings(names)
		fmt.Printf("glob %-14q -> n=%d [%s]\n", pat, len(names), strings.Join(names, " "))
	}

	// 5. WalkDir: order, and the two controls that change it.
	{
		var seen []string
		fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			seen = append(seen, fmt.Sprintf("%s(dir=%v)", p, d.IsDir()))
			return nil
		})
		fmt.Printf("walk all -> %s\n", strings.Join(seen, " "))
	}
	{
		var seen []string
		fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			seen = append(seen, p)
			if d.IsDir() && p == "dir" {
				return fs.SkipDir
			}
			return nil
		})
		fmt.Printf("walk skipdir -> %s\n", strings.Join(seen, " "))
	}
	{
		var seen []string
		fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			seen = append(seen, p)
			if p == "dir/c.txt" {
				return fs.SkipAll
			}
			return nil
		})
		fmt.Printf("walk skipall -> %s\n", strings.Join(seen, " "))
	}
	{
		// SkipDir returned from a FILE, not a directory, skips the
		// remaining files in the containing directory — a rule that
		// reads like a bug until you need it.
		var seen []string
		fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			seen = append(seen, p)
			if p == "a.txt" {
				return fs.SkipDir
			}
			return nil
		})
		fmt.Printf("walk skipdir-from-file -> %s\n", strings.Join(seen, " "))
	}
	{
		var seen []string
		err := fs.WalkDir(fsys, "missing", func(p string, d fs.DirEntry, err error) error {
			seen = append(seen, fmt.Sprintf("%s(err=%v)", p, err != nil))
			return err
		})
		fmt.Printf("walk missing -> %s err=%v\n", strings.Join(seen, " "), err != nil)
	}
	{
		var seen []string
		fs.WalkDir(fsys, "dir", func(p string, d fs.DirEntry, err error) error {
			seen = append(seen, p)
			return nil
		})
		fmt.Printf("walk subtree -> %s\n", strings.Join(seen, " "))
	}

	// 6. Sub: an FS rooted lower down, and what it refuses.
	{
		sub, err := fs.Sub(fsys, "dir")
		if err != nil {
			fmt.Printf("sub err=%q\n", err.Error())
		} else {
			ents, _ := fs.ReadDir(sub, ".")
			var names []string
			for _, e := range ents {
				names = append(names, e.Name())
			}
			fmt.Printf("sub readdir -> [%s]\n", strings.Join(names, " "))
			for _, p := range []string{"c.txt", "sub/e.txt", "../a.txt", "/c.txt", "."} {
				b, err := fs.ReadFile(sub, p)
				if err != nil {
					fmt.Printf("sub read %-12q -> err=%q\n", p, err.Error())
					continue
				}
				fmt.Printf("sub read %-12q -> %q\n", p, string(b))
			}
		}
		_, err = fs.Sub(fsys, "../escape")
		fmt.Printf("sub invalid-root err=%q\n", errText(err))
		_, err = fs.Sub(fsys, ".")
		fmt.Printf("sub dot-root err=%s\n", errText(err))
	}

	// 7. ReadFile through the interface, including the refusals.
	for _, p := range []string{"a.txt", "dir/c.txt", "missing", "dir", "../a.txt", "/a.txt", ""} {
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			fmt.Printf("readfile %-12q -> err=%q\n", p, err.Error())
			continue
		}
		fmt.Printf("readfile %-12q -> %q\n", p, string(b))
	}
}

func infoName(d fs.DirEntry) string {
	fi, err := d.Info()
	if err != nil {
		return ""
	}
	return fi.Name()
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
