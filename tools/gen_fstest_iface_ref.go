package fstest_test

import (
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"
)

// MapFS satisfies six fs interfaces, and each of its optimized methods
// is written in terms of the generic fs helper for that same interface.
// That is only safe because of `fsOnly` and `noSub`, the two wrappers
// that hide the fast path from the helper — drop either and
// `MapFS.ReadFile` calls `fs.ReadFile` calls `MapFS.ReadFile` until the
// stack runs out. The vectors below take both routes to every answer,
// so the two agree and neither recurses.
func TestGoishRef(t *testing.T) {
	m := fstest.MapFS{
		"a.txt":          {Data: []byte("alpha")},
		"b.log":          {Data: []byte("beta")},
		"sub/c.txt":      {Data: []byte("gamma")},
		"sub/deep/d.txt": {Data: []byte("delta")},
	}

	// Which interfaces does MapFS answer to?
	var fsys fs.FS = m
	_, isReadFile := fsys.(fs.ReadFileFS)
	_, isStat := fsys.(fs.StatFS)
	_, isReadDir := fsys.(fs.ReadDirFS)
	_, isGlob := fsys.(fs.GlobFS)
	_, isReadLink := fsys.(fs.ReadLinkFS)
	_, isSub := fsys.(fs.SubFS)
	fmt.Printf("iface readfile=%v stat=%v readdir=%v glob=%v readlink=%v sub=%v\n",
		isReadFile, isStat, isReadDir, isGlob, isReadLink, isSub)

	// The method and the helper must agree, and neither may recurse.
	for _, name := range []string{"a.txt", "b.log", "sub/c.txt", "nope"} {
		viaMethod, e1 := m.ReadFile(name)
		viaHelper, e2 := fs.ReadFile(fsys, name)
		fmt.Printf("readfile %-12q method=%q,%v helper=%q,%v agree=%v\n",
			name, viaMethod, e1, viaHelper, e2,
			string(viaMethod) == string(viaHelper) && fmt.Sprint(e1) == fmt.Sprint(e2))
	}

	for _, name := range []string{"a.txt", "sub", "sub/deep", "nope"} {
		i1, e1 := m.Stat(name)
		i2, e2 := fs.Stat(fsys, name)
		n1, n2 := "", ""
		if e1 == nil {
			n1 = i1.Name()
		}
		if e2 == nil {
			n2 = i2.Name()
		}
		fmt.Printf("stat %-10q method=%q,%v helper=%q,%v agree=%v\n",
			name, n1, e1, n2, e2, n1 == n2 && fmt.Sprint(e1) == fmt.Sprint(e2))
	}

	for _, name := range []string{".", "sub", "sub/deep", "nope"} {
		l1, e1 := m.ReadDir(name)
		l2, e2 := fs.ReadDir(fsys, name)
		var n1, n2 []string
		for _, e := range l1 {
			n1 = append(n1, e.Name())
		}
		for _, e := range l2 {
			n2 = append(n2, e.Name())
		}
		fmt.Printf("readdir %-10q method=%v,%v helper=%v,%v agree=%v\n",
			name, n1, e1, n2, e2,
			fmt.Sprint(n1) == fmt.Sprint(n2) && fmt.Sprint(e1) == fmt.Sprint(e2))
	}

	for _, pat := range []string{"*", "*.txt", "sub/*", "*/*.txt", "nope*", "["} {
		g1, e1 := m.Glob(pat)
		g2, e2 := fs.Glob(fsys, pat)
		fmt.Printf("glob %-10q method=%v,%v helper=%v,%v agree=%v\n",
			pat, g1, e1, g2, e2,
			fmt.Sprint(g1) == fmt.Sprint(g2) && fmt.Sprint(e1) == fmt.Sprint(e2))
	}

	// Sub through the method and through the helper. Both must produce
	// a filesystem rooted at the same place.
	for _, dir := range []string{".", "sub", "sub/deep"} {
		s1, e1 := m.Sub(dir)
		s2, e2 := fs.Sub(fsys, dir)
		var n1, n2 []string
		if e1 == nil {
			l, _ := fs.ReadDir(s1, ".")
			for _, e := range l {
				n1 = append(n1, e.Name())
			}
		}
		if e2 == nil {
			l, _ := fs.ReadDir(s2, ".")
			for _, e := range l {
				n2 = append(n2, e.Name())
			}
		}
		fmt.Printf("sub %-10q method=%v,%v helper=%v,%v agree=%v\n",
			dir, n1, e1, n2, e2,
			fmt.Sprint(n1) == fmt.Sprint(n2) && fmt.Sprint(e1) == fmt.Sprint(e2))
	}

	// ReadLink and Lstat reach MapFS only through ReadLinkFS.
	for _, name := range []string{"a.txt", "sub", "nope"} {
		t1, e1 := m.ReadLink(name)
		t2, e2 := fs.ReadLink(fsys, name)
		fmt.Printf("readlink %-8q method=%q,%v helper=%q,%v agree=%v\n",
			name, t1, e1, t2, e2, t1 == t2 && fmt.Sprint(e1) == fmt.Sprint(e2))
		i1, e3 := m.Lstat(name)
		i2, e4 := fs.Lstat(fsys, name)
		n1, n2 := "", ""
		if e3 == nil {
			n1 = i1.Name()
		}
		if e4 == nil {
			n2 = i2.Name()
		}
		fmt.Printf("lstat %-8q method=%q,%v helper=%q,%v agree=%v\n",
			name, n1, e3, n2, e4, n1 == n2 && fmt.Sprint(e3) == fmt.Sprint(e4))
	}
}
