package fstest_test

import (
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// fstest.TestFS is a conformance checker: it walks an FS and asserts
// the contract every FS implementation is supposed to keep. That makes
// it load-bearing in a way tests usually are not — a checker that
// misses a violation is worse than no checker, because an
// implementation ships with a passing test and the bug surfaces in
// whatever reads it.
//
// So this measures TestFS against filesystems that are DELIBERATELY
// WRONG, one broken rule each, and pins which ones it catches. A port
// whose TestFS is more permissive than Go's would let a broken FS
// through; one that is stricter would reject an FS Go accepts, which
// is its own problem for anyone porting a working implementation.
//
// The rules exercised: Open must reject an invalid path, ReadDir must
// agree with Open, Stat must agree with the DirEntry, a file's content
// must be the same on every read, and a name the caller says exists
// must actually be there.
func TestGoishRef(t *testing.T) {
	mt := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
	good := fstest.MapFS{
		"a.txt":     {Data: []byte("alpha"), Mode: 0644, ModTime: mt},
		"dir/b.txt": {Data: []byte("bravo"), Mode: 0644, ModTime: mt},
		"dir/sub/c": {Data: []byte("charlie"), Mode: 0644, ModTime: mt},
	}

	// A conforming FS with the right expectations must pass.
	fmt.Printf("ok all-names -> %s\n",
		errText(fstest.TestFS(good, "a.txt", "dir/b.txt", "dir/sub/c")))
	fmt.Printf("ok subset -> %s\n", errText(fstest.TestFS(good, "a.txt")))
	fmt.Printf("ok none -> %s\n", errText(fstest.TestFS(good)))

	// A name the caller claims exists but does not.
	fmt.Printf("missing-expected -> caught=%v\n",
		fstest.TestFS(good, "a.txt", "nope.txt") != nil)

	// An empty FS with no expectations is still conforming.
	fmt.Printf("empty-fs -> %s\n", errText(fstest.TestFS(fstest.MapFS{})))

	// Now the broken ones. Each wraps the good FS and violates exactly
	// one rule.
	for _, c := range []struct {
		name string
		fsys fs.FS
	}{
		{"opens-invalid-path", brokenFS{good, "invalid-path"}},
		{"content-differs", brokenFS{good, "unstable-content"}},
		{"stat-disagrees", brokenFS{good, "wrong-size"}},
		{"readdir-hides", brokenFS{good, "hide-entry"}},
		{"open-succeeds-missing", brokenFS{good, "open-anything"}},
	} {
		err := fstest.TestFS(c.fsys, "a.txt")
		fmt.Printf("broken %-22s -> caught=%-5v\n", c.name, err != nil)
	}

	// MapFS's own behaviour, which everything above rests on.
	{
		f, err := good.Open("a.txt")
		if err != nil {
			fmt.Printf("mapfs open-err=%q\n", err.Error())
		} else {
			b, _ := io.ReadAll(f)
			st, _ := f.Stat()
			fmt.Printf("mapfs read=%q name=%q size=%d mode=%s\n",
				string(b), st.Name(), st.Size(), st.Mode())
			f.Close()
		}
		for _, p := range []string{"missing", "dir", "", "/a.txt", "./a.txt", "dir/../a.txt"} {
			_, err := good.Open(p)
			fmt.Printf("mapfs open %-14q -> err=%s\n", p, errText(err))
		}
		ents, _ := fs.ReadDir(good, ".")
		var names []string
		for _, e := range ents {
			names = append(names, fmt.Sprintf("%s(dir=%v)", e.Name(), e.IsDir()))
		}
		fmt.Printf("mapfs readdir-root -> [%s]\n", strings.Join(names, " "))
		// A MapFS synthesises the directories implied by its keys.
		st, err := fs.Stat(good, "dir/sub")
		fmt.Printf("mapfs implied-dir isdir=%v err=%s\n", err == nil && st.IsDir(), errText(err))
	}
}

// brokenFS breaks exactly one rule, chosen by `how`.
type brokenFS struct {
	inner fstest.MapFS
	how   string
}

func (b brokenFS) Open(name string) (fs.File, error) {
	switch b.how {
	case "invalid-path":
		// Accepts a path fs.ValidPath rejects.
		if name == "./a.txt" || name == "/a.txt" {
			return b.inner.Open("a.txt")
		}
	case "open-anything":
		if !fs.ValidPath(name) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
		}
		f, err := b.inner.Open(name)
		if err != nil {
			// Pretend every name exists, serving a.txt's bytes.
			return b.inner.Open("a.txt")
		}
		return f, nil
	case "unstable-content":
		f, err := b.inner.Open(name)
		if err != nil || name != "a.txt" {
			return f, err
		}
		return &flakyFile{File: f, n: 0}, nil
	}
	return b.inner.Open(name)
}

func (b brokenFS) ReadDir(name string) ([]fs.DirEntry, error) {
	ents, err := fs.ReadDir(b.inner, name)
	if err != nil {
		return ents, err
	}
	switch b.how {
	case "hide-entry":
		var out []fs.DirEntry
		for _, e := range ents {
			if e.Name() != "a.txt" {
				out = append(out, e)
			}
		}
		return out, nil
	case "wrong-size":
		var out []fs.DirEntry
		for _, e := range ents {
			out = append(out, lyingEntry{e})
		}
		return out, nil
	}
	return ents, nil
}

// flakyFile returns different bytes on a second open.
type flakyFile struct {
	fs.File
	n int
}

func (f *flakyFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	for i := 0; i < n; i++ {
		p[i] ^= 0x20
	}
	return n, err
}

// lyingEntry reports a size that does not match the file.
type lyingEntry struct{ fs.DirEntry }

func (e lyingEntry) Info() (fs.FileInfo, error) {
	fi, err := e.DirEntry.Info()
	if err != nil {
		return fi, err
	}
	return lyingInfo{fi}, nil
}

type lyingInfo struct{ fs.FileInfo }

func (i lyingInfo) Size() int64 { return i.FileInfo.Size() + 100 }

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + " …"
	}
	return s
}
