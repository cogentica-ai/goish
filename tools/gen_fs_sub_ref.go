package fs_test

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"
)

// The whole point of subFS is that it is INVISIBLE: a caller holding a
// sub-filesystem must never see the parent's paths, not in results and
// not in errors. That last half is `fixErr`, and it is what a port
// drops without noticing — every happy path still passes. The vectors
// below read errors as text for exactly that reason.
func TestGoishRef(t *testing.T) {
	m := fstest.MapFS{
		"a.txt":            {Data: []byte("1")},
		"sub/b.txt":        {Data: []byte("2")},
		"sub/c.log":        {Data: []byte("3")},
		"sub/deep/d.txt":   {Data: []byte("4")},
		"sub/deep/e.log":   {Data: []byte("5")},
		"other/f.txt":      {Data: []byte("6")},
		"sub/link":         {Data: []byte("7")},
		"sub/deep/g/h.txt": {Data: []byte("8")},
	}

	// Sub's own argument checking.
	for _, dir := range []string{".", "sub", "sub/deep", "", "/sub", "sub/", "./sub", "../x", "nope"} {
		f, err := fs.Sub(m, dir)
		fmt.Printf("sub %-8q ok=%-5v err=%v invalid=%v\n",
			dir, f != nil && err == nil, err, errors.Is(err, fs.ErrInvalid))
	}

	sub, err := fs.Sub(m, "sub")
	if err != nil {
		t.Fatal(err)
	}

	// Open, and the error text a caller sees. Go reports the name the
	// caller used, never the parent's.
	for _, name := range []string{"b.txt", "deep/d.txt", "nope.txt", "deep", ".", "", "/b.txt", "../a.txt"} {
		f, err := sub.Open(name)
		if err != nil {
			fmt.Printf("open %-12q err=%v notexist=%v invalid=%v\n",
				name, err, errors.Is(err, fs.ErrNotExist), errors.Is(err, fs.ErrInvalid))
			continue
		}
		b := make([]byte, 8)
		n, _ := f.Read(b)
		f.Close()
		fmt.Printf("open %-12q data=%q\n", name, b[:n])
	}

	// ReadFile and ReadDir through the sub, including their errors.
	for _, name := range []string{"b.txt", "deep/d.txt", "nope.txt", "deep"} {
		data, err := fs.ReadFile(sub, name)
		fmt.Printf("readfile %-12q data=%q err=%v\n", name, data, err)
	}
	for _, name := range []string{".", "deep", "nope", "b.txt"} {
		list, err := fs.ReadDir(sub, name)
		names := []string{}
		for _, e := range list {
			names = append(names, e.Name())
		}
		fmt.Printf("readdir %-8q %v err=%v\n", name, names, err)
	}

	// Stat through the sub.
	for _, name := range []string{"b.txt", "deep", "nope", "."} {
		info, err := fs.Stat(sub, name)
		if err != nil {
			fmt.Printf("stat %-8q err=%v\n", name, err)
			continue
		}
		fmt.Printf("stat %-8q name=%q dir=%v size=%d\n",
			name, info.Name(), info.IsDir(), info.Size())
	}

	// Glob through the sub: results come back SHORTENED, and a pattern
	// that matches nothing is not an error.
	for _, pat := range []string{"*", "*.txt", "*.log", "deep/*", "*/*.txt", ".", "nope*", "["} {
		list, err := fs.Glob(sub, pat)
		fmt.Printf("glob %-10q %v err=%v\n", pat, list, err)
	}

	// A nested Sub collapses rather than stacking wrappers.
	deep, err := fs.Sub(sub, "deep")
	fmt.Printf("nested-sub err=%v\n", err)
	if err == nil {
		list, _ := fs.ReadDir(deep, ".")
		names := []string{}
		for _, e := range list {
			names = append(names, e.Name())
		}
		fmt.Printf("nested-readdir %v\n", names)
		_, err := deep.Open("nope.txt")
		fmt.Printf("nested-open-err %v\n", err)
		data, err := fs.ReadFile(deep, "d.txt")
		fmt.Printf("nested-readfile %q err=%v\n", data, err)
		g, err := fs.Glob(deep, "*")
		fmt.Printf("nested-glob %v err=%v\n", g, err)
	}
	same, err := fs.Sub(sub, ".")
	fmt.Printf("sub-dot-same err=%v\n", err)
	if err == nil {
		list, _ := fs.ReadDir(same, ".")
		names := []string{}
		for _, e := range list {
			names = append(names, e.Name())
		}
		fmt.Printf("sub-dot-readdir %v\n", names)
	}

	// ReadLink and Lstat: MapFS implements ReadLinkFS, so both reach it
	// through the sub. A plain file is not a link.
	for _, name := range []string{"b.txt", "link", "nope", "deep"} {
		target, err := fs.ReadLink(sub, name)
		fmt.Printf("readlink %-8q target=%q err=%v\n", name, target, err)
		info, err := fs.Lstat(sub, name)
		if err != nil {
			fmt.Printf("lstat %-8q err=%v\n", name, err)
			continue
		}
		fmt.Printf("lstat %-8q name=%q dir=%v\n", name, info.Name(), info.IsDir())
	}

	// A filesystem that does NOT implement ReadLinkFS: ReadLink is an
	// ErrInvalid PathError, but Lstat falls back to Stat.
	plain := plainFS{m}
	target, err := fs.ReadLink(plain, "a.txt")
	fmt.Printf("plain-readlink %q err=%v invalid=%v\n", target, err, errors.Is(err, fs.ErrInvalid))
	info, err := fs.Lstat(plain, "a.txt")
	if err == nil {
		fmt.Printf("plain-lstat name=%q dir=%v\n", info.Name(), info.IsDir())
	} else {
		fmt.Printf("plain-lstat err=%v\n", err)
	}
	_, err = fs.Lstat(plain, "nope")
	fmt.Printf("plain-lstat-missing err=%v\n", err)

	// PathError formatting and Timeout.
	pe := &fs.PathError{Op: "open", Path: "x/y", Err: fs.ErrNotExist}
	fmt.Printf("patherror %q unwrap=%v timeout=%v\n", pe.Error(), pe.Unwrap(), pe.Timeout())
	pe2 := &fs.PathError{Op: "read", Path: "z", Err: timeoutErr{}}
	fmt.Printf("patherror-timeout %q timeout=%v\n", pe2.Error(), pe2.Timeout())

	// ValidPath, which everything above rests on.
	for _, p := range []string{".", "", "/", "x", "x/y", "x/", "/x", "x//y",
		"./x", "../x", "x/.", "x/..", "..", "a/b/c", "\xff"} {
		fmt.Printf("validpath %-8q %v\n", p, fs.ValidPath(p))
	}

	// FormatFileInfo / FormatDirEntry, and the dirInfo String they back.
	fi, _ := fs.Stat(m, "a.txt")
	fmt.Printf("formatinfo %q\n", fs.FormatFileInfo(fi))
	di := fs.FileInfoToDirEntry(fi)
	fmt.Printf("formatentry %q\n", fs.FormatDirEntry(di))
	fmt.Printf("dirinfo-string %q\n", fmt.Sprint(di))
	dfi, _ := fs.Stat(m, "sub")
	fmt.Printf("formatinfo-dir %q\n", fs.FormatFileInfo(dfi))
	fmt.Printf("formatentry-dir %q\n", fs.FormatDirEntry(fs.FileInfoToDirEntry(dfi)))
}

// plainFS hides MapFS's ReadLinkFS, GlobFS and the rest behind a bare FS.
type plainFS struct{ m fstest.MapFS }

func (p plainFS) Open(name string) (fs.File, error) { return p.m.Open(name) }

type timeoutErr struct{}

func (timeoutErr) Error() string { return "i/o timeout" }
func (timeoutErr) Timeout() bool { return true }
