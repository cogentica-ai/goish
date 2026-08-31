package tar_test

import (
	"archive/tar"
	"fmt"
	"io/fs"
	"testing"
)

// Header.FileInfo().Mode() reads the file type from TWO places: the
// Unix type bits in Header.Mode, and Header.Typeflag. A port that
// consults only Typeflag reports every header written by a tool that
// fills Mode from a stat(2) as a regular file — and IsDir(), which is
// defined as Mode().IsDir(), goes wrong with it.
//
// The vectors below cross the seven type-bit values with the type
// flags, so the two sources are exercised together and apart.
func TestGoishRef(t *testing.T) {
	type row struct {
		name string
		mode int64
		flag byte
	}
	modes := []struct {
		label string
		bits  int64
	}{
		{"none", 0o644},
		{"dir", 0o40000 | 0o755},
		{"fifo", 0o10000 | 0o644},
		{"reg", 0o100000 | 0o644},
		{"lnk", 0o120000 | 0o777},
		{"blk", 0o60000 | 0o660},
		{"chr", 0o20000 | 0o666},
		{"sock", 0o140000 | 0o755},
		{"setuid", 0o4000 | 0o755},
		{"setgid", 0o2000 | 0o755},
		{"sticky", 0o1000 | 0o755},
		{"all-suid", 0o40000 | 0o4000 | 0o2000 | 0o1000 | 0o755},
	}
	flags := []struct {
		label string
		f     byte
	}{
		{"Reg", tar.TypeReg},
		{"Dir", tar.TypeDir},
		{"Symlink", tar.TypeSymlink},
		{"Char", tar.TypeChar},
		{"Block", tar.TypeBlock},
		{"Fifo", tar.TypeFifo},
	}
	for _, m := range modes {
		for _, fl := range flags {
			h := &tar.Header{Name: "x", Mode: m.bits, Typeflag: fl.f, Size: 7}
			fi := h.FileInfo()
			fmt.Printf("mode %-9s flag %-8s -> %s isdir=%-5v perm=%o name=%q size=%d\n",
				m.label, fl.label, fi.Mode(), fi.IsDir(), fi.Mode().Perm(), fi.Name(), fi.Size())
		}
	}

	// Name(): a directory header keeps its trailing slash out of the
	// base name.
	for _, n := range []string{"a.txt", "d/", "d/e/", "d/e/f.txt", "/", "."} {
		h := &tar.Header{Name: n, Mode: 0o40755, Typeflag: tar.TypeDir}
		fmt.Printf("name %-10q -> %q\n", n, h.FileInfo().Name())
		h2 := &tar.Header{Name: n, Mode: 0o644, Typeflag: tar.TypeReg}
		fmt.Printf("name-reg %-10q -> %q\n", n, h2.FileInfo().Name())
	}

	// FormatFileInfo over a Header's FileInfo — this is what
	// headerFileInfo.String() returns.
	for _, m := range modes[:8] {
		h := &tar.Header{Name: "x", Mode: m.bits, Typeflag: tar.TypeReg, Size: 3}
		fmt.Printf("format %-9s %q\n", m.label, fs.FormatFileInfo(h.FileInfo()))
	}

	// FileInfoHeader round-trips the mode bits back out.
	for _, m := range modes {
		h := &tar.Header{Name: "x", Mode: m.bits, Typeflag: tar.TypeReg, Size: 3}
		h2, err := tar.FileInfoHeader(h.FileInfo(), "")
		if err != nil {
			fmt.Printf("roundtrip %-9s err=%v\n", m.label, err)
			continue
		}
		fmt.Printf("roundtrip %-9s mode=%o flag=%q name=%q size=%d\n",
			m.label, h2.Mode, h2.Typeflag, h2.Name, h2.Size)
	}
}
