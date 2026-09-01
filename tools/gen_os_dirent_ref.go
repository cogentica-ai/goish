package os_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// getdents64 hands back a d_type byte, and Go maps ALL SEVEN of its
// values onto FileMode type bits — plus DT_UNKNOWN, which is not a type
// at all but an instruction to go lstat the entry. A port that maps
// only DT_DIR and DT_LNK reports a fifo, a socket and a device as
// regular files; one that ignores DT_UNKNOWN reports EVERY entry as a
// regular file on the filesystems that return it.
func TestGoishRef(t *testing.T) {
	root := t.TempDir()
	j := func(p string) string { return filepath.Join(root, p) }

	os.WriteFile(j("areg"), []byte("x"), 0644)
	os.Mkdir(j("bdir"), 0755)
	os.Symlink(j("areg"), j("clink"))
	if err := syscall.Mknod(j("dfifo"), syscall.S_IFIFO|0644, 0); err != nil {
		fmt.Printf("mkfifo err=%v\n", err)
	}
	ents, err := os.ReadDir(root)
	fmt.Printf("readdir err=%v n=%d\n", err, len(ents))
	for _, e := range ents {
		info, ierr := e.Info()
		fmt.Printf("ent %-8s type=%#x typestr=%q isdir=%-5v info=%q ierr=%v\n",
			e.Name(), uint32(e.Type()), e.Type().String(), e.IsDir(),
			info.Mode().String(), ierr)
	}

	// ReadDir sorts by name, and the sort is the whole reason callers
	// can rely on the order.
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	fmt.Printf("order %v\n", names)

	// fs.FormatDirEntry is what DirEntry.String() gives.
	for _, e := range ents {
		fmt.Printf("string %-8s %q\n", e.Name(), fs.FormatDirEntry(e))
	}

	// The type bits themselves, so a port can check its constants.
	fmt.Printf("bits dir=%#x symlink=%#x namedpipe=%#x socket=%#x device=%#x chardevice=%#x type=%#x\n",
		uint32(fs.ModeDir), uint32(fs.ModeSymlink), uint32(fs.ModeNamedPipe),
		uint32(fs.ModeSocket), uint32(fs.ModeDevice), uint32(fs.ModeCharDevice),
		uint32(fs.ModeType))

	// A char device, straight from /dev — DT_CHR through the same path.
	if des, e := os.ReadDir("/dev"); e == nil {
		for _, d := range des {
			if d.Name() == "null" || d.Name() == "zero" {
				fmt.Printf("dev %-5s type=%#x typestr=%q\n",
					d.Name(), uint32(d.Type()), d.Type().String())
			}
		}
	}

	// Readdirnames: Go returns io.EOF when n > 0 and the directory is
	// exhausted, and nil when n <= 0.
	f, _ := os.Open(root)
	for i := 0; i < 3; i++ {
		ns, e := f.Readdirnames(3)
		fmt.Printf("names n=3 got=%d err=%v\n", len(ns), e)
	}
	f.Close()
	f2, _ := os.Open(root)
	ns, e := f2.Readdirnames(-1)
	fmt.Printf("names n=-1 got=%d err=%v\n", len(ns), e)
	ns, e = f2.Readdirnames(-1)
	fmt.Printf("names n=-1 again got=%d err=%v\n", len(ns), e)
	f2.Close()
	_, e = f2.Readdirnames(-1)
	fmt.Printf("names closed err=%v\n", e)
}
