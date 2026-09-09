// Command gen_syscall_openat_ref records Linux syscall.Openat behavior used by
// examples/syscall_openat_ref_smoke.rs. Run with Go 1.25.5 on linux/amd64.
package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func main() {
	const atFDCWD = -100
	root := "/tmp/goish_openat_ref"
	_ = os.RemoveAll(root)
	if err := os.MkdirAll(root+"/sub", 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(root+"/file", []byte("x"), 0o644); err != nil {
		panic(err)
	}
	// A directory target distinguishes O_NOFOLLOW from silently following the
	// link: without O_NOFOLLOW, O_DIRECTORY would make this Openat succeed.
	if err := os.Symlink("sub", root+"/link"); err != nil {
		panic(err)
	}
	defer os.RemoveAll(root)

	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | syscall.O_DIRECTORY |
		syscall.O_NOCTTY | syscall.O_NONBLOCK | syscall.O_NOFOLLOW
	fmt.Printf("constants\t%d\t%d\t%d\t%d\t%d\n", syscall.O_DIRECTORY, syscall.O_NOCTTY, syscall.O_NOFOLLOW, syscall.O_NONBLOCK, syscall.O_CLOEXEC)

	rootFD, err := syscall.Openat(atFDCWD, root, flags, 0)
	fmt.Printf("root\t%t\t%t\n", rootFD >= 0, err == nil)

	childFD, childErr := syscall.Openat(rootFD, "sub", flags, 0)
	var stat syscall.Stat_t
	statErr := syscall.Fstat(childFD, &stat)
	fmt.Printf("child\t%t\t%t\t%t\n", childFD >= 0, childErr == nil, statErr == nil && stat.Mode&syscall.S_IFMT == syscall.S_IFDIR)
	_ = syscall.Close(childFD)

	fileFD, fileErr := syscall.Openat(rootFD, "file", flags, 0)
	fmt.Printf("file-directory\t%t\t%t\n", fileFD == -1, errors.Is(fileErr, syscall.ENOTDIR))

	linkFD, linkErr := syscall.Openat(rootFD, "link", flags, 0)
	fmt.Printf("nofollow-directory\t%t\t%d\n", linkFD == -1, errnoNumber(linkErr))

	missingFD, missingErr := syscall.Openat(rootFD, "missing", flags, 0)
	fmt.Printf("missing\t%t\t%t\n", missingFD == -1, errors.Is(missingErr, syscall.ENOENT))

	nulFD, nulErr := syscall.Openat(rootFD, "sub\x00ignored", flags, 0)
	fmt.Printf("embedded-nul\t%t\t%t\n", nulFD == 0, errors.Is(nulErr, syscall.EINVAL))

	_ = syscall.Close(rootFD)
	closedFD, closedErr := syscall.Openat(rootFD, "sub", flags, 0)
	fmt.Printf("closed-dirfd\t%t\t%t\n", closedFD == -1, errors.Is(closedErr, syscall.EBADF))

	absFD, absErr := syscall.Openat(-1, root+"/sub", flags, 0)
	fmt.Printf("absolute-ignores-dirfd\t%t\t%t\n", absFD >= 0, absErr == nil)
	_ = syscall.Close(absFD)
}

func errnoNumber(err error) uintptr {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uintptr(errno)
	}
	return 0
}
