package os_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

// os.IsExist/IsNotExist/IsPermission predate errors.Is and are NOT
// equality tests. Each calls underlyingErrorIs, which unwraps the three
// os error-wrapping types and then, for a syscall.Errno, consults
// Errno.Is. A port that writes `err == ErrNotExist` answers false for
// every error os itself returns, because os returns *PathError.
func TestGoishRef(t *testing.T) {
	mk := func(op, path string, err error) error {
		return &fs.PathError{Op: op, Path: path, Err: err}
	}

	cases := []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"ErrNotExist", fs.ErrNotExist},
		{"ErrExist", fs.ErrExist},
		{"ErrPermission", fs.ErrPermission},
		{"ErrClosed", fs.ErrClosed},
		{"ErrInvalid", fs.ErrInvalid},
		{"ENOENT", syscall.ENOENT},
		{"EEXIST", syscall.EEXIST},
		{"ENOTEMPTY", syscall.ENOTEMPTY},
		{"EACCES", syscall.EACCES},
		{"EPERM", syscall.EPERM},
		{"ENOTDIR", syscall.ENOTDIR},
		{"EINVAL", syscall.EINVAL},
		{"EAGAIN", syscall.EAGAIN},
		{"ETIMEDOUT", syscall.ETIMEDOUT},
		{"ENOSYS", syscall.ENOSYS},
		{"path/ENOENT", mk("open", "/x", syscall.ENOENT)},
		{"path/EEXIST", mk("mkdir", "/x", syscall.EEXIST)},
		{"path/EACCES", mk("open", "/x", syscall.EACCES)},
		{"path/ErrNotExist", mk("stat", "/x", fs.ErrNotExist)},
		{"path/ErrClosed", mk("read", "/x", fs.ErrClosed)},
		{"syscallerr/ENOENT", os.NewSyscallError("open", syscall.ENOENT)},
		{"syscallerr/ETIMEDOUT", os.NewSyscallError("read", syscall.ETIMEDOUT)},
		{"link/EEXIST", &os.LinkError{Op: "link", Old: "a", New: "b", Err: syscall.EEXIST}},
		{"deadline", os.ErrDeadlineExceeded},
		{"nodeadline", os.ErrNoDeadline},
		{"plain", errors.New("plain")},
		{"wrapped-fmt", fmt.Errorf("ctx: %w", syscall.ENOENT)},
	}
	for _, c := range cases {
		fmt.Printf("is %-22s exist=%-5v notexist=%-5v perm=%-5v timeout=%v\n",
			c.name, os.IsExist(c.err), os.IsNotExist(c.err),
			os.IsPermission(c.err), os.IsTimeout(c.err))
	}

	// errors.Is is the modern spelling and disagrees with the historical
	// predicates in exactly one place: a %w-wrapped errno.
	for _, c := range cases {
		if c.err == nil {
			continue
		}
		fmt.Printf("errorsis %-22s notexist=%-5v exist=%-5v perm=%-5v unsupported=%v\n",
			c.name,
			errors.Is(c.err, fs.ErrNotExist), errors.Is(c.err, fs.ErrExist),
			errors.Is(c.err, fs.ErrPermission), errors.Is(c.err, errors.ErrUnsupported))
	}

	// Errno's own predicates.
	for _, e := range []syscall.Errno{
		syscall.EAGAIN, syscall.EWOULDBLOCK, syscall.ETIMEDOUT,
		syscall.EINTR, syscall.EMFILE, syscall.ENFILE, syscall.ENOENT,
		syscall.ENOSYS, syscall.ENOTSUP, syscall.EOPNOTSUPP,
	} {
		fmt.Printf("errno %-4d timeout=%-5v temporary=%-5v text=%q\n",
			int(e), e.Timeout(), e.Temporary(), e.Error())
	}

	// SyscallError renders as "syscall: err" and unwraps to the errno.
	se := os.NewSyscallError("pipe2", syscall.EMFILE)
	fmt.Printf("syscallerr text=%q unwrap=%q\n", se.Error(), errors.Unwrap(se).Error())
	fmt.Printf("syscallerr nil=%v\n", os.NewSyscallError("x", nil) == nil)
	var target *os.SyscallError
	fmt.Printf("syscallerr as=%v syscall=%q\n", errors.As(se, &target), target.Syscall)

	// os.Setenv's three rejections all come back as one wrapped EINVAL.
	for _, c := range []struct{ k, v string }{
		{"", "x"}, {"a=b", "x"}, {"a\x00b", "x"}, {"k", "v\x00w"}, {"k", "v"},
	} {
		err := os.Setenv(c.k, c.v)
		fmt.Printf("setenv k=%q v=%q err=%v isnil=%v\n", c.k, c.v, err, err == nil)
	}

	// The real thing, end to end: what os.Open on a missing file gives.
	_, err := os.Open("/definitely/not/here")
	fmt.Printf("open text=%q isnotexist=%v errorsis=%v\n",
		err, os.IsNotExist(err), errors.Is(err, fs.ErrNotExist))
	var pe *fs.PathError
	fmt.Printf("open as=%v op=%q err=%v\n", errors.As(err, &pe), pe.Op, pe.Err)
}
