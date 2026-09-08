// gen_os_file_misc_ref — File.Chdir, File.Chown, Getpagesize and
// Process.Release.
//
//	scripts/goref.sh os tools/gen_os_file_misc_ref.go
//
// Small surface, but two of the four have a contract that is easy to
// miss. Release sets Pid to -1 on unix "for historical reasons"
// (exec.go:273-278) and Go's own comment says it cannot be changed —
// so a caller reading p.Pid after Release sees -1, and a SECOND Signal
// must answer ErrProcessDone rather than signalling pid -1, which
// would mean "every process in the group".
package os_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestGoishRef(t *testing.T) {
	fmt.Printf("GOROW\tgetpagesize\t%d\n", os.Getpagesize())

	base := t.TempDir()
	sub := filepath.Join(base, "sub")
	_ = os.MkdirAll(sub, 0o755)
	_ = os.WriteFile(filepath.Join(sub, "f.txt"), []byte("F"), 0o644)

	// File.Chdir: the cwd afterwards is the directory the fd names.
	before, _ := os.Getwd()
	d, err := os.Open(sub)
	if err != nil {
		t.Fatal(err)
	}
	cerr := d.Chdir()
	after, _ := os.Getwd()
	fmt.Printf("GOROW\tchdir:ok\terr=%v moved=%v\n", cerr, after != before)
	// Reading a relative name now resolves inside that directory.
	b, rerr := os.ReadFile("f.txt")
	fmt.Printf("GOROW\tchdir:relative\tdata=%q err=%v\n", string(b), rerr == nil)
	_ = os.Chdir(before)
	d.Close()

	// Chdir on a FILE, not a directory.
	f, _ := os.Open(filepath.Join(sub, "f.txt"))
	e := f.Chdir()
	fmt.Printf("GOROW\tchdir:notdir\terr=%v\n", e != nil)
	// ...and on a closed file.
	f.Close()
	e = f.Chdir()
	fmt.Printf("GOROW\tchdir:closed\terr=%v\n", e != nil)

	// File.Chown to our own ids: a no-op that still exercises fchown.
	g, _ := os.Open(filepath.Join(sub, "f.txt"))
	oerr := g.Chown(os.Getuid(), os.Getgid())
	fmt.Printf("GOROW\tchown:ok\terr=%v\n", oerr)
	g.Close()
	oerr = g.Chown(os.Getuid(), os.Getgid())
	fmt.Printf("GOROW\tchown:closed\terr=%v\n", oerr != nil)

	// Process.Release.
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	_ = cmd.Start()
	p := cmd.Process
	rel := p.Release()
	fmt.Printf("GOROW\trelease:err\t%v\n", rel)
	fmt.Printf("GOROW\trelease:pid\t%d\n", p.Pid)
	// A signal after Release must not reach pid -1.
	serr := p.Signal(syscall.SIGTERM)
	fmt.Printf("GOROW\trelease:signal\terr=%v\n", serr)
}
