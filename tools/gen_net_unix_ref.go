// gen_net_unix_ref — the AF_UNIX stream contract goish must match.
//
//	scripts/goref.sh net tools/gen_net_unix_ref.go
//
// Issue #8 wants `net.Listen("unix", path)` / `net.Dial("unix", path)`
// so an API pipe transport can run over a socket file. The rows that
// decide whether a port is correct rather than merely compiling:
//
//   - close_unlinks: Go's (*UnixListener).close removes the socket file
//     before closing the fd (net/unixsock_posix.go:179) — the kernel
//     does not. A port that skips it looks fine until the second Listen
//     on the same path fails with EADDRINUSE.
//   - listen_inuse: which is exactly what bind(2) does on a live path.
//     Go does NOT silently remove a stale file, so every caller's
//     `os.Remove(path)` before Listen stays load-bearing.
//   - conn_local / srv_remote: both ends of an unnamed client are the
//     EMPTY string, not the socket path. A port that echoed the path
//     back would pass a round-trip test and still be wrong.
//
// Paths are replaced with <sock> / <bad> so the transcript is stable.
package net_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoishRef(t *testing.T) {
	dir, err := os.MkdirTemp("", "goishunix")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	bad := "/nonexistent-dir-goish/x.sock"

	norm := func(s string) string {
		s = strings.ReplaceAll(s, sock, "<sock>")
		return strings.ReplaceAll(s, bad, "<bad>")
	}
	row := func(name, format string, args ...any) {
		fmt.Printf("%-18s %s\n", name, norm(fmt.Sprintf(format, args...)))
	}

	ln, err := net.Listen("unix", sock)
	row("listen_err", "%v", err)
	if err != nil {
		t.Fatal(err)
	}
	row("listen_network", "%s", ln.Addr().Network())
	row("listen_addr", "%s", ln.Addr().String())

	st, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	row("sockfile_is_sock", "%v", st.Mode()&os.ModeSocket != 0)

	// A second Listen on a live path: bind(2) refuses, Go surfaces it.
	ln2, err2 := net.Listen("unix", sock)
	row("listen_inuse", "%v", err2)
	if err2 == nil {
		ln2.Close()
	}

	done := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- "accept: " + err.Error()
			return
		}
		defer c.Close()
		done <- fmt.Sprintf("%q|%q", c.LocalAddr().String(), c.RemoteAddr().String())
		buf := make([]byte, 32)
		n, _ := c.Read(buf)
		c.Write([]byte("got:" + string(buf[:n])))
	}()

	c, err := net.Dial("unix", sock)
	row("dial_err", "%v", err)
	if err != nil {
		t.Fatal(err)
	}
	row("dial_network", "%s", c.RemoteAddr().Network())
	row("conn_local", "%q", c.LocalAddr().String())
	row("conn_remote", "%q", c.RemoteAddr().String())

	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := c.Read(buf)
	row("roundtrip", "%q", string(buf[:n]))
	srv := <-done
	row("srv_addrs", "%s", norm(srv))
	c.Close()

	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	_, serr := os.Stat(sock)
	row("close_unlinks", "%v", os.IsNotExist(serr))

	_, derr := net.Dial("unix", sock)
	row("dial_missing", "%v", derr)

	_, lerr := net.Listen("unix", bad)
	row("listen_baddir", "%v", lerr)
}
