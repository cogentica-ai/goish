package exec_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// LookPath decides WHICH binary runs. Everything about a program's
// behaviour follows from that answer, so the rules it applies are a
// security surface even though nothing in the API says so.
//
// The one that matters most is the newest. Go 1.19 changed LookPath to
// return ErrDot when a name resolves through a RELATIVE PATH entry —
// including the empty entry, which Unix shells read as "." — because
// running whatever happens to sit in the current directory is how a
// build tool becomes an arbitrary-code-execution vector
// (CVE-2022-30580 and its siblings). The path is still returned
// alongside the error, so a caller that has genuinely decided this is
// fine can proceed; one that checks the error, does not.
//
// The other rules are quieter but just as decisive: a name containing
// a slash is NOT searched for, it is tested where it stands; a
// directory is not an executable; a file without the execute bit is
// not found; and the empty name is refused before anything is touched.
//
// Everything runs against a PATH this test builds, so the answers do
// not depend on what the machine happens to have installed.
func TestGoishRef(t *testing.T) {
	base := t.TempDir()
	binDir := filepath.Join(base, "bin")
	otherDir := filepath.Join(base, "other")
	emptyDir := filepath.Join(base, "emptydir")
	for _, d := range []string{binDir, otherDir, emptyDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, mode os.FileMode) {
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(binDir, "tool"), 0o755)       // executable
	write(filepath.Join(binDir, "plain"), 0o644)      // not executable
	write(filepath.Join(otherDir, "tool"), 0o755)     // shadowed by binDir
	write(filepath.Join(otherDir, "only-other"), 0o755)
	if err := os.MkdirAll(filepath.Join(binDir, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A relative directory to exercise the ErrDot path: cwd is `base`,
	// so "reldir" is reachable relatively.
	relDir := filepath.Join(base, "reldir")
	os.MkdirAll(relDir, 0o755)
	write(filepath.Join(relDir, "reltool"), 0o755)
	write(filepath.Join(base, "cwdtool"), 0o755)

	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	if err := os.Chdir(base); err != nil {
		t.Fatal(err)
	}

	// The answer is reported relative to the temp dir so it is stable.
	norm := func(s string) string {
		s = strings.ReplaceAll(s, base+"/", "")
		return strings.ReplaceAll(s, base, "<tmp>")
	}
	show := func(label, path string, err error) {
		kind := "<nil>"
		if err != nil {
			kind = "other"
			switch {
			case errors.Is(err, exec.ErrDot):
				kind = "ErrDot"
			case errors.Is(err, exec.ErrNotFound):
				kind = "ErrNotFound"
			case errors.Is(err, os.ErrPermission):
				kind = "ErrPermission"
			}
		}
		fmt.Printf("look %-26s -> path=%-22q kind=%-13s err=%q\n",
			label, norm(path), kind, norm(errText(err)))
	}

	// 1. An absolute PATH with two directories: first match wins.
	os.Setenv("PATH", binDir+":"+otherDir)
	for _, name := range []string{
		"tool", "only-other", "plain", "adir", "missing", "",
		"./cwdtool", "cwdtool", "reldir/reltool", "/bin/sh",
		"/nonexistent/xyz", "bin/tool", "../base/bin/tool",
	} {
		p, err := exec.LookPath(name)
		show("abs-path:"+quoteEmpty(name), p, err)
	}

	// 2. A RELATIVE entry in PATH. Go finds the binary and returns it
	//    WITH ErrDot, so a caller that ignores the error runs whatever
	//    is in the current directory.
	os.Setenv("PATH", "reldir")
	for _, name := range []string{"reltool", "tool", "missing"} {
		p, err := exec.LookPath(name)
		show("rel-path:"+name, p, err)
	}

	// 3. The EMPTY PATH entry, which Unix shells read as "." — the
	//    same hazard spelled with nothing at all.
	os.Setenv("PATH", ":"+binDir)
	for _, name := range []string{"cwdtool", "tool"} {
		p, err := exec.LookPath(name)
		show("empty-entry:"+name, p, err)
	}
	os.Setenv("PATH", binDir+":")
	for _, name := range []string{"cwdtool", "tool"} {
		p, err := exec.LookPath(name)
		show("trailing-entry:"+name, p, err)
	}

	// 4. Degenerate PATHs.
	os.Setenv("PATH", "")
	for _, name := range []string{"tool", "cwdtool", "/bin/sh"} {
		p, err := exec.LookPath(name)
		show("empty-PATH:"+name, p, err)
	}
	os.Setenv("PATH", emptyDir)
	p, err := exec.LookPath("tool")
	show("empty-dir:tool", p, err)
	os.Setenv("PATH", "/no/such/dir:"+binDir)
	p, err = exec.LookPath("tool")
	show("missing-dir-first:tool", p, err)

	// 6. And the property that makes all of this matter: arguments are
	//    passed to the executable DIRECTLY. There is no shell, so a
	//    metacharacter is just a character.
	os.Setenv("PATH", "/usr/bin:/bin")
	for _, args := range [][]string{
		{"hello"},
		{"$HOME"},
		{"a; echo pwned"},
		{"a && echo pwned"},
		{"*"},
		{"`echo pwned`"},
		{"$(echo pwned)"},
		{"a\nb"},
		{"a b", "c"},
	} {
		var buf bytes.Buffer
		c := exec.Command("echo", args...)
		c.Stdout = &buf
		err := c.Run()
		fmt.Printf("noshell %-18q -> out=%q err=%s\n",
			strings.Join(args, "|"), buf.String(), errText(err))
	}
}

func quoteEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
