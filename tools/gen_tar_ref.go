package tar_test

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// archive/tar reads archives that arrived from somewhere else, and tar
// has a long history of the two failure modes that matter: a header
// that says one thing and a body that is another, and a Name that
// escapes the directory it is supposed to land in. Go's reader does not
// sanitise the Name — that is the caller's job, and a caller who does
// not know it is not sanitised will not do it — so what the reader must
// get right is reporting the header EXACTLY as written and refusing the
// archives that are structurally wrong.
//
// The rules worth pinning:
//
//   * The checksum is validated, and a header whose checksum does not
//     match is refused rather than used.
//   * A Name longer than 100 bytes needs USTAR's prefix field or a PAX
//     record, and the reader must reassemble it — a truncated Name is
//     how one tool writes a path another tool cannot find.
//   * PAX records override the USTAR header for the same field, which
//     is what makes long names and large sizes work at all.
//   * A traversing Name ("../etc/passwd") is returned VERBATIM. That is
//     Go's contract, and pinning it is the point: a port that silently
//     cleaned it would hide the hazard from callers who currently have
//     to handle it.
//   * Reading past the declared Size returns io.EOF, and the next
//     Next() skips to the following header regardless of how much of
//     the body was read.
//
// The archive bytes are printed as hex so the goish side parses the
// SAME bytes rather than bytes its own writer produced — otherwise a
// writer bug would mask a reader bug.
func TestGoishRef(t *testing.T) {
	type entry struct {
		hdr  *tar.Header
		body string
	}
	cases := []struct {
		name    string
		entries []entry
	}{
		{"simple", []entry{{&tar.Header{Name: "a.txt", Mode: 0644, Size: 5,
			ModTime: time.Unix(1000, 0), Typeflag: tar.TypeReg}, "hello"}}},
		{"two-files", []entry{
			{&tar.Header{Name: "a", Mode: 0600, Size: 1,
				ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}, "x"},
			{&tar.Header{Name: "b", Mode: 0755, Size: 3,
				ModTime: time.Unix(2000, 0), Typeflag: tar.TypeReg}, "yyy"},
		}},
		{"empty-file", []entry{{&tar.Header{Name: "empty", Mode: 0644, Size: 0,
			ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}, ""}}},
		{"dir", []entry{{&tar.Header{Name: "d/", Mode: 0755, Size: 0,
			ModTime: time.Unix(0, 0), Typeflag: tar.TypeDir}, ""}}},
		{"symlink", []entry{{&tar.Header{Name: "l", Linkname: "target",
			Mode: 0777, ModTime: time.Unix(0, 0), Typeflag: tar.TypeSymlink}, ""}}},
		{"long-name", []entry{{&tar.Header{Name: strings.Repeat("d/", 60) + "f.txt",
			Mode: 0644, Size: 2, ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}, "hi"}}},
		{"traversal", []entry{{&tar.Header{Name: "../../etc/passwd", Mode: 0644,
			Size: 3, ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}, "bad"}}},
		{"abs-path", []entry{{&tar.Header{Name: "/etc/shadow", Mode: 0644,
			Size: 1, ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}, "z"}}},
		{"uid-gid", []entry{{&tar.Header{Name: "u", Mode: 0644, Size: 0,
			Uid: 1234, Gid: 5678, Uname: "alice", Gname: "staff",
			ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}, ""}}},
		{"big-size", []entry{{&tar.Header{Name: "big", Mode: 0644, Size: 8589934592,
			ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}, ""}}},
		{"pax-times", []entry{{&tar.Header{Name: "p", Mode: 0644, Size: 0,
			ModTime: time.Unix(1600000000, 123456789),
			AccessTime: time.Unix(1600000001, 0),
			ChangeTime: time.Unix(1600000002, 0), Typeflag: tar.TypeReg}, ""}}},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		w := tar.NewWriter(&buf)
		bad := false
		for _, e := range c.entries {
			if e.hdr.Size == 0 && e.body != "" {
				e.hdr.Size = int64(len(e.body))
			}
			if err := w.WriteHeader(e.hdr); err != nil {
				fmt.Printf("tar %-12s writeheader-err=%q\n", c.name, err.Error())
				bad = true
				break
			}
			if _, err := w.Write([]byte(e.body)); err != nil {
				fmt.Printf("tar %-12s write-err=%q\n", c.name, err.Error())
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		w.Close()
		fmt.Printf("archive %-12s hex=%s\n", c.name, hex.EncodeToString(buf.Bytes()))
		dumpParse(c.name, buf.Bytes())
	}

	// Malformed archives, built by hand — the cases no writer produces.
	{
		good := makeHeader("ok", 0)
		// A header whose checksum is wrong.
		badSum := append([]byte(nil), good...)
		badSum[148] = '9'
		dumpParse("bad-checksum", withEOF(badSum))
		fmt.Printf("archive %-12s hex=%s\n", "bad-checksum",
			hex.EncodeToString(withEOF(badSum)))

		// A header truncated mid-block.
		dumpParse("truncated-hdr", good[:300])
		fmt.Printf("archive %-12s hex=%s\n", "truncated-hdr",
			hex.EncodeToString(good[:300]))

		// A body shorter than the declared size.
		short := append(append([]byte(nil), makeHeader("short", 100)...), []byte("abc")...)
		dumpParse("short-body", short)
		fmt.Printf("archive %-12s hex=%s\n", "short-body", hex.EncodeToString(short))

		// All zeros: a valid empty archive.
		dumpParse("only-eof", make([]byte, 1024))
		fmt.Printf("archive %-12s hex=%s\n", "only-eof",
			hex.EncodeToString(make([]byte, 1024)))

		// Empty input.
		dumpParse("empty", nil)
		fmt.Printf("archive %-12s hex=%s\n", "empty", "")

		// A size field that is not octal.
		badSize := makeHeader("bs", 0)
		copy(badSize[124:136], []byte("zzzzzzzzzzz\x00"))
		fixChecksum(badSize)
		dumpParse("bad-size", withEOF(badSize))
		fmt.Printf("archive %-12s hex=%s\n", "bad-size",
			hex.EncodeToString(withEOF(badSize)))
	}
}

func dumpParse(name string, data []byte) {
	r := tar.NewReader(bytes.NewReader(data))
	for i := 0; i < 5; i++ {
		h, err := r.Next()
		if err == io.EOF {
			fmt.Printf("parse %-13s #%d -> EOF\n", name, i)
			return
		}
		if err != nil {
			fmt.Printf("parse %-13s #%d -> err=%q\n", name, i, err.Error())
			return
		}
		body, rerr := io.ReadAll(r)
		re := "<nil>"
		if rerr != nil {
			re = rerr.Error()
		}
		fmt.Printf("parse %-13s #%d -> name=%q type=%q size=%d mode=%o uid=%d gid=%d uname=%q link=%q body=%q rerr=%s\n",
			name, i, h.Name, string(rune(h.Typeflag)), h.Size, h.Mode, h.Uid,
			h.Gid, h.Uname, h.Linkname, body, re)
	}
}

// makeHeader builds a minimal v7 header block by hand.
func makeHeader(name string, size int64) []byte {
	b := make([]byte, 512)
	copy(b[0:100], name)
	copy(b[100:108], "0000644\x00")
	copy(b[108:116], "0000000\x00")
	copy(b[116:124], "0000000\x00")
	copy(b[124:136], fmt.Sprintf("%011o\x00", size))
	copy(b[136:148], "00000000000\x00")
	b[156] = '0'
	fixChecksum(b)
	return b
}

func fixChecksum(b []byte) {
	copy(b[148:156], "        ")
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

func withEOF(hdr []byte) []byte {
	out := append([]byte(nil), hdr...)
	return append(out, make([]byte, 1024)...)
}
